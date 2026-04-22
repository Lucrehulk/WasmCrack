use std::collections::HashMap;
use super::super::super::binary_parsing::sections_parser::Section;
use super::super::super::binary_parsing::bin_reader::BinReader;
use super::super::super::binary_parsing::wasm_manager::{WasmManager, TypeDef};
use super::super::super::constants::opcodes::*;
use super::super::super::constants::sub_opcodes::*;
use super::data_type::DataType;

pub struct Converter {
    pub code_section: Section,
    pub out_lines: Vec<String>,
    pub constants_byte_stream: Vec<u8>,
    pub constants_fns_ptrs: Vec<[usize; 2]>,
    pub func_calls: HashMap<String, Vec<(String, bool, String, usize)>>,
    pub func_crypto_stats: Vec<(String, usize, usize, usize, usize, usize, usize)>,
    pub func_store_ops: HashMap<String, Vec<(String, String, u32, String, usize)>>,
    pub func_stores_from_common_addrs: HashMap<String, HashMap<String, Vec<(u32, String, String)>>>,
    pub func_xor_stores: HashMap<String, Vec<[String; 4]>>,
    stack: Vec<DataType>,
    control_stack: Vec<(String, usize, usize, usize, usize, Vec<DataType>)>,
    label_ctr: usize,
    temp_ctr: usize
}

impl Converter {
    pub fn new(code_section: Section) -> Self {
        Self {
            code_section,
            out_lines: Vec::new(),
            constants_byte_stream: Vec::new(),
            constants_fns_ptrs: Vec::new(),
            func_calls: HashMap::new(),
            func_crypto_stats: Vec::new(),
            func_store_ops: HashMap::new(),
            func_stores_from_common_addrs: HashMap::new(),
            func_xor_stores: HashMap::new(),
            stack: Vec::new(),
            control_stack: Vec::new(),
            label_ctr: 0,
            temp_ctr: 0
        }
    }

    fn use_stack(&mut self, count: usize) -> Vec<DataType> {
        let floor = self.control_stack.last().map(|c| c.2.saturating_sub(c.4)).unwrap_or(0);
        
        let mut items = Vec::new();
        for _ in 0..count {
            if self.stack.len() > floor {
                if let Some(item) = self.stack.pop() {
                    items.push(item);
                } else {
                    // Push "0" if there is an underflow (obviously should not occur).
                    items.push(DataType::String { value: "0".to_string() });
                }
            } else {
                // Push "0" if there is an underflow (obviously should not occur).
                items.push(DataType::String { value: "0".to_string() });
            }
        }
        items.reverse();
        items
    }

    fn get_free_temp(&mut self) -> String {
        let mut used = Vec::new();
        
        for item in &self.stack {
            if let DataType::String { value } = item {
                if value.starts_with('t') {
                    if let Ok(num) = value[1..].parse::<usize>() {
                        used.push(num);
                    }
                }
            }
        }
        
        for ctrl in &self.control_stack {
            for item in &ctrl.5 {
                if let DataType::String { value } = item {
                    if value.starts_with('t') {
                        if let Ok(num) = value[1..].parse::<usize>() {
                            used.push(num);
                        }
                    }
                }
            }
        }
        
        let mut i = 0;
        loop {
            if !used.contains(&i) {
                if i >= self.temp_ctr {
                    self.temp_ctr = i + 1;
                }
                return format!("t{}", i);
            }
            i += 1;
        }
    }

    fn add_line(&mut self, line: String) {
        self.out_lines.push(line);
    }

    // For stack values that are references to data (variables, memory stores, etc.).
    // We may have to create holders if we enter a complicated control flow or overwrite the referrer.
    // This way if the original referrer is mutated, we still have access to the original stack value.
    fn create_holders_on_stack(&mut self) {
        for i in 0..self.stack.len() {
            let temp_name = self.get_free_temp();
            match &self.stack[i] {
                DataType::String { value: expr } => {
                    // If data is already a holder we do not need to create another holder for said holder.
                    if expr.starts_with("t") || expr.starts_with("b_") || expr.starts_with("lp_") {
                        continue;
                    }
                    // Skip safely if it is numerical (since it is not referred it cannot be mutated).
                    if expr.chars().all(|c| c.is_numeric() || c == '-' || c == '.') {
                        continue;
                    }
                    if expr == "NaN" || expr == "Infinity" || expr == "-Infinity" {
                        continue;
                    }
                    
                    // Assign a temp holder "t[temp#]" to safely hold our potentially at risk value on the stack.
                    let line = format!("\t\t{} = {};", temp_name, expr);
                    self.out_lines.push(line);
                    self.stack[i] = DataType::String { value: temp_name };
                },
                _ => continue, 
            }
        }
    }

    pub fn convert(&mut self, manager: &WasmManager) -> String {
        // We'll turn this into a function that instantiates a module, just like WASM does.
        self.add_line("function instantiate_wasm_module(wasm_imports) {".to_string());

        // Now the we write out a ton of lines for initializing things like memory, modules, etc.
        // I've tried to minify these as much as possible while letting them still remain legible,
        // As entire binary outputs can be very large.

        self.add_line("\tfunction get_import(mod, name) {".to_string());
        self.add_line("\t\tif (!wasm_imports || typeof wasm_imports[mod] === 'undefined' || typeof wasm_imports[mod][name] === 'undefined') { return undefined; }".to_string());
        self.add_line("\t\treturn wasm_imports[mod][name];".to_string());
        self.add_line("\t}".to_string());
        
        self.add_line("\t// Memory initialization".to_string());
        self.add_line("\t// Create Wasm ArrayBuffer and TypedArray views based on section 5 size".to_string());
        if !manager.import_memories.is_empty() {
            let (mod_name, name, _min, _max) = &manager.import_memories[0];
            self.add_line(format!("\tlet imported_memory = get_import(\"{}\", \"{}\");", mod_name, name));
        } else {
            self.add_line("\tlet imported_memory = undefined;".to_string());
        }

        self.add_line(format!("\tlet mem = imported_memory || new WebAssembly.Memory({{ initial: {} }});", manager.initial_memory_pages));
        self.add_line("\tlet dv, u8, i8, u16, i16, u32, i32, i64, f32, f64;".to_string());
        self.add_line("\tfunction upd_vw() {".to_string());
        self.add_line("\t\tlet b = mem.buffer;".to_string());
        self.add_line("\t\tdv = new DataView(b);".to_string());
        self.add_line("\t\tu8 = new Uint8Array(b); i8 = new Int8Array(b); u16 = new Uint16Array(b); i16 = new Int16Array(b); u32 = new Uint32Array(b); i32 = new Int32Array(b); i64 = new BigInt64Array(b); f32 = new Float32Array(b); f64 = new Float64Array(b);".to_string());
        self.add_line("\t}".to_string());
        self.add_line("\tupd_vw();".to_string());

        self.add_line("\tif (mem.grow) {".to_string());
        self.add_line("\t\tif (!mem.__grow_listeners) {".to_string());
        self.add_line("\t\t\tmem.__grow_listeners = [];".to_string());
        self.add_line("\t\t\tlet original_grow = mem.grow.bind(mem);".to_string());
        self.add_line("\t\t\tmem.grow = function(pages) {".to_string());
        self.add_line("\t\t\t\tlet res = original_grow(pages);".to_string());
        self.add_line("\t\t\t\tfor (let listener of mem.__grow_listeners) listener();".to_string());
        self.add_line("\t\t\t\treturn res;".to_string());
        self.add_line("\t\t\t};".to_string());
        self.add_line("\t\t}".to_string());
        self.add_line("\t\tmem.__grow_listeners.push(upd_vw);".to_string());
        self.add_line("\t}".to_string());
        self.add_line("\tlet grow_memory = (pages) => mem.grow(pages);".to_string());

        self.add_line("\t// Wasm operation helpers (for complex operations not directly in JS)".to_string());
        self.add_line("\tconst _rv_f32 = new Float32Array(1); const _rv_i32 = new Int32Array(_rv_f32.buffer); const _rv_f64 = new Float64Array(1); const _rv_i64 = new BigInt64Array(_rv_f64.buffer);".to_string());
        self.add_line("\tconst reinterpret_i32 = (x) => { _rv_f32[0] = x; return _rv_i32[0]; }; const reinterpret_f32 = (x) => { _rv_i32[0] = x; return _rv_f32[0]; }; const reinterpret_i64 = (x) => { _rv_f64[0] = x; return _rv_i64[0]; }; const reinterpret_f64 = (x) => { _rv_i64[0] = x; return _rv_f64[0]; };".to_string());
        self.add_line("\tconst ctz32 = (x) => 32 - Math.clz32(~x & (x - 1 | 0));".to_string());
        self.add_line("\tconst popcnt32 = (x) => { x -= ((x >>> 1) & 0x55555555); x = (x & 0x33333333) + ((x >>> 2) & 0x33333333); x = (x + (x >>> 4)) & 0x0f0f0f0f; x += (x >>> 8); x += (x >>> 16); return x & 0x3f; };".to_string());
        self.add_line("\tconst clz64 = (x) => { let n = BigInt.asUintN(64, x); let hi = Number(n >> 32n) >>> 0; if (hi !== 0) return BigInt(Math.clz32(hi)); let lo = Number(n & 0xFFFFFFFFn) >>> 0; return BigInt(32 + Math.clz32(lo)); };".to_string());
        self.add_line("\tconst ctz64 = (x) => { let n = BigInt.asUintN(64, x); if (n === 0n) return 64n; let lo = Number(n & 0xFFFFFFFFn) >>> 0; if (lo !== 0) return BigInt(ctz32(lo)); let hi = Number(n >> 32n) >>> 0; return BigInt(32 + ctz32(hi)); };".to_string());
        self.add_line("\tconst _m1 = 0x5555555555555555n; const _m2 = 0x3333333333333333n; const _m4 = 0x0f0f0f0f0f0f0f0fn; const _h01 = 0x0101010101010101n;".to_string());
        self.add_line("\tconst popcnt64 = (x) => { let n = BigInt.asUintN(64, x); n -= (n >> 1n) & _m1; n = (n & _m2) + ((n >> 2n) & _m2); n = (n + (n >> 4n)) & _m4; return (n * _h01) >> 56n; };".to_string());
        self.add_line("\tconst rotl64 = (x, y) => { let s = BigInt.asUintN(64, y) & 63n; let n = BigInt.asUintN(64, x); return BigInt.asIntN(64, (n << s) | (n >> (64n - s))); };".to_string());
        self.add_line("\tconst rotr64 = (x, y) => { let s = BigInt.asUintN(64, y) & 63n; let n = BigInt.asUintN(64, x); return BigInt.asIntN(64, (n >> s) | (n << (64n - s))); };".to_string());
        self.add_line("\tconst nearest = (x) => { let f = Math.floor(x); let r = x - f; if (r < 0.5) return f; if (r > 0.5) return f + 1; return f % 2 === 0 ? f : f + 1; };".to_string());
        self.add_line("\tconst trunc_sat_i32_s = (x) => Number.isNaN(x) ? 0 : Math.max(-2147483648, Math.min(2147483647, Math.trunc(x))) | 0;".to_string());
        self.add_line("\tconst trunc_sat_i32_u = (x) => Number.isNaN(x) ? 0 : Math.max(0, Math.min(4294967295, Math.trunc(x))) | 0;".to_string());
        self.add_line("\tconst trunc_sat_i64_s = (x) => Number.isNaN(x) ? 0n : x >= 9223372036854775808 ? 9223372036854775807n : x <= -9223372036854775808 ? -9223372036854775808n : BigInt(Math.trunc(x));".to_string());
        self.add_line("\tconst trunc_sat_i64_u = (x) => Number.isNaN(x) || x <= 0 ? 0n : x >= 18446744073709551616 ? -1n : BigInt.asIntN(64, BigInt(Math.trunc(x)));".to_string());
        self.add_line("\tconst fround = Math.fround, trunc = Math.trunc, imul = Math.imul, clz32 = Math.clz32, abs = Math.abs, ceil = Math.ceil, floor = Math.floor, min = Math.min, max = Math.max;".to_string());
        self.add_line("\tconst asI64 = (x) => BigInt.asIntN(64, x), asU64 = (x) => BigInt.asUintN(64, x), asI32 = (x) => BigInt.asIntN(32, x), asI16 = (x) => BigInt.asIntN(16, x), asI8 = (x) => BigInt.asIntN(8, x);".to_string());

        for id in 0..manager.import_funcs_count {
            if let Some((mod_name, name)) = manager.import_names.get(&id) {
                self.add_line(format!("\tlet import_{} = get_import(\"{}\", \"{}\");", id, mod_name, name));
            }
        }

        self.add_line("\t// Globals".to_string());
        for (i, (mod_name, name, _val_type, _mut)) in manager.import_globals.iter().enumerate() {
            self.add_line(format!("\tlet ig_{} = get_import(\"{}\", \"{}\");", i, mod_name, name));
            self.add_line(format!("\tlet g{} = (ig_{} != null && typeof ig_{} === 'object' && 'value' in ig_{}) ? ig_{}.value : (ig_{} !== undefined ? ig_{} : 0);", i, i, i, i, i, i, i));
        }
        for (i, (_val_type, _mut, init_val)) in manager.globals.iter().enumerate() {
            let global_id = manager.import_globals.len() + i;
            self.add_line(format!("\tlet g{} = {};", global_id, init_val));
        }

        self.add_line("\t// Tables".to_string());
        let total_tables = manager.import_tables.len() + manager.tables.len();
        if total_tables > 0 {
            if !manager.import_tables.is_empty() {
                let (mod_name, name, _min, _max) = &manager.import_tables[0];
                self.add_line(format!("\tlet imported_table = get_import(\"{}\", \"{}\");", mod_name, name));
                self.add_line("\tlet table = imported_table || new Array(0);".to_string());
            } else {
                let initial_size = manager.tables.first().map(|t| t.1).unwrap_or(0);
                self.add_line(format!("\tlet table = new Array({});", initial_size));
            }
            self.add_line("\tif (!table.get) { table.get = function(i) { return this[i]; }; table.set = function(i, v) { this[i] = v; }; }".to_string());
        } else {
            self.add_line("\tlet table = new Array(0); table.get = function(i) { return this[i]; }; table.set = function(i, v) { this[i] = v; };".to_string());
        }

        self.add_line("\t// Data segments".to_string());
        self.add_line("\t// Initialize static data directly into the u8 array".to_string());
        if !manager.data_segments.is_empty() {
            for (id, (is_active, offset, data)) in manager.data_segments.iter().enumerate() {
                let data_str = data.iter().map(|b| b.to_string()).collect::<Vec<_>>().join(",");
                self.add_line(format!("\tlet d{} = new Uint8Array([{}]);", id, data_str));
                if *is_active {
                    self.add_line(format!("\tu8.set(d{}, ({}) >>> 0);", id, offset));
                }
            }
        }
        
        self.add_line("\t// Functions".to_string());
        let mut reader = BinReader::new(self.code_section.data.clone());
        let functions_count = reader.read_u32().unwrap_or(0);

        // Parse each function definition.
        for i in 0..functions_count {
            let body_size = reader.read_u32().unwrap_or(0);
            let end_addr = reader.addr + body_size as usize;
            
            let local_vec_size = reader.read_u32().unwrap_or(0);
            let mut locals_types = Vec::new();
            for _ in 0..local_vec_size {
                let count = reader.read_u32().unwrap_or(0);
                let val_type = reader.read_byte().unwrap_or(0);
                for _ in 0..count {
                    locals_types.push(val_type);
                }
            }

            // Get func metadata via WasmManager.
            let func_id = manager.import_funcs_count + i as usize;
            let type_id = *manager.func_type_indices.get(func_id).unwrap_or(&0);
            let signature = manager.types.get(type_id).cloned().unwrap_or(TypeDef { params: 0, returns: 0 });
            let func_name = manager.parse_func_name(func_id);

            let mut param_names = Vec::new();
            for params in 0..signature.params {
                param_names.push(format!("l{}", params));
            }

            // Write function declaration lines.
            let func_body_start_id = self.out_lines.len();
            self.add_line(format!("\tlet {} = function({}) {{", func_name, param_names.join(", ")));
            
            for (i, v_type) in locals_types.iter().enumerate() {
                let l = signature.params + i;
                if *v_type == 0x7E { 
                    self.add_line(format!("\t\tvar l{} = 0n;", l));
                } else {
                    self.add_line(format!("\t\tvar l{} = 0;", l));
                }
            }

            // For each func we can clear the stacks and ctrs, each func is a fresh new scope.
            self.stack.clear();
            self.control_stack.clear();
            self.label_ctr = 0;
            self.temp_ctr = 0; 
            
            let func_block_label = self.label_ctr;
            self.label_ctr += 1;
            self.control_stack.push(("BLOCK".to_string(), func_block_label, 0, signature.returns, 0, Vec::new()));
            if signature.returns > 0 {
                for i in 0..signature.returns {
                    self.add_line(format!("\t\tvar b_{}_{} = 0;", func_block_label, i));
                }
            }
            self.add_line(format!("\t\tL_{}: {{", func_block_label));

            // Track certain func info, and certain operation counts for external features.
            let mut current_func_is_in_loop = usize::MAX;
            let mut ops_count = 0;
            let mut rot_and_sh_ops_count = 0;
            let mut xor_ops_count = 0;
            let mut computation_ops_count = 0;
            let mut load_ops_count = 0;
            let mut store_ops_count = 0;
            let mut current_func_calls = Vec::new();
            let mut current_func_store_ops = Vec::new();
            let mut current_func_stores_from_common_addrs = HashMap::new();
            let mut current_xor_stores = Vec::new();
            let mut xor_last_op = 0;
            
            // Store i32 and i64 consts we locate seperately, we'll merge these in order 64->32 
            // and track a ptr, For where i64 ends, allowing us to easily parse 32 vs. 64 byte words.
            // This will actually be used in separate tools (i.e. the magic evaluator)
            // To reduce redundant calculations, we'll do it here. 
            let mut i32_consts = Vec::new();
            let mut i64_consts = Vec::new();

            // Manage opcodes and whatnot in a large match.
            while reader.addr < end_addr {
                let opcode = reader.read_byte().unwrap_or(0);
                ops_count += 1;

                // xor_last_op works on an increment system. Base is when it is at 0. When a xor op is detected, it becomes one.
                // We need to let the end of this iteration finish though, before marking it as xor about to not be the last op.
                // So we wait until it comes back to this start of the loop, and then increment it to two. If it is two at the end,
                // Then we set it back to 0.
                if xor_last_op == 1 {
                    xor_last_op = 2;
                }

                match opcode {
                    NOP => {
                        self.add_line("\t\t// NOP".to_string());
                    }
                    BLOCK => {
                        let blocktype = reader.read_i32().unwrap_or(0);
                        let returns = if blocktype == -64 { 0 } else if blocktype < 0 { 1 } else { manager.types.get(blocktype as usize).map(|t| t.returns).unwrap_or(0) };
                        let params = if blocktype >= 0 { manager.types.get(blocktype as usize).map(|t| t.params).unwrap_or(0) } else { 0 };
                        let current_label = self.label_ctr;
                        self.label_ctr += 1;
                        
                        self.create_holders_on_stack();
                        let mut param_values = Vec::new();
                        if params > 0 {
                            let start_id = self.stack.len().saturating_sub(params);
                            param_values = self.stack[start_id..].to_vec();
                        }

                        if returns > 0 {
                            for i in 0..returns {
                                self.add_line(format!("\t\tvar b_{}_{};", current_label, i));
                            }
                        }
                        
                        self.control_stack.push(("BLOCK".to_string(), current_label, self.stack.len(), returns, params, param_values));
                        self.add_line(format!("\t\tL_{}: {{", current_label));
                    }
                    LOOP => {
                        let blocktype = reader.read_i32().unwrap_or(0);
                        let returns = if blocktype == -64 { 0 } else if blocktype < 0 { 1 } else { manager.types.get(blocktype as usize).map(|t| t.returns).unwrap_or(0) };
                        let params = if blocktype >= 0 { manager.types.get(blocktype as usize).map(|t| t.params).unwrap_or(0) } else { 0 };
                        let current_label = self.label_ctr;
                        self.label_ctr += 1;
                        
                        self.create_holders_on_stack();
                        let mut param_values = Vec::new();
                        if params > 0 {
                            let start_id = self.stack.len().saturating_sub(params);
                            for i in 0..params {
                                let loop_var = format!("lp_{}_{}", current_label, i);
                                let val = self.stack[start_id + i].to_string();
                                self.add_line(format!("\t\tvar {} = {};", loop_var, val));
                                param_values.push(DataType::String { value: loop_var });
                            }
                            for i in 0..params {
                                self.stack[start_id + i] = param_values[i].clone();
                            }
                        }

                        if returns > 0 {
                            for i in 0..returns {
                                self.add_line(format!("\t\tvar b_{}_{};", current_label, i));
                            }
                        }
                        
                        self.control_stack.push(("LOOP".to_string(), current_label, self.stack.len(), returns, params, param_values));
                        self.add_line(format!("\t\tL_{}: while (true) {{", current_label));
                        if current_func_is_in_loop == usize::MAX {
                            current_func_is_in_loop = current_label;
                        }
                    }
                    IF => {
                        let blocktype = reader.read_i32().unwrap_or(0);
                        let returns = if blocktype == -64 { 0 } else if blocktype < 0 { 1 } else { manager.types.get(blocktype as usize).map(|t| t.returns).unwrap_or(0) };
                        let params = if blocktype >= 0 { manager.types.get(blocktype as usize).map(|t| t.params).unwrap_or(0) } else { 0 };
                        let current_label = self.label_ctr;
                        self.label_ctr += 1;
                        
                        self.create_holders_on_stack();
                        let condition_param = self.use_stack(1);
                        self.create_holders_on_stack();
                        
                        let mut param_values = Vec::new();
                        if params > 0 {
                            let start_id = self.stack.len().saturating_sub(params);
                            param_values = self.stack[start_id..].to_vec();
                        }

                        if returns > 0 {
                            for i in 0..returns {
                                let default_val = if i < params { param_values[i].to_string() } else { "0".to_string() };
                                self.add_line(format!("\t\tvar b_{}_{} = {};", current_label, i, default_val));
                            }
                        }
                        
                        self.control_stack.push(("IF".to_string(), current_label, self.stack.len(), returns, params, param_values));
                        self.add_line(format!("\t\tL_{}: if ({}) {{", current_label, condition_param[0].to_string()));
                    }
                    ELSE => {
                        if let Some(last_id) = self.control_stack.len().checked_sub(1) {
                            let (label, depth, returns, _params, param_values) = {
                                let (_, label, depth, returns, params, param_values) = &self.control_stack[last_id];
                                (*label, *depth, *returns, *params, param_values.clone())
                            };

                            let popped = self.use_stack(returns);
                            for (i, val) in popped.iter().enumerate() {
                                let temp_name = format!("b_{}_{}", label, i);
                                self.add_line(format!("\t\t{} = {};", temp_name, val.to_string()));
                            }

                            let final_depth = depth.saturating_sub(_params);
                            self.stack.truncate(final_depth);
                            for p in param_values {
                                self.stack.push(p);
                            }

                            if let Some(control_entry) = self.control_stack.get_mut(last_id) {
                                control_entry.0 = "ELSE".to_string();
                            }
                            
                            self.add_line("\t\t} else {".to_string());
                        } else {
                            self.add_line("\t\t} else {".to_string());
                        }
                    }
                    BR => {
                        let depth = reader.read_u32().unwrap_or(0) as usize;
                        let target_id = self.control_stack.len().saturating_sub(1).saturating_sub(depth);
                        self.create_holders_on_stack();
                        
                        if let Some(target_info) = self.control_stack.get(target_id) {
                            let control_structure = target_info.0.clone();
                            let label = target_info.1;
                            let returns = target_info.3;
                            let params = target_info.4;
                            let param_values = target_info.5.clone();

                            if control_structure == "LOOP" {
                                let yielded_count = params;
                                if yielded_count > 0 {
                                    for i in 0..yielded_count {
                                        let val_id = self.stack.len().saturating_sub(yielded_count).saturating_add(i);
                                        let holder = DataType::String { value: "0".to_string() };
                                        let val_str = self.stack.get(val_id).unwrap_or(&holder).to_string();
                                        let target_var = param_values[i].to_string();
                                        self.add_line(format!("\t\t{} = {};", target_var, val_str));
                                    }
                                }
                                self.add_line(format!("\t\tcontinue L_{};", label));
                            } else {
                                let yielded_count = returns;
                                if yielded_count > 0 {
                                    for i in 0..yielded_count {
                                        let val_id = self.stack.len().saturating_sub(yielded_count).saturating_add(i);
                                        let holder = DataType::String { value: "0".to_string() };
                                        let val_str = self.stack.get(val_id).unwrap_or(&holder).to_string();
                                        let temp_name = format!("b_{}_{}", label, i);
                                        self.add_line(format!("\t\t{} = {};", temp_name, val_str));
                                    }
                                }
                                self.add_line(format!("\t\tbreak L_{};", label));
                            }
                        }
                    }
                    BR_IF => {
                        let depth = reader.read_u32().unwrap_or(0) as usize;
                        let target_id = self.control_stack.len().saturating_sub(1).saturating_sub(depth);
                        self.create_holders_on_stack();
                        let cond = self.use_stack(1);
                        
                        if let Some(target_info) = self.control_stack.get(target_id) {
                            let control_structure = target_info.0.clone();
                            let label = target_info.1;
                            let returns = target_info.3;
                            let params = target_info.4;
                            let param_values = target_info.5.clone();

                            let condition_str = cond[0].to_string();

                            if control_structure == "LOOP" {
                                let yielded_count = params;
                                if yielded_count > 0 {
                                    self.add_line(format!("\t\tif ({}) {{", condition_str));
                                    for i in 0..yielded_count {
                                        let val_id = self.stack.len().saturating_sub(yielded_count).saturating_add(i);
                                        let holder = DataType::String { value: "0".to_string() };
                                        let val_str = self.stack.get(val_id).unwrap_or(&holder).to_string();
                                        let target_var = param_values[i].to_string();
                                        self.add_line(format!("\t\t\t{} = {};", target_var, val_str));
                                    }
                                    self.add_line(format!("\t\t\tcontinue L_{};", label));
                                    self.add_line("\t\t}".to_string());
                                } else {
                                    self.add_line(format!("\t\tif ({}) continue L_{};", condition_str, label));
                                }
                            } else {
                                let yielded_count = returns;
                                if yielded_count > 0 {
                                    self.add_line(format!("\t\tif ({}) {{", condition_str));
                                    for i in 0..yielded_count {
                                        let val_id = self.stack.len().saturating_sub(yielded_count).saturating_add(i);
                                        let holder = DataType::String { value: "0".to_string() };
                                        let val_str = self.stack.get(val_id).unwrap_or(&holder).to_string();
                                        let temp_name = format!("b_{}_{}", label, i);
                                        self.add_line(format!("\t\t\t{} = {};", temp_name, val_str));
                                    }
                                    self.add_line(format!("\t\t\tbreak L_{};", label));
                                    self.add_line("\t\t}".to_string());
                                } else {
                                    self.add_line(format!("\t\tif ({}) break L_{};", condition_str, label));
                                }
                            }
                        }
                    }
                    BR_TABLE => {
                        let count = reader.read_u32().unwrap_or(0);
                        let mut labels = Vec::new();
                        for _ in 0..count {
                            labels.push(reader.read_u32().unwrap_or(0) as usize);
                        }
                        let default_depth = reader.read_u32().unwrap_or(0) as usize;
                        self.create_holders_on_stack();
                        let condition_params = self.use_stack(1);
                        
                        self.add_line(format!("\t\tswitch (({}) >>> 0) {{", condition_params[0].to_string()));
                        for (id, depth) in labels.iter().enumerate() {
                            let target_id = self.control_stack.len().saturating_sub(1).saturating_sub(*depth);
                            self.add_line(format!("\t\t    case {}:", id));
                            if let Some(target_info) = self.control_stack.get(target_id) {
                                let control_structure = target_info.0.clone();
                                let label = target_info.1;
                                let returns = target_info.3;
                                let params = target_info.4;
                                let param_values = target_info.5.clone();

                                if control_structure == "LOOP" {
                                    let yielded_count = params;
                                    if yielded_count > 0 {
                                        for i in 0..yielded_count {
                                            let val_id = self.stack.len().saturating_sub(yielded_count).saturating_add(i);
                                            let holder = DataType::String { value: "0".to_string() };
                                            let val_str = self.stack.get(val_id).unwrap_or(&holder).to_string();
                                            let target_var = param_values[i].to_string();
                                            self.add_line(format!("\t\t        {} = {};", target_var, val_str));
                                        }
                                    }
                                    self.add_line(format!("\t\t        continue L_{};", label));
                                } else {
                                    let yielded_count = returns;
                                    if yielded_count > 0 {
                                        for i in 0..yielded_count {
                                            let val_id = self.stack.len().saturating_sub(yielded_count).saturating_add(i);
                                            let holder = DataType::String { value: "0".to_string() };
                                            let val_str = self.stack.get(val_id).unwrap_or(&holder).to_string();
                                            let temp_name = format!("b_{}_{}", label, i);
                                            self.add_line(format!("\t\t        {} = {};", temp_name, val_str));
                                        }
                                    }
                                    self.add_line(format!("\t\t        break L_{};", label));
                                }
                            }
                        }
                        
                        let target_id = self.control_stack.len().saturating_sub(1).saturating_sub(default_depth);
                        self.add_line("\t\t    default:".to_string());
                        if let Some(target_info) = self.control_stack.get(target_id) {
                            let control_structure = target_info.0.clone();
                            let label = target_info.1;
                            let returns = target_info.3;
                            let params = target_info.4;
                            let param_values = target_info.5.clone();

                            if control_structure == "LOOP" {
                                let yielded_count = params;
                                if yielded_count > 0 {
                                    for i in 0..yielded_count {
                                        let val_id = self.stack.len().saturating_sub(yielded_count).saturating_add(i);
                                        let holder = DataType::String { value: "0".to_string() };
                                        let val_str = self.stack.get(val_id).unwrap_or(&holder).to_string();
                                        let target_var = param_values[i].to_string();
                                        self.add_line(format!("\t\t        {} = {};", target_var, val_str));
                                    }
                                }
                                self.add_line(format!("\t\t        continue L_{};", label));
                            } else {
                                let yielded_count = returns;
                                if yielded_count > 0 {
                                    for i in 0..yielded_count {
                                        let val_id = self.stack.len().saturating_sub(yielded_count).saturating_add(i);
                                        let holder = DataType::String { value: "0".to_string() };
                                        let val_str = self.stack.get(val_id).unwrap_or(&holder).to_string();
                                        let temp_name = format!("b_{}_{}", label, i);
                                        self.add_line(format!("\t\t        {} = {};", temp_name, val_str));
                                    }
                                }
                                self.add_line(format!("\t\t        break L_{};", label));
                            }
                        }
                        self.add_line("\t\t}".to_string());
                    }
                    CALL => {
                        let fn_id = reader.read_u32().unwrap_or(0) as usize;
                        let target_type_id = *manager.func_type_indices.get(fn_id).unwrap_or(&0);
                        let target_signature = manager.types.get(target_type_id).cloned().unwrap_or(TypeDef { params: 0, returns: 0 });
                        
                        self.create_holders_on_stack(); 
                        let args = self.use_stack(target_signature.params);
                        let string_args = args.iter().map(|a| a.to_string()).collect::<Vec<_>>().join(", ");
                        
                        let called_name = manager.parse_func_name(fn_id);
                        current_func_calls.push((called_name.clone(), self.control_stack.len() == 0, string_args.clone(), current_func_is_in_loop));
                        
                        let call_expr = format!("{}({})", called_name, string_args);
                        if target_signature.returns > 0 {
                            let temp_name = self.get_free_temp();
                            self.add_line(format!("\t\t{} = {};", temp_name, call_expr));
                            self.stack.push(DataType::String { value: temp_name });
                        } else {
                            self.add_line(format!("\t\t{};", call_expr));
                        }
                    }
                    CALL_INDIRECT => {
                        let target_type_id = reader.read_u32().unwrap_or(0) as usize;
                        let _table_id = reader.read_u32().unwrap_or(0);
                        let target_signature = manager.types.get(target_type_id).cloned().unwrap_or(TypeDef { params: 0, returns: 0 });
                        
                        self.create_holders_on_stack(); 
                        let mut all_args = self.use_stack(target_signature.params + 1);
                        
                        let table_id_arg = all_args.pop().map(|a| a.to_string()).unwrap_or_else(|| "0".to_string());
                        let string_all_args = all_args.iter().map(|a| a.to_string()).collect::<Vec<_>>().join(", ");
                        
                        current_func_calls.push(("INDIRECT CALL".to_string(), self.control_stack.len() == 0, string_all_args.clone(), current_func_is_in_loop));
                        
                        let call_expr = format!("table.get(({}) >>> 0)({})", table_id_arg, string_all_args);
                        if target_signature.returns > 0 {
                            let temp_name = self.get_free_temp();
                            self.add_line(format!("\t\t{} = {};", temp_name, call_expr));
                            self.stack.push(DataType::String { value: temp_name });
                        } else {
                            self.add_line(format!("\t\t{};", call_expr));
                        }
                    }
                    DROP => { 
                        self.use_stack(1);
                    }
                    SELECT => {
                        let params = self.use_stack(3);
                        self.stack.push(DataType::String { value: format!("({} ? {} : {})", params[2].to_string(), params[0].to_string(), params[1].to_string()) });
                    }
                    UNREACHABLE => { 
                        self.add_line("\t\tthrow Error(\"unreachable\");".to_string());
                    }
                    RETURN => {
                        if signature.returns > 0 && !self.stack.is_empty() {
                            self.create_holders_on_stack();
                            let params = self.use_stack(1);
                            self.add_line(format!("\t\treturn {};", params[0].to_string()));
                        } else {
                            self.add_line("\t\treturn;".to_string());
                        }
                    }
                    END => {
                        if let Some((control_type, label, depth, returns, params, _param_values)) = self.control_stack.pop() {
                            let yielded_count = returns;
                            let popped = self.use_stack(yielded_count);
                            
                            let mut yielded_temps = Vec::new();
                            for (i, val) in popped.iter().enumerate() {
                                let temp_name = format!("b_{}_{}", label, i);
                                self.add_line(format!("\t\t{} = {};", temp_name, val.to_string()));
                                yielded_temps.push(DataType::String { value: temp_name });
                            }

                            let final_depth = depth.saturating_sub(params);
                            self.stack.truncate(final_depth);

                            match control_type.as_str() {
                                "LOOP" => {
                                    self.add_line(format!("\t\tbreak L_{};", label));
                                    self.add_line("\t\t}".to_string());
                                    if label == current_func_is_in_loop {
                                        current_func_is_in_loop = usize::MAX;
                                    }
                                }
                                "IF" | "ELSE" | "BLOCK" => {
                                    self.add_line("\t\t}".to_string());
                                }
                                _ => {}
                            }
                            
                            for temp in yielded_temps {
                                self.stack.push(temp);
                            }
                        }
                    }
                    I32_CONST => {
                        let val = reader.read_i32().unwrap_or(0);
                        self.stack.push(DataType::Int32 { value: val });
                        i32_consts.extend_from_slice(&val.to_le_bytes());
                    }
                    I64_CONST => {
                        let val = reader.read_i64().unwrap_or(0);
                        self.stack.push(DataType::Int64 { value: val });
                        i64_consts.extend_from_slice(&val.to_le_bytes());
                    }
                    F32_CONST => {
                        let val = reader.read_f32().unwrap_or(0.0);
                        self.stack.push(DataType::Float32 { value: val }); 
                    }
                    F64_CONST => {
                        let val = reader.read_f64().unwrap_or(0.0);
                        self.stack.push(DataType::Float64 { value: val });
                    }
                    LOCAL_GET => {
                        let local_id = reader.read_u32().unwrap_or(0);
                        self.stack.push(DataType::String { value: format!("l{}", local_id) });
                    }
                    LOCAL_SET => {
                        let local_id = reader.read_u32().unwrap_or(0);
                        self.create_holders_on_stack();
                        let params = self.use_stack(1);
                        self.add_line(format!("\t\tl{} = {};", local_id, params[0].to_string()));
                    }
                    LOCAL_TEE => {
                        let local_id = reader.read_u32().unwrap_or(0);
                        self.create_holders_on_stack();
                        let params = self.use_stack(1);
                        self.add_line(format!("\t\tl{} = {};", local_id, params[0].to_string()));
                        self.stack.push(DataType::String { value: format!("l{}", local_id) });
                    }
                    GLOBAL_GET => {
                        let global_id = reader.read_u32().unwrap_or(0) as usize;
                        if global_id < manager.import_globals.len() {
                            self.stack.push(DataType::String { 
                                value: format!("(ig_{} !== null && typeof ig_{} === 'object' && 'value' in ig_{} ? ig_{}.value : g{})", global_id, global_id, global_id, global_id, global_id) 
                            });
                        } else {
                            self.stack.push(DataType::String { value: format!("g{}", global_id) });
                        }
                    }
                    GLOBAL_SET => {
                        let global_id = reader.read_u32().unwrap_or(0) as usize;
                        self.create_holders_on_stack();
                        let params = self.use_stack(1);
                        if global_id < manager.import_globals.len() {
                            self.add_line(format!("\t\tif (ig_{} !== null && typeof ig_{} === 'object' && 'value' in ig_{}) {{ ig_{}.value = {}; }} else {{ g{} = {}; }}", global_id, global_id, global_id, global_id, params[0].to_string(), global_id, params[0].to_string()));
                        } else {
                            self.add_line(format!("\t\tg{} = {};", global_id, params[0].to_string()));
                        }
                    }
                    I32_WRAP_I64 => { 
                        let params = self.use_stack(1);
                        self.stack.push(params[0].simplify_data_type("wrap_i32", "Number(asI32({0}))", &mut i32_consts, &mut i64_consts)); 
                    }
                    I64_EXTEND_I32_S => { 
                        let params = self.use_stack(1);
                        self.stack.push(params[0].simplify_data_type("extend_i64_s", "BigInt(({0}) | 0)", &mut i32_consts, &mut i64_consts)); 
                    }
                    I64_EXTEND_I32_U => { 
                        let params = self.use_stack(1);
                        self.stack.push(params[0].simplify_data_type("extend_i64_u", "BigInt(({0}) >>> 0)", &mut i32_consts, &mut i64_consts)); 
                    }
                    F32_DEMOTE_F64 => { 
                        let params = self.use_stack(1);
                        self.stack.push(params[0].simplify_data_type("demote_f32", "fround({0})", &mut i32_consts, &mut i64_consts)); 
                    }
                    F64_PROMOTE_F32 => { 
                        let params = self.use_stack(1);
                        self.stack.push(params[0].simplify_data_type("promote_f64", "{0}", &mut i32_consts, &mut i64_consts)); 
                    }
                    I32_EQZ => { 
                        let params = self.use_stack(1);
                        self.stack.push(params[0].simplify_data_type("eqz", "(({0}) === 0 ? 1 : 0)", &mut i32_consts, &mut i64_consts));
                    }
                    I32_EQ => { 
                        let params = self.use_stack(2);
                        self.stack.push(params[0].combine_data(&params[1], "==", "(({0}) === ({1}) ? 1 : 0)", &mut i32_consts, &mut i64_consts));
                    }
                    I32_NE => { 
                        let params = self.use_stack(2);
                        self.stack.push(params[0].combine_data(&params[1], "!=", "(({0}) !== ({1}) ? 1 : 0)", &mut i32_consts, &mut i64_consts));
                    }
                    I32_LT_S => { 
                        let params = self.use_stack(2);
                        self.stack.push(params[0].combine_data(&params[1], "<s", "(({0}) < ({1}) ? 1 : 0)", &mut i32_consts, &mut i64_consts));
                    }
                    I32_LT_U => { 
                        let params = self.use_stack(2);
                        self.stack.push(params[0].combine_data(&params[1], "<u", "((({0}) >>> 0) < (({1}) >>> 0) ? 1 : 0)", &mut i32_consts, &mut i64_consts));
                    }
                    I32_GT_S => { 
                        let params = self.use_stack(2);
                        self.stack.push(params[0].combine_data(&params[1], ">s", "(({0}) > ({1}) ? 1 : 0)", &mut i32_consts, &mut i64_consts));
                    }
                    I32_GT_U => { 
                        let params = self.use_stack(2);
                        self.stack.push(params[0].combine_data(&params[1], ">u", "((({0}) >>> 0) > (({1}) >>> 0) ? 1 : 0)", &mut i32_consts, &mut i64_consts));
                    }
                    I32_LE_S => { 
                        let params = self.use_stack(2);
                        self.stack.push(params[0].combine_data(&params[1], "<=s", "(({0}) <= ({1}) ? 1 : 0)", &mut i32_consts, &mut i64_consts));
                    }
                    I32_LE_U => { 
                        let params = self.use_stack(2);
                        self.stack.push(params[0].combine_data(&params[1], "<=u", "((({0}) >>> 0) <= (({1}) >>> 0) ? 1 : 0)", &mut i32_consts, &mut i64_consts));
                    }
                    I32_GE_S => { 
                        let params = self.use_stack(2);
                        self.stack.push(params[0].combine_data(&params[1], ">=s", "(({0}) >= ({1}) ? 1 : 0)", &mut i32_consts, &mut i64_consts));
                    }
                    I32_GE_U => { 
                        let params = self.use_stack(2);
                        self.stack.push(params[0].combine_data(&params[1], ">=u", "((({0}) >>> 0) >= (({1}) >>> 0) ? 1 : 0)", &mut i32_consts, &mut i64_consts));
                    }
                    I32_CLZ => { 
                        computation_ops_count += 1;
                        let params = self.use_stack(1); 
                        self.stack.push(params[0].simplify_data_type("clz", "clz32({0})", &mut i32_consts, &mut i64_consts));
                    }
                    I32_CTZ => { 
                        computation_ops_count += 1;
                        let params = self.use_stack(1); 
                        self.stack.push(params[0].simplify_data_type("ctz", "ctz32({0})", &mut i32_consts, &mut i64_consts));
                    }
                    I32_POPCNT => { 
                        computation_ops_count += 1;
                        let params = self.use_stack(1); 
                        self.stack.push(params[0].simplify_data_type("popcnt", "popcnt32({0})", &mut i32_consts, &mut i64_consts));
                    }
                    I32_ADD => { 
                        computation_ops_count += 1;
                        let params = self.use_stack(2); 
                        self.stack.push(params[0].combine_data(&params[1], "+", "(({0}) + ({1}) | 0)", &mut i32_consts, &mut i64_consts));
                    }
                    I32_SUB => { 
                        computation_ops_count += 1;
                        let params = self.use_stack(2); 
                        self.stack.push(params[0].combine_data(&params[1], "-", "(({0}) - ({1}) | 0)", &mut i32_consts, &mut i64_consts));
                    }
                    I32_MUL => { 
                        computation_ops_count += 1;
                        let params = self.use_stack(2); 
                        self.stack.push(params[0].combine_data(&params[1], "*", "imul({0}, {1})", &mut i32_consts, &mut i64_consts));
                    }
                    I32_DIV_S => { 
                        computation_ops_count += 1;
                        let params = self.use_stack(2); 
                        self.stack.push(params[0].combine_data(&params[1], "/s", "(({0}) / ({1}) | 0)", &mut i32_consts, &mut i64_consts));
                    }
                    I32_DIV_U => { 
                        computation_ops_count += 1;
                        let params = self.use_stack(2); 
                        self.stack.push(params[0].combine_data(&params[1], "/u", "((({0}) >>> 0) / (({1}) >>> 0) | 0)", &mut i32_consts, &mut i64_consts));
                    }
                    I32_REM_S => { 
                        computation_ops_count += 1;
                        let params = self.use_stack(2); 
                        self.stack.push(params[0].combine_data(&params[1], "%s", "(({0}) % ({1}) | 0)", &mut i32_consts, &mut i64_consts));
                    }
                    I32_REM_U => { 
                        computation_ops_count += 1;
                        let params = self.use_stack(2); 
                        self.stack.push(params[0].combine_data(&params[1], "%u", "((({0}) >>> 0) % (({1}) >>> 0) | 0)", &mut i32_consts, &mut i64_consts));
                    }
                    I32_AND => { 
                        computation_ops_count += 1;
                        let params = self.use_stack(2); 
                        self.stack.push(params[0].combine_data(&params[1], "&", "(({0}) & ({1}))", &mut i32_consts, &mut i64_consts));
                    }
                    I32_OR => { 
                        computation_ops_count += 1;
                        let params = self.use_stack(2); 
                        self.stack.push(params[0].combine_data(&params[1], "|", "(({0}) | ({1}))", &mut i32_consts, &mut i64_consts));
                    }
                    I32_XOR => { 
                        computation_ops_count += 1;
                        xor_ops_count += 1;
                        xor_last_op = 1;
                        let params = self.use_stack(2); 
                        self.stack.push(params[0].combine_data(&params[1], "^", "(({0}) ^ ({1}))", &mut i32_consts, &mut i64_consts));
                    }
                    I32_SHL => { 
                        computation_ops_count += 1;
                        rot_and_sh_ops_count += 1;
                        let params = self.use_stack(2); 
                        self.stack.push(params[0].combine_data(&params[1], "<<", "(({0}) << (({1}) & 31))", &mut i32_consts, &mut i64_consts));
                    }
                    I32_SHR_S => { 
                        computation_ops_count += 1;
                        rot_and_sh_ops_count += 1;
                        let params = self.use_stack(2); 
                        self.stack.push(params[0].combine_data(&params[1], ">>s", "(({0}) >> (({1}) & 31))", &mut i32_consts, &mut i64_consts));
                    }
                    I32_SHR_U => { 
                        computation_ops_count += 1;
                        rot_and_sh_ops_count += 1;
                        let params = self.use_stack(2); 
                        self.stack.push(params[0].combine_data(&params[1], ">>u", "((({0}) >>> (({1}) & 31)) | 0)", &mut i32_consts, &mut i64_consts));
                    }
                    I32_ROTL => {
                        computation_ops_count += 1;
                        rot_and_sh_ops_count += 1;
                        let params = self.use_stack(2);
                        self.stack.push(params[0].combine_data(&params[1], "rotl", "((({0}) << (({1}) & 31)) | (({0}) >>> (32 - (({1}) & 31))))", &mut i32_consts, &mut i64_consts));
                    }
                    I32_ROTR => {
                        computation_ops_count += 1;
                        rot_and_sh_ops_count += 1;
                        let params = self.use_stack(2);
                        self.stack.push(params[0].combine_data(&params[1], "rotr", "((({0}) >>> (({1}) & 31)) | (({0}) << (32 - (({1}) & 31))))", &mut i32_consts, &mut i64_consts));
                    }
                    I64_EQZ => { 
                        let params = self.use_stack(1);
                        self.stack.push(params[0].simplify_data_type("eqz", "({0} === 0n ? 1 : 0)", &mut i32_consts, &mut i64_consts));
                    }
                    I64_EQ => { 
                        let params = self.use_stack(2);
                        self.stack.push(params[0].combine_data(&params[1], "==", "({0} === {1} ? 1 : 0)", &mut i32_consts, &mut i64_consts));
                    }
                    I64_NE => { 
                        let params = self.use_stack(2);
                        self.stack.push(params[0].combine_data(&params[1], "!=", "({0} !== {1} ? 1 : 0)", &mut i32_consts, &mut i64_consts));
                    }
                    I64_LT_S => { 
                        let params = self.use_stack(2);
                        self.stack.push(params[0].combine_data(&params[1], "<s", "({0} < {1} ? 1 : 0)", &mut i32_consts, &mut i64_consts));
                    }
                    I64_LT_U => { 
                        let params = self.use_stack(2);
                        self.stack.push(params[0].combine_data(&params[1], "<u", "(asU64({0}) < asU64({1}) ? 1 : 0)", &mut i32_consts, &mut i64_consts));
                    }
                    I64_GT_S => { 
                        let params = self.use_stack(2);
                        self.stack.push(params[0].combine_data(&params[1], ">s", "({0} > {1} ? 1 : 0)", &mut i32_consts, &mut i64_consts));
                    }
                    I64_GT_U => { 
                        let params = self.use_stack(2);
                        self.stack.push(params[0].combine_data(&params[1], ">u", "(asU64({0}) > asU64({1}) ? 1 : 0)", &mut i32_consts, &mut i64_consts));
                    }
                    I64_LE_S => { 
                        let params = self.use_stack(2);
                        self.stack.push(params[0].combine_data(&params[1], "<=s", "({0} <= {1} ? 1 : 0)", &mut i32_consts, &mut i64_consts));
                    }
                    I64_LE_U => { 
                        let params = self.use_stack(2);
                        self.stack.push(params[0].combine_data(&params[1], "<=u", "(asU64({0}) <= asU64({1}) ? 1 : 0)", &mut i32_consts, &mut i64_consts));
                    }
                    I64_GE_S => { 
                        let params = self.use_stack(2);
                        self.stack.push(params[0].combine_data(&params[1], ">=s", "({0} >= {1} ? 1 : 0)", &mut i32_consts, &mut i64_consts));
                    }
                    I64_GE_U => { 
                        let params = self.use_stack(2);
                        self.stack.push(params[0].combine_data(&params[1], ">=u", "(asU64({0}) >= asU64({1}) ? 1 : 0)", &mut i32_consts, &mut i64_consts));
                    } 
                    I64_CLZ => { 
                        computation_ops_count += 1;
                        let params = self.use_stack(1); 
                        self.stack.push(params[0].simplify_data_type("clz", "clz64({0})", &mut i32_consts, &mut i64_consts));
                    }
                    I64_CTZ => { 
                        computation_ops_count += 1;
                        let params = self.use_stack(1); 
                        self.stack.push(params[0].simplify_data_type("ctz", "ctz64({0})", &mut i32_consts, &mut i64_consts));
                    }
                    I64_POPCNT => { 
                        computation_ops_count += 1;
                        let params = self.use_stack(1); 
                        self.stack.push(params[0].simplify_data_type("popcnt", "popcnt64({0})", &mut i32_consts, &mut i64_consts));
                    }
                    I64_ADD => { 
                        computation_ops_count += 1;
                        let params = self.use_stack(2); 
                        self.stack.push(params[0].combine_data(&params[1], "+", "asI64(({0}) + ({1}))", &mut i32_consts, &mut i64_consts));
                    }
                    I64_SUB => { 
                        computation_ops_count += 1;
                        let params = self.use_stack(2); 
                        self.stack.push(params[0].combine_data(&params[1], "-", "asI64(({0}) - ({1}))", &mut i32_consts, &mut i64_consts));
                    }
                    I64_MUL => { 
                        computation_ops_count += 1;
                        let params = self.use_stack(2); 
                        self.stack.push(params[0].combine_data(&params[1], "*", "asI64(({0}) * ({1}))", &mut i32_consts, &mut i64_consts));
                    }
                    I64_DIV_S => { 
                        computation_ops_count += 1;
                        let params = self.use_stack(2); 
                        self.stack.push(params[0].combine_data(&params[1], "/s", "asI64(({0}) / ({1}))", &mut i32_consts, &mut i64_consts));
                    }
                    I64_DIV_U => { 
                        computation_ops_count += 1;
                        let params = self.use_stack(2); 
                        self.stack.push(params[0].combine_data(&params[1], "/u", "asI64(asU64({0}) / asU64({1}))", &mut i32_consts, &mut i64_consts));
                    }
                    I64_REM_S => { 
                        computation_ops_count += 1;
                        let params = self.use_stack(2); 
                        self.stack.push(params[0].combine_data(&params[1], "%s", "asI64(({0}) % ({1}))", &mut i32_consts, &mut i64_consts));
                    }
                    I64_REM_U => { 
                        computation_ops_count += 1;
                        let params = self.use_stack(2); 
                        self.stack.push(params[0].combine_data(&params[1], "%u", "asI64(asU64({0}) % asU64({1}))", &mut i32_consts, &mut i64_consts));
                    }
                    I64_AND => { 
                        computation_ops_count += 1;
                        let params = self.use_stack(2); 
                        self.stack.push(params[0].combine_data(&params[1], "&", "(({0}) & ({1}))", &mut i32_consts, &mut i64_consts));
                    }
                    I64_OR => { 
                        computation_ops_count += 1;
                        let params = self.use_stack(2); 
                        self.stack.push(params[0].combine_data(&params[1], "|", "(({0}) | ({1}))", &mut i32_consts, &mut i64_consts));
                    }
                    I64_XOR => {
                        computation_ops_count += 1;
                        xor_ops_count += 1;
                        xor_last_op = 1;
                        let params = self.use_stack(2); 
                        self.stack.push(params[0].combine_data(&params[1], "^", "(({0}) ^ ({1}))", &mut i32_consts, &mut i64_consts));
                    }
                    I64_SHL => { 
                        computation_ops_count += 1;
                        rot_and_sh_ops_count += 1;
                        let params = self.use_stack(2); 
                        self.stack.push(params[0].combine_data(&params[1], "<<", "asI64(({0}) << (asU64({1}) & 63n))", &mut i32_consts, &mut i64_consts));
                    }
                    I64_SHR_S => { 
                        computation_ops_count += 1;
                        rot_and_sh_ops_count += 1;
                        let params = self.use_stack(2); 
                        self.stack.push(params[0].combine_data(&params[1], ">>s", "asI64(({0}) >> (asU64({1}) & 63n))", &mut i32_consts, &mut i64_consts));
                    }
                    I64_SHR_U => { 
                        computation_ops_count += 1;
                        rot_and_sh_ops_count += 1;
                        let params = self.use_stack(2); 
                        self.stack.push(params[0].combine_data(&params[1], ">>u", "asI64(asU64({0}) >> (asU64({1}) & 63n))", &mut i32_consts, &mut i64_consts));
                    }
                    I64_ROTL => { 
                        computation_ops_count += 1;
                        rot_and_sh_ops_count += 1;
                        let params = self.use_stack(2); 
                        self.stack.push(params[0].combine_data(&params[1], "rotl", "rotl64({0}, {1})", &mut i32_consts, &mut i64_consts));
                    }
                    I64_ROTR => { 
                        computation_ops_count += 1;
                        rot_and_sh_ops_count += 1;
                        let params = self.use_stack(2); 
                        self.stack.push(params[0].combine_data(&params[1], "rotr", "rotr64({0}, {1})", &mut i32_consts, &mut i64_consts));
                    }
                    F32_ABS => { 
                        let params = self.use_stack(1);
                        self.stack.push(params[0].simplify_data_type("abs", "fround(abs({0}))", &mut i32_consts, &mut i64_consts)); 
                    }
                    F32_NEG => { 
                        let params = self.use_stack(1);
                        self.stack.push(params[0].simplify_data_type("neg", "fround(-({0}))", &mut i32_consts, &mut i64_consts)); 
                    }
                    F32_CEIL => { 
                        let params = self.use_stack(1);
                        self.stack.push(params[0].simplify_data_type("ceil", "fround(ceil({0}))", &mut i32_consts, &mut i64_consts)); 
                    }
                    F32_FLOOR => { 
                        let params = self.use_stack(1);
                        self.stack.push(params[0].simplify_data_type("floor", "fround(floor({0}))", &mut i32_consts, &mut i64_consts)); 
                    }
                    F32_TRUNC => { 
                        let params = self.use_stack(1);
                        self.stack.push(params[0].simplify_data_type("trunc", "fround(trunc({0}))", &mut i32_consts, &mut i64_consts)); 
                    }
                    F32_NEAREST => { 
                        let params = self.use_stack(1);
                        self.stack.push(params[0].simplify_data_type("nearest", "fround(nearest({0}))", &mut i32_consts, &mut i64_consts)); 
                    }
                    F32_SQRT => { 
                        let params = self.use_stack(1);
                        self.stack.push(params[0].simplify_data_type("sqrt", "fround(Math.sqrt({0}))", &mut i32_consts, &mut i64_consts)); 
                    }
                    F32_ADD => { 
                        let params = self.use_stack(2);
                        self.stack.push(params[0].combine_data(&params[1], "+", "fround(({0}) + ({1}))", &mut i32_consts, &mut i64_consts)); 
                    }
                    F32_SUB => { 
                        let params = self.use_stack(2);
                        self.stack.push(params[0].combine_data(&params[1], "-", "fround(({0}) - ({1}))", &mut i32_consts, &mut i64_consts)); 
                    }
                    F32_MUL => { 
                        let params = self.use_stack(2);
                        self.stack.push(params[0].combine_data(&params[1], "*", "fround(({0}) * ({1}))", &mut i32_consts, &mut i64_consts)); 
                    }
                    F32_DIV => { 
                        let params = self.use_stack(2);
                        self.stack.push(params[0].combine_data(&params[1], "/", "fround(({0}) / ({1}))", &mut i32_consts, &mut i64_consts)); 
                    }
                    F32_MIN => { 
                        let params = self.use_stack(2);
                        self.stack.push(params[0].combine_data(&params[1], "min", "fround(min(({0}), ({1})))", &mut i32_consts, &mut i64_consts)); 
                    }
                    F32_MAX => { 
                        let params = self.use_stack(2);
                        self.stack.push(params[0].combine_data(&params[1], "max", "fround(max(({0}), ({1})))", &mut i32_consts, &mut i64_consts)); 
                    }
                    F32_COPYSIGN => { 
                        let params = self.use_stack(2);
                        self.stack.push(params[0].combine_data(&params[1], "copysign", "fround(abs({0}) * (({1}) < 0 || 1 / ({1}) < 0 ? -1 : 1))", &mut i32_consts, &mut i64_consts)); 
                    }
                    F64_ABS => { 
                        let params = self.use_stack(1);
                        self.stack.push(params[0].simplify_data_type("abs", "abs({0})", &mut i32_consts, &mut i64_consts)); 
                    }
                    F64_NEG => { 
                        let params = self.use_stack(1);
                        self.stack.push(params[0].simplify_data_type("neg", "(-({0}))", &mut i32_consts, &mut i64_consts)); 
                    }
                    F64_CEIL => { 
                        let params = self.use_stack(1);
                        self.stack.push(params[0].simplify_data_type("ceil", "ceil({0})", &mut i32_consts, &mut i64_consts)); 
                    }
                    F64_FLOOR => { 
                        let params = self.use_stack(1);
                        self.stack.push(params[0].simplify_data_type("floor", "floor({0})", &mut i32_consts, &mut i64_consts)); 
                    }
                    F64_TRUNC => { 
                        let params = self.use_stack(1);
                        self.stack.push(params[0].simplify_data_type("trunc", "trunc({0})", &mut i32_consts, &mut i64_consts)); 
                    }
                    F64_NEAREST => { 
                        let params = self.use_stack(1);
                        self.stack.push(params[0].simplify_data_type("nearest", "nearest({0})", &mut i32_consts, &mut i64_consts)); 
                    }
                    F64_SQRT => { 
                        let params = self.use_stack(1);
                        self.stack.push(params[0].simplify_data_type("sqrt", "Math.sqrt({0})", &mut i32_consts, &mut i64_consts)); 
                    }
                    F64_ADD => { 
                        let params = self.use_stack(2);
                        self.stack.push(params[0].combine_data(&params[1], "+", "(({0}) + ({1}))", &mut i32_consts, &mut i64_consts)); 
                    }
                    F64_SUB => { 
                        let params = self.use_stack(2);
                        self.stack.push(params[0].combine_data(&params[1], "-", "(({0}) - ({1}))", &mut i32_consts, &mut i64_consts)); 
                    }
                    F64_MUL => { 
                        let params = self.use_stack(2);
                        self.stack.push(params[0].combine_data(&params[1], "*", "(({0}) * ({1}))", &mut i32_consts, &mut i64_consts)); 
                    }
                    F64_DIV => { 
                        let params = self.use_stack(2);
                        self.stack.push(params[0].combine_data(&params[1], "/", "(({0}) / ({1}))", &mut i32_consts, &mut i64_consts)); 
                    }
                    F64_MIN => { 
                        let params = self.use_stack(2);
                        self.stack.push(params[0].combine_data(&params[1], "min", "min(({0}), ({1}))", &mut i32_consts, &mut i64_consts)); 
                    }
                    F64_MAX => { 
                        let params = self.use_stack(2);
                        self.stack.push(params[0].combine_data(&params[1], "max", "max(({0}), ({1}))", &mut i32_consts, &mut i64_consts)); 
                    }
                    F64_COPYSIGN => { 
                        let params = self.use_stack(2);
                        self.stack.push(params[0].combine_data(&params[1], "copysign", "(abs({0}) * (({1}) < 0 || 1 / ({1}) < 0 ? -1 : 1))", &mut i32_consts, &mut i64_consts)); 
                    }
                    F32_EQ => { 
                        let params = self.use_stack(2);
                        self.stack.push(params[0].combine_data(&params[1], "==", "(({0}) === ({1}) ? 1 : 0)", &mut i32_consts, &mut i64_consts));
                    }
                    F32_NE => { 
                        let params = self.use_stack(2);
                        self.stack.push(params[0].combine_data(&params[1], "!=", "(({0}) !== ({1}) ? 1 : 0)", &mut i32_consts, &mut i64_consts));
                    }
                    F32_LT => { 
                        let params = self.use_stack(2);
                        self.stack.push(params[0].combine_data(&params[1], "<", "(({0}) < ({1}) ? 1 : 0)", &mut i32_consts, &mut i64_consts));
                    }
                    F32_GT => { 
                        let params = self.use_stack(2);
                        self.stack.push(params[0].combine_data(&params[1], ">", "(({0}) > ({1}) ? 1 : 0)", &mut i32_consts, &mut i64_consts));
                    }
                    F32_LE => { 
                        let params = self.use_stack(2);
                        self.stack.push(params[0].combine_data(&params[1], "<=", "(({0}) <= ({1}) ? 1 : 0)", &mut i32_consts, &mut i64_consts));
                    }
                    F32_GE => { 
                        let params = self.use_stack(2);
                        self.stack.push(params[0].combine_data(&params[1], ">=", "(({0}) >= ({1}) ? 1 : 0)", &mut i32_consts, &mut i64_consts));
                    }
                    F64_EQ => { 
                        let params = self.use_stack(2);
                        self.stack.push(params[0].combine_data(&params[1], "==", "(({0}) === ({1}) ? 1 : 0)", &mut i32_consts, &mut i64_consts));
                    }
                    F64_NE => { 
                        let params = self.use_stack(2);
                        self.stack.push(params[0].combine_data(&params[1], "!=", "(({0}) !== ({1}) ? 1 : 0)", &mut i32_consts, &mut i64_consts));
                    }
                    F64_LT => { 
                        let params = self.use_stack(2);
                        self.stack.push(params[0].combine_data(&params[1], "<", "(({0}) < ({1}) ? 1 : 0)", &mut i32_consts, &mut i64_consts));
                    }
                    F64_GT => { 
                        let params = self.use_stack(2);
                        self.stack.push(params[0].combine_data(&params[1], ">", "(({0}) > ({1}) ? 1 : 0)", &mut i32_consts, &mut i64_consts));
                    }
                    F64_LE => { 
                        let params = self.use_stack(2);
                        self.stack.push(params[0].combine_data(&params[1], "<=", "(({0}) <= ({1}) ? 1 : 0)", &mut i32_consts, &mut i64_consts));
                    }
                    F64_GE => { 
                        let params = self.use_stack(2);
                        self.stack.push(params[0].combine_data(&params[1], ">=", "(({0}) >= ({1}) ? 1 : 0)", &mut i32_consts, &mut i64_consts));
                    }
                    I32_TRUNC_F32_S => { 
                        let params = self.use_stack(1);
                        self.stack.push(params[0].simplify_data_type("trunc_i32_s", "(trunc({0}) | 0)", &mut i32_consts, &mut i64_consts)); 
                    }
                    I32_TRUNC_F32_U => { 
                        let params = self.use_stack(1);
                        self.stack.push(params[0].simplify_data_type("trunc_i32_u", "(trunc({0}) >>> 0)", &mut i32_consts, &mut i64_consts)); 
                    }
                    I32_TRUNC_F64_S => { 
                        let params = self.use_stack(1);
                        self.stack.push(params[0].simplify_data_type("trunc_i32_s", "(trunc({0}) | 0)", &mut i32_consts, &mut i64_consts)); 
                    }
                    I32_TRUNC_F64_U => { 
                        let params = self.use_stack(1);
                        self.stack.push(params[0].simplify_data_type("trunc_i32_u", "(trunc({0}) >>> 0)", &mut i32_consts, &mut i64_consts)); 
                    }
                    I64_TRUNC_F32_S => { 
                        let params = self.use_stack(1);
                        self.stack.push(params[0].simplify_data_type("trunc_i64_s", "asI64(BigInt(Number.isFinite({0}) ? trunc({0}) : 0))", &mut i32_consts, &mut i64_consts)); 
                    }
                    I64_TRUNC_F32_U => { 
                        let params = self.use_stack(1);
                        self.stack.push(params[0].simplify_data_type("trunc_i64_u", "asI64(BigInt(Number.isFinite({0}) ? trunc({0}) : 0))", &mut i32_consts, &mut i64_consts)); 
                    }
                    I64_TRUNC_F64_S => { 
                        let params = self.use_stack(1);
                        self.stack.push(params[0].simplify_data_type("trunc_i64_s", "asI64(BigInt(Number.isFinite({0}) ? trunc({0}) : 0))", &mut i32_consts, &mut i64_consts)); 
                    }
                    I64_TRUNC_F64_U => { 
                        let params = self.use_stack(1);
                        self.stack.push(params[0].simplify_data_type("trunc_i64_u", "asI64(BigInt(Number.isFinite({0}) ? trunc({0}) : 0))", &mut i32_consts, &mut i64_consts)); 
                    }
                    F32_CONVERT_I32_S => { 
                        let params = self.use_stack(1);
                        self.stack.push(params[0].simplify_data_type("convert_f32_s", "fround(({0}) | 0)", &mut i32_consts, &mut i64_consts)); 
                    }
                    F32_CONVERT_I32_U => { 
                        let params = self.use_stack(1);
                        self.stack.push(params[0].simplify_data_type("convert_f32_u", "fround(({0}) >>> 0)", &mut i32_consts, &mut i64_consts)); 
                    }
                    F32_CONVERT_I64_S => { 
                        let params = self.use_stack(1);
                        self.stack.push(params[0].simplify_data_type("convert_f32_s", "fround(Number(asI64({0})))", &mut i32_consts, &mut i64_consts)); 
                    }
                    F32_CONVERT_I64_U => { 
                        let params = self.use_stack(1);
                        self.stack.push(params[0].simplify_data_type("convert_f32_u", "fround(Number(asU64({0})))", &mut i32_consts, &mut i64_consts)); 
                    }
                    F64_CONVERT_I32_S => { 
                        let params = self.use_stack(1);
                        self.stack.push(params[0].simplify_data_type("convert_f64_s", "({0}) | 0", &mut i32_consts, &mut i64_consts)); 
                    }
                    F64_CONVERT_I32_U => { 
                        let params = self.use_stack(1);
                        self.stack.push(params[0].simplify_data_type("convert_f64_u", "({0}) >>> 0", &mut i32_consts, &mut i64_consts)); 
                    }
                    F64_CONVERT_I64_S => { 
                        let params = self.use_stack(1);
                        self.stack.push(params[0].simplify_data_type("convert_f64_s", "Number(asI64({0}))", &mut i32_consts, &mut i64_consts)); 
                    }
                    F64_CONVERT_I64_U => { 
                        let params = self.use_stack(1);
                        self.stack.push(params[0].simplify_data_type("convert_f64_u", "Number(asU64({0}))", &mut i32_consts, &mut i64_consts)); 
                    }
                    I32_REINTERPRET_F32 => { 
                        let params = self.use_stack(1);
                        self.stack.push(params[0].simplify_data_type("reinterpret_i32", "reinterpret_i32({0})", &mut i32_consts, &mut i64_consts)); 
                    }
                    I64_REINTERPRET_F64 => { 
                        let params = self.use_stack(1);
                        self.stack.push(params[0].simplify_data_type("reinterpret_i64", "reinterpret_i64({0})", &mut i32_consts, &mut i64_consts)); 
                    }
                    F32_REINTERPRET_I32 => { 
                        let params = self.use_stack(1);
                        self.stack.push(params[0].simplify_data_type("reinterpret_f32", "reinterpret_f32({0})", &mut i32_consts, &mut i64_consts)); 
                    }
                    F64_REINTERPRET_I64 => { 
                        let params = self.use_stack(1);
                        self.stack.push(params[0].simplify_data_type("reinterpret_f64", "reinterpret_f64({0})", &mut i32_consts, &mut i64_consts)); 
                    }
                    I32_EXTEND8_S => {
                        let params = self.use_stack(1);
                        self.stack.push(params[0].simplify_data_type("extend8_s", "((({0}) << 24) >> 24)", &mut i32_consts, &mut i64_consts));
                    }
                    I32_EXTEND16_S => {
                        let params = self.use_stack(1);
                        self.stack.push(params[0].simplify_data_type("extend16_s", "((({0}) << 16) >> 16)", &mut i32_consts, &mut i64_consts));
                    }
                    I64_EXTEND8_S => {
                        let params = self.use_stack(1);
                        self.stack.push(params[0].simplify_data_type("extend8_s", "asI8({0})", &mut i32_consts, &mut i64_consts));
                    }
                    I64_EXTEND16_S => {
                        let params = self.use_stack(1);
                        self.stack.push(params[0].simplify_data_type("extend16_s", "asI16({0})", &mut i32_consts, &mut i64_consts));
                    }
                    I64_EXTEND32_S => {
                        let params = self.use_stack(1);
                        self.stack.push(params[0].simplify_data_type("extend32_s", "asI32({0})", &mut i32_consts, &mut i64_consts));
                    }
                    MEMORY_SIZE => {
                        let _ = reader.read_byte();
                        self.stack.push(DataType::String { value: "(mem.buffer.byteLength / 65536)".to_string() });
                    }
                    MEMORY_GROW => {
                        let _ = reader.read_byte();
                        self.create_holders_on_stack(); 
                        let params = self.use_stack(1);
                        let temp_name = self.get_free_temp();
                        self.add_line(format!("\t\t{} = grow_memory({});", temp_name, params[0].to_string()));
                        self.stack.push(DataType::String { value: temp_name });
                    }

                    I32_LOAD => {
                        load_ops_count += 1;
                        let _align = reader.read_u32().unwrap_or(0);
                        let offset = reader.read_u32().unwrap_or(0);
                        let params = self.use_stack(1);
                        let addr_expr = params[0].combine_data(&DataType::Int32 { value: offset as i32 }, "+", "(({0}) + ({1}) | 0)", &mut i32_consts, &mut i64_consts);
                        self.stack.push(DataType::String { value: format!("dv.getInt32(({}) >>> 0, true)", addr_expr.to_string()) });
                    }
                    I64_LOAD => {
                        load_ops_count += 1;
                        let _align = reader.read_u32().unwrap_or(0);
                        let offset = reader.read_u32().unwrap_or(0);
                        let params = self.use_stack(1);
                        let addr_expr = params[0].combine_data(&DataType::Int32 { value: offset as i32 }, "+", "(({0}) + ({1}) | 0)", &mut i32_consts, &mut i64_consts);
                        self.stack.push(DataType::String { value: format!("dv.getBigInt64(({}) >>> 0, true)", addr_expr.to_string()) });
                    }
                    F32_LOAD => {
                        load_ops_count += 1;
                        let _align = reader.read_u32().unwrap_or(0);
                        let offset = reader.read_u32().unwrap_or(0);
                        let params = self.use_stack(1);
                        let addr_expr = params[0].combine_data(&DataType::Int32 { value: offset as i32 }, "+", "(({0}) + ({1}) | 0)", &mut i32_consts, &mut i64_consts);
                        self.stack.push(DataType::String { value: format!("dv.getFloat32(({}) >>> 0, true)", addr_expr.to_string()) });
                    }
                    F64_LOAD => {
                        load_ops_count += 1;
                        let _align = reader.read_u32().unwrap_or(0);
                        let offset = reader.read_u32().unwrap_or(0);
                        let params = self.use_stack(1);
                        let addr_expr = params[0].combine_data(&DataType::Int32 { value: offset as i32 }, "+", "(({0}) + ({1}) | 0)", &mut i32_consts, &mut i64_consts);
                        self.stack.push(DataType::String { value: format!("dv.getFloat64(({}) >>> 0, true)", addr_expr.to_string()) });
                    }
                    I32_LOAD8_S => {
                        load_ops_count += 1;
                        let _align = reader.read_u32().unwrap_or(0);
                        let offset = reader.read_u32().unwrap_or(0);
                        let params = self.use_stack(1);
                        let addr_expr = params[0].combine_data(&DataType::Int32 { value: offset as i32 }, "+", "(({0}) + ({1}) | 0)", &mut i32_consts, &mut i64_consts);
                        self.stack.push(DataType::String { value: format!("dv.getInt8(({}) >>> 0)", addr_expr.to_string()) });
                    }
                    I32_LOAD8_U => {
                        load_ops_count += 1;
                        let _align = reader.read_u32().unwrap_or(0);
                        let offset = reader.read_u32().unwrap_or(0);
                        let params = self.use_stack(1);
                        let addr_expr = params[0].combine_data(&DataType::Int32 { value: offset as i32 }, "+", "(({0}) + ({1}) | 0)", &mut i32_consts, &mut i64_consts);
                        self.stack.push(DataType::String { value: format!("dv.getUint8(({}) >>> 0)", addr_expr.to_string()) });
                    }
                    I32_LOAD16_S => {
                        load_ops_count += 1;
                        let _align = reader.read_u32().unwrap_or(0);
                        let offset = reader.read_u32().unwrap_or(0);
                        let params = self.use_stack(1);
                        let addr_expr = params[0].combine_data(&DataType::Int32 { value: offset as i32 }, "+", "(({0}) + ({1}) | 0)", &mut i32_consts, &mut i64_consts);
                        self.stack.push(DataType::String { value: format!("dv.getInt16(({}) >>> 0, true)", addr_expr.to_string()) });
                    }
                    I32_LOAD16_U => {
                        load_ops_count += 1;
                        let _align = reader.read_u32().unwrap_or(0);
                        let offset = reader.read_u32().unwrap_or(0);
                        let params = self.use_stack(1);
                        let addr_expr = params[0].combine_data(&DataType::Int32 { value: offset as i32 }, "+", "(({0}) + ({1}) | 0)", &mut i32_consts, &mut i64_consts);
                        self.stack.push(DataType::String { value: format!("dv.getUint16(({}) >>> 0, true)", addr_expr.to_string()) });
                    }
                    I64_LOAD8_S => {
                        load_ops_count += 1;
                        let _align = reader.read_u32().unwrap_or(0);
                        let offset = reader.read_u32().unwrap_or(0);
                        let params = self.use_stack(1);
                        let addr_expr = params[0].combine_data(&DataType::Int32 { value: offset as i32 }, "+", "(({0}) + ({1}) | 0)", &mut i32_consts, &mut i64_consts);
                        self.stack.push(DataType::String { value: format!("BigInt(dv.getInt8(({}) >>> 0))", addr_expr.to_string()) });
                    }
                    I64_LOAD8_U => {
                        load_ops_count += 1;
                        let _align = reader.read_u32().unwrap_or(0);
                        let offset = reader.read_u32().unwrap_or(0);
                        let params = self.use_stack(1);
                        let addr_expr = params[0].combine_data(&DataType::Int32 { value: offset as i32 }, "+", "(({0}) + ({1}) | 0)", &mut i32_consts, &mut i64_consts);
                        self.stack.push(DataType::String { value: format!("BigInt(dv.getUint8(({}) >>> 0))", addr_expr.to_string()) });
                    }
                    I64_LOAD16_S => {
                        load_ops_count += 1;
                        let _align = reader.read_u32().unwrap_or(0);
                        let offset = reader.read_u32().unwrap_or(0);
                        let params = self.use_stack(1);
                        let addr_expr = params[0].combine_data(&DataType::Int32 { value: offset as i32 }, "+", "(({0}) + ({1}) | 0)", &mut i32_consts, &mut i64_consts);
                        self.stack.push(DataType::String { value: format!("BigInt(dv.getInt16(({}) >>> 0, true))", addr_expr.to_string()) });
                    }
                    I64_LOAD16_U => {
                        load_ops_count += 1;
                        let _align = reader.read_u32().unwrap_or(0);
                        let offset = reader.read_u32().unwrap_or(0);
                        let params = self.use_stack(1);
                        let addr_expr = params[0].combine_data(&DataType::Int32 { value: offset as i32 }, "+", "(({0}) + ({1}) | 0)", &mut i32_consts, &mut i64_consts);
                        self.stack.push(DataType::String { value: format!("BigInt(dv.getUint16(({}) >>> 0, true))", addr_expr.to_string()) });
                    }
                    I64_LOAD32_S => {
                        load_ops_count += 1;
                        let _align = reader.read_u32().unwrap_or(0);
                        let offset = reader.read_u32().unwrap_or(0);
                        let params = self.use_stack(1);
                        let addr_expr = params[0].combine_data(&DataType::Int32 { value: offset as i32 }, "+", "(({0}) + ({1}) | 0)", &mut i32_consts, &mut i64_consts);
                        self.stack.push(DataType::String { value: format!("BigInt(dv.getInt32(({}) >>> 0, true))", addr_expr.to_string()) });
                    }
                    I64_LOAD32_U => {
                        load_ops_count += 1;
                        let _align = reader.read_u32().unwrap_or(0);
                        let offset = reader.read_u32().unwrap_or(0);
                        let params = self.use_stack(1);
                        let addr_expr = params[0].combine_data(&DataType::Int32 { value: offset as i32 }, "+", "(({0}) + ({1}) | 0)", &mut i32_consts, &mut i64_consts);
                        self.stack.push(DataType::String { value: format!("BigInt(dv.getUint32(({}) >>> 0, true))", addr_expr.to_string()) });
                    }
                    I32_STORE => {
                        store_ops_count += 1;
                        let _align = reader.read_u32().unwrap_or(0);
                        let offset = reader.read_u32().unwrap_or(0);
                        self.create_holders_on_stack(); 
                        let params = self.use_stack(2);
                        
                        let addr_expr = params[0].combine_data(&DataType::Int32 { value: offset as i32 }, "+", "(({0}) + ({1}) | 0)", &mut i32_consts, &mut i64_consts);
                        self.add_line(format!("\t\tdv.setInt32(({}) >>> 0, {}, true);", addr_expr.to_string(), params[1].to_string()));
                        current_func_store_ops.push(("i32.store".to_string(), params[0].to_string(), offset, params[1].to_string(), current_func_is_in_loop));
                        let common_addrs = current_func_stores_from_common_addrs.entry(params[0].to_string()).or_insert(Vec::new());
                        common_addrs.push((offset, params[1].to_string(), "i32".to_string()));

                        if xor_last_op == 2 {
                            current_xor_stores.push(["i32.store".to_string(), params[0].to_string(), offset.to_string(), params[1].to_string()]);
                        }
                    }
                    I64_STORE => {
                        store_ops_count += 1;
                        let _align = reader.read_u32().unwrap_or(0);
                        let offset = reader.read_u32().unwrap_or(0);
                        self.create_holders_on_stack(); 
                        let params = self.use_stack(2);
                        
                        let addr_expr = params[0].combine_data(&DataType::Int32 { value: offset as i32 }, "+", "(({0}) + ({1}) | 0)", &mut i32_consts, &mut i64_consts);
                        self.add_line(format!("\t\tdv.setBigInt64(({}) >>> 0, {}, true);", addr_expr.to_string(), params[1].to_string()));
                        current_func_store_ops.push(("i64.store".to_string(), params[0].to_string(), offset, params[1].to_string(), current_func_is_in_loop));
                        let common_addrs = current_func_stores_from_common_addrs.entry(params[0].to_string()).or_insert(Vec::new());
                        common_addrs.push((offset, params[1].to_string(), "i64".to_string()));

                        if xor_last_op == 2 {
                            current_xor_stores.push(["i64.store".to_string(), params[0].to_string(), offset.to_string(), params[1].to_string()]);
                        }
                    }
                    F32_STORE => {
                        store_ops_count += 1;
                        let _align = reader.read_u32().unwrap_or(0);
                        let offset = reader.read_u32().unwrap_or(0);
                        self.create_holders_on_stack(); 
                        let params = self.use_stack(2);
                        
                        let addr_expr = params[0].combine_data(&DataType::Int32 { value: offset as i32 }, "+", "(({0}) + ({1}) | 0)", &mut i32_consts, &mut i64_consts);
                        self.add_line(format!("\t\tdv.setFloat32(({}) >>> 0, {}, true);", addr_expr.to_string(), params[1].to_string()));
                        current_func_store_ops.push(("f32.store".to_string(), params[0].to_string(), offset, params[1].to_string(), current_func_is_in_loop));
                        let common_addrs = current_func_stores_from_common_addrs.entry(params[0].to_string()).or_insert(Vec::new());
                        common_addrs.push((offset, params[1].to_string(), "f32".to_string()));
                    }
                    F64_STORE => {
                        store_ops_count += 1;
                        let _align = reader.read_u32().unwrap_or(0);
                        let offset = reader.read_u32().unwrap_or(0);
                        self.create_holders_on_stack(); 
                        let params = self.use_stack(2);
                        
                        let addr_expr = params[0].combine_data(&DataType::Int32 { value: offset as i32 }, "+", "(({0}) + ({1}) | 0)", &mut i32_consts, &mut i64_consts);
                        self.add_line(format!("\t\tdv.setFloat64(({}) >>> 0, {}, true);", addr_expr.to_string(), params[1].to_string()));
                        current_func_store_ops.push(("f64.store".to_string(), params[0].to_string(), offset, params[1].to_string(), current_func_is_in_loop));
                        let common_addrs = current_func_stores_from_common_addrs.entry(params[0].to_string()).or_insert(Vec::new());
                        common_addrs.push((offset, params[1].to_string(), "f64".to_string()));
                    }
                    I32_STORE8 => {
                        store_ops_count += 1;
                        let _align = reader.read_u32().unwrap_or(0);
                        let offset = reader.read_u32().unwrap_or(0);
                        self.create_holders_on_stack(); 
                        let params = self.use_stack(2);
                        
                        let addr_expr = params[0].combine_data(&DataType::Int32 { value: offset as i32 }, "+", "(({0}) + ({1}) | 0)", &mut i32_consts, &mut i64_consts);
                        self.add_line(format!("\t\tdv.setInt8(({}) >>> 0, {});", addr_expr.to_string(), params[1].to_string()));
                        current_func_store_ops.push(("i32.store8".to_string(), params[0].to_string(), offset, params[1].to_string(), current_func_is_in_loop));
                        let common_addrs = current_func_stores_from_common_addrs.entry(params[0].to_string()).or_insert(Vec::new());
                        common_addrs.push((offset, params[1].to_string(), "u8".to_string()));

                        if xor_last_op == 2 {
                            current_xor_stores.push(["i32.store8".to_string(), params[0].to_string(), offset.to_string(), params[1].to_string()]);
                        }
                    }
                    I32_STORE16 => {
                        store_ops_count += 1;
                        let _align = reader.read_u32().unwrap_or(0);
                        let offset = reader.read_u32().unwrap_or(0);
                        self.create_holders_on_stack(); 
                        let params = self.use_stack(2);
                        
                        let addr_expr = params[0].combine_data(&DataType::Int32 { value: offset as i32 }, "+", "(({0}) + ({1}) | 0)", &mut i32_consts, &mut i64_consts);
                        self.add_line(format!("\t\tdv.setInt16(({}) >>> 0, {}, true);", addr_expr.to_string(), params[1].to_string()));
                        current_func_store_ops.push(("i32.store16".to_string(), params[0].to_string(), offset, params[1].to_string(), current_func_is_in_loop));
                        let common_addrs = current_func_stores_from_common_addrs.entry(params[0].to_string()).or_insert(Vec::new());
                        common_addrs.push((offset, params[1].to_string(), "u16".to_string()));

                        if xor_last_op == 2 {
                            current_xor_stores.push(["i32.store16".to_string(), params[0].to_string(), offset.to_string(), params[1].to_string()]);
                        }
                    }
                    I64_STORE8 => {
                        store_ops_count += 1;
                        let _align = reader.read_u32().unwrap_or(0);
                        let offset = reader.read_u32().unwrap_or(0);
                        self.create_holders_on_stack(); 
                        let params = self.use_stack(2);
                        
                        let addr_expr = params[0].combine_data(&DataType::Int32 { value: offset as i32 }, "+", "(({0}) + ({1}) | 0)", &mut i32_consts, &mut i64_consts);
                        self.add_line(format!("\t\tdv.setInt8(({}) >>> 0, Number(asI8({})));", addr_expr.to_string(), params[1].to_string()));
                        current_func_store_ops.push(("i64.store8".to_string(), params[0].to_string(), offset, params[1].to_string(), current_func_is_in_loop));
                        let common_addrs = current_func_stores_from_common_addrs.entry(params[0].to_string()).or_insert(Vec::new());
                        common_addrs.push((offset, params[1].to_string(), "u8".to_string()));

                        if xor_last_op == 2 {
                            current_xor_stores.push(["i64.store8".to_string(), params[0].to_string(), offset.to_string(), params[1].to_string()]);
                        }
                    }
                    I64_STORE16 => {
                        store_ops_count += 1;
                        let _align = reader.read_u32().unwrap_or(0);
                        let offset = reader.read_u32().unwrap_or(0);
                        self.create_holders_on_stack(); 
                        let params = self.use_stack(2);
                        
                        let addr_expr = params[0].combine_data(&DataType::Int32 { value: offset as i32 }, "+", "(({0}) + ({1}) | 0)", &mut i32_consts, &mut i64_consts);
                        self.add_line(format!("\t\tdv.setInt16(({}) >>> 0, Number(asI16({})), true);", addr_expr.to_string(), params[1].to_string()));
                        current_func_store_ops.push(("i64.store16".to_string(), params[0].to_string(), offset, params[1].to_string(), current_func_is_in_loop));
                        let common_addrs = current_func_stores_from_common_addrs.entry(params[0].to_string()).or_insert(Vec::new());
                        common_addrs.push((offset, params[1].to_string(), "u16".to_string()));

                        if xor_last_op == 2 {
                            current_xor_stores.push(["i64.store16".to_string(), params[0].to_string(), offset.to_string(), params[1].to_string()]);
                        }
                    }
                    I64_STORE32 => {
                        store_ops_count += 1;
                        let _align = reader.read_u32().unwrap_or(0);
                        let offset = reader.read_u32().unwrap_or(0);
                        self.create_holders_on_stack(); 
                        let params = self.use_stack(2);
                        
                        let addr_expr = params[0].combine_data(&DataType::Int32 { value: offset as i32 }, "+", "(({0}) + ({1}) | 0)", &mut i32_consts, &mut i64_consts);
                        self.add_line(format!("\t\tdv.setInt32(({}) >>> 0, Number(asI32({})), true);", addr_expr.to_string(), params[1].to_string()));
                        current_func_store_ops.push(("i64.store32".to_string(), params[0].to_string(), offset, params[1].to_string(), current_func_is_in_loop));
                        let common_addrs = current_func_stores_from_common_addrs.entry(params[0].to_string()).or_insert(Vec::new());
                        common_addrs.push((offset, params[1].to_string(), "u32".to_string()));

                        if xor_last_op == 2 {
                            current_xor_stores.push(["i64.store32".to_string(), params[0].to_string(), offset.to_string(), params[1].to_string()]);
                        }
                    }
                    PREFIX_FC => {
                        let sub_opcode = reader.read_u32().unwrap_or(0);
                        match sub_opcode {
                            MEMORY_INIT => {
                                let data_id = reader.read_u32().unwrap_or(0);
                                let _mem_id = reader.read_u32().unwrap_or(0);
                                self.create_holders_on_stack(); 
                                let params = self.use_stack(3);
                                self.add_line(format!("\t\tu8.set(d{}.subarray(({}) >>> 0, (({} + {}) | 0) >>> 0), ({}) >>> 0);", data_id, params[1].to_string(), params[1].to_string(), params[2].to_string(), params[0].to_string()));
                            }
                            DATA_DROP => {
                                let _data_id = reader.read_u32().unwrap_or(0);
                            }
                            MEMORY_COPY => {
                                let _mem_id_dest = reader.read_u32().unwrap_or(0);
                                let _mem_id_src = reader.read_u32().unwrap_or(0);
                                self.create_holders_on_stack(); 
                                let params = self.use_stack(3);
                                let end_expr = params[1].combine_data(&params[2], "+", "(({0}) + ({1}) | 0)", &mut i32_consts, &mut i64_consts);
                                self.add_line(format!("\t\tu8.copyWithin(({}) >>> 0, ({}) >>> 0, ({}) >>> 0);", params[0].to_string(), params[1].to_string(), end_expr.to_string()));
                            }
                            MEMORY_FILL => {
                                let _mem_id = reader.read_u32().unwrap_or(0);
                                self.create_holders_on_stack(); 
                                let params = self.use_stack(3);
                                let end_expr = params[0].combine_data(&params[2], "+", "(({0}) + ({1}) | 0)", &mut i32_consts, &mut i64_consts);
                                self.add_line(format!("\t\tu8.fill({}, ({}) >>> 0, ({}) >>> 0);", params[1].to_string(), params[0].to_string(), end_expr.to_string()));
                            }
                            TABLE_INIT => {
                                let elem_id = reader.read_u32().unwrap_or(0);
                                let _table_id = reader.read_u32().unwrap_or(0);
                                self.create_holders_on_stack(); 
                                let params = self.use_stack(3);
                                self.add_line(format!("\t\tfor (let i = 0; i < {}; i++) {{ table.set(({} + i) >>> 0, elem_segment_{}[({} + i) >>> 0]); }}", params[2].to_string(), params[0].to_string(), elem_id, params[1].to_string()));
                            }
                            ELEM_DROP => {
                                let _elem_id = reader.read_u32().unwrap_or(0);
                            }
                            TABLE_COPY => {
                                let _table_id_dest = reader.read_u32().unwrap_or(0);
                                let _table_id_src = reader.read_u32().unwrap_or(0);
                                self.create_holders_on_stack(); 
                                let params = self.use_stack(3);
                                self.add_line(format!("\t\tlet temp_copy = []; for (let i = 0; i < {}; i++) temp_copy[i] = table.get(({} + i) >>> 0); for (let i = 0; i < {}; i++) table.set(({} + i) >>> 0, temp_copy[i]);", params[2].to_string(), params[1].to_string(), params[2].to_string(), params[0].to_string()));
                            }
                            _ => { 
                                // We'll actually match the saturating truncs in their own match,
                                // By doing this we manage to only have to write out the actual function info once,
                                // Instead of having to write it all out for each individual arm 
                                // (as they are all similar and so only their name difference matters).
                                let opcode_helper = match sub_opcode {
                                    I32_TRUNC_SAT_F32_S | I32_TRUNC_SAT_F64_S => "trunc_sat_i32_s",
                                    I32_TRUNC_SAT_F32_U | I32_TRUNC_SAT_F64_U => "trunc_sat_i32_u",
                                    I64_TRUNC_SAT_F32_S | I64_TRUNC_SAT_F64_S => "trunc_sat_i64_s",
                                    I64_TRUNC_SAT_F32_U | I64_TRUNC_SAT_F64_U => "trunc_sat_i64_u",
                                    _ => panic!("Unhandled PREFIX_FC sub-opcode: {:#04x}.", sub_opcode),
                                };
                                let params = self.use_stack(1);
                                self.stack.push(params[0].simplify_data_type(opcode_helper, &format!("{}({{0}})", opcode_helper), &mut i32_consts, &mut i64_consts));
                            }
                        }
                    }
                    _ => {
                        panic!("Unhandled opcode: {:#04x}.", opcode);
                    }
                }
                // If xor_last_op = 2, then we reset to 0. It is no longer the last operation.
                if xor_last_op == 2 {
                    xor_last_op = 0;
                }
            }

            // Push collected current func data for other features into our struct.
            self.func_calls.insert(func_name.clone(), current_func_calls);
            self.func_store_ops.insert(func_name.clone(), current_func_store_ops);
            self.func_stores_from_common_addrs.insert(func_name.clone(), current_func_stores_from_common_addrs);
            self.func_xor_stores.insert(func_name.clone(), current_xor_stores);

            // Push all collected ops into func_crypto_stats.
            self.func_crypto_stats.push((
                func_name.clone(),
                ops_count,
                rot_and_sh_ops_count,
                xor_ops_count,
                computation_ops_count,
                load_ops_count,
                store_ops_count
            ));
            
            // Append our constant stores, and track our end func pos 
            // so we can identify which func these consts come from.
            self.constants_byte_stream.extend(&i64_consts);
            let end_i64_pos = self.constants_byte_stream.len();
            self.constants_byte_stream.extend(&i32_consts);
            let end_func_pos = self.constants_byte_stream.len();
            self.constants_fns_ptrs.push([end_func_pos, end_i64_pos]);
            
            // Handle control structure exiting at end of func
            if let Some((_, _, _, _, _, _)) = self.control_stack.pop() {
                self.add_line("\t\t}".to_string());
            }

            // Handle return line if the func returns.
            if signature.returns > 0 && !self.stack.is_empty() {
                let ret_val = self.use_stack(1);
                self.add_line(format!("\t\treturn {};", ret_val[0].to_string()));
            } else {
                self.add_line("\t\treturn;".to_string());
            }
            
            self.add_line("\t};".to_string());
            
            let mut vars = Vec::new();
            for var_index in 0..self.temp_ctr {
                vars.push(format!("t{} = 0", var_index));
            }
            if !vars.is_empty() {
                self.out_lines.insert(func_body_start_id + 1, format!("\t\tvar {};", vars.join(", ")));
            }

            reader.addr = end_addr;
        }

        // Elements (we add these only once the funcs have actually been initialized)
        if !manager.elements.is_empty() {
            for (id, (is_active, _table_id, offset, funcs)) in manager.elements.iter().enumerate() {
                let funcs_str = funcs.iter().map(|f| manager.parse_func_name(*f as usize)).collect::<Vec<_>>().join(", ");
                self.add_line(format!("\tlet elem_segment_{} = [{}];", id, funcs_str));
                if *is_active {
                    self.add_line(format!("\tfor (let i = 0; i < elem_segment_{}.length; i++) {{ table.set(({} + i) >>> 0, elem_segment_{}[i]); }}", id, offset, id));
                }
            }
        }

        // Start
        if let Some(start_id) = manager.start_func_id {
            let start_name = manager.parse_func_name(start_id);
            self.add_line(format!("\t{}();", start_name));
        }

        // Return our module info.
        self.add_line("\treturn {".to_string());
        
        // Exports
        self.add_line("\t\texports: {".to_string());
        let mut export_lines = Vec::new();
        for (id, name) in &manager.export_names {
            let func_name = manager.parse_func_name(*id);
            export_lines.push(format!("\t\t\t\"{}\": {}", name, func_name));
        }
        export_lines.push("\t\t\t\"memory\": mem".to_string());
        self.add_line(export_lines.join(",\n"));
        self.add_line("\t\t},".to_string());
        
        // Funcs
        self.add_line("\t\tfuncs: {".to_string());
        let mut func_lines = Vec::new();
        for i in 0..functions_count {
            let func_id = manager.import_funcs_count + i as usize;
            let func_name = manager.parse_func_name(func_id);
            func_lines.push(format!("\t\t\t\"{}\": {}", func_name, func_name));
        }
        self.add_line(func_lines.join(",\n"));
        self.add_line("\t\t},".to_string());
        
        // Globals
        self.add_line("\t\tglobals: {".to_string());
        let mut global_lines = Vec::new();
        for i in 0..manager.globals.len() {
            let global_id = manager.import_globals.len() + i;
            global_lines.push(format!("\t\t\t\"global_{}\": g{}", global_id, global_id));
        }
        self.add_line(global_lines.join(",\n"));
        self.add_line("\t\t},".to_string());
        
        // Memories
        self.add_line("\t\tmemories: {".to_string());
        self.add_line("\t\t\tmem, dv, u8, i8, u16, i16, u32, i32, i64, f32, f64, grow_memory".to_string());
        self.add_line("\t\t},".to_string());
        
        // Tables + elems
        self.add_line("\t\ttables: {".to_string());
        self.add_line("\t\t\ttable".to_string());
        self.add_line("\t\t},".to_string());
        
        // Imports
        self.add_line("\t\timports: wasm_imports".to_string());
        self.add_line("\t};".to_string());
        self.add_line("}".to_string());

        self.out_lines.join("\n")
    }
}

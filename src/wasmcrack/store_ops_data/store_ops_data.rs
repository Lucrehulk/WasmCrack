use std::collections::HashMap;

pub struct StoreOpsData;

impl StoreOpsData {
    pub fn parse_stores(func_store_ops: &HashMap<String, Vec<(String, String, u32, String, usize)>>) -> String {
        let mut output = "Note: the ctrl f entry in each store allows for quick searching of specific store types.\n\n".to_string();
        output.push_str("Wasm binary store operations data in each func:\n\n");

        // Handle call data outputs for each func.
        for (func_name, store_ops_info) in func_store_ops {
            output.push_str(&format!("{} store ops:\n\n", func_name));
            
            if store_ops_info.is_empty() {
                output.push_str("None\n");
            } else {
                for store_op in store_ops_info {
                    // Parse tuple data
                    let wat_name = store_op.0.clone();
                    let addr = store_op.1.clone();
                    let offset = store_op.2;
                    let set = store_op.3.clone();
                    let is_in_loop = store_op.4;
                    // Determine if XOR is contained in the store set.
                    // Finding stored XOR values can indicate direct encryption/decryption byte storing.
                    // This is especially true if the instruction is a store8.
                    let xor_store = if set.contains("^") {
                        "[XOR]"
                    } else {
                        "[NO XOR]"
                    };
                    // Determine if it is part of a loop or not. Loops indicate potential repeat stores.
                    let loop_info = if is_in_loop == usize::MAX {
                        "[NO LOOP]"
                    } else {
                        "[LOOP]"
                    };
                    output.push_str(&format!("({})\n{}\naddr: {}\noffset: {}\nset: {}\nctrl f: {} - {} - {} - {}\n\n", func_name, wat_name, addr, offset, set, xor_store, wat_name, loop_info, func_name));
                }
            }
            output.push('\n');
        }
        
        output
    }
}
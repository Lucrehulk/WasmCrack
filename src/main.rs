use std::env;
use std::fs;

use WasmCrack::binary_parsing::bin_reader::BinReader;
use WasmCrack::binary_parsing::sections_parser::SectionsParser;
use WasmCrack::binary_parsing::wasm_manager::WasmManager;
use WasmCrack::wasmcrack::wasm2js::converter::Converter;
use WasmCrack::wasmcrack::wasm_magic_evaluator::wasm_evaluator::WasmEvaluator;
use WasmCrack::wasmcrack::call_data::call_data::CallData;
use WasmCrack::wasmcrack::crypto_heuristic_analyzer::crypto_heuristic_analyzer::CryptoHeuristicAnalyzer;
use WasmCrack::wasmcrack::store_ops_data::store_ops_data::StoreOpsData;
use WasmCrack::wasmcrack::struct_solver::struct_solver::StructSolver;

fn main() { 
    // Initialize args and bypass initial exe dir
    let mut args = env::args();
    args.next();

    // Iterate over project directory arguments.
    for project_dir_name in args {
        // Initialize our new project directory and load WASM bytes
        let wasm_file_path = &format!("./binaries/{}.wasm", project_dir_name);
        let wasm_bytes = fs::read(wasm_file_path).unwrap_or_else(|_| {
            panic!("Failed to read {}. Please ensure the file exists.", wasm_file_path);
        });
        let project_dir = format!("./projects/{}", project_dir_name);
        let _ = fs::create_dir_all(&project_dir);
        println!("Loaded WebAssembly binary\nproject: {}\nsize: {} bytes\n", project_dir_name, wasm_bytes.len());

        // Initialize our binary reader and sections data
        let binary_reader = BinReader::new(wasm_bytes);
        let sections = SectionsParser::parse(binary_reader);
        println!("Parsed {} sections.\n", sections.len());
        
        // Initialize the shared WasmManager metadata
        let wasm_manager = WasmManager::new(&sections);

        // Execute converter first as it provides code data and constants info
        let mut wasm2js_engine = if let Some(code_section) = sections.iter().find(|section| section.id == 10) {
            Some(Converter::new(code_section.clone()))
        } else { None }.expect("Failed to locate WASM binary code section.");
        println!("Executing WASM to JS pseudocode conversion...");
        let js_output = wasm2js_engine.convert(&wasm_manager);

        // Initialize WasmEvaluator with our extracted data and the shared manager
        let wasm_evaluator = WasmEvaluator::new(
            sections.clone(),
            wasm2js_engine.constants_byte_stream.clone(),
            wasm2js_engine.constants_fns_ptrs.clone(),
            wasm_manager,
        );

        // Execute features.

        let js_path = project_dir.clone() + "/wasm2js-output.js";
        fs::write(&js_path, &js_output).unwrap_or_else(|_| {
            panic!("Failed to write to {}", js_path);
        });

        println!("Executing data magic evaluator...");
        let data_magic_output = wasm_evaluator.evaluate(11);
        let data_magic_path = project_dir.clone() + "/data-magic-output.txt";
        fs::write(&data_magic_path, &data_magic_output).unwrap_or_else(|_| {
            panic!("Failed to write to {}", data_magic_path);
        });

        println!("Executing code magic evaluator...");
        let code_magic_output = wasm_evaluator.evaluate(10);
        let code_magic_path = project_dir.clone() + "/code-magic-output.txt";
        fs::write(&code_magic_path, &code_magic_output).unwrap_or_else(|_| {
            panic!("Failed to write to {}", code_magic_path);
        });

        println!("Executing call data analyzer...");
        let call_data_output = CallData::parse_calls(&wasm2js_engine.func_calls);
        let call_data_path = project_dir.clone() + "/call-data.txt";
        fs::write(&call_data_path, &call_data_output).unwrap_or_else(|_| {
            panic!("Failed to write to {}", call_data_path);
        });

        println!("Executing crypto heuristic analyzer...");
        let bit_ops_output = CryptoHeuristicAnalyzer::rank_crypto_scores(&wasm2js_engine.func_crypto_stats);
        let bit_ops_path = project_dir.clone() + "/crypto-heuristic-rankings.txt";
        fs::write(&bit_ops_path, &bit_ops_output).unwrap_or_else(|_| {
            panic!("Failed to write to {}", bit_ops_path);
        });

        println!("Executing store ops data analyzer...");
        let store_ops_data_output = StoreOpsData::parse_stores(&wasm2js_engine.func_store_ops);
        let store_ops_data_path = project_dir.clone() + "/store-ops-data.txt";
        fs::write(&store_ops_data_path, &store_ops_data_output).unwrap_or_else(|_| {
            panic!("Failed to write to {}", store_ops_data_path);
        });

        println!("Executing potential struct identifier...");
        let struct_solver_data_output = StructSolver::find_structs(&wasm2js_engine.func_stores_from_common_addrs);
        let struct_solver_data_path = project_dir.clone() + "/potential-structs.txt";
        fs::write(&struct_solver_data_path, &struct_solver_data_output).unwrap_or_else(|_| {
            panic!("Failed to write to {}", struct_solver_data_path);
        });

        println!("\nAll tools successfully executed.\n\n");
    }
}

use super::magic_evaluator::MagicEvaluator;
use super::super::super::binary_parsing::sections_parser::Section;
use super::super::super::binary_parsing::wasm_manager::WasmManager;

pub struct WasmEvaluator {
    sections: Vec<Section>,
    constants_stream: Vec<u8>,
    func_ptrs: Vec<[usize; 2]>,
    manager: WasmManager,
    evaluator: MagicEvaluator
}

impl WasmEvaluator {
    pub fn new(
        sections: Vec<Section>, 
        constants_stream: Vec<u8>,
        func_ptrs: Vec<[usize; 2]>,
        manager: WasmManager,
    ) -> Self {
        Self {
            sections,
            constants_stream,
            func_ptrs,
            manager,
            evaluator: MagicEvaluator::new(),
        }
    }

    pub fn evaluate(&self, section_id: u8) -> String {
        let mut final_output = "".to_string();
        final_output.push_str(&format!("Magic Evaluation for Section {}:\n\n", section_id));
        
        if let Some(wasm_section) = self.sections.iter().find(|section| section.id == section_id) {
            if section_id == 11 {
                // Analyze raw byte data for data sections.
                let raw_analysis = self.evaluator.analyze_byte_slice(&wasm_section.data);
                final_output.push_str(&raw_analysis);
            } else if section_id == 10 {
                // Analyze all constants detected by our Converter if we are analyzing the code section.
                let decoded_analysis = self.evaluator.analyze_decoded_constants(
                    &self.constants_stream,
                    &self.func_ptrs,
                    &self.manager,
                );
                final_output.push_str(&decoded_analysis);
            } 
        } else {
            final_output.push_str("The requested section was not found within the WASM binary.\n");
        }

        final_output
    }
}
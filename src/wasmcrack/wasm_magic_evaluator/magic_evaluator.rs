use std::collections::HashMap;
use super::super::super::constants::signatures::KNOWN_SIGNATURES;
use super::super::super::binary_parsing::wasm_manager::WasmManager;

pub struct MagicEvaluator;

impl MagicEvaluator {
    pub fn new() -> Self {
        Self {}
    }

    // Analyze raw byte slice
    pub fn analyze_byte_slice(&self, target_bytes: &[u8]) -> String {
        let mut evaluation_report = "".to_string();

        // Parse data blocks in a separate function so we can use them for both signatures and strings
        let data_blocks = self.parse_data_blocks(target_bytes);

        // Check signatures 
        let found_signatures = self.scan_for_data_block_signatures(&data_blocks);
        if !found_signatures.is_empty() {
            evaluation_report.push_str("Found crypto signatures in data blocks:\n");
            for (signature_name, count) in found_signatures {
                evaluation_report.push_str(&format!("{} (found {} times)\n", signature_name, count));
            }
            evaluation_report.push_str("\n");
        }

        // Check "clean" vs. "unclean" strings using the decoded data blocks.
        // Track which data block each string comes from.
        let mut clean_strings_map: HashMap<String, Vec<usize>> = HashMap::new();
        let mut unclean_strings_map: HashMap<String, Vec<usize>> = HashMap::new();

        for (segment_index, data_payload) in &data_blocks {
            let (clean_strings, unclean_strings) = self.extract_ascii_strings(data_payload);
            
            for string_value in clean_strings {
                clean_strings_map.entry(string_value).or_insert_with(Vec::new).push(*segment_index);
            }
            
            for string_value in unclean_strings {
                unclean_strings_map.entry(string_value).or_insert_with(Vec::new).push(*segment_index);
            }
        }
        
        // Sort and format clean strings for deterministic output
        let mut clean_strings_sorted: Vec<_> = clean_strings_map.into_iter().collect();
        clean_strings_sorted.sort_by(|a, b| a.0.cmp(&b.0));

        if !clean_strings_sorted.is_empty() {
            evaluation_report.push_str("Clean strings:\n");
            for (string_value, mut blocks) in clean_strings_sorted {
                blocks.sort_unstable();
                blocks.dedup(); // Remove duplicate block indices for a cleaner report
                let blocks_str: Vec<String> = blocks.iter().map(|b| b.to_string()).collect();
                evaluation_report.push_str(&format!("{}\nLocated in data blocks: {}\n\n", string_value, blocks_str.join(", ")));
            }
            evaluation_report.push_str("\n");
        }

        // Sort and format unclean strings
        let mut unclean_strings_sorted: Vec<_> = unclean_strings_map.into_iter().collect();
        unclean_strings_sorted.sort_by(|a, b| a.0.cmp(&b.0));

        if !unclean_strings_sorted.is_empty() {
            evaluation_report.push_str("Unclean strings:\n");
            for (string_value, mut blocks) in unclean_strings_sorted {
                blocks.sort_unstable();
                blocks.dedup();
                let blocks_str: Vec<String> = blocks.iter().map(|b| b.to_string()).collect();
                evaluation_report.push_str(&format!("{}\nLocated in data blocks: {}\n\n", string_value, blocks_str.join(", ")));
            }
            evaluation_report.push_str("\n");
        }

        evaluation_report
    }

    // This analyzes our constants stream provided by our wasm2js Converter. 
    // The process for storing constants is done there to optimize process. 
    // Otherwise we would need to redundantly analyze the code block.
    pub fn analyze_decoded_constants(
        &self, 
        constants_stream: &[u8],
        func_ptrs: &[[usize; 2]],
        manager: &WasmManager,
    ) -> String {
        let mut evaluation_report = "".to_string();
        
        if !constants_stream.is_empty() {
            let mut ptr = 0;
            
            // Store strings in a HashMap, so duplicates will all be stored under a single string info.
            let mut result_strings: HashMap<String, (usize, Vec<String>)> = HashMap::new();

            // Use our func ptrs from our Converter, so we can analyze constants, 
            // and know which func they came from. Also track our end i64 for this function 
            // so we know whether to perform an i64 or i32 chunk comparison.
            for (i, bounds) in func_ptrs.iter().enumerate() {
                let func_id = manager.import_funcs_count + i;
                let func_name = manager.parse_func_name(func_id);
                
                let end_func_pos = bounds[0];
                let end_i64_pos = bounds[1];

                while ptr < end_func_pos {
                    // Determine if type is i64 or i32 depending on current ptr location
                    let is_i64 = ptr < end_i64_pos;
                    let int_size = if is_i64 { 8 } else { 4 };
                    let type_name = if is_i64 { "i64" } else { "i32" };

                    // Decode bytes into utf and apply heuristics to analyze the resulting strings.
                    if let Some(constant_bytes) = constants_stream.get(ptr..ptr + int_size) {
                        let text = String::from_utf8_lossy(constant_bytes).into_owned();
                        if self.string_heuristic(&text) {
                            let val_str = if is_i64 {
                                u64::from_le_bytes(constant_bytes.try_into().unwrap()).to_string()
                            } else {
                                u32::from_le_bytes(constant_bytes.try_into().unwrap()).to_string()
                            };
                            
                            let key = format!("[{}] {:<20} -> Text: \"{}\"", type_name, val_str, text);
                            let entry = result_strings.entry(key).or_insert((0, Vec::new()));
                            
                            entry.0 += 1;
                            if !entry.1.contains(&func_name) {
                                entry.1.push(func_name.clone());
                            }
                        }
                    }
                    ptr += int_size;
                }
            }
            
            // Check signatures using our same logic as before
            let found_signatures = self.scan_for_code_constants_signatures(constants_stream, func_ptrs, manager);
            if !found_signatures.is_empty() {
                evaluation_report.push_str("Found crypto signatures in decoded constants:\n");
                for (signature_name, (count, funcs)) in found_signatures {
                    evaluation_report.push_str(&format!("{} (found {} times)\nLocated in: {}\n\n", signature_name, count, funcs.join(", ")));
                }
                evaluation_report.push_str("\n");
            }

            // Push info on decoded constant strings.
            if !result_strings.is_empty() {
                evaluation_report.push_str("Strings found inside decoded integer constants:\n");
                for (string_representation, (count, funcs)) in result_strings {
                    evaluation_report.push_str(&format!("{} (occurrences: {})\nLocated in: {}\n\n", string_representation, count, funcs.join(", ")));
                }
                evaluation_report.push_str("\n");
            }
        }
        
        evaluation_report
    }

    fn extract_ascii_strings(&self, target_bytes: &[u8]) -> (Vec<String>, Vec<String>) {
        let mut clean_strings = Vec::new();
        let mut unclean_strings = Vec::new();
        let mut current_bytes = Vec::new();
        
        // 1 byte chars that skip control chars (starts from space char 32), and goes to 127 (last 1-byte)
        for &byte in target_bytes {
            if byte > 31 && byte < 128 {
                current_bytes.push(byte);
            } else {
                if current_bytes.len() > 3 {
                    self.evaluate_and_store_strings(&current_bytes, &mut clean_strings, &mut unclean_strings);
                }
                current_bytes.clear();
            }
        } 

        if current_bytes.len() > 3 {
            self.evaluate_and_store_strings(&current_bytes, &mut clean_strings, &mut unclean_strings);
        }

        (clean_strings, unclean_strings)
    }

    fn evaluate_and_store_strings(&self, bytes: &[u8], clean: &mut Vec<String>, unclean: &mut Vec<String>) {
        let text = String::from_utf8_lossy(bytes).into_owned();
        
        // Check if our text passes the string heuristic
        if self.string_heuristic(&text) {
            clean.push(text);
            return; 
        }
        
        // If text is not found as clean, attempt to find a subword so we don't accidently skip over results.
        let mut sub_word = "".to_string();
        
        for c in text.chars() {
            if c.is_ascii_alphanumeric() || ['_', '.', '-'].contains(&c) {
                sub_word.push(c);
            } else {
                if sub_word.len() > 3 && self.string_heuristic(&sub_word) {
                    clean.push(sub_word.clone());
                }
                sub_word.clear();
            }
        }

        if sub_word.len() > 3 && self.string_heuristic(&sub_word) {
            clean.push(sub_word);
            return;
        }
        
        // If the sub_word isn't found clean and the fn isn't returned, the full result is unclean.
        unclean.push(text);
    }

    fn string_heuristic(&self, s: &str) -> bool {
        let s = s.trim();
        let len = s.len();
        // Length >= 4 (i32 words minimum to ensure enough entropy).
        if len < 4 { return false };

        let mut alpha_count = 0;
        let mut num_count = 0;
        let mut symbol_count = 0;
        let mut vowel_count = 0;

        for c in s.chars() {
            let b = c as u8;
            // Must be within 1-byte ASCII range. 
            if b < 32 || b > 127 { return false };

            // Classify letters vs. numbers vs. symbols count.
            if c.is_ascii_alphabetic() {
                alpha_count += 1;
                match c.to_ascii_lowercase() {
                    'a' | 'e' | 'i' | 'o' | 'u' | 'y' => vowel_count += 1,
                    _ => {}
                }
            } else if c.is_ascii_digit() {
                num_count += 1;
            } else {
                symbol_count += 1;
            }
        }

        // If the last char is uppercase and the first char is lowercase, 
        // we may be looking at a reversed word. We do not want reverse junk so return false.
        if let (Some(first), Some(last)) = (s.chars().next(), s.chars().last()) {
            if first.is_ascii_lowercase() && last.is_ascii_uppercase() { return false };
        }

        // Filter out any strings that have large redundancy and repetition
        let mut max_consecutive = 1;
        let mut current_consecutive = 1;
        let mut last_char = '\0';
        for c in s.chars() {
            if c == last_char {
                current_consecutive += 1;
                if current_consecutive > max_consecutive { max_consecutive = current_consecutive };
            } else {
                current_consecutive = 1;
                last_char = c;
            }
        }
        if max_consecutive > 3 && alpha_count > 0 { return false };

        // Check if strings are fully symbols/numbers
        if alpha_count == 0 {
            let allowed_symbols_count = s.chars().filter(|c| [' ', '-', '_', '.', '#', ':'].contains(c)).count();
            if symbol_count == allowed_symbols_count { return true };
            return false;
        }

        // Determine if we are looking at an abbreviation/accronym (all upper case). Otherwise we need a vowel.
        if alpha_count > 0 && vowel_count == 0 {
            let is_all_upper = s.chars().filter(|c| c.is_ascii_alphabetic()).all(|c| c.is_ascii_uppercase());
            if !is_all_upper { return false };
        }

        // If too many irregular symbols are found (more than 2) then give false.
        let allowed_symbols = s.chars().filter(|c| [' ', '-', '_', '.', '#', '\'', ':'].contains(c)).count();
        let weird_symbols = symbol_count - allowed_symbols;
        if weird_symbols > 2 { return false };

        // If all else passes, ensure at least 33% of the string is alphanumeric.
        let alphanumeric_count = alpha_count + num_count;
        if (alphanumeric_count as f32 / len as f32) < 0.33 { return false };

        true
    }

    fn scan_for_code_constants_signatures(
        &self, 
        target_bytes: &[u8], 
        func_ptrs: &[[usize; 2]],
        manager: &WasmManager
    ) -> HashMap<String, (usize, Vec<String>)> {
        let mut found_signatures: HashMap<String, (usize, Vec<String>)> = HashMap::new();
        let mut ptr = 0;

        // Scan for crypto signatures by iterating over our constants stream calculated in our Converter. 
        // Calculate bounds for each individual func.
        for (i, bounds) in func_ptrs.iter().enumerate() {
            let func_id = manager.import_funcs_count + i;
            let func_name = manager.parse_func_name(func_id);
            
            let end_func_pos = bounds[0];
            let end_i64_pos = bounds[1];

            while ptr < end_func_pos {
                // Determine if we are in the i64 or i32 values. We'll need to change the bytes comparison to 4 or 8 bytes depending on this.
                let int_size = if ptr < end_i64_pos { 8 } else { 4 };
                
                if let Some(bytes_to_match) = target_bytes.get(ptr..ptr + int_size) {
                    for signature in KNOWN_SIGNATURES {
                        // Window scan to find a byte sequence
                        if signature.byte_pattern.windows(int_size).any(|window| {
                            window == bytes_to_match || window.iter().rev().eq(bytes_to_match.iter())
                        }) {
                            let val_str = if int_size == 4 {
                                u32::from_le_bytes(bytes_to_match.try_into().unwrap()).to_string()
                            } else {
                                u64::from_le_bytes(bytes_to_match.try_into().unwrap()).to_string()
                            };
                            let entry_name = format!("{} (type: i{}, value: {})", signature.name, int_size * 8, val_str);

                            // Ensure we do not have duplicates, add one to the counter for the established entry if we do.
                            let entry = found_signatures.entry(entry_name).or_insert((0, Vec::new()));
                            entry.0 += 1;
                            if !entry.1.contains(&func_name) {
                                entry.1.push(func_name.clone());
                            }
                            break;
                        }
                    }
                }
                ptr += int_size; 
            }
        }
        
        found_signatures
    }

    // Decode LEB128 integers used in WebAssembly binaries so we can parse the data section.
    fn decode_leb128(&self, bytes: &[u8]) -> (usize, usize) {
        let mut result = 0;
        let mut shift = 0;
        let mut count = 0;
        for &byte in bytes {
            count += 1;
            result |= ((byte & 0x7F) as usize) << shift;
            if (byte & 0x80) == 0 {
                break;
            }
            shift += 7;
        }
        (result, count)
    }

    // Parses the data section, allowing us to test both strings and signatures against pure payload data.
    fn parse_data_blocks(&self, target_bytes: &[u8]) -> Vec<(usize, Vec<u8>)> {
        let mut parsed_blocks = Vec::new();
        let mut ptr = 0;

        let (num_segments, bytes_read) = self.decode_leb128(&target_bytes[ptr..]);
        ptr += bytes_read;

        for segment_index in 0..num_segments {
            if ptr >= target_bytes.len() { break };

            // Parse Segment Header
            // 0 = active, 1 = passive, 2 = active with memory index. 
            // Active segments (0, 2) have instructions, which we'll need to skip.
            let bit_flags = target_bytes[ptr];
            ptr += 1;

            // If active, skip the instructions (usually i32.const offset) and the "end" opcode.
            if bit_flags == 0 || bit_flags == 2 {
                if bit_flags == 2 { 
                    // Decode and skip the memory index
                    let (_, skip_bytes) = self.decode_leb128(&target_bytes[ptr..]);
                    ptr += skip_bytes; 
                }
                // Skip until the "end" opcode (0x0B) of the offset expression.
                while ptr < target_bytes.len() && target_bytes[ptr] != 0x0B {
                    ptr += 1;
                }
                ptr += 1; // Skip the 0x0B "end"
            }

            if ptr >= target_bytes.len() { break };

            // Decode the size of the remaining actual data payload, and skip forward
            let (data_len, size_bytes) = self.decode_leb128(&target_bytes[ptr..]);
            ptr += size_bytes;

            if let Some(data_payload) = target_bytes.get(ptr..ptr + data_len) {
                parsed_blocks.push((segment_index, data_payload.to_vec()));
            }
            ptr += data_len;
        }

        parsed_blocks
    }

    fn scan_for_data_block_signatures(&self, data_blocks: &[(usize, Vec<u8>)]) -> HashMap<String, usize> {
        let mut found_signatures: HashMap<String, usize> = HashMap::new();

        for (segment_index, data_payload) in data_blocks {
            let mut sub_ptr = 0;

            // Scan the data block payloads
            while sub_ptr < data_payload.len() {
                let mut matched = false;

                for signature in KNOWN_SIGNATURES {
                    let signature_len = signature.byte_pattern.len();
                    
                    if sub_ptr + signature_len <= data_payload.len() {
                        let bytes_to_match = &data_payload[sub_ptr..sub_ptr + signature_len];
                        
                        // Match the signature and handle
                        if bytes_to_match == signature.byte_pattern || 
                           bytes_to_match.iter().copied().eq(signature.byte_pattern.iter().rev().copied()) 
                        {
                            // Format as WebAssembly Text (WAT) hex string: \xx\xx\xx\xx and get the full entry name.
                            let hex_str: String = bytes_to_match.iter().map(|b| format!("\\{:02x}", b)).collect();
                            let entry_name = format!("{} (data block: {}, hex: \"{}\")", signature.name, segment_index, hex_str);

                            let entry = found_signatures.entry(entry_name).or_insert(0);
                            *entry += 1;
                            
                            // Jump ahead by the full length to prevent overlapping matches, and break out.
                            sub_ptr += signature_len; 
                            matched = true;
                            break;
                        }
                    }
                }

                if !matched {
                    sub_ptr += 1;
                }
            }
        }

        found_signatures
    }
}

use std::collections::HashMap;

pub struct StructSolver;

impl StructSolver {
    pub fn find_structs(common_addr_stores: &HashMap<String, HashMap<String, Vec<(u32, String, String)>>>) -> String {
        let mut output = "WasmCrack detected potential structs/vectors:\n\n".to_string();

        for (func_name, common_addr_store_data) in common_addr_stores {      
            let mut func_output = String::new();

            for (addr, fields_data) in common_addr_store_data {
                let mut current_streak: Vec<(u32, String, String)> = Vec::new();
                
                // If we find a duplicate offset or end the list, we want to "finalize" a streak.
                // If a streak is obtained, then we may have a struct as we have stores at multiple offsets.
                let mut finalize_streak = |streak: &mut Vec<(u32, String, String)>, matched_types: bool| {
                    // Only if we have a streak (> 1) can we potentially say it is a struct.
                    if streak.len() > 1 {
                        // Sort offsets.
                        streak.sort_by_key(|s| s.0);

                        // Track a ptr that'll keep track of memory if it's contiguous.
                        let mut ptr = u32::MAX;

                        // Determine if offset jumps are VALID. Memory should be contiguous.
                        for (offset, _, data_type) in streak.iter() {
                            // If the offset doesnt match the addition then there's a memory skip.
                            // Not contiguous suggests no Struct/array.
                            if ptr != u32::MAX && ptr != *offset {
                                streak.clear();
                                return;
                            }
                            ptr = offset + match data_type.as_str() {
                                "i32" | "f32" | "u32" => 4,
                                "i64" | "f64" => 8,
                                "u8" => 1,
                                "u16" => 2,
                                _ => 0
                            }; 
                        }
                        
                        // If types are matched we have an array, otherwise a struct.
                        // Output well formatted data.
                        if matched_types {
                            func_output.push_str(&format!("PotentialVector (at {}):\n[", addr));
                            let first_item = &streak[0];
                            let last_item = &streak[streak.len() - 1];
                            let offset = &first_item.0;
                            let data_type = &first_item.2;
                            for i in 0..streak.len() - 1 {
                                let (_, value, _) = &streak[i];
                                func_output.push_str(&format!("{}, ", value));
                            }
                            func_output.push_str(&format!("{}", last_item.1));
                            func_output.push_str(&format!("] // (offset: {}) (data-type: {})\n\n", offset, data_type));
                        } else {     
                            func_output.push_str(&format!("PotentialStruct (at {}): {{\n", addr));
                            for (i, (offset, value, data_type)) in streak.iter().enumerate() {
                                func_output.push_str(&format!("    v{}_{}: {} // offset {}\n", i, data_type, value, offset));
                            }
                            func_output.push_str("}\n\n");
                        }
                    }
                    streak.clear();
                };

                // We'll analyze data types to see if they match per "streak." 
                // If a streak breaks and all types match, then it's an array/vector.
                let mut matched_types = true;
                let mut last_data_type = "start";

                for (offset, value, data_type) in fields_data {
                    // Check if this item belongs to a new streak
                    let is_duplicate = current_streak.iter().any(|(o, _, _)| o == offset);

                    if is_duplicate {
                        // Finalize the previous streak cleanly
                        finalize_streak(&mut current_streak, matched_types);
                        // Reset state for the new streak
                        matched_types = true;
                        last_data_type = "start";
                    }

                    // Update the matched_types flag for the current item
                    if matched_types && last_data_type != "start" && data_type != last_data_type {
                        matched_types = false;
                    } else {
                        last_data_type = data_type;
                    }
                    
                    // Add entry to ongoing streak
                    current_streak.push((*offset, value.clone(), data_type.clone()));
                }

                // Process the final streak
                finalize_streak(&mut current_streak, matched_types);
            }

            // Only include the function name if we actually found potential structs inside it.
            if !func_output.is_empty() {
                output.push_str(&format!("{}:\n\n{}", func_name, func_output));
            }
        }
        
        output
    }
}

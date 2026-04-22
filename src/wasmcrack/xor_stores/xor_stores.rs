use std::collections::HashMap;

pub struct XorStores;

impl XorStores {
    pub fn parse_stores(xor_stores: &HashMap<String, Vec<[String; 4]>>) -> String {
        let mut output = "Found direct (immediate) xor operation memory stores:\n\n".to_string();

        // Handle call data outputs for each func.
        for (func_name, store_info) in xor_stores {
            output.push_str(&format!("{} xor stores:\n\n", func_name));

            if store_info.is_empty() {
                output.push_str("None\n");
            } else {
                for info in store_info {
                    output.push_str(&format!("{} - {}\naddr: {}\noffset: {}\nset: {}\n\n", func_name, info[0], info[1], info[2], info[3]));
                }
            }
            output.push('\n');
        }
        
        output
    }
}
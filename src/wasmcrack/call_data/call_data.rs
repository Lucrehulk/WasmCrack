use std::collections::HashMap;

pub struct CallData;

impl CallData {
    pub fn parse_calls(func_calls: &HashMap<String, Vec<(String, bool, String, usize)>>) -> String {
        let mut output = "IMPORTANT NOTE: If WasmCrack indicates a call is not executed at the root level, ".to_string();
        output.push_str("WasmCrack cannot safely determine if it is garantueed to execute.\n\n");
        output.push_str("Wasm binary call data:\n\n");

        // Handle call data outputs for each func.
        for (caller_func, callee_funcs) in func_calls {
            output.push_str(&format!("{} calls:\n\n", caller_func));
            
            if callee_funcs.is_empty() {
                output.push_str("None\n");
            } else {
                for (callee, branch_stack_was_empty, stack_arguments, in_loop) in callee_funcs {
                    // If branch_stack_was_empty is false, then the branch stack wasn't empty at the time of the call. 
                    // WasmCrack cannot safely confirm it is executed.
                    let is_in_branch = if *branch_stack_was_empty {
                        "Executes at root level (execution: absolute)"
                    } else {
                        "Executes in a control structure (execution: inconclusive)"
                    };
                    // Determine if it is part of a loop or not. Loops indicate potential repeat calls.
                    let loop_info = if *in_loop == usize::MAX {
                        "[NO LOOP]"
                    } else {
                        "[LOOP]"
                    };
                    output.push_str(&format!("{} called by {}\nStack arguments: {}\n{} - {}\n\n", callee, caller_func, stack_arguments, is_in_branch, loop_info));
                }
            }
            output.push('\n');
        }
        
        output
    }
}
use super::super::super::constants::crypto_heuristic_weights::*;

pub struct CryptoHeuristicAnalyzer;

impl CryptoHeuristicAnalyzer {
    pub fn rank_crypto_scores(stats: &[(String, usize, usize, usize, usize, usize, usize)]) -> String {
        let mut output = "Wasm funcs ranked by heuristic crypto scores:\n\n".to_string();
        let mut scores = Vec::new();

        for (func_name, total_ops, rot_and_sh_count, xor_count, compute_count, load_count, store_count) in stats {
            // Ignore functions that are too small to be crypto.
            if *total_ops < MIN_TOTAL_OPS {
                scores.push((func_name.clone(), 0.0, 0.0, 0.0, 0.0));
                continue;
            }

            // Calculate ratios.
            let total_ops_f32 = *total_ops as f32;
            let rot_and_sh_ratio = *rot_and_sh_count as f32 / total_ops_f32;
            let xor_ratio = *xor_count as f32 / total_ops_f32;

            // Calculate computations to memory ratio. Higher ratios indicate a higher crypto chance.
            // Add one to mem ops count just to easily prevent division by zero.
            let mem_ops_count = (*load_count + *store_count + 1) as f32;
            let mut compute_ratio = *compute_count as f32 / mem_ops_count;
            
            // Cap the computation to memory ops ratio so it cannot get too large.
            // This is also notably the least important factor of the three factors,
            // so it shouldn't determine much.
            if compute_ratio > COMPUTE_RATIO_CAP {
                compute_ratio = COMPUTE_RATIO_CAP;
            }

            // Add together weights * ratio for each. Total sum is the final score.
            let score = (WEIGHT_ROT_AND_SH * rot_and_sh_ratio) + (WEIGHT_XOR * xor_ratio) + (WEIGHT_COMPUTE * compute_ratio);
            scores.push((func_name.clone(), score, rot_and_sh_ratio, xor_ratio, compute_ratio));
        }

        // Sort descending by score and print out info.
        scores.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        
        for (id, (func_name, score, rot_and_sh_ratio, xor_ratio, compute_ratio)) in scores.iter().enumerate() {
            output.push_str(&format!("{}. {}: {:.4}\nrotation/shift ratio: {:.4}\nxor ratio: {:.4}\ncomputation ratio: {:.4}\n\n", id + 1, func_name, score, rot_and_sh_ratio, xor_ratio, compute_ratio));
        }
        
        output
    }
}
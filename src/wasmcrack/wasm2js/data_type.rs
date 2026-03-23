// Because we are decompiling the binary, then converting to JS via strings, 
// we need an effective way to handle datatypes. Before implementing this file, 
// the converter analyzed all data types with simple string evaluation, which worked, 
// but resulted in unsimplified mathematical expressions (ex. "1 + 1" rather than "2").
// Our DataType enum will introduce handling to evaluate mathematical expressions on same data types,
// while still allowing for string concatenation when needed (e.g. references like locals).

#[derive(Debug, Clone)]
pub enum DataType {
    String { value: String },
    Int32 { value: i32 },
    Int64 { value: i64 },
    Float32 { value: f32 },
    Float64 { value: f64 }
}

impl DataType {
    // Simplify single data types for unary operations and typecasting.
    pub fn simplify_data_type(
        &self,
        op: &str,
        js_format: &str,
        i32_consts: &mut Vec<u8>,
        i64_consts: &mut Vec<u8>
    ) -> DataType {
        let res_val = match self {
            DataType::Int32 { value: a } => match op {
                "eqz" => Some(DataType::Int32 { value: if *a == 0 { 1 } else { 0 } }),
                "clz" => Some(DataType::Int32 { value: a.leading_zeros() as i32 }),
                "ctz" => Some(DataType::Int32 { value: a.trailing_zeros() as i32 }),
                "popcnt" => Some(DataType::Int32 { value: a.count_ones() as i32 }),
                "extend8_s" => Some(DataType::Int32 { value: (*a as i8) as i32 }),
                "extend16_s" => Some(DataType::Int32 { value: (*a as i16) as i32 }),
                "extend_i64_s" => Some(DataType::Int64 { value: *a as i64 }),
                "extend_i64_u" => Some(DataType::Int64 { value: (*a as u32) as i64 }),
                "convert_f32_s" => Some(DataType::Float32 { value: *a as f32 }),
                "convert_f32_u" => Some(DataType::Float32 { value: (*a as u32) as f32 }),
                "convert_f64_s" => Some(DataType::Float64 { value: *a as f64 }),
                "convert_f64_u" => Some(DataType::Float64 { value: (*a as u32) as f64 }),
                "reinterpret_f32" => Some(DataType::Float32 { value: f32::from_bits(*a as u32) }),
                _ => None,
            },
            DataType::Int64 { value: a } => match op {
                "eqz" => Some(DataType::Int32 { value: if *a == 0 { 1 } else { 0 } }),
                "clz" => Some(DataType::Int64 { value: a.leading_zeros() as i64 }),
                "ctz" => Some(DataType::Int64 { value: a.trailing_zeros() as i64 }),
                "popcnt" => Some(DataType::Int64 { value: a.count_ones() as i64 }),
                "extend8_s" => Some(DataType::Int64 { value: (*a as i8) as i64 }),
                "extend16_s" => Some(DataType::Int64 { value: (*a as i16) as i64 }),
                "extend32_s" => Some(DataType::Int64 { value: (*a as i32) as i64 }),
                "wrap_i32" => Some(DataType::Int32 { value: *a as i32 }),
                "convert_f32_s" => Some(DataType::Float32 { value: *a as f32 }),
                "convert_f32_u" => Some(DataType::Float32 { value: (*a as u64) as f32 }),
                "convert_f64_s" => Some(DataType::Float64 { value: *a as f64 }),
                "convert_f64_u" => Some(DataType::Float64 { value: (*a as u64) as f64 }),
                "reinterpret_f64" => Some(DataType::Float64 { value: f64::from_bits(*a as u64) }),
                _ => None,
            },
            DataType::Float32 { value: a } => match op {
                "abs" => Some(DataType::Float32 { value: a.abs() }),
                "neg" => Some(DataType::Float32 { value: -a }),
                "ceil" => Some(DataType::Float32 { value: a.ceil() }),
                "floor" => Some(DataType::Float32 { value: a.floor() }),
                "trunc" => Some(DataType::Float32 { value: a.trunc() }),
                "nearest" => Some(DataType::Float32 { value: a.round_ties_even() }),
                "sqrt" => Some(DataType::Float32 { value: a.sqrt() }),
                "trunc_i32_s" => Some(DataType::Int32 { value: if a.is_nan() || a.is_infinite() { 0 } else { ((a.trunc() as f64) % 4294967296.0) as i64 as i32 } }),
                "trunc_i32_u" => Some(DataType::Int32 { value: if a.is_nan() || a.is_infinite() { 0 } else { ((a.trunc() as f64) % 4294967296.0) as i64 as i32 } }),
                "trunc_i64_s" => Some(DataType::Int64 { value: if a.is_nan() || a.is_infinite() { 0 } else { a.trunc() as i64 } }),
                "trunc_i64_u" => Some(DataType::Int64 { value: if a.is_nan() || a.is_infinite() { 0 } else { (a.trunc() as i64) as u64 as i64 } }),
                
                "trunc_sat_i32_s" => Some(DataType::Int32 { value: a.trunc() as i32 }),
                "trunc_sat_i32_u" => Some(DataType::Int32 { value: (a.trunc() as u32) as i32 }),
                "trunc_sat_i64_s" => Some(DataType::Int64 { value: a.trunc() as i64 }),
                "trunc_sat_i64_u" => Some(DataType::Int64 { value: (a.trunc() as u64) as i64 }),

                "promote_f64" => Some(DataType::Float64 { value: *a as f64 }),
                "reinterpret_i32" => Some(DataType::Int32 { value: a.to_bits() as i32 }),
                _ => None,
            },
            DataType::Float64 { value: a } => match op {
                "abs" => Some(DataType::Float64 { value: a.abs() }),
                "neg" => Some(DataType::Float64 { value: -a }),
                "ceil" => Some(DataType::Float64 { value: a.ceil() }),
                "floor" => Some(DataType::Float64 { value: a.floor() }),
                "trunc" => Some(DataType::Float64 { value: a.trunc() }),
                "nearest" => Some(DataType::Float64 { value: a.round_ties_even() }),
                "sqrt" => Some(DataType::Float64 { value: a.sqrt() }),
                "trunc_i32_s" => Some(DataType::Int32 { value: if a.is_nan() || a.is_infinite() { 0 } else { (a.trunc() % 4294967296.0) as i64 as i32 } }),
                "trunc_i32_u" => Some(DataType::Int32 { value: if a.is_nan() || a.is_infinite() { 0 } else { (a.trunc() % 4294967296.0) as i64 as i32 } }),
                "trunc_i64_s" => Some(DataType::Int64 { value: if a.is_nan() || a.is_infinite() { 0 } else { a.trunc() as i64 } }),
                "trunc_i64_u" => Some(DataType::Int64 { value: if a.is_nan() || a.is_infinite() { 0 } else { (a.trunc() as i64) as u64 as i64 } }),
                
                "trunc_sat_i32_s" => Some(DataType::Int32 { value: a.trunc() as i32 }),
                "trunc_sat_i32_u" => Some(DataType::Int32 { value: (a.trunc() as u32) as i32 }),
                "trunc_sat_i64_s" => Some(DataType::Int64 { value: a.trunc() as i64 }),
                "trunc_sat_i64_u" => Some(DataType::Int64 { value: (a.trunc() as u64) as i64 }),

                "demote_f32" => Some(DataType::Float32 { value: *a as f32 }),
                "reinterpret_i64" => Some(DataType::Int64 { value: a.to_bits() as i64 }),
                _ => None,
            },
            _ => None,
        };

        if let Some(res) = res_val {
            match res {
                DataType::Int32 { value: v } => i32_consts.extend_from_slice(&v.to_le_bytes()),
                DataType::Int64 { value: v } => i64_consts.extend_from_slice(&v.to_le_bytes()),
                _ => {}
            }
            res
        } else {
            DataType::String {
                value: js_format.replace("{0}", &self.to_string())
            }
        }
    }

    // Combine data types safely and effectively, and simplify constants where possible.
    pub fn combine_data(
        &self, 
        other_data: &DataType, 
        op: &str, 
        js_format: &str, 
        i32_consts: &mut Vec<u8>, 
        i64_consts: &mut Vec<u8>
    ) -> DataType {
        match (self, other_data) {
            
            // Handle same numerical types by computing the expressions.
            
            (DataType::Int32 { value: a }, DataType::Int32 { value: b }) => {
                let res_val = match op {
                    "+" => Some(DataType::Int32 { value: a.wrapping_add(*b) }),
                    "-" => Some(DataType::Int32 { value: a.wrapping_sub(*b) }),
                    "*" => Some(DataType::Int32 { value: a.wrapping_mul(*b) }),
                    "/s" => if *b != 0 { Some(DataType::Int32 { value: a.wrapping_div(*b) }) } else { None },
                    "/u" => if *b != 0 { Some(DataType::Int32 { value: (*a as u32).wrapping_div(*b as u32) as i32 }) } else { None },
                    "%s" => if *b != 0 { Some(DataType::Int32 { value: a.wrapping_rem(*b) }) } else { None },
                    "%u" => if *b != 0 { Some(DataType::Int32 { value: (*a as u32).wrapping_rem(*b as u32) as i32 }) } else { None },
                    "&" => Some(DataType::Int32 { value: a & b }),
                    "|" => Some(DataType::Int32 { value: a | b }),
                    "^" => Some(DataType::Int32 { value: a ^ b }),
                    "<<" => Some(DataType::Int32 { value: a.wrapping_shl((*b & 31) as u32) }),
                    ">>s" => Some(DataType::Int32 { value: a.wrapping_shr((*b & 31) as u32) }),
                    ">>u" => Some(DataType::Int32 { value: (*a as u32).wrapping_shr((*b & 31) as u32) as i32 }),
                    "rotl" => Some(DataType::Int32 { value: a.rotate_left((*b & 31) as u32) }),
                    "rotr" => Some(DataType::Int32 { value: a.rotate_right((*b & 31) as u32) }),
                    "==" => Some(DataType::Int32 { value: if a == b { 1 } else { 0 } }),
                    "!=" => Some(DataType::Int32 { value: if a != b { 1 } else { 0 } }),
                    "<s" => Some(DataType::Int32 { value: if a < b { 1 } else { 0 } }),
                    "<u" => Some(DataType::Int32 { value: if (*a as u32) < (*b as u32) { 1 } else { 0 } }),
                    ">s" => Some(DataType::Int32 { value: if a > b { 1 } else { 0 } }),
                    ">u" => Some(DataType::Int32 { value: if (*a as u32) > (*b as u32) { 1 } else { 0 } }),
                    "<=s" => Some(DataType::Int32 { value: if a <= b { 1 } else { 0 } }),
                    "<=u" => Some(DataType::Int32 { value: if (*a as u32) <= (*b as u32) { 1 } else { 0 } }),
                    ">=s" => Some(DataType::Int32 { value: if a >= b { 1 } else { 0 } }),
                    ">=u" => Some(DataType::Int32 { value: if (*a as u32) >= (*b as u32) { 1 } else { 0 } }),
                    _ => None,
                };

                if let Some(res) = res_val {
                    if let DataType::Int32 { value: v } = res {
                        i32_consts.extend_from_slice(&v.to_le_bytes());
                    }
                    return res;
                } else {
                    panic!("{}", format!("Unrecognized operation for datatypes: {}", op));
                }
            },

            (DataType::Int64 { value: a }, DataType::Int64 { value: b }) => {
                let res_val = match op {
                    "+" => Some(DataType::Int64 { value: a.wrapping_add(*b) }),
                    "-" => Some(DataType::Int64 { value: a.wrapping_sub(*b) }),
                    "*" => Some(DataType::Int64 { value: a.wrapping_mul(*b) }),
                    "/s" => if *b != 0 { Some(DataType::Int64 { value: a.wrapping_div(*b) }) } else { None },
                    "/u" => if *b != 0 { Some(DataType::Int64 { value: (*a as u64).wrapping_div(*b as u64) as i64 }) } else { None },
                    "%s" => if *b != 0 { Some(DataType::Int64 { value: a.wrapping_rem(*b) }) } else { None },
                    "%u" => if *b != 0 { Some(DataType::Int64 { value: (*a as u64).wrapping_rem(*b as u64) as i64 }) } else { None },
                    "&" => Some(DataType::Int64 { value: a & b }),
                    "|" => Some(DataType::Int64 { value: a | b }),
                    "^" => Some(DataType::Int64 { value: a ^ b }),
                    "<<" => Some(DataType::Int64 { value: a.wrapping_shl((*b & 63) as u32) }),
                    ">>s" => Some(DataType::Int64 { value: a.wrapping_shr((*b & 63) as u32) }),
                    ">>u" => Some(DataType::Int64 { value: (*a as u64).wrapping_shr((*b & 63) as u32) as i64 }),
                    "rotl" => Some(DataType::Int64 { value: a.rotate_left((*b & 63) as u32) }),
                    "rotr" => Some(DataType::Int64 { value: a.rotate_right((*b & 63) as u32) }),
                    "==" => Some(DataType::Int32 { value: if a == b { 1 } else { 0 } }),
                    "!=" => Some(DataType::Int32 { value: if a != b { 1 } else { 0 } }),
                    "<s" => Some(DataType::Int32 { value: if a < b { 1 } else { 0 } }),
                    "<u" => Some(DataType::Int32 { value: if (*a as u64) < (*b as u64) { 1 } else { 0 } }),
                    ">s" => Some(DataType::Int32 { value: if a > b { 1 } else { 0 } }),
                    ">u" => Some(DataType::Int32 { value: if (*a as u64) > (*b as u64) { 1 } else { 0 } }),
                    "<=s" => Some(DataType::Int32 { value: if a <= b { 1 } else { 0 } }),
                    "<=u" => Some(DataType::Int32 { value: if (*a as u64) <= (*b as u64) { 1 } else { 0 } }),
                    ">=s" => Some(DataType::Int32 { value: if a >= b { 1 } else { 0 } }),
                    ">=u" => Some(DataType::Int32 { value: if (*a as u64) >= (*b as u64) { 1 } else { 0 } }),
                    _ => None,
                };

                if let Some(res) = res_val {
                    match res {
                        DataType::Int64 { value: v } => i64_consts.extend_from_slice(&v.to_le_bytes()),
                        DataType::Int32 { value: v } => i32_consts.extend_from_slice(&v.to_le_bytes()),
                        _ => {}
                    }
                    return res;
                } else {
                    panic!("{}", format!("Unrecognized operation for datatypes: {}", op));
                }
            },

            (DataType::Float32 { value: a }, DataType::Float32 { value: b }) => {
                let res_val = match op {
                    "+" => Some(DataType::Float32 { value: a + b }),
                    "-" => Some(DataType::Float32 { value: a - b }),
                    "*" => Some(DataType::Float32 { value: a * b }),
                    "/" => Some(DataType::Float32 { value: a / b }),
                    "min" => Some(DataType::Float32 { value: if a.is_nan() || b.is_nan() { std::f32::NAN } else { a.min(*b) } }),
                    "max" => Some(DataType::Float32 { value: if a.is_nan() || b.is_nan() { std::f32::NAN } else { a.max(*b) } }),
                    "copysign" => Some(DataType::Float32 { value: a.copysign(*b) }),
                    "==" => Some(DataType::Int32 { value: if a == b { 1 } else { 0 } }),
                    "!=" => Some(DataType::Int32 { value: if a != b { 1 } else { 0 } }),
                    "<" => Some(DataType::Int32 { value: if a < b { 1 } else { 0 } }),
                    ">" => Some(DataType::Int32 { value: if a > b { 1 } else { 0 } }),
                    "<=" => Some(DataType::Int32 { value: if a <= b { 1 } else { 0 } }),
                    ">=" => Some(DataType::Int32 { value: if a >= b { 1 } else { 0 } }),
                    _ => None,
                };

                if let Some(res) = res_val {
                    if let DataType::Int32 { value: v } = res {
                        i32_consts.extend_from_slice(&v.to_le_bytes());
                    }
                    return res;
                } else {
                    panic!("{}", format!("Unrecognized operation for datatypes: {}", op));
                }
            },

            (DataType::Float64 { value: a }, DataType::Float64 { value: b }) => {
                let res_val = match op {
                    "+" => Some(DataType::Float64 { value: a + b }),
                    "-" => Some(DataType::Float64 { value: a - b }),
                    "*" => Some(DataType::Float64 { value: a * b }),
                    "/" => Some(DataType::Float64 { value: a / b }),
                    "min" => Some(DataType::Float64 { value: if a.is_nan() || b.is_nan() { std::f64::NAN } else { a.min(*b) } }),
                    "max" => Some(DataType::Float64 { value: if a.is_nan() || b.is_nan() { std::f64::NAN } else { a.max(*b) } }),
                    "copysign" => Some(DataType::Float64 { value: a.copysign(*b) }),
                    "==" => Some(DataType::Int32 { value: if a == b { 1 } else { 0 } }),
                    "!=" => Some(DataType::Int32 { value: if a != b { 1 } else { 0 } }),
                    "<" => Some(DataType::Int32 { value: if a < b { 1 } else { 0 } }),
                    ">" => Some(DataType::Int32 { value: if a > b { 1 } else { 0 } }),
                    "<=" => Some(DataType::Int32 { value: if a <= b { 1 } else { 0 } }),
                    ">=" => Some(DataType::Int32 { value: if a >= b { 1 } else { 0 } }),
                    _ => None,
                };

                if let Some(res) = res_val {
                    if let DataType::Int32 { value: v } = res {
                        i32_consts.extend_from_slice(&v.to_le_bytes());
                    }
                    return res;
                } else {
                    panic!("{}", format!("Unrecognized operation for datatypes: {}", op));
                }
            },

            // If datatypes are not numerically matched, then we want to return a string expression.
            _ => {
                DataType::String {
                    value: js_format.replace("{0}", &self.to_string()).replace("{1}", &other_data.to_string())
                }
            }
        }
    }

    // Convert data to JS-compatible string representation.
    pub fn to_string(&self) -> String {
        match self {
            DataType::String { value: v } => v.clone(), 
            DataType::Int32 { value: v } => v.to_string(),
            DataType::Int64 { value: v } => format!("{}n", v),
            DataType::Float32 { value: v } => {
                if v.is_nan() { "NaN".to_string() }
                else if v.is_infinite() {
                    if v.is_sign_positive() { "Infinity".to_string() } else { "-Infinity".to_string() }
                }
                else { format!("{:?}", v) }
            },
            DataType::Float64 { value: v } => {
                if v.is_nan() { "NaN".to_string() }
                else if v.is_infinite() {
                    if v.is_sign_positive() { "Infinity".to_string() } else { "-Infinity".to_string() }
                }
                else { format!("{:?}", v) }
            }
        }
    }
}
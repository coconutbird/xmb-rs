//! Variant types and encoding for XMB values.
//!
//! XMB uses a variant system to store values efficiently. Each variant has a
//! 24-bit data field and an 8-bit type field with flags.

use crate::error::{Error, Result};

/// Variant type enumeration matching the XMB format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum VariantType {
    /// Null/empty value (always direct).
    Null = 0,
    /// 24-bit float (always direct).
    Float24 = 1,
    /// 32-bit float (always offset).
    Float = 2,
    /// 24-bit integer (always direct).
    Int24 = 3,
    /// 32-bit integer (always offset).
    Int32 = 4,
    /// 24-bit fixed-point fraction (value * 10,000, always direct).
    Fract24 = 5,
    /// 64-bit double (always offset).
    Double = 6,
    /// Boolean - "true" or "false" (always direct).
    Bool = 7,
    /// ANSI string (direct or offset).
    String = 8,
    /// Unicode string (direct or offset).
    UString = 9,
    /// Float vector (2, 3, or 4 components, always offset).
    FloatVec = 10,
}

/// Type mask for extracting the variant type.
pub const TYPE_MASK: u8 = 0x1F;
/// Flag indicating the value is stored as an offset.
pub const OFFSET_FLAG: u8 = 0x80;
/// Flag indicating an unsigned integer.
pub const UNSIGNED_FLAG: u8 = 0x40;
/// Mask for vector size (stored in bits 5-6 for FloatVec).
pub const VEC_SIZE_MASK: u8 = 0x60;
/// Shift for vector size bits.
pub const VEC_SIZE_SHIFT: u8 = 5;

impl VariantType {
    /// Parse a variant type from a raw byte.
    pub fn from_byte(byte: u8) -> Result<Self> {
        match byte & TYPE_MASK {
            0 => Ok(VariantType::Null),
            1 => Ok(VariantType::Float24),
            2 => Ok(VariantType::Float),
            3 => Ok(VariantType::Int24),
            4 => Ok(VariantType::Int32),
            5 => Ok(VariantType::Fract24),
            6 => Ok(VariantType::Double),
            7 => Ok(VariantType::Bool),
            8 => Ok(VariantType::String),
            9 => Ok(VariantType::UString),
            10 => Ok(VariantType::FloatVec),
            n => Err(Error::InvalidVariantType(n)),
        }
    }
}

/// A variant value in the XMB format.
#[derive(Debug, Clone, PartialEq)]
pub enum Variant {
    /// Null/empty value.
    Null,
    /// Floating point value.
    Float(f32),
    /// Double precision floating point value.
    Double(f64),
    /// Signed integer value.
    Int(i32),
    /// Unsigned integer value.
    UInt(u32),
    /// Boolean value.
    Bool(bool),
    /// String value.
    String(String),
    /// Unicode string value.
    UString(String),
    /// Float vector (2, 3, or 4 components).
    FloatVec(Vec<f32>),
}

impl Default for Variant {
    fn default() -> Self {
        Variant::Null
    }
}

impl Variant {
    /// Convert variant to string representation.
    pub fn to_string_value(&self) -> String {
        match self {
            Variant::Null => String::new(),
            Variant::Float(v) => v.to_string(),
            Variant::Double(v) => v.to_string(),
            Variant::Int(v) => v.to_string(),
            Variant::UInt(v) => v.to_string(),
            Variant::Bool(v) => if *v { "true" } else { "false" }.to_string(),
            Variant::String(s) | Variant::UString(s) => s.clone(),
            Variant::FloatVec(v) => v
                .iter()
                .map(|f| f.to_string())
                .collect::<Vec<_>>()
                .join(","),
        }
    }

    /// Try to get the value as a float.
    pub fn as_float(&self) -> Option<f32> {
        match self {
            Variant::Float(v) => Some(*v),
            Variant::Double(v) => Some(*v as f32),
            Variant::Int(v) => Some(*v as f32),
            Variant::UInt(v) => Some(*v as f32),
            _ => None,
        }
    }

    /// Try to get the value as an integer.
    pub fn as_int(&self) -> Option<i32> {
        match self {
            Variant::Int(v) => Some(*v),
            Variant::UInt(v) => Some(*v as i32),
            Variant::Float(v) => Some(*v as i32),
            Variant::Double(v) => Some(*v as i32),
            Variant::Bool(v) => Some(if *v { 1 } else { 0 }),
            _ => None,
        }
    }

    /// Try to get the value as a boolean.
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Variant::Bool(v) => Some(*v),
            Variant::Int(v) => Some(*v != 0),
            Variant::UInt(v) => Some(*v != 0),
            _ => None,
        }
    }
}

/// Pack a 32-bit float into a 24-bit representation.
///
/// Format: 1-bit sign + 6-bit exponent + 17-bit mantissa
pub fn pack_float24(value: f32) -> u32 {
    if value == 0.0 {
        return 0;
    }

    let bits = value.to_bits();
    let sign = (bits >> 31) & 1;
    let exp = ((bits >> 23) & 0xFF) as i32;
    let mantissa = bits & 0x7FFFFF;

    // Bias conversion: IEEE 754 uses 127, we use 31
    let new_exp = (exp - 127 + 31).clamp(0, 63) as u32;

    // Take top 17 bits of 23-bit mantissa
    let new_mantissa = mantissa >> 6;

    (sign << 23) | (new_exp << 17) | new_mantissa
}

/// Unpack a 24-bit float representation to a 32-bit float.
pub fn unpack_float24(packed: u32) -> f32 {
    if packed == 0 {
        return 0.0;
    }

    let sign = (packed >> 23) & 1;
    let exp = (packed >> 17) & 0x3F;
    let mantissa = packed & 0x1FFFF;

    // Convert exponent bias back: from 31 to 127
    let new_exp = (exp as i32 - 31 + 127) as u32;

    // Extend mantissa from 17 to 23 bits
    let new_mantissa = mantissa << 6;

    let bits = (sign << 31) | (new_exp << 23) | new_mantissa;
    f32::from_bits(bits)
}

/// Pack a float as a 24-bit fixed-point fraction (value * 10,000).
pub fn pack_fract24(value: f32) -> u32 {
    let scaled = (value * 10000.0).round() as i32;
    if scaled >= 0 {
        (scaled as u32) & 0x7FFFFF
    } else {
        ((-scaled) as u32 & 0x7FFFFF) | 0x800000
    }
}

/// Unpack a 24-bit fixed-point fraction to a float.
pub fn unpack_fract24(packed: u32) -> f32 {
    let is_negative = (packed & 0x800000) != 0;
    let magnitude = (packed & 0x7FFFFF) as f32;
    let value = magnitude / 10000.0;
    if is_negative { -value } else { value }
}

/// Pack a 24-bit signed integer.
pub fn pack_int24(value: i32) -> u32 {
    if value >= 0 {
        (value as u32) & 0x7FFFFF
    } else {
        ((-value) as u32 & 0x7FFFFF) | 0x800000
    }
}

/// Unpack a 24-bit signed integer.
pub fn unpack_int24(packed: u32) -> i32 {
    let is_negative = (packed & 0x800000) != 0;
    let magnitude = (packed & 0x7FFFFF) as i32;
    if is_negative { -magnitude } else { magnitude }
}

/// Pack a 24-bit unsigned integer.
pub fn pack_uint24(value: u32) -> u32 {
    value & 0xFFFFFF
}

/// Unpack a 24-bit unsigned integer.
pub fn unpack_uint24(packed: u32) -> u32 {
    packed & 0xFFFFFF
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_float24_roundtrip() {
        let values = [0.0f32, 1.0, -1.0, 0.5, 100.0, -0.001];
        for value in values {
            let packed = pack_float24(value);
            let unpacked = unpack_float24(packed);
            assert!(
                (value - unpacked).abs() < 0.01,
                "Float24 roundtrip failed for {}: got {}",
                value,
                unpacked
            );
        }
    }

    #[test]
    fn test_fract24_roundtrip() {
        let values = [0.0f32, 1.0, -1.0, 0.5, 0.1234];
        for value in values {
            let packed = pack_fract24(value);
            let unpacked = unpack_fract24(packed);
            assert!(
                (value - unpacked).abs() < 0.0002,
                "Fract24 roundtrip failed for {}: got {}",
                value,
                unpacked
            );
        }
    }

    #[test]
    fn test_int24_roundtrip() {
        let values = [0i32, 1, -1, 1000, -1000, 8388607];
        for value in values {
            let packed = pack_int24(value);
            let unpacked = unpack_int24(packed);
            assert_eq!(value, unpacked, "Int24 roundtrip failed for {}", value);
        }
    }
}

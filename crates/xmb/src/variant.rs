//! Variant types and encoding for XMB values.
//!
//! XMB uses a variant system to store values efficiently. Each variant value
//! is encoded as a 32-bit integer with the following layout:
//!
//! ```text
//! Bits 31-24 (type byte):
//!   Bit 7 (0x80): OFFSET_FLAG - Value is stored at an offset in data table
//!   Bit 6 (0x40): UNSIGNED_FLAG (for integers) or VEC_SIZE high bit (for FloatVec)
//!   Bit 5 (0x20): VEC_SIZE low bit (for FloatVec, encodes 2/3/4 components)
//!   Bits 4-0: Variant type (0-10)
//!
//! Bits 23-0 (data):
//!   For direct values: The actual value (Int24, Float24, Bool, etc.)
//!   For offset values: Offset into the data/string table
//! ```
//!
//! ## Variant Types
//!
//! | Type | Name     | Storage  | Description |
//! |------|----------|----------|-------------|
//! | 0    | Null     | Direct   | Empty/null value |
//! | 1    | Float24  | Direct   | 24-bit packed float (1-bit sign, 6-bit exp, 17-bit mantissa) |
//! | 2    | Float    | Offset   | 32-bit IEEE 754 float |
//! | 3    | Int24    | Direct   | 24-bit integer (sign bit + 23-bit magnitude) |
//! | 4    | Int32    | Offset   | 32-bit integer |
//! | 5    | Fract24  | Direct   | 24-bit fixed-point (value × 10,000) |
//! | 6    | Double   | Offset   | 64-bit IEEE 754 double |
//! | 7    | Bool     | Direct   | Boolean (0=false, 1=true) |
//! | 8    | String   | Either   | ANSI string (direct if ≤3 chars) |
//! | 9    | UString  | Offset   | UTF-16 Unicode string |
//! | 10   | FloatVec | Offset   | Float vector (2-4 components, size in bits 5-6) |

use crate::error::{Error, Result};

// ============================================================================
// Variant Type Flags
// ============================================================================

/// Type mask for extracting the variant type (bits 0-4).
///
/// Apply this mask to the type byte to get the base variant type.
/// ```
/// # use xmb::variant::TYPE_MASK;
/// let type_byte: u8 = 0x88; // String with OFFSET_FLAG
/// let variant_type = type_byte & TYPE_MASK; // = 8 (String)
/// ```
pub const TYPE_MASK: u8 = 0x1F;

/// Flag indicating the value is stored as an offset (bit 7).
///
/// When set, the 24-bit data field contains an offset into the data table.
/// When clear, the 24-bit data field contains the value directly.
pub const OFFSET_FLAG: u8 = 0x80;

/// Flag indicating an unsigned integer (bit 6).
///
/// Only meaningful for Int24 type. When set, the value is unsigned.
/// Note: This bit overlaps with VEC_SIZE_MASK for FloatVec type.
pub const UNSIGNED_FLAG: u8 = 0x40;

/// Mask for vector size bits (bits 5-6).
///
/// For FloatVec type, these bits encode the number of components:
/// - 0b00 (0) = 2 components
/// - 0b01 (1) = 3 components
/// - 0b10 (2) = 4 components
///
/// Note: These bits overlap with UNSIGNED_FLAG for integer types.
pub const VEC_SIZE_MASK: u8 = 0x60;

/// Shift amount to extract vector size from type byte.
pub const VEC_SIZE_SHIFT: u8 = 5;

// ============================================================================
// Variant Type Enum
// ============================================================================

/// Variant type enumeration matching the XMB format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum VariantType {
    /// Null/empty value (always direct, data = 0).
    Null = 0,
    /// 24-bit packed float (always direct).
    /// Format: 1-bit sign + 6-bit exponent (bias 31) + 17-bit mantissa.
    Float24 = 1,
    /// 32-bit IEEE 754 float (always offset).
    Float = 2,
    /// 24-bit integer (always direct).
    /// Format: 1-bit sign + 23-bit magnitude.
    /// Can be unsigned if UNSIGNED_FLAG is set.
    Int24 = 3,
    /// 32-bit integer (always offset).
    Int32 = 4,
    /// 24-bit fixed-point fraction (always direct).
    /// Value is stored as (value × 10,000), with sign bit.
    Fract24 = 5,
    /// 64-bit IEEE 754 double (always offset).
    Double = 6,
    /// Boolean value (always direct).
    /// Data is 0 for false, 1 for true.
    Bool = 7,
    /// ANSI string (direct if ≤3 bytes, otherwise offset).
    /// Direct strings pack up to 3 ASCII characters in the 24-bit data field.
    String = 8,
    /// Unicode string (always offset).
    /// Stored as null-terminated UTF-16.
    UString = 9,
    /// Float vector with 2-4 components (always offset).
    /// Component count encoded in VEC_SIZE bits: 0=2, 1=3, 2=4.
    FloatVec = 10,
}

impl VariantType {
    /// Parse a variant type from a raw byte.
    ///
    /// This extracts the type from the lower 5 bits of the type byte.
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

    /// Returns true if this type always uses offset storage.
    pub fn always_offset(&self) -> bool {
        matches!(
            self,
            VariantType::Float | VariantType::Int32 | VariantType::Double | VariantType::FloatVec
        )
    }

    /// Returns true if this type always uses direct storage.
    pub fn always_direct(&self) -> bool {
        matches!(
            self,
            VariantType::Null
                | VariantType::Float24
                | VariantType::Int24
                | VariantType::Fract24
                | VariantType::Bool
        )
    }

    /// Returns true if this type can use either direct or offset storage.
    pub fn can_be_direct_or_offset(&self) -> bool {
        matches!(self, VariantType::String | VariantType::UString)
    }
}

// ============================================================================
// Variant Flag Helper Functions
// ============================================================================

/// Extract the variant type from a 32-bit variant value.
///
/// This reads the type from the upper byte (bits 24-28).
pub fn extract_type(variant_value: u32) -> Result<VariantType> {
    let type_byte = (variant_value >> 24) as u8;
    VariantType::from_byte(type_byte)
}

/// Check if a variant value uses offset storage.
pub fn is_offset(variant_value: u32) -> bool {
    let type_byte = (variant_value >> 24) as u8;
    (type_byte & OFFSET_FLAG) != 0
}

/// Check if a variant value represents an unsigned integer.
///
/// Only meaningful for Int24 type.
pub fn is_unsigned(variant_value: u32) -> bool {
    let type_byte = (variant_value >> 24) as u8;
    (type_byte & UNSIGNED_FLAG) != 0
}

/// Extract the vector component count from a FloatVec variant value.
///
/// Returns 2, 3, or 4 based on the VEC_SIZE bits.
pub fn extract_vec_size(variant_value: u32) -> usize {
    let type_byte = (variant_value >> 24) as u8;
    let size_bits = (type_byte & VEC_SIZE_MASK) >> VEC_SIZE_SHIFT;
    match size_bits {
        0 => 2,
        1 => 3,
        2 => 4,
        _ => 2, // Default to 2
    }
}

/// Extract the 24-bit data field from a variant value.
pub fn extract_data(variant_value: u32) -> u32 {
    variant_value & 0xFFFFFF
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

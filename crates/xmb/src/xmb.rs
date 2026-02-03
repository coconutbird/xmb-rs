//! XMB binary XML reader and writer.

use byteorder::{BigEndian, LittleEndian, ReadBytesExt, WriteBytesExt};
use std::io::{Cursor, Read, Seek, Write};

use crate::ecf::{EcfReader, EcfWriter, XMB_ECF_FILE_ID, XMX_PACKED_DATA_CHUNK_ID};
use crate::error::{Error, Result};
use crate::types::{Attribute, Node, XmbData, XmbFormat};
use crate::variant::{
    OFFSET_FLAG, UNSIGNED_FLAG, Variant, VariantType, unpack_float24, unpack_fract24, unpack_int24,
};

/// XMB data signature.
pub const XMB_SIGNATURE: u32 = 0x71439800;

/// XMB file reader.
pub struct XmbReader;

impl XmbReader {
    /// Read an XMB file from a reader.
    pub fn read<R: Read + Seek>(reader: R) -> Result<XmbData> {
        let mut ecf = EcfReader::new(reader)?;

        // Verify file ID
        if ecf.header().id != XMB_ECF_FILE_ID {
            return Err(Error::InvalidEcfFileId {
                expected: XMB_ECF_FILE_ID,
                actual: ecf.header().id,
            });
        }

        // Read packed data chunk
        let packed_data = ecf.read_chunk_data_by_id(XMX_PACKED_DATA_CHUNK_ID)?;

        // Parse the packed data
        Self::parse_packed_data(&packed_data)
    }

    /// Parse the packed XMB data.
    ///
    /// The packed format uses:
    /// - 4 bytes: signature (0x71439800 in native endian)
    /// - 4 bytes: padding
    /// - 8 bytes: nodes array size (number of nodes as u64)
    /// - N nodes, each with packed attributes and children arrays
    /// - 8 bytes: variant data size
    /// - M bytes: variant data
    fn parse_packed_data(data: &[u8]) -> Result<XmbData> {
        let mut cursor = Cursor::new(data);

        // Read signature - detect endianness
        let sig_bytes = cursor.read_u32::<LittleEndian>()?;
        let is_big_endian = sig_bytes == XMB_SIGNATURE.swap_bytes();

        let signature = if is_big_endian {
            sig_bytes.swap_bytes()
        } else {
            sig_bytes
        };

        if signature != XMB_SIGNATURE {
            return Err(Error::InvalidXmbSignature {
                expected: XMB_SIGNATURE,
                actual: signature,
            });
        }

        // Parse based on detected format
        // Pass full buffer - offsets in the data are relative to buffer start
        if is_big_endian {
            Self::parse_packed_data_xbox360(data)
        } else {
            Self::parse_packed_data_pc(data)
        }
    }

    /// Parse packed data in PC format (Halo Wars Definitive Edition).
    ///
    /// The packed format from Halo Wars DE uses:
    /// - 4 bytes: signature (already validated)
    /// - 4 bytes: padding
    /// - 4 bytes: mNodes.mSize (number of nodes)
    /// - 4 bytes: padding to 8-byte alignment
    /// - 8 bytes: mNodes.mPtr (offset to node data from buffer start)
    /// - 4 bytes: mVariantData.mSize (size of variant data)
    /// - 4 bytes: padding
    /// - 8 bytes: mVariantData.mPtr (offset to variant data from buffer start)
    /// - Node data at mNodes.mPtr offset
    /// - Variant data at mVariantData.mPtr offset
    fn parse_packed_data_pc(data: &[u8]) -> Result<XmbData> {
        let mut cursor = Cursor::new(data);

        // Skip signature (4 bytes) - already validated
        let _signature = cursor.read_u32::<LittleEndian>()?;
        // Skip padding (4 bytes)
        let _padding = cursor.read_u32::<LittleEndian>()?;

        // Read nodes array header (BPackedArray format: mSize + padding + mPtr)
        let num_nodes = cursor.read_u32::<LittleEndian>()? as usize;
        let _nodes_padding = cursor.read_u32::<LittleEndian>()?;
        let nodes_offset = cursor.read_u64::<LittleEndian>()? as usize;

        // Read variant data array header
        let variant_data_size = cursor.read_u32::<LittleEndian>()? as usize;
        let _variant_padding = cursor.read_u32::<LittleEndian>()?;
        let variant_data_offset = cursor.read_u64::<LittleEndian>()? as usize;

        if num_nodes == 0 {
            return Ok(XmbData {
                root: None,
                format: crate::types::XmbFormat::PC,
                source_file: None,
            });
        }

        // Get the variant data slice
        let variant_data = if variant_data_offset < data.len() && variant_data_size > 0 {
            let end = (variant_data_offset + variant_data_size).min(data.len());
            &data[variant_data_offset..end]
        } else {
            &data[0..0]
        };

        // Parse nodes from the nodes_offset
        let (nodes, _) = Self::parse_packed_nodes_le(data, nodes_offset, num_nodes)?;

        // Build the tree structure from flat nodes
        let root = Self::build_node_tree_le(&nodes, 0, variant_data)?;

        Ok(XmbData {
            root: Some(root),
            format: crate::types::XmbFormat::PC,
            source_file: None,
        })
    }

    /// Parse packed nodes in LE format.
    ///
    /// Each node has the following structure (48 bytes):
    /// - mParentNode: 4 bytes
    /// - mName: 4 bytes variant
    /// - mText: 4 bytes variant
    /// - padding: 4 bytes (to align mAttributes.mPtr to 8)
    /// - mAttributes.mPtr: 8 bytes (offset to attribute data)
    /// - mAttributes.mSize: 4 bytes (-1 if no attributes)
    /// - padding: 4 bytes
    /// - mChildren.mSize: 4 bytes
    /// - padding: 4 bytes
    /// - mChildren.mPtr: 8 bytes (offset to children data, 0xFFFFFFFF if none)
    /// Total: 48 bytes per node
    ///
    /// Returns (nodes, end_offset).
    fn parse_packed_nodes_le(
        data: &[u8],
        start: usize,
        num_nodes: usize,
    ) -> Result<(Vec<PackedNodeRead>, usize)> {
        let mut nodes = Vec::with_capacity(num_nodes);

        const NODE_SIZE: usize = 48;

        for i in 0..num_nodes {
            let node_offset = start + i * NODE_SIZE;
            if node_offset + NODE_SIZE > data.len() {
                return Err(Error::UnexpectedEof);
            }

            let mut cursor = Cursor::new(&data[node_offset..]);

            // Read node fields
            let parent_node = cursor.read_u32::<LittleEndian>()?;
            let name_variant = cursor.read_u32::<LittleEndian>()?;
            let text_variant = cursor.read_u32::<LittleEndian>()?;
            let _pad1 = cursor.read_u32::<LittleEndian>()?;

            // Attributes BPackedArray: mSize (4), padding (4), mPtr (8)
            let attr_count_raw = cursor.read_u32::<LittleEndian>()?;
            let _attr_pad = cursor.read_u32::<LittleEndian>()?;
            let attrs_offset = cursor.read_u64::<LittleEndian>()? as usize;

            // Children BPackedArray: mSize (4), padding (4), mPtr (8)
            let child_count_raw = cursor.read_u32::<LittleEndian>()?;
            let _child_pad = cursor.read_u32::<LittleEndian>()?;
            let children_offset = cursor.read_u64::<LittleEndian>()? as usize;

            // attr_count = -1 (0xFFFFFFFF) means no attributes
            let num_attributes = if attr_count_raw == 0xFFFFFFFF {
                0
            } else {
                // Sanity check: attributes should be reasonable
                (attr_count_raw as usize).min(10000)
            };

            // children_offset = 0xFFFFFFFF_FFFFFFFF or lower 32 bits = 0xFFFFFFFF means no children
            let children_offset_low = (children_offset & 0xFFFFFFFF) as u32;
            let num_children = if children_offset_low == 0xFFFFFFFF || child_count_raw == 0xFFFFFFFF
            {
                0
            } else {
                // Sanity check: children should be reasonable
                (child_count_raw as usize).min(100000)
            };

            // Parse attributes from their offset
            let mut attributes = Vec::with_capacity(num_attributes);
            if num_attributes > 0 && attrs_offset < data.len() {
                // Each attribute is 8 bytes (2 x 4-byte variants)
                for j in 0..num_attributes {
                    let attr_pos = attrs_offset + j * 8;
                    if attr_pos + 8 <= data.len() {
                        let mut attr_cursor = Cursor::new(&data[attr_pos..]);
                        let attr_name = attr_cursor.read_u32::<LittleEndian>()?;
                        let attr_value = attr_cursor.read_u32::<LittleEndian>()?;
                        attributes.push((attr_name, attr_value));
                    }
                }
            }

            // Parse children from their offset
            let mut children = Vec::with_capacity(num_children);
            if num_children > 0 && children_offset < data.len() {
                // Each child is 4 bytes (index only, no padding)
                for j in 0..num_children {
                    let child_pos = children_offset + j * 4;
                    if child_pos + 4 <= data.len() {
                        let mut child_cursor = Cursor::new(&data[child_pos..]);
                        let child_index = child_cursor.read_u32::<LittleEndian>()?;
                        children.push(child_index);
                    }
                }
            }

            nodes.push(PackedNodeRead {
                parent_node,
                name_variant,
                text_variant,
                attributes,
                children,
            });
        }

        let end_offset = start + num_nodes * NODE_SIZE;
        Ok((nodes, end_offset))
    }

    /// Build node tree from packed nodes (iterative to avoid stack overflow).
    fn build_node_tree_le(
        nodes: &[PackedNodeRead],
        root_index: usize,
        variant_data: &[u8],
    ) -> Result<Node> {
        if root_index >= nodes.len() {
            return Err(Error::InvalidNode(format!(
                "Node index {} out of bounds (max {})",
                root_index,
                nodes.len()
            )));
        }

        // Build all nodes first (without children)
        let mut built_nodes: Vec<Option<Node>> = vec![None; nodes.len()];

        // Process nodes in reverse order of dependencies (leaves first)
        // We'll do multiple passes until all nodes referenced from root are built
        let mut to_process: Vec<usize> = vec![root_index];
        let mut process_order: Vec<usize> = Vec::new();

        // First pass: collect all nodes we need to process (BFS)
        let mut visited = vec![false; nodes.len()];
        while let Some(idx) = to_process.pop() {
            if idx >= nodes.len() || visited[idx] {
                continue;
            }
            visited[idx] = true;
            process_order.push(idx);

            // Add children to process
            for &child_idx in &nodes[idx].children {
                let ci = child_idx as usize;
                if ci < nodes.len() && !visited[ci] {
                    to_process.push(ci);
                }
            }
        }

        // Process in reverse order (children before parents)
        for &idx in process_order.iter().rev() {
            let packed = &nodes[idx];

            let name = Self::decode_variant_string(packed.name_variant, variant_data)?;
            let text = if packed.text_variant != 0 {
                Self::decode_variant_to_variant(packed.text_variant, variant_data)?
            } else {
                Variant::Null
            };

            let mut attributes = Vec::with_capacity(packed.attributes.len());
            for (attr_name, attr_value) in &packed.attributes {
                let name = Self::decode_variant_string(*attr_name, variant_data)?;
                let value = Self::decode_variant_to_variant(*attr_value, variant_data)?;
                attributes.push(Attribute { name, value });
            }

            // Take already-built children
            let mut children = Vec::with_capacity(packed.children.len());
            for &child_idx in &packed.children {
                let ci = child_idx as usize;
                if ci < nodes.len() {
                    if let Some(child) = built_nodes[ci].take() {
                        children.push(child);
                    }
                }
            }

            built_nodes[idx] = Some(Node {
                name,
                text,
                attributes,
                children,
            });
        }

        built_nodes[root_index]
            .take()
            .ok_or_else(|| Error::InvalidNode("Failed to build root node".to_string()))
    }

    /// Parse Xbox 360 XMB packed data format.
    ///
    /// This handles two format variants:
    /// 1. Original Halo Wars Xbox 360 format (PackedArray with 28-byte nodes)
    /// 2. Simplified format written by XmbWriter (24-byte header, 20-byte nodes)
    fn parse_packed_data_xbox360(data: &[u8]) -> Result<XmbData> {
        // Detect format variant by examining header structure
        // Original format: sig(4) + nodes_size(4) + nodes_ptr(4) + ...
        // Writer format:   sig(4) + flags(4) + node_count(4) + attr_count(4) + ...
        //
        // In original format, offset 8 is nodes_ptr (pointing to node data, typically 20)
        // In writer format, offset 8 is node_count (typically small number like 1-100)
        // Also check offset 4: in original format it's nodes_size, in writer format it's flags (0)

        Self::parse_packed_data_xbox360_original(data)
    }

    /// Parse the original Halo Wars Xbox 360 XMB packed data format.
    fn parse_packed_data_xbox360_original(data: &[u8]) -> Result<XmbData> {
        if data.len() < 24 {
            return Err(Error::InvalidNode("Xbox 360 data too short".into()));
        }

        let mut cursor = Cursor::new(data);

        // Read header (20 bytes total)
        let _signature = cursor.read_u32::<BigEndian>()?;
        let nodes_size = cursor.read_u32::<BigEndian>()? as usize;
        let nodes_ptr = cursor.read_u32::<BigEndian>()? as usize;
        let variant_data_size = cursor.read_u32::<BigEndian>()? as usize;
        let variant_data_ptr = cursor.read_u32::<BigEndian>()? as usize;

        if nodes_size == 0 {
            return Ok(XmbData {
                root: None,
                format: crate::types::XmbFormat::Xbox360,
                source_file: None,
            });
        }

        let variant_data = if variant_data_ptr < data.len() {
            let end = (variant_data_ptr + variant_data_size).min(data.len());
            &data[variant_data_ptr..end]
        } else {
            &data[0..0]
        };

        #[allow(dead_code)]
        struct PackedNodeOrig {
            parent: u32,
            name: u32,
            text: u32,
            attrs_size: u32,
            attrs_ptr: u32,
            children_size: u32,
            children_ptr: u32,
        }

        let mut packed_nodes = Vec::with_capacity(nodes_size);
        cursor.set_position(nodes_ptr as u64);
        for _ in 0..nodes_size {
            packed_nodes.push(PackedNodeOrig {
                parent: cursor.read_u32::<BigEndian>()?,
                name: cursor.read_u32::<BigEndian>()?,
                text: cursor.read_u32::<BigEndian>()?,
                attrs_size: cursor.read_u32::<BigEndian>()?,
                attrs_ptr: cursor.read_u32::<BigEndian>()?,
                children_size: cursor.read_u32::<BigEndian>()?,
                children_ptr: cursor.read_u32::<BigEndian>()?,
            });
        }

        fn read_attributes_orig(
            data: &[u8],
            attrs_size: u32,
            attrs_ptr: u32,
            variant_data: &[u8],
        ) -> Result<Vec<Attribute>> {
            if attrs_size == 0 || attrs_ptr == 0xFFFFFFFF {
                return Ok(Vec::new());
            }
            let mut attrs = Vec::with_capacity(attrs_size as usize);
            let mut cursor = Cursor::new(data);
            cursor.set_position(attrs_ptr as u64);
            for _ in 0..attrs_size {
                let name_variant = cursor.read_u32::<BigEndian>()?;
                let value_variant = cursor.read_u32::<BigEndian>()?;
                let name = XmbReader::decode_variant_string_be(name_variant, variant_data)?;
                let value = XmbReader::decode_variant_to_variant_be(value_variant, variant_data)?;
                attrs.push(Attribute { name, value });
            }
            Ok(attrs)
        }

        fn read_children_indices_orig(
            data: &[u8],
            children_size: u32,
            children_ptr: u32,
        ) -> Result<Vec<u32>> {
            if children_size == 0 || children_ptr == 0xFFFFFFFF {
                return Ok(Vec::new());
            }
            let mut indices = Vec::with_capacity(children_size as usize);
            let mut cursor = Cursor::new(data);
            cursor.set_position(children_ptr as u64);
            for _ in 0..children_size {
                indices.push(cursor.read_u32::<BigEndian>()?);
            }
            Ok(indices)
        }

        fn build_node_orig(
            idx: usize,
            packed_nodes: &[PackedNodeOrig],
            data: &[u8],
            variant_data: &[u8],
        ) -> Result<Node> {
            let pn = &packed_nodes[idx];
            let name = XmbReader::decode_variant_string_be(pn.name, variant_data)?;
            let text = if pn.text != 0 {
                XmbReader::decode_variant_to_variant_be(pn.text, variant_data)?
            } else {
                Variant::Null
            };
            let attributes = read_attributes_orig(data, pn.attrs_size, pn.attrs_ptr, variant_data)?;
            let children_indices =
                read_children_indices_orig(data, pn.children_size, pn.children_ptr)?;
            let mut children = Vec::with_capacity(children_indices.len());
            for child_idx in children_indices {
                if (child_idx as usize) < packed_nodes.len() {
                    children.push(build_node_orig(
                        child_idx as usize,
                        packed_nodes,
                        data,
                        variant_data,
                    )?);
                }
            }
            Ok(Node {
                name,
                text,
                attributes,
                children,
            })
        }

        let root = build_node_orig(0, &packed_nodes, data, variant_data)?;
        Ok(XmbData {
            root: Some(root),
            format: crate::types::XmbFormat::Xbox360,
            source_file: None,
        })
    }

    /// Decode a variant to string for big-endian format.
    fn decode_variant_string_be(variant_value: u32, string_table: &[u8]) -> Result<String> {
        let type_bits = (variant_value >> 24) as u8;
        let data_bits = variant_value & 0xFFFFFF;
        let variant_type = type_bits & 0x0F;
        let is_offset = (type_bits & 0x80) != 0;

        match variant_type {
            0 => Ok(String::new()), // Null
            8 => {
                // ANSI String
                if is_offset {
                    let offset = data_bits as usize;
                    Self::read_null_terminated_string(string_table, offset)
                } else {
                    Self::decode_direct_string(data_bits)
                }
            }
            _ => Ok(format!("<type:{}>", variant_type)),
        }
    }

    /// Decode a variant to Variant enum for big-endian format.
    fn decode_variant_to_variant_be(variant_value: u32, variant_data: &[u8]) -> Result<Variant> {
        use crate::variant;

        let type_bits = (variant_value >> 24) as u8;
        let data_bits = variant_value & 0xFFFFFF;
        let variant_type = type_bits & 0x0F;
        let is_offset = (type_bits & 0x80) != 0;
        let is_unsigned = (type_bits & variant::UNSIGNED_FLAG) != 0;
        // Vector size encoding: bits 5-6 store 0, 1, 2 for 2, 3, 4 components
        let vec_size = 2 + ((type_bits & variant::VEC_SIZE_MASK) >> variant::VEC_SIZE_SHIFT);

        match variant_type {
            0 => Ok(Variant::Null), // cXMXVTNull
            1 => {
                // cXMXVTFloat24 - 24-bit float, always direct
                Ok(Variant::Float(variant::unpack_float24(data_bits)))
            }
            2 => {
                // cXMXVTFloat - 32-bit float, always offset
                if is_offset && (data_bits as usize + 4) <= variant_data.len() {
                    let offset = data_bits as usize;
                    let bytes = &variant_data[offset..offset + 4];
                    let f = f32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
                    Ok(Variant::Float(f))
                } else {
                    Ok(Variant::Float(0.0))
                }
            }
            3 => {
                // cXMXVTInt24 - 24-bit integer, always direct
                if is_unsigned {
                    Ok(Variant::UInt(data_bits))
                } else {
                    // Sign extend from 24 bits
                    let val = if data_bits & 0x800000 != 0 {
                        (data_bits | 0xFF000000) as i32
                    } else {
                        data_bits as i32
                    };
                    Ok(Variant::Int(val))
                }
            }
            4 => {
                // cXMXVTInt32 - 32-bit integer, always offset
                if is_offset && (data_bits as usize + 4) <= variant_data.len() {
                    let offset = data_bits as usize;
                    let bytes = &variant_data[offset..offset + 4];
                    let val = i32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
                    Ok(Variant::Int(val))
                } else {
                    Ok(Variant::Int(0))
                }
            }
            5 => {
                // cXMXVTFract24 - 24-bit fixed point (value * 10000), always direct
                Ok(Variant::Float(variant::unpack_fract24(data_bits)))
            }
            6 => {
                // cXMXVTDouble - 64-bit double, always offset
                if is_offset && (data_bits as usize + 8) <= variant_data.len() {
                    let offset = data_bits as usize;
                    let bytes = &variant_data[offset..offset + 8];
                    let d = f64::from_be_bytes([
                        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6],
                        bytes[7],
                    ]);
                    Ok(Variant::Float(d as f32))
                } else {
                    Ok(Variant::Float(0.0))
                }
            }
            7 => Ok(Variant::Bool(data_bits != 0)), // cXMXVTBool
            8 => {
                // cXMXVTString - ANSI string
                let s = if is_offset {
                    Self::read_null_terminated_string(variant_data, data_bits as usize)?
                } else {
                    Self::decode_direct_string(data_bits)?
                };
                Ok(Variant::String(s))
            }
            9 => {
                // cXMXVTUString - Unicode string (read as UTF-16 BE)
                if is_offset && (data_bits as usize) < variant_data.len() {
                    let offset = data_bits as usize;
                    let mut chars = Vec::new();
                    let mut i = offset;
                    while i + 1 < variant_data.len() {
                        let wchar = u16::from_be_bytes([variant_data[i], variant_data[i + 1]]);
                        if wchar == 0 {
                            break;
                        }
                        chars.push(wchar);
                        i += 2;
                    }
                    Ok(Variant::String(
                        String::from_utf16(&chars).unwrap_or_else(|_| String::new()),
                    ))
                } else {
                    Ok(Variant::String(String::new()))
                }
            }
            10 => {
                // cXMXVTFloatVec - float vector (2, 3, or 4 components)
                if is_offset && (data_bits as usize + (vec_size as usize * 4)) <= variant_data.len()
                {
                    let offset = data_bits as usize;
                    let mut floats = Vec::with_capacity(vec_size as usize);
                    for i in 0..vec_size as usize {
                        let fo = offset + i * 4;
                        let f = f32::from_be_bytes([
                            variant_data[fo],
                            variant_data[fo + 1],
                            variant_data[fo + 2],
                            variant_data[fo + 3],
                        ]);
                        floats.push(f);
                    }
                    Ok(Variant::FloatVec(floats))
                } else {
                    Ok(Variant::FloatVec(vec![0.0; vec_size as usize]))
                }
            }
            _ => Ok(Variant::String(format!("<variant:{}>", variant_type))),
        }
    }

    /// Decode a variant value to a string (for names which are always strings).
    fn decode_variant_string(variant_value: u32, variant_data: &[u8]) -> Result<String> {
        let type_bits = (variant_value >> 24) as u8;
        let data_bits = variant_value & 0xFFFFFF;
        let variant_type = type_bits & 0x0F;
        let is_offset = (type_bits & 0x80) != 0;

        match variant_type {
            0 => Ok(String::new()), // Null = empty string
            8 => {
                // ANSI String
                if is_offset {
                    // String stored at offset
                    let offset = data_bits as usize;
                    Self::read_null_terminated_string(variant_data, offset)
                } else {
                    // Direct string (packed in data_bits - 3 bytes max)
                    Self::decode_direct_string(data_bits)
                }
            }
            _ => {
                // For non-string types, convert to string representation
                Ok(format!("<type:{}>", variant_type))
            }
        }
    }

    /// Decode a variant value to a Variant enum.
    fn decode_variant_to_variant(variant_value: u32, variant_data: &[u8]) -> Result<Variant> {
        let type_bits = (variant_value >> 24) as u8;
        let data_bits = variant_value & 0xFFFFFF;
        let variant_type = type_bits & 0x0F;
        let is_offset = (type_bits & 0x80) != 0;
        let is_unsigned = (type_bits & 0x40) != 0;

        match variant_type {
            0 => Ok(Variant::Null), // Null
            1 => {
                // Float24
                let f = unpack_float24(data_bits);
                Ok(Variant::Float(f))
            }
            2 => {
                // Float32 (always offset)
                if is_offset && data_bits as usize + 4 <= variant_data.len() {
                    let bytes = &variant_data[data_bits as usize..data_bits as usize + 4];
                    let f = f32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
                    Ok(Variant::Float(f))
                } else {
                    Ok(Variant::Float(0.0))
                }
            }
            3 => {
                // Int24
                if is_unsigned {
                    Ok(Variant::UInt(data_bits))
                } else {
                    let i = unpack_int24(data_bits);
                    Ok(Variant::Int(i))
                }
            }
            4 => {
                // Int32 (always offset)
                if is_offset && data_bits as usize + 4 <= variant_data.len() {
                    let bytes = &variant_data[data_bits as usize..data_bits as usize + 4];
                    let i = i32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
                    Ok(Variant::Int(i))
                } else {
                    Ok(Variant::Int(0))
                }
            }
            5 => {
                // Fract24
                let f = unpack_fract24(data_bits) as f32;
                Ok(Variant::Float(f))
            }
            6 => {
                // Double (always offset)
                if is_offset && data_bits as usize + 8 <= variant_data.len() {
                    let bytes = &variant_data[data_bits as usize..data_bits as usize + 8];
                    let d = f64::from_le_bytes([
                        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6],
                        bytes[7],
                    ]);
                    Ok(Variant::Double(d))
                } else {
                    Ok(Variant::Double(0.0))
                }
            }
            7 => {
                // Bool (encoded in data_bits)
                Ok(Variant::Bool(data_bits != 0))
            }
            8 => {
                // ANSI String
                if is_offset {
                    let offset = data_bits as usize;
                    let s = Self::read_null_terminated_string(variant_data, offset)?;
                    Ok(Variant::String(s))
                } else {
                    let s = Self::decode_direct_string(data_bits)?;
                    Ok(Variant::String(s))
                }
            }
            9 => {
                // Unicode String (always offset for real strings)
                if is_offset {
                    let offset = data_bits as usize;
                    let s = Self::read_null_terminated_wstring(variant_data, offset)?;
                    Ok(Variant::String(s))
                } else {
                    Ok(Variant::String(String::new()))
                }
            }
            10 => {
                // FloatVec (always offset)
                let vec_size = 1 + ((type_bits >> 4) & 0x03);
                if is_offset && data_bits as usize + (vec_size as usize * 4) <= variant_data.len() {
                    let offset = data_bits as usize;
                    let mut vec = Vec::with_capacity(vec_size as usize);
                    for i in 0..vec_size as usize {
                        let bytes = &variant_data[offset + i * 4..offset + i * 4 + 4];
                        vec.push(f32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]));
                    }
                    Ok(Variant::FloatVec(vec))
                } else {
                    Ok(Variant::FloatVec(vec![0.0; vec_size as usize]))
                }
            }
            _ => Ok(Variant::Null),
        }
    }

    fn read_null_terminated_string(data: &[u8], offset: usize) -> Result<String> {
        if offset >= data.len() {
            return Ok(String::new());
        }
        let end = data[offset..]
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(data.len() - offset);
        // Use lossy conversion to handle any invalid UTF-8 sequences
        Ok(String::from_utf8_lossy(&data[offset..offset + end]).into_owned())
    }

    fn read_null_terminated_wstring(data: &[u8], offset: usize) -> Result<String> {
        if offset >= data.len() {
            return Ok(String::new());
        }
        let mut chars = Vec::new();
        let mut i = offset;
        while i + 1 < data.len() {
            let c = u16::from_le_bytes([data[i], data[i + 1]]);
            if c == 0 {
                break;
            }
            chars.push(c);
            i += 2;
        }
        // Use lossy conversion to handle invalid UTF-16
        Ok(String::from_utf16_lossy(&chars))
    }

    fn decode_direct_string(data_bits: u32) -> Result<String> {
        // Direct string is packed in 3 bytes (data_bits)
        let mut bytes = Vec::new();
        let b0 = (data_bits & 0xFF) as u8;
        let b1 = ((data_bits >> 8) & 0xFF) as u8;
        let b2 = ((data_bits >> 16) & 0xFF) as u8;
        if b0 != 0 {
            bytes.push(b0);
        }
        if b1 != 0 {
            bytes.push(b1);
        }
        if b2 != 0 {
            bytes.push(b2);
        }
        // Use lossy conversion
        Ok(String::from_utf8_lossy(&bytes).into_owned())
    }
}

/// XMB file writer.
pub struct XmbWriter;

impl XmbWriter {
    /// Write an XMB document to a writer with the specified format.
    ///
    /// Uses deflate compression by default. Use `write_uncompressed` to disable compression.
    pub fn write<W: Write + Seek>(xmb: &XmbData, writer: W, format: XmbFormat) -> Result<()> {
        Self::write_with_options(xmb, writer, format, true)
    }

    /// Write an XMB document without compression.
    pub fn write_uncompressed<W: Write + Seek>(
        xmb: &XmbData,
        writer: W,
        format: XmbFormat,
    ) -> Result<()> {
        Self::write_with_options(xmb, writer, format, false)
    }

    /// Write an XMB document with explicit compression option.
    ///
    /// When compression is enabled, the appropriate endianness is used:
    /// - PC format: little-endian BDeflateStream
    /// - Xbox 360 format: big-endian BDeflateStream
    pub fn write_with_options<W: Write + Seek>(
        xmb: &XmbData,
        writer: W,
        format: XmbFormat,
        compress: bool,
    ) -> Result<()> {
        let packed_data = match format {
            XmbFormat::PC => Self::build_packed_data_pc(xmb)?,
            XmbFormat::Xbox360 => Self::build_packed_data_xbox360(xmb)?,
        };

        let mut ecf = EcfWriter::new(writer, XMB_ECF_FILE_ID);
        if compress {
            // Use appropriate endianness for compression based on target format
            match format {
                XmbFormat::PC => ecf.add_chunk_compressed(XMX_PACKED_DATA_CHUNK_ID, packed_data)?,
                XmbFormat::Xbox360 => {
                    ecf.add_chunk_compressed_be(XMX_PACKED_DATA_CHUNK_ID, packed_data)?
                }
            }
        } else {
            ecf.add_chunk(XMX_PACKED_DATA_CHUNK_ID, packed_data);
        }

        ecf.finalize()?;

        Ok(())
    }

    /// Write an XMB document in its native format (the format it was read from).
    ///
    /// Uses `xmb.format()` to determine which format to use.
    /// Uses compression by default.
    pub fn write_native<W: Write + Seek>(xmb: &XmbData, writer: W) -> Result<()> {
        Self::write(xmb, writer, xmb.format())
    }

    /// Build the packed XMB data in original Xbox 360 format.
    ///
    /// Original format layout:
    /// - Header (20 bytes): signature, nodes_size, nodes_ptr, variant_data_size, variant_data_ptr
    /// - Nodes array (28 bytes each): parent, name, text, attrs_size, attrs_ptr, children_size, children_ptr
    /// - Attributes arrays (8 bytes each): name_variant, value_variant
    /// - Children index arrays (4 bytes each): child node index
    /// - Variant data: string table + data table
    fn build_packed_data_xbox360(xmb: &XmbData) -> Result<Vec<u8>> {
        // Collect all nodes in depth-first order
        let mut collected_nodes: Vec<Xbox360NodeData> = Vec::new();
        let mut variant_data = VariantDataBuilder::new();

        if let Some(root) = &xmb.root {
            Self::collect_nodes_xbox360(root, 0xFFFFFFFF, &mut collected_nodes, &mut variant_data)?;
        }

        if collected_nodes.is_empty() {
            // Empty document
            let mut data = Vec::new();
            data.write_u32::<BigEndian>(XMB_SIGNATURE)?;
            data.write_u32::<BigEndian>(0)?; // nodes_size
            data.write_u32::<BigEndian>(0)?; // nodes_ptr
            data.write_u32::<BigEndian>(0)?; // variant_data_size
            data.write_u32::<BigEndian>(0)?; // variant_data_ptr
            return Ok(data);
        }

        // Calculate layout
        let header_size = 20u32;
        let nodes_ptr = header_size;
        let nodes_size = collected_nodes.len() as u32;
        let nodes_array_size = nodes_size * 28;

        // Calculate where attributes and children arrays go
        let mut current_offset = nodes_ptr + nodes_array_size;

        // Assign pointers for each node's attributes and children
        let mut node_attrs_ptrs: Vec<u32> = Vec::with_capacity(collected_nodes.len());
        let mut node_children_ptrs: Vec<u32> = Vec::with_capacity(collected_nodes.len());

        for node in &collected_nodes {
            if node.attributes.is_empty() {
                node_attrs_ptrs.push(0xFFFFFFFF);
            } else {
                node_attrs_ptrs.push(current_offset);
                current_offset += (node.attributes.len() as u32) * 8;
            }

            if node.children_indices.is_empty() {
                node_children_ptrs.push(0xFFFFFFFF);
            } else {
                node_children_ptrs.push(current_offset);
                current_offset += (node.children_indices.len() as u32) * 4;
            }
        }

        let variant_data_ptr = current_offset;

        // Apply fixups to all variant values that reference data_table
        // This adjusts offsets to account for the final string_data size
        for node in &mut collected_nodes {
            node.text_variant = variant_data.fixup_variant(node.text_variant);
            for (name_var, value_var) in &mut node.attributes {
                *name_var = variant_data.fixup_variant(*name_var);
                *value_var = variant_data.fixup_variant(*value_var);
            }
        }

        let variant_data_bytes = variant_data.finish();
        let variant_data_size = variant_data_bytes.len() as u32;

        // Now write everything
        let mut data = Vec::new();

        // Header (20 bytes)
        data.write_u32::<BigEndian>(XMB_SIGNATURE)?;
        data.write_u32::<BigEndian>(nodes_size)?;
        data.write_u32::<BigEndian>(nodes_ptr)?;
        data.write_u32::<BigEndian>(variant_data_size)?;
        data.write_u32::<BigEndian>(variant_data_ptr)?;

        // Nodes array (28 bytes each)
        for (i, node) in collected_nodes.iter().enumerate() {
            data.write_u32::<BigEndian>(node.parent_index)?;
            data.write_u32::<BigEndian>(node.name_variant)?;
            data.write_u32::<BigEndian>(node.text_variant)?;
            data.write_u32::<BigEndian>(node.attributes.len() as u32)?;
            data.write_u32::<BigEndian>(node_attrs_ptrs[i])?;
            data.write_u32::<BigEndian>(node.children_indices.len() as u32)?;
            data.write_u32::<BigEndian>(node_children_ptrs[i])?;
        }

        // Attributes and children arrays (interleaved per node to match pointer layout)
        for node in &collected_nodes {
            // Write this node's attributes
            for (name_var, value_var) in &node.attributes {
                data.write_u32::<BigEndian>(*name_var)?;
                data.write_u32::<BigEndian>(*value_var)?;
            }

            // Write this node's children indices
            for child_idx in &node.children_indices {
                data.write_u32::<BigEndian>(*child_idx)?;
            }
        }

        // Variant data (string table + data table)
        data.extend_from_slice(&variant_data_bytes);

        Ok(data)
    }

    /// Collect nodes for original Xbox 360 format.
    fn collect_nodes_xbox360(
        node: &Node,
        parent_index: u32,
        collected: &mut Vec<Xbox360NodeData>,
        variant_data: &mut VariantDataBuilder,
    ) -> Result<u32> {
        let my_index = collected.len() as u32;

        // Pack name and text variants
        let name_variant = variant_data.add_string(&node.name);
        let text_variant = Self::pack_variant_xbox360(&node.text, variant_data);

        // Pack attributes
        let mut attributes = Vec::with_capacity(node.attributes.len());
        for attr in &node.attributes {
            let attr_name = variant_data.add_string(&attr.name);
            let attr_value = Self::pack_variant_xbox360(&attr.value, variant_data);
            attributes.push((attr_name, attr_value));
        }

        // Add placeholder node (children_indices will be filled after recursion)
        collected.push(Xbox360NodeData {
            parent_index,
            name_variant,
            text_variant,
            attributes,
            children_indices: Vec::new(),
        });

        // Process children and collect their indices
        let mut children_indices = Vec::with_capacity(node.children.len());
        for child in &node.children {
            let child_idx = Self::collect_nodes_xbox360(child, my_index, collected, variant_data)?;

            children_indices.push(child_idx);
        }

        // Update node with children indices
        collected[my_index as usize].children_indices = children_indices;

        Ok(my_index)
    }

    /// Pack a variant for Xbox 360 format.
    fn pack_variant_xbox360(variant: &Variant, variant_data: &mut VariantDataBuilder) -> u32 {
        use crate::variant;
        match variant {
            Variant::Null => 0,
            Variant::Bool(v) => ((VariantType::Bool as u32) << 24) | (if *v { 1 } else { 0 }),
            Variant::Int(v) => {
                // Use Int24 for small values, Int32 for larger
                if *v >= -8_388_608 && *v <= 8_388_607 {
                    // Int24 type (3) with data in lower 24 bits
                    ((VariantType::Int24 as u32) << 24) | variant::pack_int24(*v)
                } else {
                    variant_data.add_int32(*v)
                }
            }
            Variant::UInt(v) => {
                // Unsigned integers - use Int24 with unsigned flag for small values
                if *v <= 0xFFFFFF {
                    // Int24 type (3) with unsigned flag (0x40) and data in lower 24 bits
                    ((VariantType::Int24 as u32 | (variant::UNSIGNED_FLAG as u32)) << 24)
                        | variant::pack_uint24(*v)
                } else {
                    // Store as Int32 (will lose unsigned info but preserve value)
                    variant_data.add_int32(*v as i32)
                }
            }
            Variant::Float(v) => {
                // Use Float24 for values that fit, otherwise Float32
                let packed24 = variant::pack_float24(*v);
                let unpacked = variant::unpack_float24(packed24);
                if (unpacked - *v).abs() < 0.001 || *v == 0.0 {
                    // Float24 type (1) with data in lower 24 bits
                    ((VariantType::Float24 as u32) << 24) | packed24
                } else {
                    variant_data.add_float(*v)
                }
            }
            Variant::Double(v) => variant_data.add_double(*v),
            Variant::FloatVec(vec) => variant_data.add_float_vec(vec),
            Variant::String(s) => variant_data.add_string(s),
            Variant::UString(s) => variant_data.add_ustring(s),
        }
    }

    /// Build the packed XMB data in PC format (Halo Wars Definitive Edition).
    ///
    /// PC format uses 48-byte nodes with BPackedArray for attributes and children.
    /// Header layout:
    /// - 4 bytes: signature
    /// - 4 bytes: padding
    /// - 4 bytes: mNodes.mSize
    /// - 4 bytes: padding
    /// - 8 bytes: mNodes.mPtr
    /// - 4 bytes: mVariantData.mSize
    /// - 4 bytes: padding
    /// - 8 bytes: mVariantData.mPtr
    fn build_packed_data_pc(xmb: &XmbData) -> Result<Vec<u8>> {
        let mut string_table = StringTableLe::new();
        let mut data_table = DataTableLe::new();

        // Collect all nodes and attributes
        let mut packed_nodes: Vec<PackedNodeLe> = Vec::new();
        let mut all_attributes: Vec<(u32, u32)> = Vec::new();

        if let Some(root) = &xmb.root {
            Self::collect_nodes_le(
                root,
                u32::MAX, // root has no parent (0xFFFFFFFF)
                &mut packed_nodes,
                &mut all_attributes,
                &mut string_table,
                &mut data_table,
            )?;
        }

        // Now we need to build the binary format
        // Calculate sizes and offsets
        const HEADER_SIZE: usize = 40; // signature(4) + pad(4) + nodes_bpa(16) + variant_bpa(16)
        const NODE_SIZE: usize = 48;

        let nodes_offset = HEADER_SIZE;
        let nodes_size = packed_nodes.len() * NODE_SIZE;

        // After nodes, we place attributes and children arrays
        // We need to track where each node's attrs and children go
        let attrs_offset = nodes_offset + nodes_size;
        let mut children_offset = attrs_offset;

        // Calculate total attribute space needed
        for pn in &packed_nodes {
            children_offset += pn.num_attrs as usize * 8; // 8 bytes per attribute
        }

        // Calculate total children space needed
        let mut variant_data_offset = children_offset;
        for pn in &packed_nodes {
            variant_data_offset += pn.num_children as usize * 4; // 4 bytes per child index
        }

        // Variant data = string table + data table
        let variant_data_size = string_table.data.len() + data_table.data.len();

        // Now build the actual binary
        let mut data = Vec::new();

        // Write header
        data.write_u32::<LittleEndian>(XMB_SIGNATURE)?;
        data.write_u32::<LittleEndian>(0)?; // padding

        // Nodes BPackedArray
        data.write_u32::<LittleEndian>(packed_nodes.len() as u32)?;
        data.write_u32::<LittleEndian>(0)?; // padding
        data.write_u64::<LittleEndian>(nodes_offset as u64)?;

        // Variant data BPackedArray
        data.write_u32::<LittleEndian>(variant_data_size as u32)?;
        data.write_u32::<LittleEndian>(0)?; // padding
        data.write_u64::<LittleEndian>(variant_data_offset as u64)?;

        // Track current positions for attrs and children
        let mut current_attrs_offset = attrs_offset;
        let mut current_children_offset = children_offset;

        // Write nodes with correct offsets
        for (i, pn) in packed_nodes.iter().enumerate() {
            data.write_u32::<LittleEndian>(pn.parent_index)?;
            data.write_u32::<LittleEndian>(pn.name_variant)?;
            data.write_u32::<LittleEndian>(pn.text_variant)?;
            data.write_u32::<LittleEndian>(0)?; // padding

            // Attributes BPackedArray
            if pn.num_attrs > 0 {
                data.write_u32::<LittleEndian>(pn.num_attrs as u32)?;
                data.write_u32::<LittleEndian>(0)?; // padding
                data.write_u64::<LittleEndian>(current_attrs_offset as u64)?;
                current_attrs_offset += pn.num_attrs as usize * 8;
            } else {
                data.write_u32::<LittleEndian>(0xFFFFFFFF)?; // -1 means no attrs
                data.write_u32::<LittleEndian>(0)?;
                data.write_u64::<LittleEndian>(0)?;
            }

            // Children BPackedArray
            if pn.num_children > 0 {
                data.write_u32::<LittleEndian>(pn.num_children as u32)?;
                data.write_u32::<LittleEndian>(0)?; // padding
                data.write_u64::<LittleEndian>(current_children_offset as u64)?;
                current_children_offset += pn.num_children as usize * 4;
            } else {
                data.write_u32::<LittleEndian>(0xFFFFFFFF)?;
                data.write_u32::<LittleEndian>(0)?;
                data.write_u64::<LittleEndian>(0xFFFFFFFFFFFFFFFF)?;
            }

            // Sanity check: we should be writing 48 bytes per node
            debug_assert_eq!(
                data.len(),
                HEADER_SIZE + (i + 1) * NODE_SIZE,
                "Node size mismatch at index {}",
                i
            );
        }

        // Write attributes (8 bytes each: name_variant + value_variant)
        let mut attr_idx = 0;
        for pn in &packed_nodes {
            for _ in 0..pn.num_attrs {
                let (name_var, value_var) = all_attributes[attr_idx];
                data.write_u32::<LittleEndian>(name_var)?;
                data.write_u32::<LittleEndian>(value_var)?;
                attr_idx += 1;
            }
        }

        // Write children (4 bytes each: child index)
        for pn in &packed_nodes {
            for &child_idx in &pn.children {
                data.write_u32::<LittleEndian>(child_idx)?;
            }
        }

        // Write variant data (string table + data table)
        data.extend_from_slice(&string_table.data);
        data.extend_from_slice(&data_table.data);

        Ok(data)
    }

    /// Collect nodes for LE format.
    fn collect_nodes_le(
        node: &Node,
        parent_index: u32,
        nodes: &mut Vec<PackedNodeLe>,
        all_attributes: &mut Vec<(u32, u32)>,
        string_table: &mut StringTableLe,
        data_table: &mut DataTableLe,
    ) -> Result<u32> {
        let node_index = nodes.len() as u32;
        let first_attr = all_attributes.len();
        let num_attrs = node.attributes.len();

        // Collect children indices (we'll fill them in after processing children)
        let first_child = nodes.len() + 1; // Next node will be first child
        let num_children = node.children.len();

        // Add placeholder node
        nodes.push(PackedNodeLe {
            parent_index,
            name_variant: string_table.add_string(&node.name),
            text_variant: Self::pack_variant_le(&node.text, string_table, data_table),
            first_attr,
            num_attrs,
            first_child,
            num_children,
            children: Vec::new(),
        });

        // Add attributes
        for attr in &node.attributes {
            let name_var = string_table.add_string(&attr.name);
            let value_var = Self::pack_variant_le(&attr.value, string_table, data_table);
            all_attributes.push((name_var, value_var));
        }

        // Process children and collect their indices
        let mut child_indices = Vec::with_capacity(num_children);
        for child in &node.children {
            let child_idx = Self::collect_nodes_le(
                child,
                node_index,
                nodes,
                all_attributes,
                string_table,
                data_table,
            )?;
            child_indices.push(child_idx);
        }

        // Update node with child indices
        nodes[node_index as usize].children = child_indices;

        Ok(node_index)
    }

    /// Pack a variant value for LE format.
    fn pack_variant_le(
        variant: &Variant,
        string_table: &mut StringTableLe,
        data_table: &mut DataTableLe,
    ) -> u32 {
        match variant {
            Variant::Null => 0,
            Variant::Bool(v) => {
                let value = if *v { 1u32 } else { 0u32 };
                (VariantType::Bool as u32) << 24 | value
            }
            Variant::Int(v) => {
                if *v >= -8388607 && *v <= 8388607 {
                    let packed = crate::variant::pack_int24(*v);
                    (VariantType::Int24 as u32) << 24 | packed
                } else {
                    data_table.add_int32(*v)
                }
            }
            Variant::UInt(v) => {
                if *v <= 0xFFFFFF {
                    ((VariantType::Int24 as u32 | UNSIGNED_FLAG as u32) << 24) | *v
                } else {
                    data_table.add_int32(*v as i32)
                }
            }
            Variant::Float(v) => {
                let packed = crate::variant::pack_float24(*v);
                let unpacked = crate::variant::unpack_float24(packed);
                if (*v - unpacked).abs() < 0.001 || *v == 0.0 {
                    (VariantType::Float24 as u32) << 24 | packed
                } else {
                    data_table.add_float(*v)
                }
            }
            Variant::Double(v) => data_table.add_double(*v),
            Variant::String(s) => string_table.add_string(s),
            Variant::UString(s) => string_table.add_ustring(s),
            Variant::FloatVec(v) => data_table.add_float_vec(v),
        }
    }
}

/// Packed node structure for reading (LE packed format with embedded arrays).
struct PackedNodeRead {
    #[allow(dead_code)]
    parent_node: u32,
    name_variant: u32,
    text_variant: u32,
    attributes: Vec<(u32, u32)>, // (name_variant, value_variant)
    children: Vec<u32>,          // child indices
}

/// Node data for Xbox 360 original format writing.
struct Xbox360NodeData {
    parent_index: u32,
    name_variant: u32,
    text_variant: u32,
    attributes: Vec<(u32, u32)>, // (name_variant, value_variant)
    children_indices: Vec<u32>,
}

/// Variant data builder for Xbox 360 format.
/// Combines string table and data table with proper offset handling.
///
/// IMPORTANT: Data table entries (floats, float vecs, int32s) store their offsets
/// relative to data_table start. These offsets need to be adjusted when the builder
/// is finalized, since string_data length is not known until all strings are added.
struct VariantDataBuilder {
    string_data: Vec<u8>,
    data_table: Vec<u8>,
    string_offsets: std::collections::HashMap<String, u32>,
    /// Stores variant values that need fixup (their offsets are relative to data_table start)
    data_table_fixups: Vec<u32>,
}

impl VariantDataBuilder {
    fn new() -> Self {
        Self {
            string_data: Vec::new(),
            data_table: Vec::new(),
            string_offsets: std::collections::HashMap::new(),
            data_table_fixups: Vec::new(),
        }
    }

    fn add_string(&mut self, s: &str) -> u32 {
        if let Some(&offset) = self.string_offsets.get(s) {
            return ((VariantType::String as u32 | OFFSET_FLAG as u32) << 24) | offset;
        }
        let offset = self.string_data.len() as u32;
        self.string_data.extend_from_slice(s.as_bytes());
        self.string_data.push(0); // null terminator
        self.string_offsets.insert(s.to_string(), offset);
        ((VariantType::String as u32 | OFFSET_FLAG as u32) << 24) | offset
    }

    fn add_ustring(&mut self, s: &str) -> u32 {
        let offset = self.string_data.len() as u32;
        for c in s.encode_utf16() {
            self.string_data.push((c >> 8) as u8); // Big-endian
            self.string_data.push((c & 0xFF) as u8);
        }
        // Null terminator (2 bytes for UTF-16)
        self.string_data.push(0);
        self.string_data.push(0);
        ((VariantType::UString as u32 | OFFSET_FLAG as u32) << 24) | offset
    }

    /// Add a float to data_table. Returns a variant value that needs fixup via `fixup_variant`.
    fn add_float(&mut self, v: f32) -> u32 {
        let data_table_offset = self.data_table.len() as u32;
        self.data_table.extend_from_slice(&v.to_be_bytes());
        // Store with NEEDS_FIXUP marker in bits 23-22 (we use 0x800000 as marker)
        // The actual type byte goes in upper 8 bits, data_table_offset in lower 22 bits
        let variant = ((VariantType::Float as u32 | OFFSET_FLAG as u32) << 24) | data_table_offset;
        self.data_table_fixups.push(variant);
        variant
    }

    /// Add a double to data_table. Returns a variant value that needs fixup via `fixup_variant`.
    fn add_double(&mut self, v: f64) -> u32 {
        let data_table_offset = self.data_table.len() as u32;
        self.data_table.extend_from_slice(&v.to_be_bytes());
        let variant = ((VariantType::Double as u32 | OFFSET_FLAG as u32) << 24) | data_table_offset;
        self.data_table_fixups.push(variant);
        variant
    }

    /// Add an int32 to data_table. Returns a variant value that needs fixup via `fixup_variant`.
    fn add_int32(&mut self, v: i32) -> u32 {
        let data_table_offset = self.data_table.len() as u32;
        self.data_table.extend_from_slice(&v.to_be_bytes());
        let variant = ((VariantType::Int32 as u32 | OFFSET_FLAG as u32) << 24) | data_table_offset;
        self.data_table_fixups.push(variant);
        variant
    }

    /// Add a float vector to data_table. Returns a variant value that needs fixup via `fixup_variant`.
    fn add_float_vec(&mut self, v: &[f32]) -> u32 {
        let data_table_offset = self.data_table.len() as u32;
        for f in v {
            self.data_table.extend_from_slice(&f.to_be_bytes());
        }
        // Encode vector size in bits 5-6 (0=2, 1=3, 2=4)
        let vec_size_bits = match v.len() {
            2 => 0u32,
            3 => 1u32,
            4 => 2u32,
            _ => 0u32,
        };
        let variant = ((VariantType::FloatVec as u32 | OFFSET_FLAG as u32 | (vec_size_bits << 5))
            << 24)
            | data_table_offset;
        self.data_table_fixups.push(variant);
        variant
    }

    /// Adjust a variant value that references data_table.
    /// Call this after all strings have been added but before writing the variant.
    fn fixup_variant(&self, variant: u32) -> u32 {
        // Check if this variant needs fixup (is in our fixup list)
        if self.data_table_fixups.contains(&variant) {
            // Add string_data.len() to the offset portion (lower 24 bits)
            let type_byte = variant & 0xFF000000;
            let data_offset = variant & 0x00FFFFFF;
            let fixed_offset = data_offset + (self.string_data.len() as u32);
            type_byte | fixed_offset
        } else {
            variant
        }
    }

    fn finish(self) -> Vec<u8> {
        let mut result = self.string_data;
        result.extend_from_slice(&self.data_table);
        result
    }
}

// ============================================================================
// Little-endian (PC/HWDE) format structs
// ============================================================================

/// Packed node structure for writing LE format.
struct PackedNodeLe {
    parent_index: u32,
    name_variant: u32,
    text_variant: u32,
    #[allow(dead_code)]
    first_attr: usize,
    num_attrs: usize,
    #[allow(dead_code)]
    first_child: usize,
    num_children: usize,
    children: Vec<u32>, // actual child node indices
}

/// String table builder for LE format.
struct StringTableLe {
    data: Vec<u8>,
    strings: std::collections::HashMap<String, u32>,
}

impl StringTableLe {
    fn new() -> Self {
        Self {
            data: Vec::new(),
            strings: std::collections::HashMap::new(),
        }
    }

    fn add_string(&mut self, s: &str) -> u32 {
        if let Some(&offset) = self.strings.get(s) {
            return ((VariantType::String as u32 | OFFSET_FLAG as u32) << 24) | offset;
        }
        let offset = self.data.len() as u32;
        self.data.extend_from_slice(s.as_bytes());
        self.data.push(0); // null terminator
        self.strings.insert(s.to_string(), offset);
        ((VariantType::String as u32 | OFFSET_FLAG as u32) << 24) | offset
    }

    fn add_ustring(&mut self, s: &str) -> u32 {
        let offset = self.data.len() as u32;
        for c in s.encode_utf16() {
            self.data.push((c & 0xFF) as u8);
            self.data.push((c >> 8) as u8);
        }
        self.data.push(0);
        self.data.push(0);
        ((VariantType::UString as u32 | OFFSET_FLAG as u32) << 24) | offset
    }
}

/// Data table builder for LE format (uses little-endian byte order).
struct DataTableLe {
    data: Vec<u8>,
}

impl DataTableLe {
    fn new() -> Self {
        Self { data: Vec::new() }
    }

    fn add_double(&mut self, v: f64) -> u32 {
        let offset = self.data.len() as u32;
        self.data.extend_from_slice(&v.to_le_bytes());
        ((VariantType::Double as u32 | OFFSET_FLAG as u32) << 24) | offset
    }

    fn add_float(&mut self, v: f32) -> u32 {
        let offset = self.data.len() as u32;
        self.data.extend_from_slice(&v.to_le_bytes());
        ((VariantType::Float as u32 | OFFSET_FLAG as u32) << 24) | offset
    }

    fn add_int32(&mut self, v: i32) -> u32 {
        let offset = self.data.len() as u32;
        self.data.extend_from_slice(&v.to_le_bytes());
        ((VariantType::Int32 as u32 | OFFSET_FLAG as u32) << 24) | offset
    }

    fn add_float_vec(&mut self, v: &[f32]) -> u32 {
        let offset = self.data.len() as u32;
        for f in v {
            self.data.extend_from_slice(&f.to_le_bytes());
        }
        let vec_size_bits = match v.len() {
            2 => 0u32,
            3 => 1u32,
            4 => 2u32,
            _ => 0u32,
        };
        ((VariantType::FloatVec as u32 | OFFSET_FLAG as u32 | (vec_size_bits << 5)) << 24) | offset
    }
}

//! XMB binary XML reader and writer.

use byteorder::{BigEndian, LittleEndian, ReadBytesExt, WriteBytesExt};
use std::io::{Cursor, Read, Seek, Write};

use crate::ecf::{EcfReader, EcfWriter, XMB_ECF_FILE_ID, XMX_PACKED_DATA_CHUNK_ID};
use crate::error::{Error, Result};
use crate::types::{Attribute, Node, XmbData};
use crate::variant::{
    unpack_float24, unpack_fract24, unpack_int24, Variant, VariantType, OFFSET_FLAG, UNSIGNED_FLAG,
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

        // Parse based on detected endianness
        // Pass full buffer - offsets in the data are relative to buffer start
        if is_big_endian {
            Self::parse_packed_data_be(data)
        } else {
            Self::parse_packed_data_le(data)
        }
    }

    /// Parse packed data in little-endian format (PC/DE version).
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
    fn parse_packed_data_le(data: &[u8]) -> Result<XmbData> {
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

    /// Parse packed data in big-endian format (Xbox 360 version / writer format).
    ///
    /// This handles the format written by XmbWriter:
    /// - 4 bytes: signature (0x71439800)
    /// - 4 bytes: flags
    /// - 4 bytes: node count
    /// - 4 bytes: attribute count
    /// - 4 bytes: string table size
    /// - 4 bytes: data table size
    /// - Node data (20 bytes per node)
    /// - Attribute data (8 bytes per attribute)
    /// - String table
    fn parse_packed_data_be(data: &[u8]) -> Result<XmbData> {
        let mut cursor = Cursor::new(data);

        // Read header
        let _signature = cursor.read_u32::<BigEndian>()?;
        let _flags = cursor.read_u32::<BigEndian>()?;
        let num_nodes = cursor.read_u32::<BigEndian>()? as usize;
        let num_attrs = cursor.read_u32::<BigEndian>()? as usize;
        let string_table_size = cursor.read_u32::<BigEndian>()? as usize;
        let _data_table_size = cursor.read_u32::<BigEndian>()?;

        if num_nodes == 0 {
            return Ok(XmbData {
                root: None,
                format: crate::types::XmbFormat::Xbox360,
                source_file: None,
            });
        }

        // Calculate offsets
        let header_size = 24;
        let nodes_offset = header_size;
        let attrs_offset = nodes_offset + num_nodes * 20;
        let string_table_offset = attrs_offset + num_attrs * 8;

        // Read nodes
        let mut packed_nodes = Vec::with_capacity(num_nodes);
        cursor.set_position(nodes_offset as u64);
        for _ in 0..num_nodes {
            let parent_index = cursor.read_i32::<BigEndian>()?;
            let name_variant = cursor.read_u32::<BigEndian>()?;
            let text_variant = cursor.read_u32::<BigEndian>()?;
            let first_attr = cursor.read_u16::<BigEndian>()? as usize;
            let num_attrs_node = cursor.read_u16::<BigEndian>()? as usize;
            let first_child = cursor.read_u16::<BigEndian>()? as usize;
            let num_children = cursor.read_u16::<BigEndian>()? as usize;

            packed_nodes.push((
                parent_index,
                name_variant,
                text_variant,
                first_attr,
                num_attrs_node,
                first_child,
                num_children,
            ));
        }

        // Read attributes
        let mut attrs = Vec::with_capacity(num_attrs);
        cursor.set_position(attrs_offset as u64);
        for _ in 0..num_attrs {
            let name_variant = cursor.read_u32::<BigEndian>()?;
            let value_variant = cursor.read_u32::<BigEndian>()?;
            attrs.push((name_variant, value_variant));
        }

        // String table
        let string_table = &data[string_table_offset
            ..string_table_offset + string_table_size.min(data.len() - string_table_offset)];

        // Build nodes recursively
        fn build_node(
            idx: usize,
            packed_nodes: &[(i32, u32, u32, usize, usize, usize, usize)],
            attrs: &[(u32, u32)],
            string_table: &[u8],
        ) -> Result<Node> {
            let (_, name_variant, text_variant, first_attr, num_attrs, first_child, num_children) =
                packed_nodes[idx];

            // Decode name
            let name = XmbReader::decode_variant_string_be(name_variant, string_table)?;

            // Decode text
            let text = if text_variant != 0 {
                XmbReader::decode_variant_to_variant_be(text_variant, string_table)?
            } else {
                Variant::Null
            };

            // Decode attributes
            let mut attributes = Vec::with_capacity(num_attrs);
            for i in 0..num_attrs {
                let (attr_name, attr_value) = attrs[first_attr + i];
                let name = XmbReader::decode_variant_string_be(attr_name, string_table)?;
                let value = XmbReader::decode_variant_to_variant_be(attr_value, string_table)?;
                attributes.push(Attribute { name, value });
            }

            // Build children
            let mut children = Vec::with_capacity(num_children);
            for i in 0..num_children {
                children.push(build_node(
                    first_child + i,
                    packed_nodes,
                    attrs,
                    string_table,
                )?);
            }

            Ok(Node {
                name,
                text,
                attributes,
                children,
            })
        }

        let root = build_node(0, &packed_nodes, &attrs, string_table)?;

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
    fn decode_variant_to_variant_be(variant_value: u32, string_table: &[u8]) -> Result<Variant> {
        let type_bits = (variant_value >> 24) as u8;
        let data_bits = variant_value & 0xFFFFFF;
        let variant_type = type_bits & 0x0F;
        let is_offset = (type_bits & 0x80) != 0;

        match variant_type {
            0 => Ok(Variant::Null),
            7 => Ok(Variant::Bool(data_bits != 0)),
            8 => {
                // ANSI String
                let s = if is_offset {
                    Self::read_null_terminated_string(string_table, data_bits as usize)?
                } else {
                    Self::decode_direct_string(data_bits)?
                };
                Ok(Variant::String(s))
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
    /// Write an XMB document to a writer (defaults to LE/PC format).
    pub fn write<W: Write + Seek>(xmb: &XmbData, writer: W) -> Result<()> {
        Self::write_le(xmb, writer)
    }

    /// Write an XMB document in little-endian format (PC/HWDE).
    pub fn write_le<W: Write + Seek>(xmb: &XmbData, writer: W) -> Result<()> {
        let packed_data = Self::build_packed_data_le(xmb)?;

        let mut ecf = EcfWriter::new(writer, XMB_ECF_FILE_ID);
        ecf.add_chunk(XMX_PACKED_DATA_CHUNK_ID, packed_data);
        ecf.finalize()?;

        Ok(())
    }

    /// Write an XMB document in big-endian format (Xbox 360).
    pub fn write_be<W: Write + Seek>(xmb: &XmbData, writer: W) -> Result<()> {
        let packed_data = Self::build_packed_data_be(xmb)?;

        let mut ecf = EcfWriter::new(writer, XMB_ECF_FILE_ID);
        ecf.add_chunk(XMX_PACKED_DATA_CHUNK_ID, packed_data);
        ecf.finalize()?;

        Ok(())
    }

    /// Write an XMB document in its native format (the format it was read from).
    ///
    /// Uses `xmb.format()` to determine which format to use.
    pub fn write_native<W: Write + Seek>(xmb: &XmbData, writer: W) -> Result<()> {
        if xmb.is_xbox360() {
            Self::write_be(xmb, writer)
        } else {
            Self::write_le(xmb, writer)
        }
    }

    /// Build the packed XMB data in big-endian format (Xbox 360).
    fn build_packed_data_be(xmb: &XmbData) -> Result<Vec<u8>> {
        let mut data = Vec::new();
        let mut string_table = StringTable::new();
        let mut data_table = DataTable::new();

        // Collect all nodes, attributes
        let mut nodes: Vec<PackedNode> = Vec::new();
        let mut attributes: Vec<PackedAttribute> = Vec::new();

        if let Some(root) = &xmb.root {
            Self::collect_nodes(
                root,
                -1,
                &mut nodes,
                &mut attributes,
                &mut string_table,
                &mut data_table,
            )?;
        }

        // Write header
        data.write_u32::<BigEndian>(XMB_SIGNATURE)?;
        data.write_u32::<BigEndian>(0)?; // flags
        data.write_u32::<BigEndian>(nodes.len() as u32)?;
        data.write_u32::<BigEndian>(attributes.len() as u32)?;
        data.write_u32::<BigEndian>(string_table.data.len() as u32)?;
        data.write_u32::<BigEndian>(data_table.data.len() as u32)?;

        // Write nodes
        for node in &nodes {
            data.write_i32::<BigEndian>(node.parent_index)?;
            data.write_u32::<BigEndian>(node.name_variant)?;
            data.write_u32::<BigEndian>(node.text_variant)?;
            data.write_u16::<BigEndian>(node.first_attr)?;
            data.write_u16::<BigEndian>(node.num_attrs)?;
            data.write_u16::<BigEndian>(node.first_child)?;
            data.write_u16::<BigEndian>(node.num_children)?;
        }

        // Write attributes
        for attr in &attributes {
            data.write_u32::<BigEndian>(attr.name_variant)?;
            data.write_u32::<BigEndian>(attr.value_variant)?;
        }

        // Write string table
        data.extend_from_slice(&string_table.data);

        // Write data table (for Double, FloatVec, Int32, Float values)
        data.extend_from_slice(&data_table.data);

        Ok(data)
    }

    /// Build the packed XMB data in little-endian format (PC/HWDE).
    ///
    /// LE format uses 48-byte nodes with BPackedArray for attributes and children.
    /// Header layout:
    /// - 4 bytes: signature
    /// - 4 bytes: padding
    /// - 4 bytes: mNodes.mSize
    /// - 4 bytes: padding
    /// - 8 bytes: mNodes.mPtr
    /// - 4 bytes: mVariantData.mSize
    /// - 4 bytes: padding
    /// - 8 bytes: mVariantData.mPtr
    fn build_packed_data_le(xmb: &XmbData) -> Result<Vec<u8>> {
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

    /// Recursively collect nodes and attributes.
    fn collect_nodes(
        node: &Node,
        parent_index: i32,
        nodes: &mut Vec<PackedNode>,
        attributes: &mut Vec<PackedAttribute>,
        string_table: &mut StringTable,
        data_table: &mut DataTable,
    ) -> Result<u32> {
        let node_index = nodes.len() as u32;
        let first_attr = attributes.len() as u16;
        let num_attrs = node.attributes.len() as u16;

        // Add placeholder node
        nodes.push(PackedNode {
            parent_index,
            name_variant: string_table.add_string(&node.name),
            text_variant: Self::pack_variant(&node.text, string_table, data_table),
            first_attr,
            num_attrs,
            first_child: 0,
            num_children: 0,
        });

        // Add attributes
        for attr in &node.attributes {
            attributes.push(PackedAttribute {
                name_variant: string_table.add_string(&attr.name),
                value_variant: Self::pack_variant(&attr.value, string_table, data_table),
            });
        }

        // Process children
        let first_child = nodes.len() as u16;
        let num_children = node.children.len() as u16;
        for child in &node.children {
            Self::collect_nodes(
                child,
                node_index as i32,
                nodes,
                attributes,
                string_table,
                data_table,
            )?;
        }

        // Update node with child info
        nodes[node_index as usize].first_child = first_child;
        nodes[node_index as usize].num_children = num_children;

        Ok(node_index)
    }

    /// Pack a variant value.
    fn pack_variant(
        variant: &Variant,
        string_table: &mut StringTable,
        data_table: &mut DataTable,
    ) -> u32 {
        match variant {
            Variant::Null => 0,
            Variant::Bool(v) => {
                let value = if *v { 1u32 } else { 0u32 };
                (VariantType::Bool as u32) << 24 | value
            }
            Variant::Int(v) => {
                // Use Int24 if it fits, otherwise Int32
                if *v >= -8388607 && *v <= 8388607 {
                    let packed = crate::variant::pack_int24(*v);
                    (VariantType::Int24 as u32) << 24 | packed
                } else {
                    data_table.add_int32(*v)
                }
            }
            Variant::UInt(v) => {
                // Use Int24 (unsigned) if it fits, otherwise Int32
                if *v <= 0xFFFFFF {
                    ((VariantType::Int24 as u32 | UNSIGNED_FLAG as u32) << 24) | *v
                } else {
                    data_table.add_int32(*v as i32)
                }
            }
            Variant::Float(v) => {
                // Use Float24 for common values, Float32 for precision
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

/// Packed node structure for writing.
struct PackedNode {
    parent_index: i32,
    name_variant: u32,
    text_variant: u32,
    first_attr: u16,
    num_attrs: u16,
    first_child: u16,
    num_children: u16,
}

/// Packed attribute structure for writing.
struct PackedAttribute {
    name_variant: u32,
    value_variant: u32,
}

/// String table builder.
struct StringTable {
    data: Vec<u8>,
    strings: std::collections::HashMap<String, u32>,
}

impl StringTable {
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
        // For UString, we store UTF-16LE
        let offset = self.data.len() as u32;
        for c in s.encode_utf16() {
            self.data.push((c & 0xFF) as u8);
            self.data.push((c >> 8) as u8);
        }
        // Null terminator (2 bytes for UTF-16)
        self.data.push(0);
        self.data.push(0);
        ((VariantType::UString as u32 | OFFSET_FLAG as u32) << 24) | offset
    }
}

/// Data table builder for storing Double, FloatVec, Int32, Float values.
struct DataTable {
    data: Vec<u8>,
}

impl DataTable {
    fn new() -> Self {
        Self { data: Vec::new() }
    }

    fn add_double(&mut self, v: f64) -> u32 {
        let offset = self.data.len() as u32;
        self.data.extend_from_slice(&v.to_be_bytes());
        ((VariantType::Double as u32 | OFFSET_FLAG as u32) << 24) | offset
    }

    fn add_float(&mut self, v: f32) -> u32 {
        let offset = self.data.len() as u32;
        self.data.extend_from_slice(&v.to_be_bytes());
        ((VariantType::Float as u32 | OFFSET_FLAG as u32) << 24) | offset
    }

    fn add_int32(&mut self, v: i32) -> u32 {
        let offset = self.data.len() as u32;
        self.data.extend_from_slice(&v.to_be_bytes());
        ((VariantType::Int32 as u32 | OFFSET_FLAG as u32) << 24) | offset
    }

    fn add_float_vec(&mut self, v: &[f32]) -> u32 {
        let offset = self.data.len() as u32;
        for f in v {
            self.data.extend_from_slice(&f.to_be_bytes());
        }
        // Encode vector size in bits 5-6 (0=2, 1=3, 2=4)
        let vec_size_bits = match v.len() {
            2 => 0u32,
            3 => 1u32,
            4 => 2u32,
            _ => 0u32, // Default to 2
        };
        ((VariantType::FloatVec as u32 | OFFSET_FLAG as u32 | (vec_size_bits << 5)) << 24) | offset
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

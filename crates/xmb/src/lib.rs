//! # xmb-rs
//!
//! XMB binary XML format reader/writer for Halo Wars (Ensemble Studios).
//!
//! XMB is a binary XML format used by Ensemble Studios in Halo Wars to store
//! configuration and data files. This crate provides functionality to read and
//! write XMB files.
//!
//! ## Format Overview
//!
//! XMB files are stored inside ECF (Ensemble Common Format) containers. The
//! format uses a variant system for storing values efficiently with different
//! types like Float24, Int24, Fract24, etc.
//!
//! ## Supported Formats
//!
//! - **PC Format**: Used in Halo Wars Definitive Edition and Halo Wars 2.
//!   Little-endian with 48-byte nodes.
//! - **Xbox 360 Format**: Used in the original Halo Wars (2007).
//!   Big-endian with 28-byte nodes using PackedArray format.
//!
//! ## Compression
//!
//! XMB files can be optionally compressed using BDeflateStream format.
//! See [`ecf::deflate_stream`] for compression-related constants.
//!
//! ## ECF Flags
//!
//! See [`ecf::chunk_resource_flags`] for ECF chunk resource flags.

pub mod ecf;
pub mod error;
pub mod types;
pub mod variant;
pub mod xmb;

// Re-export main types
pub use ecf::{EcfChunkHeader, EcfHeader, EcfReader, EcfWriter};
pub use error::{Error, Result};
pub use types::{Attribute, Node, XmbData, XmbFormat};
pub use variant::{Variant, VariantType};
pub use xmb::{XmbReader, XmbWriter};

// Re-export ECF constants
pub use ecf::{
    ECF_HEADER_MAGIC, XMB_ECF_FILE_ID, XMX_FILE_INFO_CHUNK_ID, XMX_PACKED_DATA_CHUNK_ID,
};

// Re-export variant flag constants
pub use variant::{OFFSET_FLAG, TYPE_MASK, UNSIGNED_FLAG, VEC_SIZE_MASK, VEC_SIZE_SHIFT};

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_xmb_roundtrip() {
        // Create a simple XMB document
        let mut root = Node::new("Root");
        root.add_attribute(Attribute::with_string("version", "1.0"));

        let mut child = Node::with_text("Child", "Hello World");
        child.add_attribute(Attribute::with_string("id", "1"));
        root.add_child(child);

        let xmb = XmbData::with_root(root);

        // Write to buffer
        let mut buffer = Cursor::new(Vec::new());
        XmbWriter::write(&xmb, &mut buffer, XmbFormat::PC).expect("Failed to write XMB");

        // Read back
        buffer.set_position(0);
        let read_xmb = XmbReader::read(buffer).expect("Failed to read XMB");

        // Verify
        let read_root = read_xmb.root().expect("No root node");
        assert_eq!(read_root.name, "Root");
        assert_eq!(read_root.attributes.len(), 1);
        assert_eq!(read_root.attributes[0].name, "version");
        assert_eq!(read_root.children.len(), 1);
        assert_eq!(read_root.children[0].name, "Child");
    }

    #[test]
    fn test_node_creation() {
        let mut node = Node::new("TestNode");
        assert_eq!(node.name, "TestNode");
        assert!(!node.has_children());
        assert!(!node.has_attributes());

        node.add_attribute(Attribute::with_string("attr1", "value1"));
        assert!(node.has_attributes());

        let child = Node::new("ChildNode");
        node.add_child(child);
        assert!(node.has_children());
        assert_eq!(node.node_count(), 2);
    }

    #[test]
    fn test_variant_to_string() {
        assert_eq!(Variant::Null.to_string_value(), "");
        assert_eq!(Variant::Bool(true).to_string_value(), "true");
        assert_eq!(Variant::Bool(false).to_string_value(), "false");
        assert_eq!(Variant::Int(42).to_string_value(), "42");
        assert_eq!(Variant::Float(3.14).to_string_value(), "3.14");
        assert_eq!(
            Variant::String("test".to_string()).to_string_value(),
            "test"
        );
    }

    // ==================== VARIANT TYPE TESTS ====================

    #[test]
    fn test_variant_null() {
        let mut root = Node::new("Test");
        root.add_child(Node::new("EmptyNode")); // No text = Null variant
        let xmb = XmbData::with_root(root);

        let mut buffer = Cursor::new(Vec::new());
        XmbWriter::write(&xmb, &mut buffer, XmbFormat::PC).unwrap();
        buffer.set_position(0);
        let read = XmbReader::read(buffer).unwrap();

        assert_eq!(read.root().unwrap().children[0].text, Variant::Null);
    }

    #[test]
    fn test_variant_bool() {
        let mut root = Node::new("Test");
        root.add_child(Node::with_text("True", "true"));
        root.add_child(Node::with_text("False", "false"));
        root.add_attribute(Attribute::new("enabled", Variant::Bool(true)));
        root.add_attribute(Attribute::new("disabled", Variant::Bool(false)));

        let xmb = XmbData::with_root(root);
        let xml = xmb.to_xml();
        let parsed = XmbData::from_xml(&xml).unwrap();

        let r = parsed.root().unwrap();
        assert_eq!(r.children[0].text_string(), "true");
        assert_eq!(r.children[1].text_string(), "false");
    }

    #[test]
    fn test_variant_int_small() {
        // Int24 - fits in 24 bits (-8388608 to 8388607)
        let mut root = Node::new("Test");
        root.add_child(Node::with_text("Zero", "0"));
        root.add_child(Node::with_text("Small", "42"));
        root.add_child(Node::with_text("Negative", "-100"));
        root.add_child(Node::with_text("MaxInt24", "8388607"));
        root.add_child(Node::with_text("MinInt24", "-8388608"));

        let xmb = XmbData::with_root(root);
        let mut buffer = Cursor::new(Vec::new());
        XmbWriter::write(&xmb, &mut buffer, XmbFormat::PC).unwrap();
        buffer.set_position(0);
        let read = XmbReader::read(buffer).unwrap();
        let r = read.root().unwrap();

        assert_eq!(r.children[0].text_string(), "0");
        assert_eq!(r.children[1].text_string(), "42");
        assert_eq!(r.children[2].text_string(), "-100");
    }

    #[test]
    fn test_variant_int_large() {
        // Int32 - larger values that don't fit in 24 bits
        let mut root = Node::new("Test");
        root.add_child(Node::with_text("Large", "10000000"));
        root.add_child(Node::with_text("VeryLarge", "2147483647")); // i32::MAX
        root.add_child(Node::with_text("VeryNegative", "-2147483648")); // i32::MIN

        let xmb = XmbData::with_root(root);
        let mut buffer = Cursor::new(Vec::new());
        XmbWriter::write(&xmb, &mut buffer, XmbFormat::PC).unwrap();
        buffer.set_position(0);
        let read = XmbReader::read(buffer).unwrap();
        let r = read.root().unwrap();

        assert_eq!(r.children[0].text_string(), "10000000");
    }

    #[test]
    fn test_variant_float() {
        let mut root = Node::new("Test");
        root.add_child(Node::with_text("Simple", "3.14"));
        root.add_child(Node::with_text("Negative", "-2.5"));
        root.add_child(Node::with_text("Zero", "0.0"));
        root.add_child(Node::with_text("Small", "0.001"));

        let xmb = XmbData::with_root(root);
        let mut buffer = Cursor::new(Vec::new());
        XmbWriter::write(&xmb, &mut buffer, XmbFormat::PC).unwrap();
        buffer.set_position(0);
        let read = XmbReader::read(buffer).unwrap();

        // Values should round-trip (may have slight precision differences)
        let r = read.root().unwrap();
        assert!(r.children[0].text_string().starts_with("3.14"));
    }

    #[test]
    fn test_variant_float_vec() {
        let mut root = Node::new("Test");
        root.add_child(Node::with_text("Vec2", "1.0,2.0"));
        root.add_child(Node::with_text("Vec3", "1.0,2.0,3.0"));
        root.add_child(Node::with_text("Vec4", "1.0,2.0,3.0,4.0"));
        root.add_child(Node::with_text("Negative", "-1.0,-2.0"));

        let xmb = XmbData::with_root(root);
        let mut buffer = Cursor::new(Vec::new());
        XmbWriter::write(&xmb, &mut buffer, XmbFormat::PC).unwrap();
        buffer.set_position(0);
        let read = XmbReader::read(buffer).unwrap();
        let r = read.root().unwrap();

        assert!(r.children[0].text_string().contains(","));
        assert!(r.children[2].text_string().contains(","));
    }

    #[test]
    fn test_variant_string() {
        let mut root = Node::new("Test");
        root.add_child(Node::with_text("Simple", "hello"));
        root.add_child(Node::with_text("WithSpaces", "hello world"));
        root.add_child(Node::with_text("Empty", ""));

        let xmb = XmbData::with_root(root);
        let mut buffer = Cursor::new(Vec::new());
        XmbWriter::write(&xmb, &mut buffer, XmbFormat::PC).unwrap();
        buffer.set_position(0);
        let read = XmbReader::read(buffer).unwrap();
        let r = read.root().unwrap();

        assert_eq!(r.children[0].text_string(), "hello");
        assert_eq!(r.children[1].text_string(), "hello world");
    }

    #[test]
    fn test_variant_string_xml_special_chars() {
        // Characters that need XML escaping
        let mut root = Node::new("Test");
        root.add_child(Node::with_text("Ampersand", "a & b"));
        root.add_child(Node::with_text("LessThan", "a < b"));
        root.add_child(Node::with_text("GreaterThan", "a > b"));
        root.add_child(Node::with_text("Quote", "say \"hello\""));
        root.add_child(Node::with_text("Apostrophe", "it's"));

        let xmb = XmbData::with_root(root);
        let xml = xmb.to_xml();

        // Only & and < MUST be escaped in text content
        assert!(xml.contains("&amp;"), "XML must escape &");
        assert!(xml.contains("&lt;"), "XML must escape <");
        // >, ", ' don't need escaping in text (quick-xml may or may not escape them)

        // Round-trip through XML - all special chars should be preserved
        let parsed = XmbData::from_xml(&xml).unwrap();
        let r = parsed.root().unwrap();
        assert_eq!(r.children[0].text_string(), "a & b");
        assert_eq!(r.children[1].text_string(), "a < b");
        assert_eq!(r.children[2].text_string(), "a > b");
        assert_eq!(r.children[3].text_string(), "say \"hello\"");
        assert_eq!(r.children[4].text_string(), "it's");
    }

    // ==================== NODE STRUCTURE TESTS ====================

    #[test]
    fn test_node_empty() {
        let root = Node::new("EmptyRoot");
        let xmb = XmbData::with_root(root);

        let mut buffer = Cursor::new(Vec::new());
        XmbWriter::write(&xmb, &mut buffer, XmbFormat::PC).unwrap();
        buffer.set_position(0);
        let read = XmbReader::read(buffer).unwrap();
        let r = read.root().unwrap();

        assert_eq!(r.name, "EmptyRoot");
        assert!(r.children.is_empty());
        assert!(r.attributes.is_empty());
        assert_eq!(r.text, Variant::Null);
    }

    #[test]
    fn test_node_with_text_only() {
        let root = Node::with_text("TextNode", "some text content");
        let xmb = XmbData::with_root(root);

        let mut buffer = Cursor::new(Vec::new());
        XmbWriter::write(&xmb, &mut buffer, XmbFormat::PC).unwrap();
        buffer.set_position(0);
        let read = XmbReader::read(buffer).unwrap();
        let r = read.root().unwrap();

        assert_eq!(r.text_string(), "some text content");
        assert!(r.children.is_empty());
        assert!(r.attributes.is_empty());
    }

    #[test]
    fn test_node_with_attributes_only() {
        let mut root = Node::new("AttrNode");
        root.add_attribute(Attribute::with_string("attr1", "value1"));
        root.add_attribute(Attribute::new("attr2", Variant::Int(42)));
        root.add_attribute(Attribute::new("attr3", Variant::Bool(true)));

        let xmb = XmbData::with_root(root);

        let mut buffer = Cursor::new(Vec::new());
        XmbWriter::write(&xmb, &mut buffer, XmbFormat::PC).unwrap();
        buffer.set_position(0);
        let read = XmbReader::read(buffer).unwrap();
        let r = read.root().unwrap();

        assert_eq!(r.attributes.len(), 3);
        assert!(r.children.is_empty());
    }

    #[test]
    fn test_node_with_children_only() {
        let mut root = Node::new("Parent");
        root.add_child(Node::new("Child1"));
        root.add_child(Node::new("Child2"));
        root.add_child(Node::new("Child3"));

        let xmb = XmbData::with_root(root);

        let mut buffer = Cursor::new(Vec::new());
        XmbWriter::write(&xmb, &mut buffer, XmbFormat::PC).unwrap();
        buffer.set_position(0);
        let read = XmbReader::read(buffer).unwrap();
        let r = read.root().unwrap();

        assert_eq!(r.children.len(), 3);
        assert!(r.attributes.is_empty());
    }

    #[test]
    fn test_node_deeply_nested() {
        // Create 10 levels of nesting
        let mut current = Node::with_text("Level10", "deep");
        for i in (1..10).rev() {
            let mut parent = Node::new(format!("Level{}", i));
            parent.add_child(current);
            current = parent;
        }

        let xmb = XmbData::with_root(current);

        let mut buffer = Cursor::new(Vec::new());
        XmbWriter::write(&xmb, &mut buffer, XmbFormat::PC).unwrap();
        buffer.set_position(0);
        let read = XmbReader::read(buffer).unwrap();

        // Navigate down
        let mut node = read.root().unwrap();
        for i in 1..=9 {
            assert_eq!(node.name, format!("Level{}", i));
            node = &node.children[0];
        }
        assert_eq!(node.name, "Level10");
        assert_eq!(node.text_string(), "deep");
    }

    #[test]
    fn test_node_wide() {
        // Node with many children at same level
        let mut root = Node::new("Wide");
        for i in 0..100 {
            root.add_child(Node::with_text(
                format!("Child{}", i),
                format!("value{}", i),
            ));
        }

        let xmb = XmbData::with_root(root);

        let mut buffer = Cursor::new(Vec::new());
        XmbWriter::write(&xmb, &mut buffer, XmbFormat::PC).unwrap();
        buffer.set_position(0);
        let read = XmbReader::read(buffer).unwrap();
        let r = read.root().unwrap();

        assert_eq!(r.children.len(), 100);
        assert_eq!(r.children[99].name, "Child99");
    }

    #[test]
    fn test_node_many_attributes() {
        let mut root = Node::new("ManyAttrs");
        for i in 0..50 {
            root.add_attribute(Attribute::with_string(
                format!("attr{}", i),
                format!("val{}", i),
            ));
        }

        let xmb = XmbData::with_root(root);

        let mut buffer = Cursor::new(Vec::new());
        XmbWriter::write(&xmb, &mut buffer, XmbFormat::PC).unwrap();
        buffer.set_position(0);
        let read = XmbReader::read(buffer).unwrap();
        let r = read.root().unwrap();

        assert_eq!(r.attributes.len(), 50);
    }

    #[test]
    fn test_to_xml() {
        // Create a simple XMB document
        let mut root = Node::new("Config");
        root.add_attribute(Attribute::with_string("version", "1.0"));

        let mut child = Node::with_text("Setting", "value1");
        child.add_attribute(Attribute::with_string("name", "option1"));
        root.add_child(child);

        let empty_child = Node::new("EmptyNode");
        root.add_child(empty_child);

        let xmb = XmbData::with_root(root);
        let xml = xmb.to_xml();

        println!("Generated XML:\n{}", xml);

        assert!(xml.contains("<?xml version=\"1.0\""));
        assert!(xml.contains("<Config version=\"1.0\">"));
        assert!(xml.contains("<Setting name=\"option1\">value1</Setting>"));
        // quick-xml outputs <EmptyNode/> without space before />
        assert!(xml.contains("<EmptyNode/>") || xml.contains("<EmptyNode />"));
        assert!(xml.contains("</Config>"));
    }

    #[test]
    fn test_xmb_to_xml_synthetic() {
        // Create a complex nested structure
        let mut root = Node::new("GameConfig");

        let mut audio = Node::new("Audio");
        audio.add_child(Node::with_text("MasterVolume", "0.8"));
        audio.add_child(Node::with_text("MusicVolume", "0.6"));
        audio.add_child(Node::with_text("SFXVolume", "1.0"));
        root.add_child(audio);

        let mut video = Node::new("Video");
        video.add_attribute(Attribute::with_string("resolution", "1920x1080"));
        video.add_child(Node::with_text("Fullscreen", "true"));
        video.add_child(Node::with_text("VSync", "true"));
        root.add_child(video);

        let xmb = XmbData::with_root(root);

        // Write to XMB and read back
        let mut buffer = Cursor::new(Vec::new());
        XmbWriter::write(&xmb, &mut buffer, XmbFormat::PC).expect("Failed to write XMB");
        buffer.set_position(0);
        let read_xmb = XmbReader::read(buffer).expect("Failed to read XMB");

        // Convert to XML
        let xml = read_xmb.to_xml();

        // Verify it's valid-looking XML
        assert!(xml.starts_with("<?xml version=\"1.0\""));
        assert!(xml.contains("<GameConfig"));
        assert!(xml.contains("</GameConfig>"));
        assert!(xml.contains("<Audio>"));
        assert!(xml.contains("<MasterVolume>0.8</MasterVolume>"));

        println!("Generated XML:\n{}", xml);
    }

    #[test]
    fn test_various_variant_types_roundtrip() {
        // Test all variant types in a roundtrip
        let mut root = Node::new("VariantTest");

        // Boolean values
        root.add_child(Node::with_text("BoolTrue", "true"));
        root.add_child(Node::with_text("BoolFalse", "false"));

        // Integer values
        root.add_child(Node::with_text("SmallInt", "42"));
        root.add_child(Node::with_text("NegativeInt", "-100"));
        root.add_child(Node::with_text("LargeInt", "1000000"));

        // Float values
        root.add_child(Node::with_text("SimpleFloat", "3.14"));
        root.add_child(Node::with_text("NegativeFloat", "-2.5"));

        // Float vectors
        root.add_child(Node::with_text("FloatVec2", "1.0,2.0"));
        root.add_child(Node::with_text("FloatVec3", "1.0,2.0,3.0"));
        root.add_child(Node::with_text("FloatVec4", "1.0,2.0,3.0,4.0"));

        // Strings
        root.add_child(Node::with_text("StringValue", "Hello World"));
        root.add_child(Node::with_text("EmptyString", ""));

        let xmb = XmbData::with_root(root);

        // Write and read back
        let mut buffer = Cursor::new(Vec::new());
        XmbWriter::write(&xmb, &mut buffer, XmbFormat::PC).expect("Failed to write XMB");
        buffer.set_position(0);
        let read_xmb = XmbReader::read(buffer).expect("Failed to read XMB");
        let read_root = read_xmb.root().expect("No root node");

        assert_eq!(read_root.name, "VariantTest");
        assert_eq!(read_root.children.len(), 12);

        // Convert to XML and verify
        let xml = read_xmb.to_xml();
        assert!(xml.contains("<BoolTrue>true</BoolTrue>"));
        assert!(xml.contains("<SmallInt>42</SmallInt>"));
    }

    #[test]
    fn test_xml_parsing() {
        let xml = r#"<?xml version="1.0" encoding="utf-8"?>
<Root version="1.0">
  <Child id="1">Hello World</Child>
  <Empty />
</Root>"#;

        let xmb = XmbData::from_xml(xml).expect("Failed to parse XML");
        let root = xmb.root().expect("No root node");

        assert_eq!(root.name, "Root");
        assert_eq!(root.attributes.len(), 1);
        assert_eq!(root.attributes[0].name, "version");
        assert_eq!(root.children.len(), 2);

        let child = &root.children[0];
        assert_eq!(child.name, "Child");
        assert_eq!(child.attributes.len(), 1);
        assert_eq!(child.attributes[0].name, "id");
        assert_eq!(child.text_string(), "Hello World");

        let empty = &root.children[1];
        assert_eq!(empty.name, "Empty");
        assert!(empty.children.is_empty());
    }

    #[test]
    fn test_xml_to_xmb_roundtrip() {
        // Parse XML
        let xml = r#"<?xml version="1.0" encoding="utf-8"?>
<Config name="test" enabled="true">
  <Setting key="value1">100</Setting>
  <Setting key="value2">Hello</Setting>
  <Nested>
    <Deep>Content</Deep>
  </Nested>
</Config>"#;

        let xmb = XmbData::from_xml(xml).expect("Failed to parse XML");

        // Write to XMB binary
        let mut buffer = Cursor::new(Vec::new());
        XmbWriter::write(&xmb, &mut buffer, XmbFormat::PC).expect("Failed to write XMB");

        // Read back from XMB binary
        buffer.set_position(0);
        let read_xmb = XmbReader::read(buffer).expect("Failed to read XMB");

        // Verify structure
        let root = read_xmb.root().expect("No root node");
        assert_eq!(root.name, "Config");
        assert_eq!(root.children.len(), 3);
        assert_eq!(root.children[0].name, "Setting");
        assert_eq!(root.children[2].name, "Nested");
        assert_eq!(root.children[2].children[0].name, "Deep");
    }

    #[test]
    fn test_full_xmb_xml_xmb_roundtrip() {
        // Create a complex synthetic document
        let mut root = Node::new("TileTypes");
        for i in 0..10 {
            let mut tile = Node::new("Tile");
            tile.add_attribute(Attribute::with_string("Type", &format!("Terrain{}", i)));
            tile.add_attribute(Attribute::new("ObstructLand", Variant::Bool(i % 2 == 0)));
            root.add_child(tile);
        }

        let original_xmb = XmbData::with_root(root);

        // Convert to XML
        let xml = original_xmb.to_xml();
        println!("XML:\n{}", &xml[..xml.len().min(500)]);

        // Parse XML back to XmbData
        let parsed_xmb = XmbData::from_xml(&xml).expect("Failed to parse XML");

        // Write to XMB binary
        let mut buffer = Cursor::new(Vec::new());
        XmbWriter::write(&parsed_xmb, &mut buffer, XmbFormat::PC).expect("Failed to write XMB");

        // Read back from XMB binary
        buffer.set_position(0);
        let final_xmb = XmbReader::read(buffer).expect("Failed to read XMB");

        // Compare structure
        let orig_root = original_xmb.root().expect("No original root");
        let final_root = final_xmb.root().expect("No final root");

        assert_eq!(orig_root.name, final_root.name);
        assert_eq!(orig_root.children.len(), final_root.children.len());

        // Compare first child
        if !orig_root.children.is_empty() {
            let orig_child = &orig_root.children[0];
            let final_child = &final_root.children[0];
            assert_eq!(orig_child.name, final_child.name);
            assert_eq!(orig_child.attributes.len(), final_child.attributes.len());
        }

        println!("Full roundtrip successful!");
    }

    #[test]
    fn test_pc_format_roundtrip() {
        // Create a complex synthetic document for PC format testing
        let mut root = Node::new("CameraSettings");
        root.add_attribute(Attribute::with_string("version", "2.0"));

        let mut camera = Node::new("Camera");
        camera.add_child(Node::with_text("Name", "MainCamera"));
        camera.add_child(Node::with_text("FOV", "60"));
        camera.add_child(Node::with_text("NearClip", "0.1"));
        camera.add_child(Node::with_text("FarClip", "1000.0"));

        let mut transform = Node::new("Transform");
        transform.add_child(Node::with_text("Position", "0,10,0"));
        transform.add_child(Node::with_text("Rotation", "45,0,0"));
        camera.add_child(transform);

        root.add_child(camera);

        // Add more cameras for complexity
        for i in 1..5 {
            let mut cam = Node::new("Camera");
            cam.add_child(Node::with_text("Name", &format!("Camera{}", i)));
            cam.add_child(Node::with_text("FOV", &format!("{}", 50 + i * 5)));
            root.add_child(cam);
        }

        let original = XmbData::with_root(root);

        // Write in PC format
        let mut buffer = Cursor::new(Vec::new());
        XmbWriter::write(&original, &mut buffer, XmbFormat::PC).expect("Failed to write PC XMB");

        // Read back
        buffer.set_position(0);
        let read_back = XmbReader::read(buffer).expect("Failed to read PC XMB");

        // Compare
        let orig_root = original.root().expect("No original root");
        let read_root = read_back.root().expect("No read root");

        assert_eq!(orig_root.name, read_root.name);
        assert_eq!(orig_root.children.len(), read_root.children.len());
        assert_eq!(orig_root.attributes.len(), read_root.attributes.len());

        // Compare all nodes recursively
        fn count_nodes(node: &Node) -> usize {
            1 + node.children.iter().map(|c| count_nodes(c)).sum::<usize>()
        }
        assert_eq!(count_nodes(orig_root), count_nodes(read_root));

        // Verify it was read as PC format
        assert!(read_back.is_pc());

        println!(
            "PC format roundtrip successful! {} nodes",
            count_nodes(orig_root)
        );
    }

    #[test]
    fn test_xbox360_floatvec_roundtrip() {
        // Test FloatVec attribute roundtrip specifically
        let mut root = Node::new("Test");
        let mut child = Node::new("Unit");
        child.add_attribute(Attribute {
            name: "Offset".to_string(),
            value: Variant::FloatVec(vec![50.0, 0.0, 0.0]),
        });
        root.add_child(child);

        let original = XmbData::with_root(root);

        // Write in Xbox 360 format
        let mut buffer = Cursor::new(Vec::new());
        XmbWriter::write(&original, &mut buffer, XmbFormat::Xbox360)
            .expect("Failed to write Xbox 360 XMB");

        // Read back
        buffer.set_position(0);
        let read_back = XmbReader::read(buffer).expect("Failed to read Xbox 360 XMB");

        let orig_root = original.root().expect("No original root");
        let read_root = read_back.root().expect("No read root");

        let orig_offset = &orig_root.children[0].attributes[0];
        let read_offset = &read_root.children[0].attributes[0];

        println!("Original Offset: {:?}", orig_offset.value);
        println!("Read Offset: {:?}", read_offset.value);

        assert_eq!(
            orig_offset.value_string(),
            read_offset.value_string(),
            "FloatVec attribute value mismatch"
        );
    }

    #[test]
    fn test_xbox360_xml_floatvec_roundtrip() {
        // Test XML -> XMB -> XML roundtrip for FloatVec on a CHILD node
        let xml = r#"<?xml version="1.0"?>
<Test>
    <Unit Offset="50,0,0">
        <Name>TestUnit</Name>
    </Unit>
</Test>"#;

        // Parse XML
        let xmb = XmbData::from_xml(xml).expect("Failed to parse XML");

        // Check what we parsed
        let parsed_root = xmb.root().expect("No root after XML parse");
        let parsed_offset = &parsed_root.children[0].attributes[0];
        println!(
            "Parsed from XML (child attr) - Offset: {:?}",
            parsed_offset.value
        );

        // Write in Xbox 360 format
        let mut buffer = Cursor::new(Vec::new());
        XmbWriter::write(&xmb, &mut buffer, XmbFormat::Xbox360)
            .expect("Failed to write Xbox 360 XMB");

        // Read back
        buffer.set_position(0);
        let read_back = XmbReader::read(buffer).expect("Failed to read Xbox 360 XMB");

        let read_root = read_back.root().expect("No root after XMB read");
        let read_offset = &read_root.children[0].attributes[0];
        println!(
            "Read from XMB (child attr) - Offset: {:?}",
            read_offset.value
        );

        assert_eq!(
            parsed_offset.value_string(),
            read_offset.value_string(),
            "FloatVec attribute value mismatch after XML -> XMB -> read roundtrip"
        );
    }

    #[test]
    fn test_xbox360_simple_floatvec_on_root() {
        // Test with FloatVec on root node (simpler case)
        let mut root = Node::new("Test");
        root.add_attribute(Attribute {
            name: "Offset".to_string(),
            value: Variant::FloatVec(vec![50.0, 0.0, 0.0]),
        });

        let original = XmbData::with_root(root);

        println!(
            "Original root attr: {:?}",
            original.root().unwrap().attributes[0].value
        );

        // Write in Xbox 360 format
        let mut buffer = Cursor::new(Vec::new());
        XmbWriter::write(&original, &mut buffer, XmbFormat::Xbox360)
            .expect("Failed to write Xbox 360 XMB");

        // Read back
        buffer.set_position(0);
        let read_back = XmbReader::read(buffer).expect("Failed to read Xbox 360 XMB");

        let read_root = read_back.root().expect("No root");
        println!("Read root attr: {:?}", read_root.attributes[0].value);

        assert_eq!(
            original.root().unwrap().attributes[0].value_string(),
            read_root.attributes[0].value_string(),
            "FloatVec on root mismatch"
        );
    }

    #[test]
    fn test_xbox360_floatvec_with_child() {
        // Test with FloatVec on child node (more complex)
        let mut root = Node::new("Test");
        let mut child = Node::new("Unit");
        child.add_attribute(Attribute {
            name: "Offset".to_string(),
            value: Variant::FloatVec(vec![50.0, 0.0, 0.0]),
        });
        root.add_child(child);

        let original = XmbData::with_root(root);

        println!(
            "Original child attr: {:?}",
            original.root().unwrap().children[0].attributes[0].value
        );

        // Write in Xbox 360 format
        let mut buffer = Cursor::new(Vec::new());
        XmbWriter::write(&original, &mut buffer, XmbFormat::Xbox360)
            .expect("Failed to write Xbox 360 XMB");

        // Read back
        buffer.set_position(0);
        let read_back = XmbReader::read(buffer).expect("Failed to read Xbox 360 XMB");

        let read_root = read_back.root().expect("No root");
        println!(
            "Read child attr: {:?}",
            read_root.children[0].attributes[0].value
        );

        assert_eq!(
            original.root().unwrap().children[0].attributes[0].value_string(),
            read_root.children[0].attributes[0].value_string(),
            "FloatVec on child mismatch"
        );
    }

    #[test]
    fn test_xbox360_floatvec_with_grandchild() {
        // Test with FloatVec on child node that has a grandchild
        let mut root = Node::new("Test");
        let mut child = Node::new("Unit");
        child.add_attribute(Attribute {
            name: "Offset".to_string(),
            value: Variant::FloatVec(vec![50.0, 0.0, 0.0]),
        });
        // Add a grandchild (this is what the XML test has)
        child.add_child(Node::with_text("Name", "TestUnit"));
        root.add_child(child);

        let original = XmbData::with_root(root);

        println!(
            "Original child attr: {:?}",
            original.root().unwrap().children[0].attributes[0].value
        );

        // Write in Xbox 360 format
        let mut buffer = Cursor::new(Vec::new());
        XmbWriter::write(&original, &mut buffer, XmbFormat::Xbox360)
            .expect("Failed to write Xbox 360 XMB");

        // Read back
        buffer.set_position(0);
        let read_back = XmbReader::read(buffer).expect("Failed to read Xbox 360 XMB");

        let read_root = read_back.root().expect("No root");
        println!(
            "Read child attr: {:?}",
            read_root.children[0].attributes[0].value
        );

        assert_eq!(
            original.root().unwrap().children[0].attributes[0].value_string(),
            read_root.children[0].attributes[0].value_string(),
            "FloatVec on child with grandchild mismatch"
        );
    }

    #[test]
    fn test_xbox360_format_roundtrip() {
        // Create a synthetic document for Xbox 360 format testing
        let mut root = Node::new("GameData");
        root.add_attribute(Attribute::with_string("version", "1.0"));

        for i in 0..5 {
            let mut unit = Node::new("Unit");
            unit.add_attribute(Attribute::with_string("id", &format!("unit_{}", i)));
            unit.add_child(Node::with_text("Name", &format!("Unit {}", i)));
            unit.add_child(Node::with_text("Health", &format!("{}", 100 + i * 20)));
            unit.add_child(Node::with_text("Attack", &format!("{}", 10 + i * 5)));
            root.add_child(unit);
        }

        let original = XmbData::with_root(root);

        // Write in Xbox 360 format
        let mut buffer = Cursor::new(Vec::new());
        XmbWriter::write(&original, &mut buffer, XmbFormat::Xbox360)
            .expect("Failed to write Xbox 360 XMB");

        // Read back
        buffer.set_position(0);
        let read_back = XmbReader::read(buffer).expect("Failed to read Xbox 360 XMB");

        // Verify it was read as Xbox 360 format
        assert!(read_back.is_xbox360());

        // Compare structure
        let orig_root = original.root().expect("No original root");
        let read_root = read_back.root().expect("No read root");

        assert_eq!(orig_root.name, read_root.name);
        assert_eq!(orig_root.children.len(), read_root.children.len());

        // Verify children structure
        for (i, (orig_child, read_child)) in orig_root
            .children
            .iter()
            .zip(read_root.children.iter())
            .enumerate()
        {
            assert_eq!(
                orig_child.name, read_child.name,
                "Child {} name mismatch",
                i
            );
            assert_eq!(
                orig_child.children.len(),
                read_child.children.len(),
                "Child {} children count mismatch",
                i
            );
        }
    }

    // ==================== FORMAT ROUNDTRIP TESTS ====================

    #[test]
    fn test_both_formats_deep_nesting() {
        // Test that both PC and Xbox 360 formats handle deep nesting
        fn create_test_doc() -> XmbData {
            let mut root = Node::new("L1");
            let mut l2 = Node::new("L2");
            let mut l3 = Node::new("L3");
            l3.add_child(Node::with_text("L4", "deep"));
            l2.add_child(l3);
            root.add_child(l2);
            XmbData::with_root(root)
        }

        // Test PC format
        let xmb = create_test_doc();
        let mut buffer = Cursor::new(Vec::new());
        XmbWriter::write(&xmb, &mut buffer, XmbFormat::PC).unwrap();
        buffer.set_position(0);
        let read = XmbReader::read(buffer).unwrap();
        assert!(read.is_pc());
        assert_eq!(
            read.root().unwrap().children[0].children[0].children[0].name,
            "L4"
        );

        // Test Xbox 360 format
        let xmb = create_test_doc();
        let mut buffer = Cursor::new(Vec::new());
        XmbWriter::write(&xmb, &mut buffer, XmbFormat::Xbox360).unwrap();
        buffer.set_position(0);
        let read = XmbReader::read(buffer).unwrap();
        assert!(read.is_xbox360());
        assert_eq!(
            read.root().unwrap().children[0].children[0].children[0].name,
            "L4"
        );
    }

    #[test]
    fn test_format_detection() {
        let root = Node::with_text("Test", "value");
        let xmb = XmbData::with_root(root);

        // Write PC format, verify detection
        let mut buffer = Cursor::new(Vec::new());
        XmbWriter::write(&xmb, &mut buffer, XmbFormat::PC).unwrap();
        buffer.set_position(0);
        let read = XmbReader::read(buffer).unwrap();
        assert!(read.is_pc());
        assert!(!read.is_xbox360());
        assert_eq!(read.format(), XmbFormat::PC);

        // Write Xbox 360 format, verify detection
        let mut buffer = Cursor::new(Vec::new());
        XmbWriter::write(&xmb, &mut buffer, XmbFormat::Xbox360).unwrap();
        buffer.set_position(0);
        let read = XmbReader::read(buffer).unwrap();
        assert!(read.is_xbox360());
        assert!(!read.is_pc());
        assert_eq!(read.format(), XmbFormat::Xbox360);
    }

    #[test]
    fn test_write_native_preserves_format() {
        let mut root = Node::new("Test");
        root.add_child(Node::with_text("Child", "value"));

        // Create as PC, write native, should stay PC
        let mut xmb = XmbData::with_root(root.clone());
        xmb.set_format(XmbFormat::PC);
        let mut buffer = Cursor::new(Vec::new());
        XmbWriter::write_native(&xmb, &mut buffer).unwrap();
        buffer.set_position(0);
        let read = XmbReader::read(buffer).unwrap();
        assert!(read.is_pc());

        // Create as Xbox360, write native, should stay Xbox360
        let mut xmb = XmbData::with_root(root);
        xmb.set_format(XmbFormat::Xbox360);
        let mut buffer = Cursor::new(Vec::new());
        XmbWriter::write_native(&xmb, &mut buffer).unwrap();
        buffer.set_position(0);
        let read = XmbReader::read(buffer).unwrap();
        assert!(read.is_xbox360());
    }

    // ==================== EDGE CASE TESTS ====================

    #[test]
    fn test_edge_case_empty_document() {
        // Just a root node, nothing else
        let xmb = XmbData::with_root(Node::new("Empty"));

        let mut buffer = Cursor::new(Vec::new());
        XmbWriter::write(&xmb, &mut buffer, XmbFormat::PC).unwrap();
        buffer.set_position(0);
        let read = XmbReader::read(buffer).unwrap();

        assert_eq!(read.root().unwrap().name, "Empty");
    }

    #[test]
    fn test_edge_case_long_string() {
        let long_text = "x".repeat(1000);
        let root = Node::with_text("Long", &long_text);
        let xmb = XmbData::with_root(root);

        let mut buffer = Cursor::new(Vec::new());
        XmbWriter::write(&xmb, &mut buffer, XmbFormat::PC).unwrap();
        buffer.set_position(0);
        let read = XmbReader::read(buffer).unwrap();

        assert_eq!(read.root().unwrap().text_string().len(), 1000);
    }

    #[test]
    fn test_edge_case_mixed_content() {
        // Node with attributes, text, and children
        let mut root = Node::with_text("Mixed", "text content");
        root.add_attribute(Attribute::with_string("attr", "value"));
        root.add_child(Node::with_text("Child", "child text"));

        let xmb = XmbData::with_root(root);

        let mut buffer = Cursor::new(Vec::new());
        XmbWriter::write(&xmb, &mut buffer, XmbFormat::PC).unwrap();
        buffer.set_position(0);
        let read = XmbReader::read(buffer).unwrap();
        let r = read.root().unwrap();

        assert_eq!(r.text_string(), "text content");
        assert_eq!(r.attributes.len(), 1);
        assert_eq!(r.children.len(), 1);
    }

    #[test]
    fn test_edge_case_attribute_types() {
        // All variant types as attributes
        let mut root = Node::new("Test");
        root.add_attribute(Attribute::new("null", Variant::Null));
        root.add_attribute(Attribute::new("bool", Variant::Bool(true)));
        root.add_attribute(Attribute::new("int", Variant::Int(42)));
        root.add_attribute(Attribute::new("float", Variant::Float(3.14)));
        root.add_attribute(Attribute::new("string", Variant::String("hello".into())));
        root.add_attribute(Attribute::new(
            "floatvec",
            Variant::FloatVec(vec![1.0, 2.0]),
        ));

        let xmb = XmbData::with_root(root);

        let mut buffer = Cursor::new(Vec::new());
        XmbWriter::write(&xmb, &mut buffer, XmbFormat::PC).unwrap();
        buffer.set_position(0);
        let read = XmbReader::read(buffer).unwrap();

        assert_eq!(read.root().unwrap().attributes.len(), 6);
    }

    #[test]
    fn test_edge_case_hex_integer() {
        // Hex integers should be parsed as integers
        let mut root = Node::new("Test");
        root.add_child(Node::with_text("Hex", "0xFF"));
        root.add_child(Node::with_text("HexLarge", "0xDEADBEEF"));

        let xmb = XmbData::with_root(root);
        let xml = xmb.to_xml();
        let parsed = XmbData::from_xml(&xml).unwrap();

        // These should parse as integers
        let r = parsed.root().unwrap();
        assert_eq!(r.children[0].text_string(), "255");
    }

    #[test]
    fn test_complex_realistic_document() {
        // A more realistic complex document structure
        let mut root = Node::new("GameConfig");
        root.add_attribute(Attribute::with_string("version", "1.0"));

        // Audio section
        let mut audio = Node::new("Audio");
        audio.add_child(Node::with_text("MasterVolume", "0.8"));
        audio.add_child(Node::with_text("MusicVolume", "0.6"));
        audio.add_child(Node::with_text("Enabled", "true"));
        root.add_child(audio);

        // Units section with multiple entries
        let mut units = Node::new("Units");
        for i in 0..5 {
            let mut unit = Node::new("Unit");
            unit.add_attribute(Attribute::with_string("id", &format!("unit_{}", i)));
            unit.add_attribute(Attribute::new("cost", Variant::Int(100 + i * 50)));
            unit.add_child(Node::with_text("Health", &format!("{}", 100 + i * 25)));
            unit.add_child(Node::with_text("Position", &format!("{},{},{}", i, 0, i)));
            units.add_child(unit);
        }
        root.add_child(units);

        let xmb = XmbData::with_root(root);

        // Full roundtrip: XMB -> XML -> XMB -> verify
        let mut buffer = Cursor::new(Vec::new());
        XmbWriter::write(&xmb, &mut buffer, XmbFormat::PC).unwrap();
        buffer.set_position(0);
        let read1 = XmbReader::read(buffer).unwrap();

        let xml = read1.to_xml();
        let parsed = XmbData::from_xml(&xml).unwrap();

        let mut buffer = Cursor::new(Vec::new());
        XmbWriter::write(&parsed, &mut buffer, XmbFormat::PC).unwrap();
        buffer.set_position(0);
        let final_xmb = XmbReader::read(buffer).unwrap();

        let r = final_xmb.root().unwrap();
        assert_eq!(r.name, "GameConfig");
        assert_eq!(r.children.len(), 2);
        assert_eq!(r.children[1].children.len(), 5); // 5 units
    }
}

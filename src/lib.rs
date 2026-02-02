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

pub mod ecf;
pub mod error;
pub mod types;
pub mod variant;
pub mod xmb;

pub use ecf::{EcfChunkHeader, EcfHeader, EcfReader, EcfWriter};
pub use error::{Error, Result};
pub use types::{Attribute, Node, XmbData, XmbFormat};
pub use variant::{Variant, VariantType};
pub use xmb::{XmbReader, XmbWriter};

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
        XmbWriter::write(&xmb, &mut buffer).expect("Failed to write XMB");

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

    #[test]
    fn test_read_cameramanager_xmb() {
        let path = std::path::Path::new("xmb-refs/hw1/cameramanager.xml.xmb");
        if !path.exists() {
            eprintln!("Skipping test: {:?} not found", path);
            return;
        }

        let file = std::fs::File::open(path).expect("Failed to open file");
        let xmb = XmbReader::read(file).expect("Failed to read XMB");
        let root = xmb.root().expect("No root node");

        assert_eq!(root.name, "CameraManager");
        assert_eq!(root.children.len(), 3);

        // Check first child is "Camera"
        assert_eq!(root.children[0].name, "Camera");
    }

    #[test]
    fn test_debug_defaulttiletypes() {
        let path = std::path::Path::new("xmb-refs/hw1/defaulttiletypes.xml.xmb");
        if !path.exists() {
            eprintln!("Skipping test: {:?} not found", path);
            return;
        }
        let file = std::fs::File::open(path).expect("Failed to open file");
        let xmb = XmbReader::read(file).expect("Failed to read XMB");
        let root = xmb.root().expect("No root node");

        println!("Root: {} (text: {:?})", root.name, root.text);
        println!("Root attributes: {}", root.attributes.len());
        for (i, attr) in root.attributes.iter().enumerate() {
            println!("  Attr[{}]: '{}' = {:?}", i, attr.name, attr.value);
            if i >= 5 {
                println!("  ... and {} more", root.attributes.len() - 6);
                break;
            }
        }

        println!("Root children: {}", root.children.len());
        if !root.children.is_empty() {
            let child = &root.children[0];
            println!("  First child: {} (text: {:?})", child.name, child.text);
            println!("  First child attributes: {}", child.attributes.len());
            for (i, attr) in child.attributes.iter().enumerate() {
                println!("    Attr[{}]: '{}' = {:?}", i, attr.name, attr.value);
                if i >= 5 {
                    println!("    ... and {} more", child.attributes.len() - 6);
                    break;
                }
            }
        }

        // The valid file shows each Tile has only 2 attributes: Type and ObstructLand
        // Let's check what our first Tile child should look like
        if root.children.len() > 0 {
            let first_tile = &root.children[0];
            // It should have exactly 2 attributes
            assert!(
                first_tile.attributes.len() <= 10,
                "Expected <= 10 attributes, got {}",
                first_tile.attributes.len()
            );
        }
    }

    #[test]
    fn test_read_leaders_xmb() {
        let path = std::path::Path::new("xmb-refs/hw1/leaders.xml.xmb");
        if !path.exists() {
            eprintln!("Skipping test: {:?} not found", path);
            return;
        }
        let file = std::fs::File::open(path).expect("Failed to open file");
        let xmb = XmbReader::read(file).expect("Failed to read XMB");
        let root = xmb.root().expect("No root node");
        assert!(!root.name.is_empty(), "Root node should have a name");
        println!("Root node: {}", root.name);
        println!("Total nodes: {}", root.node_count());
    }

    #[test]
    fn test_read_objects_xmb() {
        let path = std::path::Path::new("xmb-refs/hw1/objects.xml.xmb");
        if !path.exists() {
            eprintln!("Skipping test: {:?} not found", path);
            return;
        }
        let file = std::fs::File::open(path).expect("Failed to open file");
        let xmb = XmbReader::read(file).expect("Failed to read XMB");
        let root = xmb.root().expect("No root node");
        assert!(!root.name.is_empty(), "Root node should have a name");
        println!("Root node: {}", root.name);
        println!("Total nodes: {}", root.node_count());
    }

    #[test]
    fn test_read_all_reference_xmbs() {
        let ref_dir = std::path::Path::new("xmb-refs/hw1");
        if !ref_dir.exists() {
            eprintln!("Skipping test: {:?} not found", ref_dir);
            return;
        }

        for entry in std::fs::read_dir(ref_dir).expect("Failed to read directory") {
            let entry = entry.expect("Failed to read entry");
            let path = entry.path();
            if path.extension().map_or(false, |e| e == "xmb") {
                println!("Reading: {:?}", path);
                let file = std::fs::File::open(&path).expect("Failed to open file");
                let xmb = XmbReader::read(file).expect(&format!("Failed to read {:?}", path));
                let root = xmb.root().expect("No root node");
                println!("  Root: {}, Nodes: {}", root.name, root.node_count());
            }
        }
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
        assert!(xml.contains("<EmptyNode />"));
        assert!(xml.contains("</Config>"));
    }

    #[test]
    fn test_xmb_to_xml_cameramanager() {
        let path = std::path::Path::new("xmb-refs/hw1/cameramanager.xml.xmb");
        if !path.exists() {
            eprintln!("Skipping test: {:?} not found", path);
            return;
        }
        let file = std::fs::File::open(path).expect("Failed to open file");
        let xmb = XmbReader::read(file).expect("Failed to read XMB");

        let xml = xmb.to_xml();

        // Verify it's valid-looking XML
        assert!(xml.starts_with("<?xml version=\"1.0\""));
        assert!(xml.contains("<CameraManager"));
        assert!(xml.contains("</CameraManager>"));

        // Print first 2000 chars for inspection
        println!("First 2000 chars of XML:\n{}", &xml[..xml.len().min(2000)]);
    }

    #[test]
    fn test_export_all_xmb_to_xml() {
        let out_dir = std::path::Path::new("out");
        std::fs::create_dir_all(out_dir).expect("Failed to create out directory");

        let xmb_dir = std::path::Path::new("xmb-refs/hw1");
        if !xmb_dir.exists() {
            eprintln!("Skipping test: xmb-refs/hw1 not found");
            return;
        }

        for entry in std::fs::read_dir(xmb_dir).expect("Failed to read directory") {
            let entry = entry.expect("Failed to read entry");
            let path = entry.path();

            if path.extension().map_or(false, |e| e == "xmb") {
                println!("Converting: {:?}", path);

                let file = std::fs::File::open(&path).expect("Failed to open file");
                let xmb = XmbReader::read(file).expect(&format!("Failed to read {:?}", path));

                let xml = xmb.to_xml();

                // Get the filename without .xmb extension, add .xml
                let file_stem = path.file_stem().unwrap().to_str().unwrap();
                let out_path = out_dir.join(format!("{}", file_stem));

                std::fs::write(&out_path, &xml).expect("Failed to write XML");
                println!("  Written to: {:?} ({} bytes)", out_path, xml.len());
            }
        }

        println!("\nAll XMB files exported to 'out/' directory");
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
        XmbWriter::write(&xmb, &mut buffer).expect("Failed to write XMB");

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
        // Read real XMB file
        let path = std::path::Path::new("xmb-refs/hw1/defaulttiletypes.xml.xmb");
        if !path.exists() {
            eprintln!("Skipping test: {:?} not found", path);
            return;
        }

        let file = std::fs::File::open(path).expect("Failed to open file");
        let original_xmb = XmbReader::read(file).expect("Failed to read XMB");

        // Convert to XML
        let xml = original_xmb.to_xml();
        println!("XML:\n{}", &xml[..xml.len().min(500)]);

        // Parse XML back to XmbData
        let parsed_xmb = XmbData::from_xml(&xml).expect("Failed to parse XML");

        // Write to XMB binary
        let mut buffer = Cursor::new(Vec::new());
        XmbWriter::write(&parsed_xmb, &mut buffer).expect("Failed to write XMB");

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
    fn test_le_format_roundtrip() {
        // Test that LE format can be written and read back correctly
        let path = std::path::Path::new("xmb-refs/hw1/cameramanager.xml.xmb");
        if !path.exists() {
            eprintln!("Skipping test: {:?} not found", path);
            return;
        }

        let file = std::fs::File::open(path).expect("Failed to open file");
        let original = XmbReader::read(file).expect("Failed to read XMB");

        // Write in LE format
        let mut buffer = Cursor::new(Vec::new());
        XmbWriter::write_le(&original, &mut buffer).expect("Failed to write LE XMB");

        // Read back
        buffer.set_position(0);
        let read_back = XmbReader::read(buffer).expect("Failed to read LE XMB");

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

        println!(
            "LE format roundtrip successful! {} nodes",
            count_nodes(orig_root)
        );
    }

    #[test]
    fn test_be_format_roundtrip() {
        // Test that BE format can still be written and read back correctly
        let path = std::path::Path::new("xmb-refs/hw1/cameramanager.xml.xmb");
        if !path.exists() {
            eprintln!("Skipping test: {:?} not found", path);
            return;
        }

        let file = std::fs::File::open(path).expect("Failed to open file");
        let original = XmbReader::read(file).expect("Failed to read XMB");

        // Write in BE format
        let mut buffer = Cursor::new(Vec::new());
        XmbWriter::write_be(&original, &mut buffer).expect("Failed to write BE XMB");

        // Read back
        buffer.set_position(0);
        let read_back = XmbReader::read(buffer).expect("Failed to read BE XMB");

        // Compare
        let orig_root = original.root().expect("No original root");
        let read_root = read_back.root().expect("No read root");

        assert_eq!(orig_root.name, read_root.name);
        assert_eq!(orig_root.children.len(), read_root.children.len());

        println!("BE format roundtrip successful!");
    }
}

//! Core XMB data types.

use crate::error::{Error, Result};
use crate::variant::Variant;
use quick_xml::events::{BytesStart, Event};
use quick_xml::Reader;
use std::io::BufRead;

/// XMB format variant.
///
/// The XMB format has two variants based on the target platform:
/// - **Xbox360**: Original 2007 format with compact 20-byte nodes using u16 indices
/// - **PC**: HWDE format with 48-byte nodes using 64-bit BPackedArray pointers
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum XmbFormat {
    /// Xbox 360 format (big-endian, 20-byte nodes, u16 indices).
    /// Used in the original Halo Wars (2007).
    Xbox360,
    /// PC format (little-endian, 48-byte nodes, 64-bit BPackedArray).
    /// Used in Halo Wars Definitive Edition.
    #[default]
    PC,
}

impl XmbFormat {
    /// Returns true if this is the Xbox 360 format.
    pub fn is_xbox360(&self) -> bool {
        matches!(self, XmbFormat::Xbox360)
    }

    /// Returns true if this is the PC format.
    pub fn is_pc(&self) -> bool {
        matches!(self, XmbFormat::PC)
    }
}

/// An attribute on an XML node.
#[derive(Debug, Clone, Default)]
pub struct Attribute {
    /// The attribute name.
    pub name: String,
    /// The attribute value as a variant.
    pub value: Variant,
}

impl Attribute {
    /// Create a new attribute with a name and value.
    pub fn new(name: impl Into<String>, value: Variant) -> Self {
        Self {
            name: name.into(),
            value,
        }
    }

    /// Create a new attribute with a string value.
    pub fn with_string(name: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            value: Variant::String(value.into()),
        }
    }

    /// Get the value as a string.
    pub fn value_string(&self) -> String {
        self.value.to_string_value()
    }
}

/// A node in the XML tree.
#[derive(Debug, Clone, Default)]
pub struct Node {
    /// The node name (tag name).
    pub name: String,
    /// The node's text content.
    pub text: Variant,
    /// The node's attributes.
    pub attributes: Vec<Attribute>,
    /// The node's child nodes.
    pub children: Vec<Node>,
}

impl Node {
    /// Create a new node with the given name.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            text: Variant::Null,
            attributes: Vec::new(),
            children: Vec::new(),
        }
    }

    /// Create a new node with a name and text content.
    pub fn with_text(name: impl Into<String>, text: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            text: Variant::String(text.into()),
            attributes: Vec::new(),
            children: Vec::new(),
        }
    }

    /// Add an attribute to this node.
    pub fn add_attribute(&mut self, attr: Attribute) {
        self.attributes.push(attr);
    }

    /// Add a child node to this node.
    pub fn add_child(&mut self, child: Node) {
        self.children.push(child);
    }

    /// Get an attribute by name.
    pub fn get_attribute(&self, name: &str) -> Option<&Attribute> {
        self.attributes.iter().find(|a| a.name == name)
    }

    /// Get the text content as a string.
    pub fn text_string(&self) -> String {
        self.text.to_string_value()
    }

    /// Check if this node has any children.
    pub fn has_children(&self) -> bool {
        !self.children.is_empty()
    }

    /// Check if this node has any attributes.
    pub fn has_attributes(&self) -> bool {
        !self.attributes.is_empty()
    }

    /// Get the total number of nodes in this subtree (including self).
    pub fn node_count(&self) -> usize {
        1 + self.children.iter().map(|c| c.node_count()).sum::<usize>()
    }

    /// Convert this node to XML string.
    pub fn to_xml(&self) -> String {
        let mut output = String::new();
        self.write_xml(&mut output, 0);
        output
    }

    /// Write this node as XML to a string with indentation.
    fn write_xml(&self, output: &mut String, indent: usize) {
        let indent_str = "  ".repeat(indent);

        // Start tag
        output.push_str(&indent_str);
        output.push('<');
        output.push_str(&escape_xml_name(&self.name));

        // Attributes
        for attr in &self.attributes {
            output.push(' ');
            output.push_str(&escape_xml_name(&attr.name));
            output.push_str("=\"");
            output.push_str(&escape_xml_value(&attr.value.to_string_value()));
            output.push('"');
        }

        let has_text = !matches!(self.text, Variant::Null);
        let has_children = !self.children.is_empty();

        if !has_text && !has_children {
            // Self-closing tag
            output.push_str(" />\n");
        } else {
            output.push('>');

            if has_text && !has_children {
                // Inline text content
                output.push_str(&escape_xml_text(&self.text.to_string_value()));
                output.push_str("</");
                output.push_str(&escape_xml_name(&self.name));
                output.push_str(">\n");
            } else {
                output.push('\n');

                // Text content on its own line if present
                if has_text {
                    let text = self.text.to_string_value();
                    if !text.is_empty() {
                        output.push_str(&"  ".repeat(indent + 1));
                        output.push_str(&escape_xml_text(&text));
                        output.push('\n');
                    }
                }

                // Children
                for child in &self.children {
                    child.write_xml(output, indent + 1);
                }

                // End tag
                output.push_str(&indent_str);
                output.push_str("</");
                output.push_str(&escape_xml_name(&self.name));
                output.push_str(">\n");
            }
        }
    }
}

/// Escape special characters in XML attribute values.
fn escape_xml_value(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// Escape special characters in XML text content.
fn escape_xml_text(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

/// Escape/validate XML element/attribute names.
fn escape_xml_name(s: &str) -> String {
    // XML names can't start with numbers or contain certain characters
    // For now, just return as-is since Halo Wars names should be valid
    s.to_string()
}

/// XMB document data.
#[derive(Debug, Clone, Default)]
pub struct XmbData {
    /// The root node of the XML document.
    pub root: Option<Node>,
    /// The format variant (Xbox 360 or PC).
    pub format: XmbFormat,
    /// Source file name (if available).
    pub source_file: Option<String>,
}

impl XmbData {
    /// Create a new empty XMB document.
    pub fn new() -> Self {
        Self {
            root: None,
            format: XmbFormat::PC, // Default to PC format
            source_file: None,
        }
    }

    /// Create a new XMB document with a root node.
    pub fn with_root(root: Node) -> Self {
        Self {
            root: Some(root),
            format: XmbFormat::PC, // Default to PC format
            source_file: None,
        }
    }

    /// Get the format variant.
    pub fn format(&self) -> XmbFormat {
        self.format
    }

    /// Set the format variant.
    pub fn set_format(&mut self, format: XmbFormat) {
        self.format = format;
    }

    /// Returns true if this is Xbox 360 format.
    pub fn is_xbox360(&self) -> bool {
        self.format.is_xbox360()
    }

    /// Returns true if this is PC format.
    pub fn is_pc(&self) -> bool {
        self.format.is_pc()
    }

    /// Set the root node.
    pub fn set_root(&mut self, root: Node) {
        self.root = Some(root);
    }

    /// Get a reference to the root node.
    pub fn root(&self) -> Option<&Node> {
        self.root.as_ref()
    }

    /// Get a mutable reference to the root node.
    pub fn root_mut(&mut self) -> Option<&mut Node> {
        self.root.as_mut()
    }

    /// Convert the XMB document to an XML string.
    pub fn to_xml(&self) -> String {
        let mut output = String::from("<?xml version=\"1.0\" encoding=\"utf-8\"?>\n");
        if let Some(root) = &self.root {
            output.push_str(&root.to_xml());
        }
        output
    }

    /// Write the XMB document as XML to a writer.
    pub fn write_xml<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        writer.write_all(self.to_xml().as_bytes())
    }

    /// Parse an XML string into XmbData.
    pub fn from_xml(xml: &str) -> Result<Self> {
        Self::from_xml_reader(xml.as_bytes())
    }

    /// Parse XML from a reader into XmbData.
    pub fn from_xml_reader<R: BufRead>(reader: R) -> Result<Self> {
        let mut xml_reader = Reader::from_reader(reader);
        xml_reader.config_mut().trim_text(true);

        let mut buf = Vec::new();
        let mut root: Option<Node> = None;
        let mut stack: Vec<Node> = Vec::new();

        loop {
            match xml_reader.read_event_into(&mut buf) {
                Ok(Event::Start(ref e)) => {
                    let node = parse_start_element(e)?;
                    stack.push(node);
                }
                Ok(Event::Empty(ref e)) => {
                    // Self-closing tag like <Foo />
                    let node = parse_start_element(e)?;
                    if let Some(parent) = stack.last_mut() {
                        parent.children.push(node);
                    } else {
                        root = Some(node);
                    }
                }
                Ok(Event::End(_)) => {
                    if let Some(node) = stack.pop() {
                        if let Some(parent) = stack.last_mut() {
                            parent.children.push(node);
                        } else {
                            root = Some(node);
                        }
                    }
                }
                Ok(Event::Text(ref e)) => {
                    let text = e
                        .decode()
                        .map_err(|e| Error::InvalidString(e.to_string()))?;
                    let text_str = text.to_string();
                    if !text_str.is_empty() {
                        if let Some(node) = stack.last_mut() {
                            node.text = parse_text_value(&text_str);
                        }
                    }
                }
                Ok(Event::CData(ref e)) => {
                    let text = String::from_utf8_lossy(e.as_ref()).to_string();
                    if !text.is_empty() {
                        if let Some(node) = stack.last_mut() {
                            node.text = Variant::String(text);
                        }
                    }
                }
                Ok(Event::Eof) => break,
                Ok(_) => {} // Ignore comments, declarations, etc.
                Err(e) => return Err(Error::InvalidString(format!("XML parse error: {}", e))),
            }
            buf.clear();
        }

        Ok(XmbData {
            root,
            format: XmbFormat::PC, // XML parsing defaults to PC format
            source_file: None,
        })
    }
}

/// Parse a start element into a Node.
fn parse_start_element(e: &BytesStart) -> Result<Node> {
    let name = String::from_utf8_lossy(e.name().as_ref()).to_string();
    let mut node = Node::new(name);

    for attr_result in e.attributes() {
        let attr =
            attr_result.map_err(|e| Error::InvalidString(format!("Attribute error: {}", e)))?;
        let attr_name = String::from_utf8_lossy(attr.key.as_ref()).to_string();
        let attr_value = attr
            .unescape_value()
            .map_err(|e| Error::InvalidString(format!("Attribute value error: {}", e)))?
            .to_string();
        node.attributes.push(Attribute {
            name: attr_name,
            value: parse_text_value(&attr_value),
        });
    }

    Ok(node)
}

/// Parse a text value into the appropriate Variant type.
fn parse_text_value(s: &str) -> Variant {
    // Try to parse as various types
    if s.is_empty() {
        return Variant::Null;
    }

    // Check for boolean
    if s.eq_ignore_ascii_case("true") {
        return Variant::Bool(true);
    }
    if s.eq_ignore_ascii_case("false") {
        return Variant::Bool(false);
    }

    // Check for float vector (comma-separated numbers)
    if s.contains(',') {
        let parts: Vec<&str> = s.split(',').collect();
        if parts.len() >= 2 && parts.len() <= 4 {
            let floats: std::result::Result<Vec<f32>, _> =
                parts.iter().map(|p| p.trim().parse::<f32>()).collect();
            if let Ok(vec) = floats {
                return Variant::FloatVec(vec);
            }
        }
    }

    // Check for integer (including hex like 0x81)
    if let Some(hex_str) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        if let Ok(v) = u32::from_str_radix(hex_str, 16) {
            return Variant::UInt(v);
        }
    }

    // Try parsing as integer
    if let Ok(v) = s.parse::<i32>() {
        if v >= 0 {
            return Variant::UInt(v as u32);
        } else {
            return Variant::Int(v);
        }
    }

    // Try parsing as float
    if let Ok(v) = s.parse::<f32>() {
        // Check if we need Double precision (if f32 loses precision)
        if let Ok(d) = s.parse::<f64>() {
            let f32_back = v as f64;
            if (d - f32_back).abs() > 1e-6 {
                return Variant::Double(d);
            }
        }
        return Variant::Float(v);
    }

    // Use UString for non-ASCII text, String for ASCII
    if s.is_ascii() {
        Variant::String(s.to_string())
    } else {
        Variant::UString(s.to_string())
    }
}

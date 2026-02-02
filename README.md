# xmb-rs

[![CI](https://github.com/coconutbird/xmb-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/coconutbird/xmb-rs/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A Rust library and CLI for reading and writing XMB files - the binary XML format used by Ensemble Studios in Halo Wars.

## Features

- **Read XMB → XML**: Convert XMB binary files to human-readable XML
- **Write XML → XMB**: Convert XML back to XMB binary format
- **Format Support**:
  - PC/HWDE (little-endian, 48-byte nodes)
  - Xbox 360 (big-endian, 20-byte nodes)
- **Variant Types**: Bool, Int, Float, Double, String, UString, FloatVec
- **Compression**: Automatic deflate decompression for PC format

## Installation

### From Source

```bash
git clone https://github.com/coconutbird/xmb-rs.git
cd xmb-rs
cargo build --release
```

The binary will be at `target/release/xmb.exe` (Windows).

## Usage

### Drag and Drop

Just drag files onto the executable - it auto-detects the conversion direction:

- `.xml` files → `.xml.xmb` (PC format by default)
- `.xmb` files → `.xmb.xml`

```bash
# Convert files (works with multiple files)
xmb file1.xml file2.xmb file3.xml

# Use Xbox 360 format for XML → XMB
xmb -f xbox360 file.xml

# Overwrite existing files instead of adding _1, _2, etc.
xmb -w file.xml
```

### Commands

```bash
# Convert XMB to XML
xmb to-xml -i input.xmb -o output.xml

# Convert XML to XMB (PC format)
xmb to-xmb -i input.xml -o output.xmb

# Convert XML to XMB (Xbox 360 format)
xmb to-xmb -i input.xml -o output.xmb -f xbox360

# Show file info
xmb info -i input.xmb
```

## Library Usage

Add to your `Cargo.toml`:

```toml
[dependencies]
xmb = { git = "https://github.com/coconutbird/xmb-rs.git" }
```

```rust
use xmb::{XmbReader, XmbWriter, XmbData, XmbFormat};

// Read XMB file
let xmb = XmbReader::read_file("input.xmb")?;

// Convert to XML
let xml = xmb.to_xml();

// Parse XML
let xmb = XmbData::from_xml(&xml)?;

// Write XMB with explicit format
XmbWriter::write(&xmb, output_file, XmbFormat::PC)?;      // PC/HWDE
XmbWriter::write(&xmb, output_file, XmbFormat::Xbox360)?; // Xbox 360

// Or preserve the format it was read from
XmbWriter::write_native(&xmb, output_file)?;
```

## License

MIT License - see [LICENSE](LICENSE) for details.

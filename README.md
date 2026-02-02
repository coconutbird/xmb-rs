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

### Convert XMB to XML

```bash
xmb to-xml -i input.xmb -o output.xml
```

### Convert XML to XMB

```bash
# PC format (default)
xmb to-xmb -i input.xml -o output.xmb

# Xbox 360 format
xmb to-xmb -i input.xml -o output.xmb -f xbox360
```

### Show File Info

```bash
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

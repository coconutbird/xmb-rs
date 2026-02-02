//! XMB CLI - Convert between XMB and XML formats.

use clap::{Parser, Subcommand, ValueEnum};
use std::fs::File;
use std::io::{BufReader, BufWriter};
use std::path::PathBuf;
use xmb::{XmbData, XmbFormat, XmbReader, XmbWriter};

#[derive(Parser)]
#[command(name = "xmb")]
#[command(author, version, about = "XMB binary XML format converter for Halo Wars", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Convert XMB to XML
    ToXml {
        /// Input XMB file
        #[arg(short, long)]
        input: PathBuf,

        /// Output XML file (defaults to input with .xml extension)
        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    /// Convert XML to XMB
    ToXmb {
        /// Input XML file
        #[arg(short, long)]
        input: PathBuf,

        /// Output XMB file (defaults to input with .xmb extension)
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Output format
        #[arg(short, long, value_enum, default_value = "pc")]
        format: FormatArg,
    },

    /// Show information about an XMB file
    Info {
        /// Input XMB file
        #[arg(short, long)]
        input: PathBuf,
    },
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, ValueEnum)]
enum FormatArg {
    /// PC/HWDE format (little-endian, 48-byte nodes)
    Pc,
    /// Xbox 360 format (big-endian, 20-byte nodes)
    Xbox360,
}

impl From<FormatArg> for XmbFormat {
    fn from(arg: FormatArg) -> Self {
        match arg {
            FormatArg::Pc => XmbFormat::PC,
            FormatArg::Xbox360 => XmbFormat::Xbox360,
        }
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match cli.command {
        Commands::ToXml { input, output } => {
            let output = output.unwrap_or_else(|| {
                let mut p = input.clone();
                p.set_extension("xml");
                p
            });

            println!("Converting {} -> {}", input.display(), output.display());

            let file = File::open(&input)?;
            let reader = BufReader::new(file);
            let xmb = XmbReader::read(reader)?;

            let xml = xmb.to_xml();
            std::fs::write(&output, xml)?;

            println!("Done!");
        }

        Commands::ToXmb {
            input,
            output,
            format,
        } => {
            let output = output.unwrap_or_else(|| {
                let mut p = input.clone();
                p.set_extension("xmb");
                p
            });

            println!(
                "Converting {} -> {} ({:?} format)",
                input.display(),
                output.display(),
                format
            );

            let xml = std::fs::read_to_string(&input)?;
            let xmb = XmbData::from_xml(&xml)?;

            let file = File::create(&output)?;
            let writer = BufWriter::new(file);
            XmbWriter::write(&xmb, writer, format.into())?;

            println!("Done!");
        }

        Commands::Info { input } => {
            let file = File::open(&input)?;
            let reader = BufReader::new(file);
            let xmb = XmbReader::read(reader)?;

            println!("File: {}", input.display());
            println!("Format: {:?}", xmb.format());

            if let Some(root) = xmb.root() {
                println!("Root element: <{}>", root.name);
                println!("Attributes: {}", root.attributes.len());
                println!("Children: {}", root.children.len());

                fn count_nodes(node: &xmb::Node) -> usize {
                    1 + node.children.iter().map(count_nodes).sum::<usize>()
                }
                println!("Total nodes: {}", count_nodes(root));
            } else {
                println!("(empty document)");
            }
        }
    }

    Ok(())
}

//! ECF (Ensemble Common Format) container handling.
//!
//! ECF is a container format used by Ensemble Studios to wrap various
//! file types including XMB. The format uses big-endian byte order.
//!
//! ## ECF Structure
//!
//! An ECF file consists of:
//! - ECF Header (32 bytes)
//! - Chunk Headers (24 bytes each + optional extra data)
//! - Chunk Data (optionally compressed)
//!
//! ## Compression
//!
//! Chunks can be compressed using BDeflateStream format, which wraps
//! standard deflate compression with checksums and metadata.

use byteorder::{BigEndian, LittleEndian, ReadBytesExt, WriteBytesExt};
use flate2::Compression;
use flate2::read::DeflateDecoder;
use flate2::write::DeflateEncoder;
use std::io::{Cursor, Read, Seek, SeekFrom, Write};

use crate::error::{Error, Result};

// ============================================================================
// ECF Chunk Resource Flags
// ============================================================================

/// ECF chunk resource flags.
///
/// These flags are stored in the `resource_flags` field of `EcfChunkHeader`.
/// Based on the original Halo Wars source code enum `eECFChunkResourceFlags`.
///
/// In practice, only `IS_DEFLATE_STREAM` is commonly used in XMB files.
/// The other flags relate to memory allocation hints for the game engine.
pub mod chunk_resource_flags {
    /// Bit 0: Memory is contiguous.
    ///
    /// Hint that the resource should be allocated in contiguous memory.
    pub const CONTIGUOUS: u16 = 1 << 0;

    /// Bit 1: Memory is write-combined.
    ///
    /// GPU optimization hint for write-combined memory allocation.
    pub const WRITE_COMBINED: u16 = 1 << 1;

    /// Bit 2: Chunk data is compressed using BDeflateStream format.
    ///
    /// When set, the chunk data is wrapped in a BDeflateStream container
    /// with checksums and metadata. The reader will automatically decompress.
    pub const IS_DEFLATE_STREAM: u16 = 1 << 2;

    /// Bit 3: Chunk contains a resource tag.
    ///
    /// Indicates the chunk data includes resource tagging information.
    pub const IS_RESOURCE_TAG: u16 = 1 << 3;
}

/// ECF resource flag indicating the chunk data is deflate compressed.
/// Use `chunk_resource_flags::IS_DEFLATE_STREAM` for the public constant.
const ECF_CHUNK_RES_FLAG_IS_DEFLATE_STREAM: u16 = chunk_resource_flags::IS_DEFLATE_STREAM;

// ============================================================================
// BDeflateStream Constants
// ============================================================================

/// BDeflateStream constants and types.
///
/// BDeflateStream is EA's custom compression wrapper format that adds
/// checksums and metadata around standard deflate compression.
pub mod deflate_stream {
    /// BDeflateStream signature for little-endian format (PC).
    ///
    /// When read as little-endian u32, this is 0xCC34EEAD.
    pub const SIGNATURE: u32 = 0xCC34EEAD;

    /// BDeflateStream inverted signature for big-endian format (Xbox 360).
    ///
    /// When the signature bytes are written as big-endian (0xCC, 0x34, 0xEE, 0xAD),
    /// reading them as little-endian u32 yields 0xADEE34CC.
    pub const SIGNATURE_INVERTED: u32 = 0xADEE34CC;

    /// BDeflateStream header size in bytes.
    ///
    /// The header contains:
    /// - 4 bytes: signature
    /// - 4 bytes: header_adler32 (checksum of bytes 8-36)
    /// - 8 bytes: src_bytes (uncompressed size)
    /// - 4 bytes: src_adler32 (uncompressed data checksum)
    /// - 8 bytes: dst_bytes (compressed size)
    /// - 4 bytes: dst_adler32 (compressed data checksum)
    /// - 4 bytes: header_type
    pub const HEADER_SIZE: usize = 36;

    /// BDeflateStream end magic value.
    ///
    /// Written after the compressed data as a terminator.
    pub const END_MAGIC: u32 = 0xA5D91776;

    /// BDeflateStream header type values.
    ///
    /// The header_type field indicates how the stream was compressed.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    #[repr(u32)]
    pub enum HeaderType {
        /// Size is known upfront (standard compression).
        SizeKnown = 0,
        /// Streaming mode where size was not known during compression.
        Streaming = 1,
    }

    impl HeaderType {
        /// Parse a header type from a raw u32 value.
        pub fn from_u32(value: u32) -> Option<Self> {
            match value {
                0 => Some(HeaderType::SizeKnown),
                1 => Some(HeaderType::Streaming),
                _ => None,
            }
        }
    }
}

// Internal aliases for backward compatibility
const DEFLATE_STREAM_SIG: u32 = deflate_stream::SIGNATURE;
const DEFLATE_STREAM_INVERTED_SIG: u32 = deflate_stream::SIGNATURE_INVERTED;
const DEFLATE_STREAM_HEADER_SIZE: usize = deflate_stream::HEADER_SIZE;
const DEFLATE_STREAM_END_MAGIC: u32 = deflate_stream::END_MAGIC;

// ============================================================================
// ECF Constants
// ============================================================================

/// ECF header magic number.
pub const ECF_HEADER_MAGIC: u32 = 0xDABA7737;
/// ECF inverted header magic (for little-endian detection, currently unused).
pub const ECF_INVERTED_HEADER_MAGIC: u32 = 0x3777BADA;

/// XMB ECF file ID.
pub const XMB_ECF_FILE_ID: u32 = 0xE43ABC00;
/// XMX Packed Data chunk ID.
pub const XMX_PACKED_DATA_CHUNK_ID: u64 = 0xA9C96500;
/// XMX File Info chunk ID.
pub const XMX_FILE_INFO_CHUNK_ID: u64 = 0xA9C96501;

/// ECF file header.
#[derive(Debug, Clone, Default)]
pub struct EcfHeader {
    /// Header magic number (should be ECF_HEADER_MAGIC).
    pub magic: u32,
    /// Total header size including extra data.
    pub header_size: u32,
    /// Adler-32 checksum.
    pub adler32: u32,
    /// Total file size including header.
    pub file_size: u32,
    /// Number of chunks in the file.
    pub num_chunks: u16,
    /// Header flags.
    pub flags: u16,
    /// User-provided file ID.
    pub id: u32,
    /// Size of extra data per chunk header.
    pub chunk_extra_data_size: u16,
}

impl EcfHeader {
    /// The size of the ECF header in bytes (including padding).
    pub const SIZE: usize = 32;

    /// Read an ECF header from a reader.
    pub fn read<R: Read>(reader: &mut R) -> Result<Self> {
        let magic = reader.read_u32::<BigEndian>()?;
        if magic != ECF_HEADER_MAGIC && magic != ECF_INVERTED_HEADER_MAGIC {
            return Err(Error::InvalidEcfMagic {
                expected: ECF_HEADER_MAGIC,
                actual: magic,
            });
        }

        let header = Self {
            magic,
            header_size: reader.read_u32::<BigEndian>()?,
            adler32: reader.read_u32::<BigEndian>()?,
            file_size: reader.read_u32::<BigEndian>()?,
            num_chunks: reader.read_u16::<BigEndian>()?,
            flags: reader.read_u16::<BigEndian>()?,
            id: reader.read_u32::<BigEndian>()?,
            chunk_extra_data_size: reader.read_u16::<BigEndian>()?,
        };
        // Read padding bytes
        let _pad0 = reader.read_u16::<BigEndian>()?;
        let _pad1 = reader.read_u32::<BigEndian>()?;
        Ok(header)
    }

    /// Write an ECF header to a writer.
    pub fn write<W: Write>(&self, writer: &mut W) -> Result<()> {
        writer.write_u32::<BigEndian>(self.magic)?;
        writer.write_u32::<BigEndian>(self.header_size)?;
        writer.write_u32::<BigEndian>(self.adler32)?;
        writer.write_u32::<BigEndian>(self.file_size)?;
        writer.write_u16::<BigEndian>(self.num_chunks)?;
        writer.write_u16::<BigEndian>(self.flags)?;
        writer.write_u32::<BigEndian>(self.id)?;
        writer.write_u16::<BigEndian>(self.chunk_extra_data_size)?;
        writer.write_u16::<BigEndian>(0)?; // pad0
        writer.write_u32::<BigEndian>(0)?; // pad1
        Ok(())
    }
}

/// ECF chunk header.
#[derive(Debug, Clone, Default)]
pub struct EcfChunkHeader {
    /// Chunk ID.
    pub id: u64,
    /// Offset to chunk data from start of file.
    pub offset: u32,
    /// Size of chunk data.
    pub size: u32,
    /// Adler-32 checksum of chunk data.
    pub adler32: u32,
    /// Chunk flags.
    pub flags: u8,
    /// Alignment as log2 (e.g., 2 = 4-byte alignment).
    pub alignment_log2: u8,
    /// Resource flags.
    pub resource_flags: u16,
}

impl EcfChunkHeader {
    /// The size of the ECF chunk header in bytes (without extra data).
    pub const SIZE: usize = 24;

    /// Read a chunk header from a reader.
    pub fn read<R: Read>(reader: &mut R) -> Result<Self> {
        Ok(Self {
            id: reader.read_u64::<BigEndian>()?,
            offset: reader.read_u32::<BigEndian>()?,
            size: reader.read_u32::<BigEndian>()?,
            adler32: reader.read_u32::<BigEndian>()?,
            flags: reader.read_u8()?,
            alignment_log2: reader.read_u8()?,
            resource_flags: reader.read_u16::<BigEndian>()?,
        })
    }

    /// Write a chunk header to a writer.
    pub fn write<W: Write>(&self, writer: &mut W) -> Result<()> {
        writer.write_u64::<BigEndian>(self.id)?;
        writer.write_u32::<BigEndian>(self.offset)?;
        writer.write_u32::<BigEndian>(self.size)?;
        writer.write_u32::<BigEndian>(self.adler32)?;
        writer.write_u8(self.flags)?;
        writer.write_u8(self.alignment_log2)?;
        writer.write_u16::<BigEndian>(self.resource_flags)?;
        Ok(())
    }

    /// Get the alignment in bytes.
    pub fn alignment(&self) -> usize {
        1 << self.alignment_log2
    }
}

/// ECF file reader.
pub struct EcfReader<R: Read + Seek> {
    reader: R,
    header: EcfHeader,
    chunks: Vec<EcfChunkHeader>,
}

impl<R: Read + Seek> EcfReader<R> {
    /// Create a new ECF reader from a Read + Seek source.
    pub fn new(mut reader: R) -> Result<Self> {
        let header = EcfHeader::read(&mut reader)?;

        // Skip extra header data
        let extra_size = header.header_size as usize - EcfHeader::SIZE;
        if extra_size > 0 {
            reader.seek(SeekFrom::Current(extra_size as i64))?;
        }

        // Read chunk headers
        let _chunk_header_size = EcfChunkHeader::SIZE + header.chunk_extra_data_size as usize;
        let mut chunks = Vec::with_capacity(header.num_chunks as usize);
        for _ in 0..header.num_chunks {
            let chunk = EcfChunkHeader::read(&mut reader)?;
            // Skip extra chunk data
            if header.chunk_extra_data_size > 0 {
                reader.seek(SeekFrom::Current(header.chunk_extra_data_size as i64))?;
            }
            chunks.push(chunk);
        }

        Ok(Self {
            reader,
            header,
            chunks,
        })
    }

    /// Get the ECF header.
    pub fn header(&self) -> &EcfHeader {
        &self.header
    }

    /// Get the chunk headers.
    pub fn chunks(&self) -> &[EcfChunkHeader] {
        &self.chunks
    }

    /// Find a chunk by ID.
    pub fn find_chunk(&self, id: u64) -> Option<&EcfChunkHeader> {
        self.chunks.iter().find(|c| c.id == id)
    }

    /// Read chunk data by index.
    ///
    /// If the chunk is compressed (deflate stream flag set), the data will be
    /// automatically decompressed before being returned.
    pub fn read_chunk_data(&mut self, index: usize) -> Result<Vec<u8>> {
        if index >= self.chunks.len() {
            return Err(Error::ChunkNotFound(index as u64));
        }
        let chunk = &self.chunks[index];
        self.reader.seek(SeekFrom::Start(chunk.offset as u64))?;
        let mut data = vec![0u8; chunk.size as usize];
        self.reader.read_exact(&mut data)?;

        // Check if the chunk data is deflate compressed
        if (chunk.resource_flags & ECF_CHUNK_RES_FLAG_IS_DEFLATE_STREAM) != 0 {
            // BDeflateStream format (36-byte header + compressed data + 4-byte end magic):
            // Header (little-endian on x86):
            //   - 4 bytes: mSig (signature 0xCC34EEAD)
            //   - 4 bytes: mHeaderAdler32 (checksum of header data)
            //   - 8 bytes: mSrcBytes (uncompressed size)
            //   - 4 bytes: mSrcAdler32 (uncompressed data checksum)
            //   - 8 bytes: mDstBytes (compressed size)
            //   - 4 bytes: mDstAdler32 (compressed data checksum)
            //   - 4 bytes: mHeaderType
            // Followed by:
            //   - mDstBytes of raw deflate compressed data
            //   - 4 bytes: end magic (0xA5D91776)
            if data.len() < DEFLATE_STREAM_HEADER_SIZE {
                return Err(Error::UnexpectedEof);
            }

            let mut cursor = Cursor::new(&data);

            // Read signature to determine endianness
            let sig = cursor.read_u32::<LittleEndian>()?;
            let is_big_endian = sig == DEFLATE_STREAM_INVERTED_SIG;

            if sig != DEFLATE_STREAM_SIG && sig != DEFLATE_STREAM_INVERTED_SIG {
                return Err(Error::InvalidDeflateStreamSignature(sig));
            }

            // Read header fields based on detected endianness
            let (src_bytes, dst_bytes) = if is_big_endian {
                let _header_adler32 = cursor.read_u32::<BigEndian>()?;
                let src_bytes = cursor.read_u64::<BigEndian>()? as usize;
                let _src_adler32 = cursor.read_u32::<BigEndian>()?;
                let dst_bytes = cursor.read_u64::<BigEndian>()? as usize;
                let _dst_adler32 = cursor.read_u32::<BigEndian>()?;
                let _header_type = cursor.read_u32::<BigEndian>()?;
                (src_bytes, dst_bytes)
            } else {
                let _header_adler32 = cursor.read_u32::<LittleEndian>()?;
                let src_bytes = cursor.read_u64::<LittleEndian>()? as usize;
                let _src_adler32 = cursor.read_u32::<LittleEndian>()?;
                let dst_bytes = cursor.read_u64::<LittleEndian>()? as usize;
                let _dst_adler32 = cursor.read_u32::<LittleEndian>()?;
                let _header_type = cursor.read_u32::<LittleEndian>()?;
                (src_bytes, dst_bytes)
            };

            // Verify we have enough data for the compressed stream
            if data.len() < DEFLATE_STREAM_HEADER_SIZE + dst_bytes {
                return Err(Error::UnexpectedEof);
            }

            let compressed_data =
                &data[DEFLATE_STREAM_HEADER_SIZE..DEFLATE_STREAM_HEADER_SIZE + dst_bytes];

            let mut decoder = DeflateDecoder::new(compressed_data);
            let mut decompressed = Vec::with_capacity(src_bytes);
            decoder.read_to_end(&mut decompressed)?;

            Ok(decompressed)
        } else {
            Ok(data)
        }
    }

    /// Read chunk data by ID.
    pub fn read_chunk_data_by_id(&mut self, id: u64) -> Result<Vec<u8>> {
        let index = self
            .chunks
            .iter()
            .position(|c| c.id == id)
            .ok_or(Error::ChunkNotFound(id))?;
        self.read_chunk_data(index)
    }
}

/// ECF file writer.
pub struct EcfWriter<W: Write + Seek> {
    writer: W,
    header: EcfHeader,
    chunks: Vec<(EcfChunkHeader, Vec<u8>)>,
}

impl<W: Write + Seek> EcfWriter<W> {
    /// Create a new ECF writer.
    pub fn new(writer: W, file_id: u32) -> Self {
        Self {
            writer,
            header: EcfHeader {
                magic: ECF_HEADER_MAGIC,
                header_size: EcfHeader::SIZE as u32,
                adler32: 0,
                file_size: 0,
                num_chunks: 0,
                flags: 0,
                id: file_id,
                chunk_extra_data_size: 0,
            },
            chunks: Vec::new(),
        }
    }

    /// Add a chunk to the ECF file.
    pub fn add_chunk(&mut self, id: u64, data: Vec<u8>) {
        let chunk = EcfChunkHeader {
            id,
            offset: 0, // Will be calculated on finalize
            size: data.len() as u32,
            adler32: adler32(&data),
            flags: 0,
            alignment_log2: 2, // 4-byte alignment
            resource_flags: 0,
        };
        self.chunks.push((chunk, data));
    }

    /// Add a compressed chunk to the ECF file using BDeflateStream format (little-endian, for PC).
    pub fn add_chunk_compressed(&mut self, id: u64, data: Vec<u8>) -> Result<()> {
        self.add_chunk_compressed_with_endian(id, data, false)
    }

    /// Add a compressed chunk to the ECF file using BDeflateStream format (big-endian, for Xbox 360).
    pub fn add_chunk_compressed_be(&mut self, id: u64, data: Vec<u8>) -> Result<()> {
        self.add_chunk_compressed_with_endian(id, data, true)
    }

    /// Add a compressed chunk to the ECF file using BDeflateStream format with specified endianness.
    ///
    /// # Arguments
    /// * `id` - Chunk ID
    /// * `data` - Uncompressed data to compress
    /// * `big_endian` - If true, use big-endian format (Xbox 360); if false, use little-endian (PC)
    pub fn add_chunk_compressed_with_endian(
        &mut self,
        id: u64,
        data: Vec<u8>,
        big_endian: bool,
    ) -> Result<()> {
        use std::io::Write;

        let src_bytes = data.len() as u64;
        let src_adler32 = adler32(&data);

        // Compress the data using deflate
        let mut encoder = DeflateEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&data)?;
        let compressed_data = encoder.finish()?;
        let dst_bytes = compressed_data.len() as u64;
        let dst_adler32 = adler32(&compressed_data);

        // Build BDeflateStream wrapper:
        // Header (36 bytes):
        //   - sig: u32 (0xCC34EEAD for native endian, appears as 0xADEE34CC when read as opposite endian)
        //   - header_adler32: u32 (checksum of header bytes 8-36)
        //   - src_bytes: u64 (uncompressed size)
        //   - src_adler32: u32 (uncompressed data checksum)
        //   - dst_bytes: u64 (compressed size)
        //   - dst_adler32: u32 (compressed data checksum)
        //   - header_type: u32 (0 = size known, 1 = streaming)
        // Followed by:
        //   - dst_bytes of raw deflate compressed data
        //   - end magic: u32 (0xA5D91776)

        // Build header bytes 8-36 first to compute header_adler32
        let mut header_data = Vec::with_capacity(28);
        if big_endian {
            header_data.extend_from_slice(&src_bytes.to_be_bytes());
            header_data.extend_from_slice(&src_adler32.to_be_bytes());
            header_data.extend_from_slice(&dst_bytes.to_be_bytes());
            header_data.extend_from_slice(&dst_adler32.to_be_bytes());
            header_data.extend_from_slice(&0u32.to_be_bytes()); // header_type
        } else {
            header_data.extend_from_slice(&src_bytes.to_le_bytes());
            header_data.extend_from_slice(&src_adler32.to_le_bytes());
            header_data.extend_from_slice(&dst_bytes.to_le_bytes());
            header_data.extend_from_slice(&dst_adler32.to_le_bytes());
            header_data.extend_from_slice(&0u32.to_le_bytes()); // header_type
        }
        let header_adler32 = adler32(&header_data);

        let total_size = DEFLATE_STREAM_HEADER_SIZE + compressed_data.len() + 4; // header + data + end magic

        let mut wrapped_data = Vec::with_capacity(total_size);
        if big_endian {
            // For big-endian: signature bytes are written so that when read as LE u32,
            // it appears as DEFLATE_STREAM_INVERTED_SIG (0xADEE34CC)
            wrapped_data.extend_from_slice(&DEFLATE_STREAM_SIG.to_be_bytes());
            wrapped_data.extend_from_slice(&header_adler32.to_be_bytes());
        } else {
            wrapped_data.extend_from_slice(&DEFLATE_STREAM_SIG.to_le_bytes());
            wrapped_data.extend_from_slice(&header_adler32.to_le_bytes());
        }
        wrapped_data.extend_from_slice(&header_data);
        wrapped_data.extend_from_slice(&compressed_data);
        if big_endian {
            wrapped_data.extend_from_slice(&DEFLATE_STREAM_END_MAGIC.to_be_bytes());
        } else {
            wrapped_data.extend_from_slice(&DEFLATE_STREAM_END_MAGIC.to_le_bytes());
        }

        let chunk = EcfChunkHeader {
            id,
            offset: 0, // Will be calculated on finalize
            size: wrapped_data.len() as u32,
            adler32: adler32(&wrapped_data),
            flags: 0,
            alignment_log2: 2, // 4-byte alignment
            resource_flags: ECF_CHUNK_RES_FLAG_IS_DEFLATE_STREAM,
        };
        self.chunks.push((chunk, wrapped_data));
        Ok(())
    }

    /// Finalize and write the ECF file.
    pub fn finalize(mut self) -> Result<()> {
        let num_chunks = self.chunks.len() as u16;
        self.header.num_chunks = num_chunks;

        // Calculate data offset (after header and chunk headers)
        let headers_size = EcfHeader::SIZE + (EcfChunkHeader::SIZE * self.chunks.len());
        let mut data_offset = align_up(headers_size, 4);

        // Update chunk offsets
        for (chunk, data) in &mut self.chunks {
            chunk.offset = data_offset as u32;
            data_offset = align_up(data_offset + data.len(), chunk.alignment());
        }

        self.header.file_size = data_offset as u32;
        self.header.adler32 = 0; // TODO: Calculate proper checksum

        // Write header
        self.header.write(&mut self.writer)?;

        // Write chunk headers
        for (chunk, _) in &self.chunks {
            chunk.write(&mut self.writer)?;
        }

        // Write chunk data with alignment padding
        for (chunk, data) in &self.chunks {
            let current_pos = self.writer.stream_position()? as usize;
            let padding = chunk.offset as usize - current_pos;
            if padding > 0 {
                self.writer.write_all(&vec![0u8; padding])?;
            }
            self.writer.write_all(&data)?;
        }

        Ok(())
    }
}

/// Compute Adler-32 checksum.
pub fn adler32(data: &[u8]) -> u32 {
    const MOD_ADLER: u32 = 65521;
    let mut a: u32 = 1;
    let mut b: u32 = 0;
    for byte in data {
        a = (a + *byte as u32) % MOD_ADLER;
        b = (b + a) % MOD_ADLER;
    }
    (b << 16) | a
}

/// Align a value up to the given alignment.
fn align_up(value: usize, alignment: usize) -> usize {
    (value + alignment - 1) & !(alignment - 1)
}

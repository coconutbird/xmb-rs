//! ECF (Ensemble Common Format) container handling.
//!
//! ECF is a container format used by Ensemble Studios to wrap various
//! file types including XMB. The format uses big-endian byte order.

use byteorder::{BigEndian, LittleEndian, ReadBytesExt, WriteBytesExt};
use flate2::read::DeflateDecoder;
use std::io::{Cursor, Read, Seek, SeekFrom, Write};

use crate::error::{Error, Result};

/// ECF resource flag indicating the chunk data is deflate compressed.
const ECF_CHUNK_RES_FLAG_IS_DEFLATE_STREAM: u16 = 1 << 2;

/// BDeflateStream signature (little-endian).
const DEFLATE_STREAM_SIG: u32 = 0xCC34EEAD;

/// BDeflateStream inverted signature (big-endian / byte-swapped).
const DEFLATE_STREAM_INVERTED_SIG: u32 = 0xADEE34CC;

/// BDeflateStream header size in bytes.
const DEFLATE_STREAM_HEADER_SIZE: usize = 36;

/// ECF header magic number.
pub const ECF_HEADER_MAGIC: u32 = 0xDABA7737;
/// ECF inverted header magic (for little-endian detection).
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

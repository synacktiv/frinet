use std::{fmt, fs::File, io, ops::Deref, path::Path};

use frinet_db::{
    db::{ModuleInfo, RegisterInfo},
    format::{Addr, Time},
    module_timeline::{MAX_MODULES, normalize_module_order},
    scalar::{Scalar, ScalarSize},
};
use log::warn;
use memmap2::{Mmap, MmapOptions};

use crate::parser::{
    MemoryMode, Parser, ParserGenerator, ProgressReporter, RawEvent, TimedRawEvent, TraceHeader,
};

const MAGIC_LINE: &str = "FRINET-TRACE 1";

const TAG_STEP: u8 = 0x00;
const TAG_MEM_READ: u8 = 0x01;
const TAG_MEM_WRITE: u8 = 0x02;
const TAG_MEM_READ_WRITE: u8 = 0x03;
const TAG_REG_BASE: u8 = 0x10;

const MAX_REGISTERS: usize = (u8::MAX - TAG_REG_BASE) as usize + 1;
const MAX_REGISTER_BYTE_SIZE: usize = ScalarSize::MAX_BYTE_SIZE;
const MAX_LINE_LEN: usize = 64 * 1024;

macro_rules! bail {
    ($($arg:tt)*) => {
        return Err(TraceParseError::Invalid(format!($($arg)*)))
    };
}

pub struct TraceFile {
    file: File,
}

impl TraceFile {
    pub fn open(path: impl AsRef<Path>) -> io::Result<Self> {
        let file = File::open(path)?;
        Ok(Self { file })
    }
}

impl ParserGenerator for TraceFile {
    type Parser = TraceFileParser;

    fn generate(&mut self) -> Result<Self::Parser, TraceParseError> {
        let mut mmap_options = MmapOptions::default();
        mmap_options.populate();

        // SAFETY: the trace must not be modified while it is indexed
        let mmap = unsafe { mmap_options.map(&self.file) }?;

        TraceParser::new(mmap)
    }
}

pub type TraceFileParser = TraceParser<Mmap>;

/// Parser of a trace held in memory, a mapped file or a plain slice
pub struct TraceParser<Data> {
    header: TraceHeader,
    data: Data,
    stream_offset: usize,
}

impl<Data: Deref<Target = [u8]>> TraceParser<Data> {
    /// Parses the header, the events are parsed by [Parser::parse]
    pub fn new(data: Data) -> Result<Self, TraceParseError> {
        let (header, stream_offset) = parse_header(&data)?;
        Ok(Self {
            header,
            data,
            stream_offset,
        })
    }
}

impl<Data: Deref<Target = [u8]>> Parser for TraceParser<Data> {
    type Err = TraceParseError;

    fn header(&self) -> &TraceHeader {
        &self.header
    }

    fn parse<'trace, EmitFn>(
        &'trace self,
        progress: &mut dyn ProgressReporter,
        mut emit: EmitFn,
    ) -> Result<(), Self::Err>
    where
        EmitFn: FnMut(RawEvent<'trace>),
    {
        let mut stream = &self.data[self.stream_offset..];
        let stream_len = stream.len();

        progress.total(stream_len);

        let mut time: Time = 0;

        while let Some((&tag, rest)) = stream.split_first() {
            let pos = stream_len - stream.len();
            let offset = self.stream_offset + pos;
            stream = rest;

            let event = match tag {
                TAG_STEP => {
                    time += 1;
                    if time.is_multiple_of(1024) {
                        if progress.is_cancelled() {
                            return Ok(());
                        }
                        progress.current(pos);
                    }
                    continue;
                }
                TAG_MEM_READ | TAG_MEM_WRITE | TAG_MEM_READ_WRITE => {
                    let Some(prefix) = take(&mut stream, 10, offset) else {
                        break;
                    };

                    let (addr_bytes, len_bytes) = prefix.split_at(8);
                    let addr = u64::from_le_bytes(addr_bytes.try_into().unwrap());
                    let len = u16::from_le_bytes(len_bytes.try_into().unwrap()) as usize;

                    if len == 0 {
                        bail!(
                            "invalid trace event at offset {offset:#x}: memory access of length 0"
                        );
                    }

                    let Some(bytes) = take(&mut stream, len, offset) else {
                        break;
                    };

                    let mode = match tag {
                        TAG_MEM_READ => MemoryMode::Read,
                        TAG_MEM_WRITE => MemoryMode::Write,
                        _ => MemoryMode::ReadWrite,
                    };

                    TimedRawEvent::Memory { addr, bytes, mode }
                }
                TAG_REG_BASE.. => {
                    let idx = (tag - TAG_REG_BASE) as usize;

                    let Some(register) = self.header.registers.get(idx) else {
                        bail!(
                            "invalid trace event at offset {offset:#x}: tag {tag:#04x} is \
                             register {idx}, the header declares {}",
                            self.header.registers.len()
                        );
                    };

                    let Some(bytes) = take(&mut stream, register.scalar_size.bytes(), offset)
                    else {
                        break;
                    };

                    TimedRawEvent::Register {
                        idx,
                        bytes: Scalar(bytes),
                    }
                }
                _ => bail!("invalid trace event at offset {offset:#x}: reserved tag {tag:#04x}"),
            };

            emit(RawEvent { time, event });
        }

        progress.current(stream_len);

        Ok(())
    }
}

/// Next `len` bytes of the stream, [None] if the trace is truncated
fn take<'trace>(stream: &mut &'trace [u8], len: usize, offset: usize) -> Option<&'trace [u8]> {
    let Some((bytes, rest)) = stream.split_at_checked(len) else {
        warn!("trace truncated: incomplete event at offset {offset:#x}, ignoring the end");
        return None;
    };
    *stream = rest;
    Some(bytes)
}

/// Parse the ASCII header, returns it with the offset of the binary stream
fn parse_header(bytes: &[u8]) -> Result<(TraceHeader, usize), TraceParseError> {
    let mut rest = bytes;
    let mut header = TraceHeader::default();
    let mut line_no = 0;

    loop {
        line_no += 1;

        // limit the window in which we scan for line ending to prevent
        // failing badly on bad inputs
        let window_size = rest.len().min(MAX_LINE_LEN + 1);
        let window = &rest[..window_size];

        let Some(line_len) = window.iter().position(|&byte| byte == b'\n') else {
            bail!("invalid trace header: line {line_no}: did not find line ending ('\\n')");
        };

        let line = &rest[..line_len];
        rest = &rest[line_len + 1..];

        if line_no == 1 {
            if line == MAGIC_LINE.as_bytes() {
                continue;
            }
            bail!("invalid trace header: not a '{MAGIC_LINE}' trace");
        }

        let Ok(line) = str::from_utf8(line) else {
            bail!("invalid trace header: line {line_no}: not valid UTF-8");
        };

        let mut words = line.split(' ');
        let keyword = words.next().unwrap_or_default();
        let args: Vec<&str> = words.collect();

        match keyword {
            "reg" => {
                let Some(reg) = parse_register(&args) else {
                    bail!(
                        "invalid trace header: line {line_no}: register must be \
                         'reg <name> <byte_size>', byte_size a power of two \
                         <= {MAX_REGISTER_BYTE_SIZE}"
                    );
                };
                if header.registers.iter().any(|it| it.name == reg.name) {
                    bail!(
                        "invalid trace header: line {line_no}: duplicate register '{}'",
                        reg.name
                    );
                }
                header.registers.push(reg);
            }
            "module" => {
                let Some(module) = parse_module(&args) else {
                    bail!(
                        "invalid trace header: line {line_no}: module must be \
                         'module <name> 0x<start> 0x<end>', start <= end"
                    );
                };
                header.modules.push(module);
            }
            "end" => {
                if !args.is_empty() {
                    bail!("invalid trace header: line {line_no}: malformed");
                }
                break;
            }
            _ => warn!("unknown trace header line {line_no}: '{line}'"),
        }
    }

    if header.registers.is_empty() {
        bail!("invalid trace header: no register (the first one must be the PC)");
    }
    if header.registers.len() > MAX_REGISTERS {
        bail!("invalid trace header: more than {MAX_REGISTERS} registers");
    }
    if header.modules.len() > MAX_MODULES {
        bail!("invalid trace header: more than {MAX_MODULES} modules");
    }

    normalize_module_order(&mut header.modules);

    Ok((header, bytes.len() - rest.len()))
}

/// `reg <name> <byte_size>` arguments
fn parse_register(args: &[&str]) -> Option<RegisterInfo> {
    let &[name, byte_size] = args else {
        return None;
    };

    if name.is_empty() {
        return None;
    }

    let scalar_size = match byte_size {
        "1" => ScalarSize::U8,
        "2" => ScalarSize::U16,
        "4" => ScalarSize::U32,
        "8" => ScalarSize::U64,
        "16" => ScalarSize::U128,
        "32" => ScalarSize::U256,
        "64" => ScalarSize::U512,
        _ => return None,
    };

    Some(RegisterInfo {
        name: name.into(),
        scalar_size,
    })
}

/// `module <name> 0x<start> 0x<end>` arguments
fn parse_module(args: &[&str]) -> Option<ModuleInfo> {
    let &[name, start, end] = args else {
        return None;
    };
    let start = parse_addr_hex(start)?;
    let end = parse_addr_hex(end)?;

    if name.is_empty() || start > end {
        return None;
    }

    Some(ModuleInfo {
        name: name.into(),
        start,
        end,
    })
}

fn parse_addr_hex(word: &str) -> Option<Addr> {
    let digits = word.strip_prefix("0x")?;
    u64::from_str_radix(digits, 16).ok()
}

#[derive(Debug)]
pub enum TraceParseError {
    Io(io::Error),
    Invalid(String),
}

impl fmt::Display for TraceParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(err) => write!(f, "{err}"),
            Self::Invalid(what) => write!(f, "{what}"),
        }
    }
}

impl std::error::Error for TraceParseError {}

impl From<io::Error> for TraceParseError {
    fn from(err: io::Error) -> Self {
        Self::Io(err)
    }
}

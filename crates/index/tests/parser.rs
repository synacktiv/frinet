use frinet_db::{
    db::{ModuleInfo, RegisterInfo},
    format::{Addr, Time},
    scalar::ScalarSize,
};
use frinet_index::parser::{MemoryMode, Parser, TimedRawEvent, TraceHeader, TraceParser};

#[test]
fn parse_minimal_header() {
    let header = parse_header("FRINET-TRACE 1\nreg pc 8\nend\n");
    assert_eq!(header.registers, vec![register_info("pc", ScalarSize::U64)]);
    assert_eq!(header.modules, vec![]);
}

#[test]
fn parse_register_sizes() {
    let header = parse_header(
        "FRINET-TRACE 1\n\
         reg pc 8\n\
         reg al 1\n\
         reg ax 2\n\
         reg eax 4\n\
         reg xmm0 16\n\
         reg ymm0 32\n\
         reg zmm0 64\n\
         end\n",
    );

    assert_eq!(
        header.registers,
        vec![
            register_info("pc", ScalarSize::U64),
            register_info("al", ScalarSize::U8),
            register_info("ax", ScalarSize::U16),
            register_info("eax", ScalarSize::U32),
            register_info("xmm0", ScalarSize::U128),
            register_info("ymm0", ScalarSize::U256),
            register_info("zmm0", ScalarSize::U512),
        ]
    );

    assert_eq!(parse_header(&registers(240)).registers.len(), 240);
}

#[test]
fn parse_modules() {
    let header = parse_header(
        "FRINET-TRACE 1\n\
         reg pc 8\n\
         module ls 0x5555555a0000 0x5555555c4000\n\
         module libc.so.6 0x7FFFF7C00000 0x7FFFF7E05000\n\
         module empty 0x1000 0x1000\n\
         module last 0x0 0xffffffffffffffff\n\
         end\n",
    );

    assert_eq!(
        header.modules,
        vec![
            module_info("empty", 0x1000, 0x1000),
            module_info("ls", 0x5555555a0000, 0x5555555c4000),
            module_info("libc.so.6", 0x7ffff7c00000, 0x7ffff7e05000),
            module_info("last", 0, u64::MAX),
        ]
    );
}

#[test]
fn unknown_lines_are_ignored() {
    let header = parse_header("FRINET-TRACE 1\n\nfoo bar\nreg pc 8\n# comment\nend\n");

    assert_eq!(header.registers, vec![register_info("pc", ScalarSize::U64)]);
    assert_eq!(header.modules, vec![]);
}

#[test]
#[rustfmt::skip]
fn header_errors() {
    const BAD_MAGIC: &str = "invalid trace header: not a 'FRINET-TRACE 1' trace";

    assert_eq!(header_error("FRINET-TRACE 2\n"), BAD_MAGIC);
    assert_eq!(header_error("FRINET-TRACE 1 \n"), BAD_MAGIC);
    assert_eq!(header_error(" FRINET-TRACE 1\n"), BAD_MAGIC);

    assert_eq!(header_error(""), no_line_feed(1));
    assert_eq!(header_error("FRINET-TRACE 1"), no_line_feed(1));
    assert_eq!(header_error("FRINET-TRACE 1\n"), no_line_feed(2));
    assert_eq!(header_error("FRINET-TRACE 1\nreg pc 8\n"), no_line_feed(3));
    assert_eq!(header_error("FRINET-TRACE 1\nreg pc 8\nend"), no_line_feed(3));

    // CRLF is not supported, the `\r` stays in the line
    assert_eq!(header_error("FRINET-TRACE 1\r\nreg pc 8\r\nend\r\n"), BAD_MAGIC);
    assert_eq!(header_error("FRINET-TRACE 1\nreg pc 8\nend now\n"), "invalid trace header: line 3: malformed");
    assert_eq!(header_error(b"FRINET-TRACE 1\nreg pc 8\nmodule \xff 0x0 0x1\nend\n"), "invalid trace header: line 3: not valid UTF-8");

    assert_eq!(header_error("FRINET-TRACE 1\nend\n"), "invalid trace header: no register (the first one must be the PC)");
    assert_eq!(header_error(registers(241)), "invalid trace header: more than 240 registers");
    assert_eq!(header_error("FRINET-TRACE 1\nreg pc 8\nreg pc 4\nend\n"), "invalid trace header: line 3: duplicate register 'pc'");

    assert_eq!(header_error(reg_line("reg pc")), bad_register(2));
    assert_eq!(header_error(reg_line("reg pc 8 8")), bad_register(2));
    assert_eq!(header_error(reg_line("reg  8")), bad_register(2));
    assert_eq!(header_error(reg_line("reg pc eight")), bad_register(2));
    assert_eq!(header_error(reg_line("reg pc 08")), bad_register(2));
    assert_eq!(header_error(reg_line("reg pc 0")), bad_register(2));
    assert_eq!(header_error(reg_line("reg pc 3")), bad_register(2));
    assert_eq!(header_error(reg_line("reg pc 128")), bad_register(2));
    assert_eq!(header_error(reg_line("reg pc 256")), bad_register(2));

    assert_eq!(header_error(module_line("module ls 0x1000")), bad_module(3));
    assert_eq!(header_error(module_line("module ls 0x1 0x2 0x3")), bad_module(3));
    assert_eq!(header_error(module_line("module  0x1000 0x2000")), bad_module(3));
    assert_eq!(header_error(module_line("module ls 1000 0x2000")), bad_module(3));
    assert_eq!(header_error(module_line("module ls 0x 0x2000")), bad_module(3));
    assert_eq!(header_error(module_line("module ls 0x10g0 0x2000")), bad_module(3));
    assert_eq!(header_error(module_line("module ls 0x2000 0x1000")), bad_module(3));
    assert_eq!(header_error(module_line("module ls 0x0 0x10000000000000000")), bad_module(3));
}

#[test]
fn long_lines_are_rejected() {
    const MAX_LINE_LEN: usize = 64 * 1024;

    let longest = format!(
        "FRINET-TRACE 1\nreg pc 8\n{}\nend\n",
        "a".repeat(MAX_LINE_LEN)
    );
    assert_eq!(parse_header(&longest).registers.len(), 1);

    let too_long = format!(
        "FRINET-TRACE 1\nreg pc 8\n{}\nend\n",
        "a".repeat(MAX_LINE_LEN + 1)
    );
    assert_eq!(header_error(too_long), no_line_feed(3));
}

const HEADER: &[u8] = b"FRINET-TRACE 1\nreg pc 8\nreg al 1\nend\n";
const STEP: u8 = 0x00;
const READ: u8 = 0x01;
const WRITE: u8 = 0x02;
const READ_WRITE: u8 = 0x03;

#[test]
fn steps_advance_time() {
    assert_eq!(events(&[]), Ok(vec![]));
    assert_eq!(events(&[STEP, STEP, STEP]), Ok(vec![]));

    let stream = [
        reg_event(1, &[7]),
        vec![STEP],
        reg_event(1, &[8]),
        vec![STEP, STEP],
        reg_event(1, &[9]),
        vec![STEP],
    ]
    .concat();
    assert_eq!(
        events(&stream),
        Ok(vec![reg(0, 1, &[7]), reg(1, 1, &[8]), reg(3, 1, &[9])])
    );
}

#[test]
fn memory_events() {
    let stream = [
        mem_event(READ, 0x1000, b"ab"),
        mem_event(WRITE, 0x2000, b"c"),
        mem_event(READ_WRITE, 0x3000, b"def"),
    ]
    .concat();
    assert_eq!(
        events(&stream),
        Ok(vec![
            mem(0, MemoryMode::Read, 0x1000, b"ab"),
            mem(0, MemoryMode::Write, 0x2000, b"c"),
            mem(0, MemoryMode::ReadWrite, 0x3000, b"def"),
        ])
    );

    let longest = vec![0xaa; u16::MAX as usize];
    assert_eq!(
        events(&mem_event(WRITE, u64::MAX, &longest)),
        Ok(vec![mem(0, MemoryMode::Write, u64::MAX, &longest)])
    );
}

#[test]
fn register_events() {
    let pc = 0x5555_5555_a000u64.to_le_bytes();
    let stream = [reg_event(0, &pc), reg_event(1, &[0xff])].concat();

    assert_eq!(
        events(&stream),
        Ok(vec![reg(0, 0, &pc), reg(0, 1, &[0xff])])
    );
}

#[test]
fn truncated_stream_keeps_earlier_events() {
    let first = reg_event(1, &[1]);
    let kept = Ok(vec![reg(0, 1, &[1])]);

    // a tag alone, cut in the address, in the length and in the data
    let write = mem_event(WRITE, 0x1000, b"abcd");
    assert_eq!(events(&[&first[..], &write[..1]].concat()), kept);
    assert_eq!(events(&[&first[..], &write[..5]].concat()), kept);
    assert_eq!(events(&[&first[..], &write[..10]].concat()), kept);
    assert_eq!(events(&[&first[..], &write[..13]].concat()), kept);

    // cut in the value of a register
    let pc = reg_event(0, &[0; 8]);
    assert_eq!(events(&[&first[..], &pc[..1]].concat()), kept);
    assert_eq!(events(&[&first[..], &pc[..5]].concat()), kept);
}

#[test]
fn stream_errors() {
    assert_eq!(
        events(&mem_event(WRITE, 0x1000, b"")),
        Err("invalid trace event at offset 0x25: memory access of length 0".into())
    );
    assert_eq!(
        events(&[STEP, 0x12]),
        Err(
            "invalid trace event at offset 0x26: tag 0x12 is register 2, \
             the header declares 2"
                .into()
        )
    );
    assert_eq!(
        events(&[STEP, STEP, 0xff]),
        Err(
            "invalid trace event at offset 0x27: tag 0xff is register 239, \
             the header declares 2"
                .into()
        )
    );
    assert_eq!(
        events(&[0x04]),
        Err("invalid trace event at offset 0x25: reserved tag 0x04".into())
    );
    assert_eq!(
        events(&[0x0f]),
        Err("invalid trace event at offset 0x25: reserved tag 0x0f".into())
    );
}

// Helpers

fn parse_header(trace: &str) -> TraceHeader {
    TraceParser::new(trace.as_bytes())
        .map(|parser| parser.header().clone())
        .unwrap()
}

fn header_error(trace: impl AsRef<[u8]>) -> String {
    match TraceParser::new(trace.as_ref()) {
        Ok(_) => panic!("the header should be rejected"),
        Err(err) => err.to_string(),
    }
}

fn register_info(name: &str, scalar_size: ScalarSize) -> RegisterInfo {
    RegisterInfo {
        name: name.into(),
        scalar_size,
    }
}

fn module_info(name: &str, start: Addr, end: Addr) -> ModuleInfo {
    ModuleInfo {
        name: name.into(),
        start,
        end,
    }
}

/// A header declaring `count` registers
fn registers(count: usize) -> String {
    let lines: String = (0..count).map(|idx| format!("reg r{idx} 8\n")).collect();
    format!("FRINET-TRACE 1\n{lines}end\n")
}

/// A header with `line` as its only register, on line 2
fn reg_line(line: &str) -> String {
    format!("FRINET-TRACE 1\n{line}\nend\n")
}

/// A header with `line` after the PC, on line 3
fn module_line(line: &str) -> String {
    format!("FRINET-TRACE 1\nreg pc 8\n{line}\nend\n")
}

fn bad_register(line: usize) -> String {
    format!(
        "invalid trace header: line {line}: register must be 'reg <name> <byte_size>', \
         byte_size a power of two <= 64"
    )
}

fn bad_module(line: usize) -> String {
    format!(
        "invalid trace header: line {line}: module must be \
         'module <name> 0x<start> 0x<end>', start <= end"
    )
}

fn no_line_feed(line: usize) -> String {
    format!("invalid trace header: line {line}: did not find line ending ('\\n')")
}

/// An owned [TimedRawEvent], to compare after the trace is gone
#[derive(Debug, PartialEq)]
enum Event {
    Memory {
        time: Time,
        mode: MemoryMode,
        addr: Addr,
        bytes: Vec<u8>,
    },
    Register {
        time: Time,
        idx: usize,
        bytes: Vec<u8>,
    },
}

fn mem(time: Time, mode: MemoryMode, addr: Addr, bytes: &[u8]) -> Event {
    Event::Memory {
        time,
        mode,
        addr,
        bytes: bytes.to_vec(),
    }
}

fn reg(time: Time, idx: usize, bytes: &[u8]) -> Event {
    Event::Register {
        time,
        idx,
        bytes: bytes.to_vec(),
    }
}

fn mem_event(tag: u8, addr: Addr, data: &[u8]) -> Vec<u8> {
    let len = u16::try_from(data.len()).unwrap();
    [&[tag][..], &addr.to_le_bytes(), &len.to_le_bytes(), data].concat()
}

fn reg_event(idx: u8, value: &[u8]) -> Vec<u8> {
    [&[0x10 + idx][..], value].concat()
}

/// The events of `stream` after [HEADER], or the error message
fn events(stream: &[u8]) -> Result<Vec<Event>, String> {
    let trace = [HEADER, stream].concat();
    let parser = TraceParser::new(&trace[..]).unwrap();

    let mut events = Vec::new();
    let result = parser.parse(&mut (), |raw| {
        events.push(match raw.event {
            TimedRawEvent::Memory { addr, bytes, mode } => mem(raw.time, mode, addr, bytes),
            TimedRawEvent::Register { idx, bytes } => reg(raw.time, idx, bytes.0),
        })
    });

    result.map(|()| events).map_err(|err| err.to_string())
}

use std::convert::Infallible;

use frinet_db::db::{ModuleInfo, RegisterInfo};
use frinet_db::format::{Addr, Time};
use frinet_db::scalar::Scalar;

mod file;
pub use file::*;

/// Trace metadata, known before parsing events
#[derive(Debug, Clone, Default)]
pub struct TraceHeader {
    pub registers: Vec<RegisterInfo>,
    pub modules: Vec<ModuleInfo>,
}

pub trait ParserGenerator {
    type Parser: Parser;

    fn generate(&mut self) -> Result<Self::Parser, <Self::Parser as Parser>::Err>;
}

pub trait Parser {
    type Err;

    fn header(&self) -> &TraceHeader;
    fn parse<'trace, EmitFn>(
        &'trace self,
        progress: &mut dyn ProgressReporter,
        emit: EmitFn,
    ) -> Result<(), Self::Err>
    where
        EmitFn: FnMut(RawEvent<'trace>);
}

impl ProgressReporter for () {}

/// Follows the passes over the trace, a parser stops early once it is cancelled
pub trait ProgressReporter: Send {
    fn start(&mut self, _pass: Pass) {}
    fn total(&mut self, _total: usize) {}
    fn current(&mut self, _current: usize) {}
    fn is_cancelled(&self) -> bool {
        false
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Pass {
    Scout,
    Partitions,
    Fill,
}

/// Raw (unprocessed) event from the trace parser
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RawEvent<'trace> {
    pub time: Time,
    pub event: TimedRawEvent<'trace>,
}

/// Timed raw (unprocessed) event from the trace parser
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimedRawEvent<'trace> {
    Memory {
        addr: Addr,
        bytes: &'trace [u8],
        mode: MemoryMode,
    },
    Register {
        idx: usize,
        bytes: Scalar<'trace>,
    },
}

/// Memory event mode
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryMode {
    Read,
    Write,
    ReadWrite,
}

/// In-memory list of events for testing/fuzzing purposes (cheaply copiable)
#[derive(Clone, Copy)]
pub struct StaticEventList<'a> {
    pub header: &'a TraceHeader,
    pub events: &'a [RawEvent<'a>],
}

impl<'a> ParserGenerator for StaticEventList<'a> {
    type Parser = Self;

    fn generate(&mut self) -> Result<Self::Parser, Infallible> {
        Ok(*self)
    }
}

impl<'a> Parser for StaticEventList<'a> {
    type Err = Infallible;

    fn header(&self) -> &TraceHeader {
        self.header
    }

    fn parse<'trace, EmitFn>(
        &'trace self,
        progress: &mut dyn ProgressReporter,
        mut emit: EmitFn,
    ) -> Result<(), Self::Err>
    where
        EmitFn: FnMut(RawEvent<'trace>),
    {
        progress.total(self.events.len());
        for (idx, event) in self.events.iter().enumerate() {
            if progress.is_cancelled() {
                return Ok(());
            }
            emit(*event);
            progress.current(idx);
        }
        Ok(())
    }
}

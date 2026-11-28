use frinet_db::{
    db::ModuleInfo,
    format::{Addr, MemNode, MemReadLeaf, Time},
    irange::IRange,
    module_timeline::{MAX_MODULES, MODULE_MARKER_NONE, ModuleId, find_module_by_addr},
    register::{INTERNAL_REGISTERS, InternalRegister, PC_REGISTER_IDX},
    rtree::Spec,
    scalar::Scalar,
};

use crate::{
    disjoint::{DisjointMemLeaf, DisjointPass},
    parser::{MemoryMode, Parser, ProgressReporter, RawEvent, TimedRawEvent},
};

mod hilbert_partition;
pub use hilbert_partition::*;

mod scout;
pub use scout::*;

mod fill;
pub use fill::*;

/// Normalized event
pub enum Event<'trace> {
    MemoryWrite(DisjointMemLeaf<'trace>),
    MemoryRead(MemReadLeaf),
    Register {
        idx: usize,
        time: Time,
        value: RegisterValue<'trace>,
    },
}

/// Written to a trace register, or to an internal register
#[derive(Clone, Copy, Debug)]
pub enum RegisterValue<'trace> {
    Scalar(Scalar<'trace>),
    Module(ModuleId),
}

impl RegisterValue<'_> {
    /// As little-endian bytes, the storage representation
    fn copy_to(self, bytes: &mut [u8]) {
        match self {
            Self::Scalar(scalar) => bytes.copy_from_slice(scalar.0),
            Self::Module(module) => bytes.copy_from_slice(&module.to_le_bytes()),
        }
    }
}

/// Returns the end of the trace: the time of the last event
fn parse_and_normalize_events<'trace, P, Emit>(
    parser: &'trace mut P,
    progress: &mut dyn ProgressReporter,
    mut emit: Emit,
) -> Result<Time, P::Err>
where
    Emit: FnMut(Event<'trace>),
    P: Parser,
{
    let mut curr_time: Time = 0;

    let mut disjoint = DisjointPass::default();
    let mut last_reg_writes: Vec<Option<(Time, Scalar)>> =
        vec![None; parser.header().registers.len()];
    let mut modules = ModuleTracker::new(&parser.header().modules);

    parser.parse(progress, |RawEvent { time, event }| {
        assert!(curr_time <= time);
        curr_time = time;

        match event {
            TimedRawEvent::Memory { addr, bytes, mode } => {
                assert!(!bytes.is_empty());

                let is_read_only = matches!(mode, MemoryMode::Read);
                let is_read = matches!(mode, MemoryMode::Read | MemoryMode::ReadWrite);

                disjoint.push_memory_write(time, addr, bytes, is_read_only, |disjoint_leaf| {
                    emit(Event::MemoryWrite(disjoint_leaf))
                });

                if is_read {
                    let range = IRange::from_start_len(addr, bytes.len() as _);
                    emit(Event::MemoryRead(MemReadLeaf { addr: range, time }))
                }
            }
            TimedRawEvent::Register { idx, bytes } => {
                // at the same time, the last write wins
                let write = (time, bytes);
                if let Some((last_time, last_value)) = last_reg_writes[idx].replace(write)
                    && last_time != time
                {
                    emit_register(&mut emit, &mut modules, idx, last_time, last_value);
                }
            }
        }
    })?;

    disjoint.finish(curr_time, |disjoint_leaf| {
        emit(Event::MemoryWrite(disjoint_leaf))
    });

    for (idx, last) in last_reg_writes.into_iter().enumerate() {
        if let Some((time, value)) = last {
            emit_register(&mut emit, &mut modules, idx, time, value);
        }
    }

    Ok(curr_time)
}

/// Sends the write of a register of the trace, and the module of the PC when it changes
fn emit_register<'trace>(
    emit: &mut impl FnMut(Event<'trace>),
    modules: &mut ModuleTracker,
    idx: usize,
    time: Time,
    value: Scalar<'trace>,
) {
    emit(Event::Register {
        idx: INTERNAL_REGISTERS.len() + idx,
        time,
        value: RegisterValue::Scalar(value),
    });

    if idx == PC_REGISTER_IDX
        && let Some(module) = modules.push_pc(value)
    {
        emit(Event::Register {
            idx: InternalRegister::Module.idx(),
            time,
            value: RegisterValue::Module(module),
        });
    }
}

/// Track the current module
struct ModuleTracker {
    /// In the order of a database
    modules: Vec<ModuleInfo>,
    current: Option<ModuleId>,
}

impl ModuleTracker {
    fn new(modules: &[ModuleInfo]) -> Self {
        assert!(modules.len() <= MAX_MODULES);
        Self {
            modules: modules.to_vec(),
            current: None,
        }
    }

    fn push_pc(&mut self, pc: Scalar<'_>) -> Option<ModuleId> {
        let Some(addr) = pc.try_into_u64() else {
            return None; // PC do not fit into 64-bit (bail out)
        };
        let module = find_module_by_addr(&self.modules, addr).unwrap_or(MODULE_MARKER_NONE);
        (self.current.replace(module) != Some(module)).then_some(module)
    }
}

/// Index of the memory zone containing `addr_range`
fn find_zone_containing_addr_range<S>(
    zones: &[RTreePartitions<S>],
    addr_range: IRange<Addr>,
) -> usize
where
    S: Spec<Node = MemNode>,
{
    zones
        .iter()
        .position(|zone| !zone.bbox.addr.is_disjoint(addr_range))
        .expect("no zone found for memory leaf")
}

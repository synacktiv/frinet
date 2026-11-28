//! Register indexes of a [Db]: a by time series for every register, and a by value series for
//! the PC (see [crate::time_series])

use core::ops::RangeInclusive;

use crate::db::Db;
use crate::format::{RegisterByTimeHeader, RegisterByValueHeader, Section, Storage, Time};
use crate::irange::IRange;
use crate::scalar::{Scalar, ScalarSize, ScalarSlice};
use crate::time_series::{SeriesByTime, SeriesByValue, TimeSearch};

impl<'s> Db<'s> {
    pub fn registers(&self) -> &[Register<'s>] {
        &self.registers[INTERNAL_REGISTERS.len()..]
    }

    pub fn register_by_index(&self, idx: usize) -> Option<&Register<'s>> {
        self.registers().get(idx)
    }

    pub fn register_by_name(&self, name: &str) -> Option<&Register<'s>> {
        self.register_by_index(self.register_index_by_name(name)?)
    }

    /// Internal register that track the current module
    pub fn module_register(&self) -> &Register<'s> {
        &self.registers[InternalRegister::Module.idx()]
    }

    fn register_index_by_name(&self, name: &str) -> Option<usize> {
        self.metadata
            .registers
            .iter()
            .position(|it| it.name == name)
    }

    pub fn pc(&self) -> Option<&Register<'s>> {
        self.register_by_index(PC_REGISTER_IDX)
    }
}

/// The program counter is the first trace-defined register
pub const PC_REGISTER_IDX: usize = 0;

/// Internal registers
pub const INTERNAL_REGISTERS: &[InternalRegister] = &[InternalRegister::Module];

pub enum InternalRegister {
    Module,
}

impl InternalRegister {
    pub fn size(&self) -> ScalarSize {
        match self {
            InternalRegister::Module => ScalarSize::U16,
        }
    }

    pub fn idx(&self) -> usize {
        match self {
            InternalRegister::Module => 0,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Register<'s> {
    pub scalar_size: ScalarSize,
    pub by_time: Option<SeriesByTime<'s>>,
    pub by_value: Option<SeriesByValue<'s>>,
}

impl<'s> Register<'s> {
    /// First write ..= end of the trace, [None] if never written
    pub fn time_range(&self) -> Option<IRange<Time>> {
        Some(self.by_time?.time_range())
    }

    pub fn value_at(&self, time: Time) -> Option<Scalar<'s>> {
        self.by_time?.value_at(time)
    }

    pub fn is_write_at(&self, time: Time) -> bool {
        self.by_time
            .is_some_and(|by_time| by_time.is_write_at(time))
    }

    /// Last time before `time` holding another value
    pub fn prev_change(&self, time: Time) -> Option<Time> {
        self.by_time?.prev_change(time)
    }

    /// First time after `time` holding another value
    pub fn next_change(&self, time: Time) -> Option<Time> {
        self.by_time?.next_change(time)
    }

    pub fn has_by_value_index(&self) -> bool {
        self.by_value.is_some()
    }

    /// Nearest write of `value`, only with a by value index
    pub fn find_time_with(
        &self,
        search: TimeSearch,
        value: Scalar<'_>,
    ) -> Result<Option<Time>, ValueQueryError> {
        let by_value = self.by_value_index(value)?;
        Ok(by_value.find_time_with(search, value))
    }

    /// Every write time of `value`, sorted: a slice of the index, without a copy
    pub fn times_with(&self, value: Scalar<'_>) -> Result<&'s [Time], ValueQueryError> {
        let by_value = self.by_value_index(value)?;
        Ok(by_value.times_of(value))
    }

    /// Every value the register ever held, sorted, only with a by value index
    pub fn distinct_values(&self) -> Option<ScalarSlice<'s>> {
        Some(self.by_value?.values)
    }

    /// Prefix sums of the write times, the count of the `n`-th value being `[n + 1] - [n]`
    pub fn value_offsets(&self) -> Option<&'s [u64]> {
        Some(self.by_value?.offsets)
    }

    /// Write count of each [Self::distinct_values], in the same order
    pub fn value_counts(&self) -> Option<impl ExactSizeIterator<Item = u64> + 's> {
        let offsets = self.value_offsets()?;
        Some(offsets.windows(2).map(|pair| pair[1] - pair[0]))
    }

    /// The value at every step of `time_range`, [None] for the steps holding none
    pub fn values_in(&self, time_range: IRange<Time>) -> ValuesIn<'s> {
        ValuesIn {
            by_time: self.by_time,
            times: time_range.min..=time_range.max,
        }
    }

    fn by_value_index(&self, value: Scalar<'_>) -> Result<SeriesByValue<'s>, ValueQueryError> {
        let expected = self.scalar_size.bytes();
        if value.0.len() != expected {
            return Err(ValueQueryError::BadScalarSize {
                expected,
                got: value.0.len(),
            });
        }
        self.by_value.ok_or(ValueQueryError::NoByValueIndex)
    }
}

/// One value per step, see [Register::values_in]
#[derive(Debug, Clone)]
pub struct ValuesIn<'s> {
    by_time: Option<SeriesByTime<'s>>,
    times: RangeInclusive<Time>,
}

impl<'s> Iterator for ValuesIn<'s> {
    type Item = Option<Scalar<'s>>;

    fn next(&mut self) -> Option<Self::Item> {
        let time = self.times.next()?;
        Some(self.by_time.and_then(|by_time| by_time.value_at(time)))
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.times.size_hint()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValueQueryError {
    NoByValueIndex,
    BadScalarSize { expected: usize, got: usize },
}

impl core::fmt::Display for ValueQueryError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ValueQueryError::NoByValueIndex => {
                write!(f, "the register has no by value index")
            }
            ValueQueryError::BadScalarSize { expected, got } => {
                write!(f, "the register is {expected} bytes wide, got {got}")
            }
        }
    }
}

impl core::error::Error for ValueQueryError {}

/// Read the register indexes, `by_time` has one header per register in trace header order
pub(crate) fn read_registers<'s>(
    storage: Storage<'s>,
    by_time: Section<RegisterByTimeHeader>,
    by_value: Section<RegisterByValueHeader>,
) -> Vec<Register<'s>> {
    let mut registers: Vec<Register> = storage
        .slice(by_time)
        .iter()
        .map(|header| Register {
            scalar_size: header.scalar_size(),
            by_time: read_series_by_time(storage, header),
            by_value: None,
        })
        .collect();

    for header in storage.slice(by_value) {
        let register = &mut registers[header.register_idx as usize];
        assert_eq!(header.scalar_size(), register.scalar_size);
        assert!(register.by_value.is_none());
        register.by_value = Some(read_series_by_value(storage, header));
    }

    registers
}

/// [None] if the register was never written: it has no chunk at all
fn read_series_by_time<'s>(
    storage: Storage<'s>,
    header: &RegisterByTimeHeader,
) -> Option<SeriesByTime<'s>> {
    let chunks = storage.slice(header.chunks);
    let local_time_pool = storage.slice(header.local_time_pool);
    let value_pool = storage.scalar_slice(header.value_pool, header.scalar_size());

    if chunks.is_empty() {
        assert!(local_time_pool.is_empty());
        assert!(value_pool.is_empty());
        return None;
    }

    Some(SeriesByTime::new(
        header.time_range,
        chunks,
        local_time_pool,
        value_pool,
    ))
}

fn read_series_by_value<'s>(
    storage: Storage<'s>,
    header: &RegisterByValueHeader,
) -> SeriesByValue<'s> {
    SeriesByValue::new(
        storage.scalar_slice(header.keys, header.scalar_size()),
        storage.slice(header.offsets),
        storage.slice(header.times),
    )
}

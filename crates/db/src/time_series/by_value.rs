use crate::format::Time;
use crate::scalar::{Scalar, ScalarSlice};

#[derive(Debug, Clone, Copy)]
pub struct SeriesByValue<'storage> {
    pub values: ScalarSlice<'storage>,
    /// `u64`: there can be up to `Time::MAX + 1` writes
    pub offsets: &'storage [u64],
    pub times: &'storage [Time],
}

impl<'storage> SeriesByValue<'storage> {
    pub fn new(
        values: ScalarSlice<'storage>,
        offsets: &'storage [u64],
        times: &'storage [Time],
    ) -> Self {
        assert_eq!(offsets.len(), values.len() + 1);
        assert_eq!(offsets.first(), Some(&0));
        assert_eq!(offsets.last(), Some(&(times.len() as u64)));
        debug_assert!(offsets.is_sorted());
        debug_assert!(values.iter().is_sorted_by(|a, b| a < b));
        Self {
            values,
            offsets,
            times,
        }
    }

    /// Sorted write times of `value`, empty if it was never written
    pub fn times_of(&self, value: Scalar<'_>) -> &'storage [Time] {
        assert_eq!(value.0.len(), self.values.size().bytes());

        let value_idx = self.values.partition_point(|it| it < value);
        if self.values.try_get(value_idx) != Some(value) {
            // the value is absent from the index
            return &[];
        }

        let start = self.offsets[value_idx] as usize;
        let end = self.offsets[value_idx + 1] as usize;
        &self.times[start..end]
    }

    /// Nearest write time of `value`
    pub fn find_time_with(&self, search: TimeSearch, value: Scalar<'_>) -> Option<Time> {
        search.pick_in_sorted(self.times_of(value))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TimeSearch {
    First,
    Before(Time),
    After(Time),
    Last,
}

impl TimeSearch {
    /// Pick the matching time in a sorted list of times
    fn pick_in_sorted(self, sorted_times: &[Time]) -> Option<Time> {
        match self {
            TimeSearch::Before(time) => {
                let idx = sorted_times.partition_point(|it| *it < time);
                Some(sorted_times[idx.checked_sub(1)?])
            }
            TimeSearch::After(time) => {
                let idx = sorted_times.partition_point(|it| *it <= time);
                sorted_times.get(idx).copied()
            }
            TimeSearch::First => sorted_times.first().copied(),
            TimeSearch::Last => sorted_times.last().copied(),
        }
    }
}

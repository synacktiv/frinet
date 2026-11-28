use std::ops::Range;

use frinet_db::format::*;
use frinet_db::irange::IRange;
use frinet_db::memory::{MemReadSpec, MemWriteSpec};
use frinet_db::rtree::Spec;

use crate::hilbert_spec::HilbertSpec;
use crate::parser::{Parser, ProgressReporter};
use crate::pass::{Event, ScoutPass, find_zone_containing_addr_range, parse_and_normalize_events};

pub const BITS_PER_DIM: usize = 4;
pub const PARTITIONS: usize = (1_usize << BITS_PER_DIM).pow(2);

pub struct HilbertPartitionPass {
    pub write_zones: Vec<RTreePartitions<MemWriteSpec>>,
    pub read_zones: Vec<RTreePartitions<MemReadSpec>>,
}

pub fn hilbert_partition_pass<P>(
    mut parser: P,
    progress: &mut dyn ProgressReporter,
    scout: &ScoutPass,
) -> Result<HilbertPartitionPass, P::Err>
where
    P: Parser,
{
    let plan = &scout.plan;
    let mut pass = HilbertPartitionPass {
        write_zones: tree_partitions(&plan.write_zones),
        read_zones: tree_partitions(&plan.read_zones),
    };

    parse_and_normalize_events(&mut parser, progress, |item| match item {
        Event::MemoryWrite(leaf) => {
            let addr_range = leaf.node.addr;
            let idx = find_zone_containing_addr_range(&pass.write_zones, addr_range);
            pass.write_zones[idx].push_leaf(MemWriteLeaf {
                node: leaf.node,
                data: 0, // we do not care about `data` in this pass
            });
        }
        Event::MemoryRead(leaf) => {
            let idx = find_zone_containing_addr_range(&pass.read_zones, leaf.addr);
            pass.read_zones[idx].push_leaf(leaf);
        }
        Event::Register { .. } => {}
    })?;

    for partitions in &mut pass.write_zones {
        partitions.compute_starts();
    }
    for partitions in &mut pass.read_zones {
        partitions.compute_starts();
    }

    Ok(pass)
}

fn tree_partitions<S: HilbertSpec>(plans: &[RTreePlan<S>]) -> Vec<RTreePartitions<S>> {
    plans
        .iter()
        .map(|plan| RTreePartitions::new(plan.bbox))
        .collect()
}

pub struct RTreePartitions<S: Spec> {
    pub partitions: Box<[Partition; PARTITIONS]>,
    pub bbox: S::Node,
}

#[derive(Debug, Clone, Copy)]
pub struct Partition {
    /// Index of the first leaf of this partition in the R-Tree leaves
    pub start: usize,
    pub leaf_count: usize,
    pub time_range: IRange<Time>,
}

impl<S: HilbertSpec> RTreePartitions<S> {
    pub fn new(bbox: S::Node) -> Self {
        Self {
            bbox,
            partitions: Box::new([Partition::default(); PARTITIONS]),
        }
    }

    pub fn push_leaf(&mut self, leaf: S::Leaf) {
        let key = S::hilbert_partition_key(&leaf, &self.bbox);
        let key = key as usize;

        let partition = &mut self.partitions[key];
        partition.leaf_count += 1;

        let time_range = S::leaf_time_range(&leaf);
        partition.time_range.min = partition.time_range.min.min(time_range.min);
        partition.time_range.max = partition.time_range.max.max(time_range.max);
    }

    fn compute_starts(&mut self) {
        let mut start = 0;
        for partition in self.partitions.iter_mut() {
            partition.start = start;
            start += partition.leaf_count;
        }
    }
}

impl Partition {
    /// Range of leaves of this partition in the R-Tree leaves
    pub fn range(&self) -> Range<usize> {
        self.start..self.start + self.leaf_count
    }
}

impl Default for Partition {
    fn default() -> Self {
        Self {
            start: 0,
            leaf_count: 0,
            time_range: IRange {
                min: Time::MAX,
                max: Time::MIN,
            },
        }
    }
}

use crate::db::Db;
use crate::format::*;
use crate::irange::*;
use crate::nearest_neighbor::Status;
use crate::nearest_neighbor::nearest_neighbor;
use crate::rtree::*;

/// R-Tree specification for indexing memory writes
#[derive(Debug, Clone, Copy)]
pub struct MemWriteSpec;
pub type MemWriteRTree<'storage> = RTree<'storage, MemWriteSpec>;

impl Spec for MemWriteSpec {
    type Node = MemNode;
    type Leaf = MemWriteLeaf;
}

/// R-Tree specification for indexing memory reads
#[derive(Debug, Clone, Copy)]
pub struct MemReadSpec;
pub type MemReadRTree<'storage> = RTree<'storage, MemReadSpec>;

impl Spec for MemReadSpec {
    type Node = MemNode;
    type Leaf = MemReadLeaf;
}

impl MemNode {
    #[inline]
    pub fn extends_to_contain(&mut self, other: &Self) {
        self.addr.min = self.addr.min.min(other.addr.min);
        self.addr.max = self.addr.max.max(other.addr.max);
        self.time.min = self.time.min.min(other.time.min);
        self.time.max = self.time.max.max(other.time.max);
    }

    #[inline]
    pub fn is_disjoint(&self, other: &Self) -> bool {
        #[cfg(debug_assertions)]
        {
            self.check_invariant();
            other.check_invariant();
        }

        let addr = self.addr.is_disjoint(other.addr);
        let time = self.time.is_disjoint(other.time);
        addr || time
    }

    #[allow(unused)]
    fn check_invariant(&self) {
        assert!(self.addr.min <= self.addr.max);
        assert!(self.time.min <= self.time.max);
    }

    /// Fragment one rectangle by another
    ///
    /// Based on the pseudo-code of the NIR-Tree paper : <https://dl.acm.org/doi/10.1145/3468791.3468818>
    pub fn fragment_by(&self, other: &Self, fragments: &mut Vec<MemNode>) {
        if self.is_disjoint(other) {
            fragments.push(*self);
            return;
        }

        struct MemPoint {
            pub addr: Addr,
            pub time: Time,
        }

        let mut ceils = MemPoint { addr: 0, time: 0 };
        let mut floors = MemPoint { addr: 0, time: 0 };

        // Address
        {
            let self_floor = self.addr.min;
            let other_floor = other.addr.min;
            floors.addr = other_floor.max(self_floor);

            if other_floor > self_floor {
                fragments.push(MemNode {
                    addr: IRange::new(self_floor, other_floor - 1),
                    time: self.time,
                });
            }

            let self_ceil = self.addr.max;
            let other_ceil = other.addr.max;
            ceils.addr = other_ceil.min(self_ceil);

            if other_ceil < self_ceil {
                fragments.push(MemNode {
                    addr: IRange::new(other_ceil + 1, self_ceil),
                    time: self.time,
                });
            }
        }

        // Time
        {
            let self_floor = self.time.min;
            let other_floor = other.time.min;
            floors.time = other_floor.max(self_floor);

            if other_floor > self_floor {
                fragments.push(MemNode {
                    addr: IRange::new(floors.addr, ceils.addr),
                    time: IRange::new(self_floor, other_floor - 1),
                });
            }

            let self_ceil = self.time.max;
            let other_ceil = other.time.max;
            ceils.time = other_ceil.min(self_ceil);

            if other_ceil < self_ceil {
                fragments.push(MemNode {
                    addr: IRange::new(floors.addr, ceils.addr),
                    time: IRange::new(other_ceil + 1, self_ceil),
                });
            }
        }
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> arbitrary::Arbitrary<'a> for MemWriteLeaf {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let addr_range: IRange<Addr> = u.arbitrary()?;
        let time_range: IRange<Time> = u.arbitrary()?;
        let data = u.arbitrary()?;

        Ok(Self {
            node: MemNode {
                addr: addr_range,
                time: time_range,
            },
            data,
        })
    }
}

impl MemReadLeaf {
    #[inline]
    pub fn node(&self) -> MemNode {
        let addr = self.addr;
        MemNode {
            addr,
            time: IRange::one(self.time),
        }
    }
}

impl Db<'_> {
    /// Nearest time before `time` setting the content of `addr_range`, a first read included
    pub fn prev_mem_write(&self, time: Time, addr_range: IRange<Addr>) -> Option<Time> {
        self.write_zones
            .iter()
            .filter(|rtree| !addr_range.is_disjoint(rtree.bbox.addr))
            .filter_map(|rtree| rtree.prev_leaf_where_addr_match(time, addr_range))
            .max()
    }

    /// Nearest time after `time` setting the content of `addr_range`, a first read included
    pub fn next_mem_write(&self, time: Time, addr_range: IRange<Addr>) -> Option<Time> {
        self.write_zones
            .iter()
            .filter(|rtree| !addr_range.is_disjoint(rtree.bbox.addr))
            .filter_map(|rtree| rtree.next_leaf_where_addr_match(time, addr_range))
            .min()
    }

    pub fn prev_mem_read(&self, time: Time, addr_range: IRange<Addr>) -> Option<Time> {
        self.read_zones
            .iter()
            .filter(|rtree| !addr_range.is_disjoint(rtree.bbox.addr))
            .filter_map(|rtree| rtree.prev_leaf_where_addr_match(time, addr_range))
            .max()
    }

    pub fn next_mem_read(&self, time: Time, addr_range: IRange<Addr>) -> Option<Time> {
        self.read_zones
            .iter()
            .filter(|rtree| !addr_range.is_disjoint(rtree.bbox.addr))
            .filter_map(|rtree| rtree.next_leaf_where_addr_match(time, addr_range))
            .min()
    }

    /// Nearest read or content update of `addr_range` before `time`
    pub fn prev_mem_access(&self, time: Time, addr_range: IRange<Addr>) -> Option<Time> {
        let both = [
            self.prev_mem_write(time, addr_range),
            self.prev_mem_read(time, addr_range),
        ];
        both.into_iter().flatten().max()
    }

    /// Nearest read or content update of `addr_range` after `time`
    pub fn next_mem_access(&self, time: Time, addr_range: IRange<Addr>) -> Option<Time> {
        let both = [
            self.next_mem_write(time, addr_range),
            self.next_mem_read(time, addr_range),
        ];
        both.into_iter().flatten().min()
    }
}

macro_rules! impl_prev_next {
    ($rtree:ident, $node_visitor:ident, $leaf_visitor:ident, $map:expr) => {
        impl $rtree<'_> {
            pub fn prev_leaf_where_addr_match(
                &self,
                time: Time,
                addr_range: IRange<Addr>,
            ) -> Option<Time> {
                let time_range = IRange::new(0, time.checked_sub(1)?);
                nearest_neighbor(
                    self,
                    $node_visitor(time_range, addr_range, time),
                    $leaf_visitor(time_range, addr_range, time),
                )
                .map($map)
            }

            pub fn next_leaf_where_addr_match(
                &self,
                time: Time,
                addr_range: IRange<Addr>,
            ) -> Option<Time> {
                let time_range = IRange::new(time.checked_add(1)?, Time::MAX);
                nearest_neighbor(
                    self,
                    $node_visitor(time_range, addr_range, time),
                    $leaf_visitor(time_range, addr_range, time),
                )
                .map($map)
            }
        }
    };
}

impl_prev_next!(
    MemReadRTree,
    mem_node_visitor,
    mem_read_leaf_visitor,
    |leaf| leaf.time
);

impl_prev_next!(
    MemWriteRTree,
    mem_node_visitor,
    mem_write_leaf_visitor,
    |leaf| leaf.node.time.min
);

fn mem_node_visitor(
    time_range: IRange<u32>,
    addr_range: IRange<Addr>,
    target_time: u32,
) -> impl Fn(&MemNode) -> Status<Time> {
    move |node| {
        if time_range.is_disjoint(node.time) {
            return Status::Ignore;
        }
        if addr_range.is_disjoint(node.addr) {
            return Status::Ignore;
        }
        let dist = node.time.min_distance(target_time);
        Status::Keep(dist)
    }
}

fn mem_read_leaf_visitor(
    time_range: IRange<u32>,
    addr_range: IRange<Addr>,
    target_time: u32,
) -> impl Fn(&MemReadLeaf) -> Status<Time> {
    move |leaf| {
        if !time_range.contains(leaf.time) {
            return Status::Ignore;
        }
        if addr_range.is_disjoint(leaf.addr) {
            return Status::Ignore;
        }
        let dist = leaf.time.abs_diff(target_time);
        Status::Keep(dist)
    }
}

fn mem_write_leaf_visitor(
    time_range: IRange<u32>,
    addr_range: IRange<Addr>,
    target_time: u32,
) -> impl Fn(&MemWriteLeaf) -> Status<Time> {
    move |leaf| {
        if !time_range.contains(leaf.node.time.min) {
            return Status::Ignore;
        }
        if addr_range.is_disjoint(leaf.node.addr) {
            return Status::Ignore;
        }
        let dist = leaf.node.time.min.abs_diff(target_time);
        Status::Keep(dist)
    }
}

use serde::{Deserialize, Serialize};

use crate::format::*;
use crate::irange::IRange;
use crate::memory::{MemReadSpec, MemWriteSpec};
use crate::module_timeline::{ModuleId, find_module_by_addr};

use crate::query::{Query, QueryIter};
use crate::register::{INTERNAL_REGISTERS, Register, read_registers};
use crate::rtree::{RTree, Spec};
use crate::scalar::ScalarSize;

pub use crate::format::LoadError;

/// Indexed database of an execution trace
pub struct Db<'s> {
    pub metadata: Metadata,
    pub write_zones: Vec<RTree<'s, MemWriteSpec>>,
    pub read_zones: Vec<RTree<'s, MemReadSpec>>,
    pub registers: Vec<Register<'s>>,
    pub raw_data: &'s [u8],
}

/// Data that are not worth laying out for being zerocopiable
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct Metadata {
    pub registers: Vec<RegisterInfo>,
    pub modules: Vec<ModuleInfo>,
    pub time_end: Time,
}

/// Metadata about a register declared in the trace header
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegisterInfo {
    pub name: String,
    pub scalar_size: ScalarSize,
}

/// Metadata about a module declared in the trace header
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModuleInfo {
    pub name: String,
    pub start: Addr,
    pub end: Addr,
}

impl ModuleInfo {
    pub fn contains(&self, addr: Addr) -> bool {
        self.start <= addr && addr < self.end
    }
}

impl<'s> Db<'s> {
    pub fn from_aligned_slice(bytes: &'s [u8]) -> Result<Self, LoadError> {
        let storage = Storage::new(bytes);
        let header = storage.header()?;

        if header.magic[..4] != DB_MAGIC[..4] {
            return Err(LoadError::InvalidMagic);
        }

        if header.magic != DB_MAGIC {
            return Err(LoadError::InvalidVersion {
                got: header.magic,
                expected: DB_MAGIC,
            });
        }

        let raw_data = storage.slice(header.data);

        let metadata_json = storage.slice(header.metadata);
        let metadata: Metadata = serde_json::from_slice(metadata_json)
            .unwrap_or_else(|err| panic!("invalid metadata: {err}"));

        let write_zones = read_rtrees(storage, header.write_zones);
        let read_zones = read_rtrees(storage, header.read_zones);

        let registers =
            read_registers(storage, header.registers_by_time, header.registers_by_value);

        assert_eq!(
            registers.len(),
            INTERNAL_REGISTERS.len() + metadata.registers.len()
        );

        Ok(Self {
            write_zones,
            read_zones,
            registers,
            metadata,
            raw_data,
        })
    }

    pub fn module_at(&self, addr: Addr) -> Option<ModuleId> {
        find_module_by_addr(&self.metadata.modules, addr)
    }

    pub fn mem_write_query<Q>(&self, query: Q) -> MultiQueryIter<'s, MemWriteSpec, Q>
    where
        Q: Query<MemWriteSpec> + Clone,
    {
        MultiQueryIter::new(query, &self.write_zones)
    }

    pub fn mem_read_query<Q>(&self, query: Q) -> MultiQueryIter<'s, MemReadSpec, Q>
    where
        Q: Query<MemReadSpec> + Clone,
    {
        MultiQueryIter::new(query, &self.read_zones)
    }

    pub fn mem_write_intersects(
        &self,
        node: MemNode,
    ) -> MultiQueryIter<'s, MemWriteSpec, MemIntersects> {
        self.mem_write_query(MemIntersects { node })
    }

    pub fn mem_read_intersects(
        &self,
        node: MemNode,
    ) -> MultiQueryIter<'s, MemReadSpec, MemIntersects> {
        self.mem_read_query(MemIntersects { node })
    }

    /// Memory content of `addr_range` at `time`, the bytes the trace does not know read as zero
    pub fn read_memory(&self, addr_range: IRange<Addr>, time: Time) -> Vec<u8> {
        self.read_memory_with_unknowns(addr_range, time)
            .into_iter()
            .map(Option::unwrap_or_default)
            .collect()
    }

    /// Memory content of `addr_range` at `time`, [None] for the bytes the trace does not know
    pub fn read_memory_with_unknowns(
        &self,
        addr_range: IRange<Addr>,
        time: Time,
    ) -> Vec<Option<u8>> {
        // no leaf reaches past the end of the trace, where nothing is known anymore
        let time = time.min(self.metadata.time_end);

        let query_rect = MemNode {
            addr: addr_range,
            time: IRange::one(time),
        };

        let mut content = vec![None; addr_range.span_usize()];

        for leaf in self.mem_write_intersects(query_rect) {
            let overlap = leaf
                .node
                .addr
                .intersection(&addr_range)
                .expect("the leaf intersects the query");

            let out_off = (overlap.min - addr_range.min) as usize;
            let node_off = (overlap.min - leaf.node.addr.min) as usize;
            let size = overlap.span_usize();

            let leaf_data = &self.mem_leaf_data(leaf)[node_off..][..size];
            for (out, byte) in content[out_off..][..size].iter_mut().zip(leaf_data) {
                *out = Some(*byte);
            }
        }

        content
    }

    pub fn mem_leaf_data(&self, leaf: &'s MemWriteLeaf) -> &'s [u8] {
        let len = leaf.node.addr.span_usize();
        if len <= 8 {
            // NOTE: not portable but endianness will be checked in index header
            &bytes_of(&leaf.data)[..len]
        } else {
            let offset = leaf.data as usize;
            &self.raw_data[offset..][..len]
        }
    }
}

fn read_rtrees<'s, S: Spec>(
    storage: Storage<'s>,
    section: Section<RTreeHeader<S>>,
) -> Vec<RTree<'s, S>> {
    let mut rtrees = Vec::with_capacity(section.len());
    for header in storage.slice(section) {
        let node_size_order = u32::try_from(header.node_size_order)
            .expect("node size order is not representable as a u32");
        rtrees.push(RTree {
            node_size_order,
            leaves: storage.slice(header.leaves),
            nodes: storage.slice(header.nodes),
            levels: storage.slice(header.levels),
            bbox: header.bbox,
        });
    }

    rtrees
}

pub struct MultiQueryIter<'storage, S: Spec, Q> {
    zones: Vec<QueryIter<'storage, S, Q>>,
}

impl<'storage, S: Spec, Q> MultiQueryIter<'storage, S, Q>
where
    S: Spec,
    Q: Query<S> + Clone,
{
    pub fn new(query: Q, rtrees: &[RTree<'storage, S>]) -> Self {
        let zones = rtrees
            .iter()
            .filter(|zone| query.clone().filter_node(&zone.bbox))
            .map(|zone| zone.query(query.clone()))
            .collect();
        Self { zones }
    }
}

impl<'storage, S: Spec, Q> Iterator for MultiQueryIter<'storage, S, Q>
where
    Q: Query<S>,
{
    type Item = &'storage S::Leaf;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let zone = self.zones.last_mut()?;
            match zone.next() {
                Some(leaf) => {
                    return Some(leaf);
                }
                None => {
                    self.zones.pop();
                }
            }
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct MemIntersects {
    node: MemNode,
}

impl Query<MemWriteSpec> for MemIntersects {
    fn filter_node(&mut self, node: &MemNode) -> bool {
        !self.node.is_disjoint(node)
    }
    fn filter_leaf(&mut self, leaf: &MemWriteLeaf) -> bool {
        !self.node.is_disjoint(&leaf.node)
    }
}

impl Query<MemReadSpec> for MemIntersects {
    fn filter_node(&mut self, node: &MemNode) -> bool {
        !self.node.is_disjoint(node)
    }
    fn filter_leaf(&mut self, leaf: &MemReadLeaf) -> bool {
        !self.node.is_disjoint(&leaf.node())
    }
}

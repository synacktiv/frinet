use frinet_db::{
    db::Metadata,
    format::{
        Addr, ByTimeChunk, ChunkKind, DbPlan, MemNode, RTreePlan, RegisterByTimePlan,
        RegisterByValuePlan, Time, U64OrOffset,
    },
    irange::IRange,
    register::{INTERNAL_REGISTERS, PC_REGISTER_IDX},
    rtree::Spec,
    scalar::{Scalar, ScalarSize},
    time_series::{
        CHUNK_LOG2, number_of_chunk_covering_a_time_range, time_range_covered_by_a_chunk,
    },
};
use hashbrown::HashMap;
use log::{debug, warn};

use crate::{
    disjoint::DisjointMemLeaf,
    parser::{Parser, ProgressReporter},
    pass::{Event, RegisterValue, parse_and_normalize_events},
};

pub struct ScoutPass {
    pub plan: DbPlan,
}

pub fn scout_pass<P>(
    mut parser: P,
    progress: &mut dyn ProgressReporter,
    node_size_order: u8,
) -> Result<ScoutPass, P::Err>
where
    P: Parser,
{
    let header = parser.header().clone();
    let mut data_bytes = 0;
    let mut write_zones = Vec::<RTreeScout<MemNode>>::new();
    let mut read_zones = Vec::<RTreeScout<MemNode>>::new();

    let register_count = INTERNAL_REGISTERS.len() + header.registers.len();
    let mut registers = vec![RegisterScout::default(); register_count];

    // index PC by_value
    registers[INTERNAL_REGISTERS.len() + PC_REGISTER_IDX].value_occurences = Some(HashMap::new());

    let time_end = parse_and_normalize_events(&mut parser, progress, |event| match event {
        Event::MemoryWrite(DisjointMemLeaf { node, bytes }) => {
            if bytes.len() > size_of::<U64OrOffset>() {
                // not inlined in the leaf
                data_bytes += bytes.len();
            }
            insert_node_into_zones(&mut write_zones, node);
        }
        Event::MemoryRead(leaf) => {
            insert_node_into_zones(&mut read_zones, leaf.node());
        }
        Event::Register { idx, time, value } => {
            registers[idx].push(time, value);
        }
    })?;

    let mut registers_by_time = Vec::with_capacity(registers.len());
    let mut registers_by_value = Vec::new();

    let register_sizes = INTERNAL_REGISTERS
        .iter()
        .map(|reg| reg.size())
        .chain(header.registers.iter().map(|info| info.scalar_size));

    for (idx, (reg_scout, size)) in registers.iter().zip(register_sizes).enumerate() {
        registers_by_time.push(reg_scout.by_time_plan(size, time_end));
        if let Some(plan) = reg_scout.by_value_plan(idx, size) {
            registers_by_value.push(plan);
        }
    }

    let metadata = Metadata {
        registers: header.registers,
        modules: header.modules,
        time_end,
    };

    if metadata.modules.is_empty() {
        warn!("no module in the trace header");
    }

    debug!("{} memory write zones", write_zones.len());
    debug!("{} memory read zones", read_zones.len());

    let plan = DbPlan {
        metadata_json: serde_json::to_string(&metadata).unwrap(),
        data_bytes,
        write_zones: tree_plans(write_zones, node_size_order),
        read_zones: tree_plans(read_zones, node_size_order),
        registers_by_time,
        registers_by_value,
    };

    Ok(ScoutPass { plan })
}

fn tree_plans<S: Spec>(scouts: Vec<RTreeScout<S::Node>>, node_size_order: u8) -> Vec<RTreePlan<S>> {
    scouts
        .into_iter()
        .map(|scout| RTreePlan::new(scout.bbox, scout.leaf_count, node_size_order))
        .collect()
}

fn insert_node_into_zones(zones: &mut Vec<RTreeScout<MemNode>>, node: MemNode) {
    let mut was_inserted = false;
    let mut conflict_found = false;

    for zone in zones.iter_mut() {
        let padded = zone.padded_addr_range();
        if !padded.is_disjoint(node.addr) {
            if was_inserted {
                conflict_found = true;
                break;
            }

            zone.bbox.extends_to_contain(&node);
            zone.leaf_count += 1;

            was_inserted = true;
        }
    }

    if conflict_found {
        let mut at_least_one_conflict_fixed = false;

        'find_conflict: loop {
            for i in 0..zones.len() {
                for j in i + 1..zones.len() {
                    let a = &zones[i];
                    let b = &zones[j];

                    let a_range = a.half_padded_addr_range();
                    let b_range = b.half_padded_addr_range();

                    if !a_range.is_disjoint(b_range) {
                        debug!("Zone conflict");
                        at_least_one_conflict_fixed = true;

                        // This is OK only if `i < j` and if the iteration restart from the beginning
                        debug_assert!(i < j);
                        let b = zones.swap_remove(j);
                        let a = &mut zones[i];

                        a.bbox.extends_to_contain(&b.bbox);
                        a.leaf_count += b.leaf_count;

                        continue 'find_conflict;
                    }
                }
            }

            debug_assert!(at_least_one_conflict_fixed);

            // no more conflict
            break;
        }
    }

    if !was_inserted {
        zones.push(RTreeScout {
            bbox: node,
            leaf_count: 1,
        });
    }
}

#[derive(Clone, Debug, Default)]
struct RegisterScout<'trace> {
    chunk_writes: Vec<u32>,
    first_write: Option<Time>,
    value_occurences: Option<HashMap<Scalar<'trace>, u32>>,
}

impl<'trace> RegisterScout<'trace> {
    fn push(&mut self, time: Time, value: RegisterValue<'trace>) {
        let chunk = (time >> CHUNK_LOG2) as usize;
        if chunk >= self.chunk_writes.len() {
            self.chunk_writes.resize(chunk + 1, 0);
        }
        self.chunk_writes[chunk] += 1;

        self.first_write.get_or_insert(time);
        if let Some(occurences) = &mut self.value_occurences {
            match value {
                RegisterValue::Scalar(value) => {
                    *occurences.entry(value).or_default() += 1;
                }
                RegisterValue::Module(_) => todo!("module register is not by-value indexable"),
            }
        }
    }

    /// `time_end`: end of the trace, inclusive
    fn by_time_plan(&self, size: ScalarSize, time_end: Time) -> RegisterByTimePlan {
        let Some(first_write) = self.first_write else {
            // never written: no chunk at all
            return RegisterByTimePlan {
                scalar_size: size,
                time_range: IRange::new(0, time_end),
                chunks: Vec::new(),
                local_time_pool_len: 0,
                value_pool_len: 0,
            };
        };

        let time_range = IRange::new(first_write, time_end);
        let first_chunk = (first_write >> CHUNK_LOG2) as usize;
        let count = number_of_chunk_covering_a_time_range(time_range);

        let mut chunks = Vec::with_capacity(count);
        let mut value_off = 0;
        let mut time_off = 0;

        for idx in 0..count {
            let writes = self
                .chunk_writes
                .get(first_chunk + idx)
                .copied()
                .unwrap_or(0);
            let steps = time_range_covered_by_a_chunk(time_range, idx).span_usize() as u32;

            // a dense chunk has a write at every step
            let kind = if writes == steps {
                ChunkKind::Dense
            } else {
                ChunkKind::Sparse
            };

            let local_time_len = match kind {
                ChunkKind::Dense => 0,
                ChunkKind::Sparse => writes,
            };

            chunks.push(ByTimeChunk {
                value_pool_offset: value_off,
                local_time_pool_offset: time_off,
                kind_pod: kind.into_pod(),
                _padding: Default::default(),
                local_time_len: u16::try_from(local_time_len).unwrap(),
            });

            value_off += match kind {
                ChunkKind::Dense => steps,
                ChunkKind::Sparse => writes,
            };
            time_off += local_time_len;
        }

        RegisterByTimePlan {
            scalar_size: size,
            time_range,
            chunks,
            local_time_pool_len: time_off as usize,
            value_pool_len: value_off as usize,
        }
    }

    fn by_value_plan(
        &self,
        register_idx: usize,
        scalar_size: ScalarSize,
    ) -> Option<RegisterByValuePlan> {
        let mut value_occurences: Vec<_> = self.value_occurences.as_ref()?.iter().collect();
        value_occurences.sort_unstable_by_key(|(value, _)| **value);

        let mut keys_le = Vec::with_capacity(value_occurences.len() * scalar_size.bytes());
        let mut offsets = Vec::with_capacity(value_occurences.len() + 1);
        offsets.push(0);

        for (value, occurence) in value_occurences {
            keys_le.extend_from_slice(value.0);
            offsets.push(offsets.last().unwrap() + u64::from(*occurence));
        }

        Some(RegisterByValuePlan {
            register_idx,
            scalar_size,
            keys_le,
            offsets,
        })
    }
}

#[derive(Clone, Debug, Default)]
struct RTreeScout<Node> {
    bbox: Node,
    leaf_count: usize,
}

/// Minimal address padding between zones
const ZONE_MIN_PADDING: u64 = 128 * GB;
const GB: u64 = 1024 * 1024 * 1024;

impl RTreeScout<MemNode> {
    fn padded_addr_range(&self) -> IRange<Addr> {
        IRange {
            min: self.bbox.addr.min.saturating_sub(ZONE_MIN_PADDING),
            max: self.bbox.addr.max.saturating_add(ZONE_MIN_PADDING),
        }
    }

    fn half_padded_addr_range(&self) -> IRange<Addr> {
        IRange {
            min: self.bbox.addr.min.saturating_sub(ZONE_MIN_PADDING / 2),
            max: self.bbox.addr.max.saturating_add(ZONE_MIN_PADDING / 2),
        }
    }
}

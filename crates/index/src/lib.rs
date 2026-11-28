use core::mem;

use frinet_db::format::{RTreeHeader, Section, StorageMut};
use log::debug;

use crate::hilbert_spec::HilbertSpec;
use crate::parser::{Parser, ParserGenerator, Pass, ProgressReporter};
use crate::pass::{fill_pass, hilbert_partition_pass, scout_pass};
use crate::storage::StorageBackend;

mod disjoint;
mod hilbert_spec;
mod pass;

pub mod parser;
pub mod storage;

/// Builds the database into `backend`, `Ok(false)` once `progress` is cancelled
pub fn build_index<Gen>(
    parser_gen: &mut Gen,
    progress: &mut dyn ProgressReporter,
    backend: &mut dyn StorageBackend,
    node_size_order: u8,
) -> Result<bool, <Gen::Parser as Parser>::Err>
where
    Gen: ParserGenerator,
{
    assert!(
        (1..=16).contains(&node_size_order),
        "node size order must be in 1..=16"
    );

    progress.start(Pass::Scout);
    let scout = scout_pass(parser_gen.generate()?, progress, node_size_order)?;
    if progress.is_cancelled() {
        return Ok(false);
    }
    let plan = &scout.plan;

    let storage_size = plan.storage_size();
    debug!("Storage size : {storage_size}");

    progress.start(Pass::Partitions);
    let partitions = hilbert_partition_pass(parser_gen.generate()?, progress, &scout)?;
    if progress.is_cancelled() {
        return Ok(false);
    }

    let mut storage = plan.init_storage(backend.allocate(storage_size));

    progress.start(Pass::Fill);
    let Some(fill) = fill_pass(parser_gen.generate()?, progress, &storage, &partitions)? else {
        return Ok(false);
    };
    let data_unused = plan.data_bytes - fill.data_used;

    // truncate data section
    storage.header_mut().data.item_len -= data_unused as u64;

    let header = *storage.header();
    compute_and_write_rtrees_nodes(&storage, header.write_zones);
    compute_and_write_rtrees_nodes(&storage, header.read_zones);

    // truncate unused trailing storage
    backend.truncate(storage_size - data_unused);

    Ok(true)
}

fn compute_and_write_rtrees_nodes<S: HilbertSpec>(
    storage: &StorageMut<'_>,
    rtrees: Section<RTreeHeader<S>>,
) {
    // SAFETY: R-Tree headers and leaves are only read, nodes of each tree are borrowed once
    unsafe {
        for rtree in storage.slice(rtrees) {
            let leaves = storage.slice(rtree.leaves);
            let nodes = storage.slice_mut(rtree.nodes);

            debug_assert!(
                leaves.is_sorted_by_key(|leaf| S::hilbert_key(leaf, &rtree.bbox)),
                "leaves must be sorted at this point"
            );

            build_intermediate_nodes_from_sorted_leaves::<S>(rtree.node_size_order, leaves, nodes);
        }
    }
}

fn build_intermediate_nodes_from_sorted_leaves<S>(
    node_size_order: u64,
    in_leaves: &[S::Leaf],
    out_nodes: &mut [S::Node],
) where
    S: HilbertSpec,
    S::Node: Copy,
{
    let node_size = 1 << node_size_order;
    let mut out_nodes = out_nodes.iter_mut();

    if in_leaves.len() > node_size {
        let level_size = in_leaves.len().div_ceil(node_size);
        let mut nodes = Vec::with_capacity(level_size);

        // first level : group leaves
        for children in in_leaves.chunks(node_size) {
            let bbox = S::bbox_of_leaves(children);
            *out_nodes.next().unwrap() = bbox;
            nodes.push(bbox);
        }
        assert_eq!(nodes.len(), level_size);

        // next levels : group nodes
        let mut prev_nodes = nodes;
        let mut nodes = Vec::new();
        loop {
            if prev_nodes.len() <= node_size {
                break;
            }

            for children in prev_nodes.chunks(node_size) {
                let bbox = S::bbox_of_nodes(children);
                *out_nodes.next().unwrap() = bbox;
                nodes.push(bbox);
            }

            mem::swap(&mut prev_nodes, &mut nodes);
            nodes.clear();
        }
    }
}

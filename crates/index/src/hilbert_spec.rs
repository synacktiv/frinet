use std::hash::Hash;

use frinet_db::format::{Addr, MemNode, Time};
use frinet_db::irange::IRange;
use frinet_db::memory::{MemReadSpec, MemWriteSpec};
use frinet_db::rtree::Spec;

pub trait HilbertSpec: Spec {
    type Key: Copy + Send + Sync + Ord + Hash;

    fn bbox_of_leaves(leaves: &[Self::Leaf]) -> Self::Node;
    fn bbox_of_nodes(nodes: &[Self::Node]) -> Self::Node;
    fn hilbert_key(leaf: &Self::Leaf, bbox: &Self::Node) -> Self::Key;
    fn hilbert_partition_key(leaf: &Self::Leaf, bbox: &Self::Node) -> u8;
    fn leaf_time_range(leaf: &Self::Leaf) -> IRange<Time>;
}

impl HilbertSpec for MemWriteSpec {
    type Key = u128;

    fn bbox_of_leaves(leaves: &[Self::Leaf]) -> Self::Node {
        let mut iter = leaves.iter();
        let mut bbox = iter.next().expect("bbox of empty list").node;
        for leaf in iter {
            bbox.extends_to_contain(&leaf.node);
        }
        bbox
    }

    fn bbox_of_nodes(nodes: &[Self::Node]) -> Self::Node {
        let mut iter = nodes.iter();
        let mut bbox = *iter.next().expect("bbox of empty list");
        for node in iter {
            bbox.extends_to_contain(node);
        }
        bbox
    }

    fn hilbert_key(leaf: &Self::Leaf, bbox: &Self::Node) -> Self::Key {
        let [addr, time] = mem_hilbert_coordinates(&leaf.node, bbox);
        fast_hilbert::xy2h(addr, time, 64)
    }

    fn hilbert_partition_key(leaf: &Self::Leaf, bbox: &Self::Node) -> u8 {
        let [addr, time] = mem_hilbert_coordinates(&leaf.node, bbox);

        // keep high 4-bits
        let addr = (addr >> 60) as u8;
        let time = (time >> 60) as u8;

        fast_hilbert::xy2h(addr, time, 4) as u8
    }

    fn leaf_time_range(leaf: &Self::Leaf) -> IRange<Time> {
        leaf.node.time
    }
}

impl HilbertSpec for MemReadSpec {
    type Key = u128;

    fn bbox_of_leaves(leaves: &[Self::Leaf]) -> Self::Node {
        let mut iter = leaves.iter();
        let mut bbox = iter.next().expect("bbox of empty list").node();
        for leaf in iter {
            bbox.extends_to_contain(&leaf.node());
        }
        bbox
    }

    fn bbox_of_nodes(nodes: &[Self::Node]) -> Self::Node {
        MemWriteSpec::bbox_of_nodes(nodes)
    }

    fn hilbert_key(leaf: &Self::Leaf, bbox: &Self::Node) -> Self::Key {
        let [addr, time] = mem_hilbert_coordinates(&leaf.node(), bbox);
        fast_hilbert::xy2h(addr, time, 64)
    }

    fn hilbert_partition_key(leaf: &Self::Leaf, bbox: &Self::Node) -> u8 {
        let [addr, time] = mem_hilbert_coordinates(&leaf.node(), bbox);

        // keep high 4-bits
        let addr = (addr >> 60) as u8;
        let time = (time >> 60) as u8;

        fast_hilbert::xy2h(addr, time, 4) as u8
    }

    fn leaf_time_range(leaf: &Self::Leaf) -> IRange<Time> {
        IRange::one(leaf.time)
    }
}

fn mem_hilbert_coordinates(node: &MemNode, bbox: &MemNode) -> [u64; 2] {
    let addr_bits = bbox.addr.span_bits();
    let time_bits = bbox.time.span_bits();

    let mut addr = node.addr.min.midpoint(node.addr.max);
    let mut time = node.time.min.midpoint(node.time.max);

    // spread coordinate across the bounding box
    addr -= bbox.addr.min;
    time -= bbox.time.min;
    addr <<= Addr::BITS - addr_bits;
    time <<= Time::BITS - time_bits;

    // spread time over 64 bit
    let time = (time as u64) << 32;

    [addr, time]
}

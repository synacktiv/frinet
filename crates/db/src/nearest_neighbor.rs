use std::{cmp::Reverse, collections::BinaryHeap};

use crate::rtree::{RTree, Spec};

/// Generic nearest neighbor search through a [RTree]
pub fn nearest_neighbor<'s, S: Spec, K: Ord>(
    rtree: &RTree<'s, S>,
    visit_node: impl Fn(&S::Node) -> Status<K>,
    visit_leaf: impl Fn(&S::Leaf) -> Status<K>,
) -> Option<&'s S::Leaf> {
    let mut heap = BinaryHeap::<Item<K>>::new();
    let group_size = rtree.node_size();

    if let Some(nodes) = rtree.root_nodes() {
        assert!(nodes.len() <= group_size);
        visit_nodes(rtree, &mut heap, &visit_node, nodes, 0, 0);
    } else {
        assert!(rtree.leaves.len() <= group_size);
        visit_leaves(rtree, &mut heap, &visit_leaf, 0);
    }

    while let Some(item) = heap.pop() {
        // Check if the item is a node or a leaf
        if item.level < rtree.depth() {
            let next_start = item.idx << rtree.node_size_order;

            match rtree.level_nodes(item.level + 1) {
                Some(next_level) => {
                    visit_nodes(
                        rtree,
                        &mut heap,
                        &visit_node,
                        next_level,
                        item.level + 1,
                        next_start,
                    );
                }
                None => {
                    visit_leaves(rtree, &mut heap, &visit_leaf, next_start);
                }
            }
        } else {
            return Some(&rtree.leaves[item.idx]);
        }
    }

    None
}

fn visit_nodes<'s, S: Spec, K: Ord>(
    rtree: &RTree<'s, S>,
    heap: &mut BinaryHeap<Item<K>>,
    visit_node: &impl Fn(&S::Node) -> Status<K>,
    level_nodes: &'s [S::Node],
    level: usize,
    start_idx: usize,
) {
    let group_size = rtree.node_size();

    for (idx, node) in level_nodes
        .iter()
        .enumerate()
        .skip(start_idx)
        .take(group_size)
    {
        match visit_node(node) {
            Status::Keep(min_key) => {
                heap.push(Item {
                    min_key: Reverse(min_key),
                    level,
                    idx,
                });
            }
            Status::Ignore => {}
        }
    }
}

fn visit_leaves<'s, S: Spec, K: Ord>(
    rtree: &RTree<'s, S>,
    heap: &mut BinaryHeap<Item<K>>,
    visit_leaf: &impl Fn(&S::Leaf) -> Status<K>,
    start_idx: usize,
) {
    let level = rtree.depth();
    let group_size = rtree.node_size();

    for (idx, leaf) in rtree
        .leaves
        .iter()
        .enumerate()
        .skip(start_idx)
        .take(group_size)
    {
        match visit_leaf(leaf) {
            Status::Keep(min_key) => {
                heap.push(Item {
                    min_key: Reverse(min_key),
                    level,
                    idx,
                });
            }
            Status::Ignore => {}
        }
    }
}

pub enum Status<K> {
    Keep(K),
    Ignore,
}

/// Ordered in the order the heap must pop them, the field order being the comparison
#[derive(PartialEq, Eq, PartialOrd, Ord)]
struct Item<K> {
    /// Reversed: the heap pops the greatest, the nearest key must come out first
    min_key: Reverse<K>,
    /// Then the deepest level, the closest to a leaf
    level: usize,
    idx: usize,
}

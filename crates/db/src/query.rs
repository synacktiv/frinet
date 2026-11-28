use std::iter::Enumerate;

use crate::rtree::*;

impl<'storage, S: Spec> RTree<'storage, S> {
    /// Query using the specified strategy
    pub fn query<Q>(&self, query: Q) -> QueryIter<'storage, S, Q>
    where
        Q: Query<S>,
    {
        QueryIter::new(*self, query)
    }
}

pub trait Query<S: Spec> {
    /// Return true if this node is worth visiting
    fn filter_node(&mut self, node: &S::Node) -> bool;

    /// Return true if this leaf match the query
    fn filter_leaf(&mut self, leaf: &S::Leaf) -> bool;
}

/// A lazy traversal using a specific strategy
pub struct QueryIter<'storage, S: Spec, Q> {
    rtree: RTree<'storage, S>,
    query: Q,
    level_iters: Vec<Enumerate<core::slice::Iter<'storage, S::Node>>>,
    leaf_iter: Option<core::slice::Iter<'storage, S::Leaf>>,
    /// Current absolute position in the tree
    pos: usize,
}

impl<'storage, S, Q> QueryIter<'storage, S, Q>
where
    S: Spec,
    Q: Query<S>,
{
    /// Build a new query
    fn new(rtree: RTree<'storage, S>, query: Q) -> Self {
        let mut level_iters = Vec::with_capacity(rtree.depth());
        let mut leaf_iter = None;

        if let Some(roots) = rtree.root_nodes() {
            level_iters.push(roots.iter().enumerate());
        } else {
            leaf_iter = Some(rtree.leaves.iter());
        }

        Self {
            level_iters,
            leaf_iter,
            query,
            rtree,
            pos: 0,
        }
    }
}

impl<'storage, S, Q> Iterator for QueryIter<'storage, S, Q>
where
    S: Spec,
    Q: Query<S>,
{
    type Item = &'storage S::Leaf;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let node_size_order = self.rtree.node_size_order;
            let node_size = self.rtree.node_size();

            if let Some(leaf_iter) = &mut self.leaf_iter {
                match leaf_iter.next() {
                    Some(leaf) => {
                        if !self.query.filter_leaf(leaf) {
                            continue;
                        }
                        // we found a match !
                        break Some(leaf);
                    }
                    None => {
                        self.leaf_iter = None;

                        self.pos >>= node_size_order;

                        // erase += child_idx
                        self.pos >>= node_size_order;
                        self.pos <<= node_size_order;
                    }
                }
            }

            if self.level_iters.is_empty() {
                assert_eq!(self.pos, 0);
                return None; // query end
            }

            let level = self.level_iters.len() - 1;
            let iter = self.level_iters.last_mut()?;

            match iter.next() {
                Some((child_idx, rect)) => {
                    if !self.query.filter_node(rect) {
                        continue;
                    }

                    self.pos += child_idx;
                    self.pos <<= node_size_order;

                    let start = self.pos;
                    let max_end = start + node_size;

                    if let Some(next_level_nodes) = self.rtree.level_nodes(level + 1) {
                        // Push the next level iterator
                        let end = max_end.min(next_level_nodes.len());

                        let children = &next_level_nodes[start..end];
                        self.level_iters.push(children.iter().enumerate());
                    } else {
                        // Push leave iterator
                        let leaves = self.rtree.leaves;
                        let end = max_end.min(leaves.len());

                        let children = &leaves[start..end];
                        self.leaf_iter = Some(children.iter());
                    }
                }
                None => {
                    // The current level iterator is over, pop it and loop
                    let _ = self.level_iters.pop().expect("should never fail");
                    self.pos >>= node_size_order;

                    // erase += child_idx
                    self.pos >>= node_size_order;
                    self.pos <<= node_size_order;
                }
            }
        }
    }
}

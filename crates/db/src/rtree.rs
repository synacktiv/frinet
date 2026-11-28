use core::fmt::Debug;

use crate::format::{Level, Pod};

/// R-Tree specification
pub trait Spec: 'static {
    /// R-Tree node
    type Node: Pod + Debug;
    /// R-Tree leaf
    type Leaf: Pod + Debug;
}

/// Packed R-Tree
#[derive(Debug)]
pub struct RTree<'storage, S: Spec> {
    /// node_size = 1 << node_size_order
    pub node_size_order: u32,

    pub leaves: &'storage [S::Leaf],
    pub nodes: &'storage [S::Node],

    /// Range of `self.nodes` per level, root first
    pub levels: &'storage [Level],

    /// Bounding box of all leaves
    pub bbox: S::Node,
}

impl<'storage, S: Spec> Clone for RTree<'storage, S> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<S: Spec> Copy for RTree<'_, S> {}

impl<'storage, S: Spec> RTree<'storage, S> {
    /// Number of intermediate node level (without leaves)
    pub fn depth(&self) -> usize {
        self.levels.len()
    }

    /// Number of children per node
    pub fn node_size(&self) -> usize {
        debug_assert!(self.node_size_order < usize::BITS);
        1_usize << self.node_size_order
    }

    /// Nodes of a level, root first, [None] past [Self::depth]
    pub fn level_nodes(&self, level: usize) -> Option<&'storage [S::Node]> {
        let level = self.levels.get(level)?;
        Some(&self.nodes[level.offset as usize..][..level.size as usize])
    }

    /// Nodes of the root level, returns [None] if there are less leaves than `node_size`
    pub fn root_nodes(&self) -> Option<&'storage [S::Node]> {
        self.level_nodes(0)
    }
}

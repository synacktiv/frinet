use std::collections::BTreeMap;

use frinet_db::{
    format::{Addr, MemNode, Time},
    irange::IRange,
};

/// Pass over memory write leaves, producing a stream of [DisjointMemLeaf]
#[derive(Default)]
pub struct DisjointPass<'trace> {
    current_time: Time,
    /// Temporary leaves by start address
    temporaries: BTreeMap<Addr, TemporaryLeaf<'trace>>,

    // keep vecs around to save some allocations
    to_remove: Vec<Addr>,
    to_add: Vec<TemporaryLeaf<'trace>>,
    fragments: Vec<MemNode>,
}

/// Output of [DisjointPass]
pub struct DisjointMemLeaf<'trace> {
    pub node: MemNode,
    pub bytes: &'trace [u8],
}

struct TemporaryLeaf<'trace> {
    time_min: Time,
    addr_min: Addr,
    bytes: &'trace [u8],
}

impl<'trace> TemporaryLeaf<'trace> {
    /// Inclusive addr_max
    fn addr_max(&self) -> Addr {
        self.addr_min + self.bytes.len() as Addr - 1
    }

    fn complete(&self, time_max: Time) -> DisjointMemLeaf<'trace> {
        DisjointMemLeaf {
            node: MemNode {
                time: IRange::new(self.time_min, time_max),
                addr: IRange::new(self.addr_min, self.addr_max()),
            },
            bytes: self.bytes,
        }
    }

    fn mask_with_bbox(&self, bbox: MemNode) -> Self {
        debug_assert!(self.time_min <= bbox.time.min);
        debug_assert!(self.addr_min <= bbox.addr.min);
        debug_assert!(bbox.addr.max <= self.addr_max());
        debug_assert!(bbox.addr.span_usize() <= self.bytes.len());

        let mask_offset = (bbox.addr.min - self.addr_min) as usize;
        let mask_size = bbox.addr.span_usize();

        Self {
            time_min: bbox.time.min,
            addr_min: bbox.addr.min,
            bytes: &self.bytes[mask_offset..][..mask_size],
        }
    }
}

impl<'trace> DisjointPass<'trace> {
    pub fn push_memory_write<EmitLeaf>(
        &mut self,
        time: Time,
        addr: Addr,
        bytes: &'trace [u8],
        can_dedup: bool,
        mut emit_leaf: EmitLeaf,
    ) where
        EmitLeaf: FnMut(DisjointMemLeaf<'trace>),
    {
        // checked by the caller
        debug_assert!(!bytes.is_empty());
        debug_assert!(self.current_time <= time);

        self.current_time = time;

        if can_dedup && self.is_duplicate_write(addr, bytes) {
            return;
        }

        let addr_range = IRange::from_start_len(addr, bytes.len() as _);

        let new = TemporaryLeaf {
            time_min: time,
            addr_min: addr,
            bytes,
        };

        let new_rect = new.complete(Time::MAX).node;

        for existing in Self::iter_temporaries_in_range(&self.temporaries, addr_range) {
            let existing_rect = existing.complete(Time::MAX).node;
            debug_assert!(!existing_rect.is_disjoint(&new_rect));

            // track if it will be replaced by a fragment with `.insert(...)`
            let mut will_be_replaced = false;

            existing_rect.fragment_by(&new_rect, &mut self.fragments);

            for fragment in self.fragments.drain(..) {
                debug_assert!(
                    !existing_rect.is_disjoint(&fragment),
                    "'fragment' must be contained inside 'existing'"
                );
                debug_assert!(
                    new_rect.is_disjoint(&fragment),
                    "'fragment' must be disjoint from 'new'"
                );

                let existing_masked = existing.mask_with_bbox(fragment);
                if fragment.time.max == Time::MAX {
                    // add fragment to the working set
                    if existing_rect.addr.min == existing_masked.addr_min {
                        will_be_replaced = true;
                    }
                    self.to_add.push(existing_masked);
                } else {
                    // emit the fragment as a leaf
                    let leaf = existing_masked.complete(fragment.time.max);
                    emit_leaf(leaf);
                }
            }

            if !will_be_replaced {
                self.to_remove.push(existing_rect.addr.min);
            }
        }

        for min_addr in self.to_remove.drain(..) {
            self.temporaries.remove(&min_addr);
        }
        for partial in self.to_add.drain(..) {
            self.temporaries.insert(partial.addr_min, partial);
        }

        self.temporaries.insert(new.addr_min, new);
    }

    /// Emits the leaves that are never overwritten, they last until `time_end` (end of the trace)
    pub fn finish<EmitLeaf>(self, time_end: Time, mut emit_leaf: EmitLeaf)
    where
        EmitLeaf: FnMut(DisjointMemLeaf<'trace>),
    {
        debug_assert!(self.current_time <= time_end);

        for partial in self.temporaries.values() {
            let leaf = partial.complete(time_end);
            emit_leaf(leaf);
        }
    }

    fn is_duplicate_write(&self, addr: Addr, check_bytes: &[u8]) -> bool {
        let check_range = IRange::from_start_len(addr, check_bytes.len() as _);

        let mut cursor = check_range.min;
        for tmp in Self::iter_temporaries_in_range(&self.temporaries, check_range) {
            if cursor < tmp.addr_min {
                return false; // the byte at `cursor` is unknown
            }

            debug_assert!(tmp.addr_min <= cursor);
            debug_assert!(cursor <= tmp.addr_max());

            let iter_from = cursor;
            let iter_to = tmp.addr_max().min(check_range.max);

            for check_addr in iter_from..=iter_to {
                debug_assert!(tmp.addr_min <= check_addr);
                debug_assert!(check_addr <= tmp.addr_max());

                let check_byte = check_bytes[(check_addr - check_range.min) as usize];
                let tmp_byte = tmp.bytes[(check_addr - tmp.addr_min) as usize];

                if check_byte != tmp_byte {
                    return false;
                }
            }

            if iter_to == check_range.max {
                return true;
            }

            cursor = iter_to + 1;
        }

        false
    }

    fn iter_temporaries_in_range<'a>(
        temporaries: &'a BTreeMap<Addr, TemporaryLeaf<'trace>>,
        query_range: IRange<Addr>,
    ) -> impl Iterator<Item = &'a TemporaryLeaf<'trace>> {
        // TODO : rewrite with the cursor api when it become stable
        // (https://github.com/rust-lang/rust/issues/107540)

        let query_min = query_range.min;
        let query_max = query_range.max;

        let mut iter_from = query_min;

        // temporaries are indexes by their `addr_min`,
        // if `query_min` is in the middle of a temporary,
        // include it in the result
        if let Some((_, tmp)) = temporaries.range(..query_min).next_back()
            && query_min <= tmp.addr_max()
        {
            iter_from = tmp.addr_min;
        }

        temporaries
            .range(iter_from..)
            .map(|it| it.1)
            .take_while(move |it| it.addr_min <= query_max)
    }
}

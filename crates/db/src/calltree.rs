use itertools::Itertools;

use crate::db::Db;
use crate::format::{Addr, Time};
use crate::register::Register;
use crate::scalar::Scalar;
use crate::task::Task;

pub const MAX_SPANS: usize = 1 << 24;

pub const PROGRESS_INTERVAL: usize = 1 << 18;

pub const NO_PARENT: u32 = u32::MAX;

/// The instructions the build looks for in the PC
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Points {
    /// First instructions of the functions
    pub entries: Vec<Addr>,
    /// Instructions leaving their function: returns and jumps out of it
    pub exits: Vec<Addr>,
    /// Calls, with the address they return to
    pub calls: Vec<(Addr, Addr)>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Span {
    pub entrypoint: Addr,
    pub time_min: Time,
    pub time_max: Time,
    pub parent: u32,
    pub subtree_end: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Calltree {
    pub spans: Vec<Span>,
    pub complete: bool,
}

impl Calltree {
    pub fn children(&self, span: Option<u32>) -> Children<'_> {
        let (next, end) = match span {
            None => (0, self.spans.len() as u32),
            Some(index) => (index + 1, self.spans[index as usize].subtree_end),
        };
        Children {
            spans: &self.spans,
            next,
            end,
        }
    }

    pub fn span_at(&self, time: Time) -> Option<u32> {
        let after = self.spans.partition_point(|span| span.time_min <= time);
        let mut index = u32::try_from(after.checked_sub(1)?).ok()?;

        loop {
            let span = &self.spans[index as usize];
            if span.time_max >= time {
                return Some(index);
            }
            if span.parent == NO_PARENT {
                return None;
            }
            index = span.parent;
        }
    }

    /// [None] past the end of the tree
    pub fn span(&self, index: u32) -> Option<&Span> {
        self.spans.get(index as usize)
    }

    pub fn has_children(&self, index: u32) -> bool {
        self.at(index).subtree_end > index + 1
    }

    /// Number of ancestors of `index`, 0 for a root
    pub fn depth(&self, index: u32) -> usize {
        let mut depth = 0;
        let mut parent = self.at(index).parent;
        while parent != NO_PARENT {
            depth += 1;
            parent = self.at(parent).parent;
        }
        depth
    }

    /// Spans from the root down to the parent of `index`
    pub fn ancestors(&self, index: u32) -> Vec<u32> {
        let mut chain = Vec::new();
        let mut parent = self.at(index).parent;
        while parent != NO_PARENT {
            chain.push(parent);
            parent = self.at(parent).parent;
        }
        chain.reverse();
        chain
    }

    /// Time after the call the instruction at `time` makes, or the next instruction
    pub fn step_over(&self, time: Time) -> Time {
        let next = time.saturating_add(1);

        if let (Some(span), Some(called)) = (self.span_at(time), self.span_at(next)) {
            let child = self.at(called);
            if child.parent == span {
                // the next instruction is inside a call: skip all of it
                return child.time_max.saturating_add(1);
            }
        }

        next
    }

    /// Time before the call returning just before `time`, or the previous instruction
    pub fn step_back_over(&self, time: Time) -> Time {
        let prev = time.saturating_sub(1);

        let (Some(span), Some(mut called)) = (self.span_at(time), self.span_at(prev)) else {
            return prev;
        };

        // the previous instruction may be anywhere inside a call made by this span
        while called != span {
            let child = self.at(called);
            if child.parent == span {
                return child.time_min.saturating_sub(1);
            }
            if child.parent == NO_PARENT {
                break;
            }
            called = child.parent;
        }

        prev
    }

    /// Time after the span holding at `time` returns
    pub fn step_out(&self, time: Time) -> Time {
        match self.span_at(time) {
            Some(index) => self.at(index).time_max.saturating_add(1),
            None => time.saturating_add(1),
        }
    }

    fn at(&self, index: u32) -> &Span {
        &self.spans[index as usize]
    }
}

pub struct Children<'a> {
    spans: &'a [Span],
    next: u32,
    end: u32,
}

impl Iterator for Children<'_> {
    type Item = u32;

    fn next(&mut self) -> Option<u32> {
        if self.next >= self.end {
            return None;
        }
        let index = self.next;
        self.next = self.spans[index as usize].subtree_end;
        Some(index)
    }
}

/// Walks the times the PC reaches `points`, reporting its progress in visits, [None] once
/// cancelled
pub fn build(db: &Db, points: &Points, task: &Task) -> Option<Calltree> {
    let mut builder = Builder::default();
    let Some((pc, time_range)) = db.pc().and_then(|pc| Some((pc, pc.time_range()?))) else {
        return Some(builder.finish(0, true));
    };
    let pc_at = |time: Time| pc.value_at(time)?.try_into_u64();
    let next_pc = |time: Time| pc_at(time.checked_add(1)?);

    if let Some(first) = pc_at(time_range.min) {
        builder.push(first, time_range.min, None);
    }

    let visits: Vec<_> = points
        .events()
        .map(|(addr, event)| (times_at(pc, addr), event))
        .collect();
    task.set_total(visits.iter().map(|(times, _)| times.len()).sum());

    let events = visits
        .into_iter()
        .map(|(times, event)| times.iter().map(move |&time| (time, event)))
        .kmerge();

    for (done, (time, event)) in events.enumerate() {
        if done.is_multiple_of(PROGRESS_INTERVAL) {
            if task.is_cancelled() {
                return None;
            }
            task.set_done(done);
        }
        if builder.spans.len() >= MAX_SPANS {
            return Some(builder.finish(time_range.max, false));
        }
        builder.handle(time, event, next_pc);
    }

    Some(builder.finish(time_range.max, true))
}

fn times_at<'s>(pc: &Register<'s>, addr: Addr) -> &'s [Time] {
    let bytes = addr.to_le_bytes();
    let (value, high) = bytes.split_at(pc.scalar_size.bytes().min(bytes.len()));
    if high.iter().any(|&byte| byte != 0) {
        return &[];
    }
    pc.times_with(Scalar(value)).unwrap_or_default()
}

/// What the PC reaching a point means, the events of one step handled in this order
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Event {
    Resume(Addr),
    Entry(Addr),
    Exit,
    Call(Addr),
}

impl Points {
    fn events(&self) -> impl Iterator<Item = (Addr, Event)> + '_ {
        let entries = self.entries.iter().map(|&addr| (addr, Event::Entry(addr)));
        let exits = self.exits.iter().map(|&addr| (addr, Event::Exit));
        let calls = self.calls.iter().flat_map(|&(addr, resume)| {
            [(addr, Event::Call(resume)), (resume, Event::Resume(resume))]
        });
        entries.chain(exits).chain(calls)
    }
}

#[derive(Default)]
struct Builder {
    spans: Vec<Span>,
    open: Vec<Open>,
}

struct Open {
    span: u32,
    resume: Option<Addr>,
    /// Running outside the entries: it ends when its call returns
    external: bool,
}

impl Builder {
    fn handle(&mut self, time: Time, event: Event, next_pc: impl Fn(Time) -> Option<Addr>) {
        match event {
            Event::Resume(resume) => {
                if let Some(depth) = self.returning_to(resume)
                    && self.open[depth].external
                {
                    self.close_from(depth, time.saturating_sub(1));
                }
            }
            Event::Entry(addr) => match self.open.last_mut() {
                Some(open) if self.spans[open.span as usize].time_min == time => {
                    open.external = false;
                }
                _ => self.push(addr, time, None),
            },
            Event::Exit => {
                if let Some(depth) = next_pc(time).and_then(|to| self.returning_to(to)) {
                    self.close_from(depth, time);
                } else if let Some(open) = self.open.last_mut()
                    && open.resume.is_some()
                {
                    open.external = true;
                } else if let Some(top) = self.open.len().checked_sub(1) {
                    self.close_from(top, time);
                }
            }
            Event::Call(resume) => {
                if let Some(target) = next_pc(time) {
                    self.push(target, time + 1, Some(resume));
                }
            }
        }
    }

    fn finish(mut self, time_end: Time, complete: bool) -> Calltree {
        self.close_from(0, time_end);
        Calltree {
            spans: self.spans,
            complete,
        }
    }

    fn push(&mut self, entrypoint: Addr, time: Time, resume: Option<Addr>) {
        let index = self.spans.len() as u32;
        self.spans.push(Span {
            entrypoint,
            time_min: time,
            time_max: time,
            parent: self.open.last().map_or(NO_PARENT, |open| open.span),
            subtree_end: index + 1,
        });
        self.open.push(Open {
            span: index,
            resume,
            external: resume.is_some(),
        });
    }

    fn returning_to(&self, addr: Addr) -> Option<usize> {
        self.open.iter().rposition(|open| open.resume == Some(addr))
    }

    fn close_from(&mut self, depth: usize, time_max: Time) {
        let subtree_end = self.spans.len() as u32;
        for open in self.open.drain(depth..) {
            let span = &mut self.spans[open.span as usize];
            span.time_max = time_max;
            span.subtree_end = subtree_end;
        }
    }
}

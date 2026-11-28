use std::{
    cmp::Ordering,
    sync::mpsc::{self, Sender},
    thread,
};

use frinet_regex::{Dfa, State, determine_and_minimize_nfa, hir_to_nfa};
use itertools::Itertools;
use log::{Level, debug, error, log_enabled, trace};
use rayon::{
    Scope,
    iter::{IntoParallelRefIterator, ParallelIterator},
    slice::ParallelSliceMut,
};
use regex_syntax::{
    ParserBuilder,
    hir::{Hir, HirKind},
};
use rustc_hash::{FxHashMap, FxHashSet};
use smallvec::SmallVec;

use crate::{
    db::Db,
    format::{Addr, MemWriteLeaf, Time},
    irange::IRange,
    memory::MemWriteRTree,
    task::Task,
};

pub struct Pattern(Hir);

#[derive(Debug)]
pub enum PatternError {
    Syntax(Box<regex_syntax::Error>),
    Unsupported(&'static str),
}

impl std::fmt::Display for PatternError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PatternError::Syntax(err) => write!(f, "{err}"),
            PatternError::Unsupported(what) => write!(f, "{what} is not supported"),
        }
    }
}

impl std::error::Error for PatternError {}

impl From<regex_syntax::Error> for PatternError {
    fn from(err: regex_syntax::Error) -> Self {
        PatternError::Syntax(Box::new(err))
    }
}

impl Pattern {
    pub fn literal(needle: &[u8]) -> Result<Self, PatternError> {
        let hir = Hir::literal(needle);
        check_supported(&hir)?;
        Ok(Self(hir))
    }

    pub fn parse(regex: &str) -> Result<Self, PatternError> {
        let mut parser = ParserBuilder::default().unicode(false).utf8(false).build();
        let hir = parser.parse(regex)?;
        check_supported(&hir)?;
        Ok(Self(hir))
    }
}

/// Rejects what [hir_to_nfa] panics on, before a search thread runs it
fn check_supported(hir: &Hir) -> Result<(), PatternError> {
    match hir.kind() {
        HirKind::Empty => Err(PatternError::Unsupported("empty pattern")),
        HirKind::Literal(lit) if lit.0.is_empty() => {
            Err(PatternError::Unsupported("empty pattern"))
        }
        HirKind::Look(_) => Err(PatternError::Unsupported("look-around (`^`, `$`, `\\b`)")),
        HirKind::Literal(_) | HirKind::Class(_) => Ok(()),
        HirKind::Repetition(repetition) => check_supported(&repetition.sub),
        HirKind::Capture(capture) => check_supported(&capture.sub),
        HirKind::Concat(subs) | HirKind::Alternation(subs) => {
            subs.iter().try_for_each(check_supported)
        }
    }
}

type TransitionTable = FxHashMap<(State, u8), State>;

#[derive(Debug, Hash, PartialEq, Eq, Clone)]
struct Chain {
    from: State,
    half: ChainHalf,
}

#[derive(Debug, Hash, PartialEq, Eq, Clone)]
struct ChainHalf {
    to: Handle,
    addr_range: IRange<Addr>,
    time_range: IRange<Time>,
}

impl Chain {
    pub fn key(&self) -> ChainKey {
        ChainKey {
            addr_start: self.half.addr_range.min,
            time_start: self.half.time_range.min,
            state: self.from,
        }
    }
}

impl ChainHalf {
    pub fn connect(&self, other: &Self) -> Option<Self> {
        let time_range = self.time_range.intersection(&other.time_range)?;
        Some(ChainHalf {
            addr_range: IRange::new(self.addr_range.min, other.addr_range.max),
            to: other.to,
            time_range,
        })
    }
}

#[derive(Debug, Hash, PartialEq, Eq, Clone, Copy)]
enum Handle {
    Tip,
    State(State),
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
struct ChainKey {
    addr_start: Addr,
    time_start: Time,
    state: State,
}

#[derive(PartialEq, Eq, Debug, Clone)]
pub struct SearchMatch {
    pub addr_min: Addr,
    pub addr_max: Addr,
    pub time_min: Time,
    pub time_max: Time,
}

impl ChainKey {
    fn exact_key(&self) -> (State, Addr) {
        (self.state, self.addr_start)
    }
    fn order_key(&self) -> Time {
        self.time_start
    }
}

impl PartialOrd for ChainKey {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ChainKey {
    fn cmp(&self, other: &Self) -> Ordering {
        let exact_self = self.exact_key();
        let exact_other = other.exact_key();

        match exact_self.cmp(&exact_other) {
            Ordering::Equal => {
                let order_self = self.order_key();
                let order_other = other.order_key();
                order_self.cmp(&order_other)
            }
            ordering => ordering,
        }
    }
}

/// Searches every memory snapshot, reporting its progress in leaves of the memory index
pub fn search_pattern(db: &Db<'_>, Pattern(hir): &Pattern, task: &Task) -> Vec<SearchMatch> {
    debug!("Building NFA");
    let nfa = hir_to_nfa(hir);

    debug!("Building Minimal DFA");
    let dfa = determine_and_minimize_nfa(nfa);

    // dfa should have only one `inital_state`
    assert_eq!(
        dfa.initial_states.len(),
        1,
        "DFA should have exactly one 'initial_state'"
    );

    let initial_state: State = dfa.initial_state();
    let non_special_states: Vec<_> = dfa.non_special_states().unique().collect();

    if dfa.accept_states.contains(&initial_state) {
        error!("fully optional regex given (the initial state is an accepting state)");
        return Vec::new();
    }

    debug!("DFA non special states : {}", non_special_states.len());
    debug!("DFA accepting states : {}", dfa.accept_states.len());

    // Build fast transition lookup table to execute the DFA
    let mut transition_table = TransitionTable::default();
    for link in &dfa.links {
        transition_table.insert((link.from, link.symbol), link.to);
    }

    if log_enabled!(Level::Trace) {
        trace!("initial state = s{initial_state}");
        for s in &dfa.accept_states {
            trace!("accept state = s{s}");
        }

        for ((from, sym), to) in &transition_table {
            if let Some(c) = char::from_u32(*sym as _) {
                trace!("s{from} + {c:#?} => s{to}")
            } else {
                trace!("s{from} + {sym:#x} => s{to}")
            }
        }
    }

    let leaves = db.write_zones.iter().map(|zone| zone.leaves.len()).sum();
    task.set_total(leaves);

    let mut matches = Vec::new();
    for zone in &db.write_zones {
        if task.is_cancelled() {
            break;
        }

        matches.extend(search_in_zone(
            db,
            zone,
            &dfa,
            initial_state,
            &non_special_states,
            &transition_table,
            task,
        ));
    }

    matches
}

fn search_in_zone(
    db: &Db<'_>,
    zone: &MemWriteRTree<'_>,
    dfa: &Dfa<u8>,
    initial_state: State,
    non_special_states: &[State],
    transition_table: &TransitionTable,
    task: &Task,
) -> Vec<SearchMatch> {
    let mut chain_starts = Vec::new();
    let mut ordered_chains = Vec::new();

    thread::scope(|scope| {
        let chains_starts = &mut chain_starts;
        let (chain_starts_sender, chain_starts_receiver) = mpsc::channel();
        scope.spawn(move || {
            for vec in chain_starts_receiver.iter() {
                chains_starts.extend(vec);
            }
        });

        let chains = &mut ordered_chains;
        let (chains_sender, chains_receiver) = mpsc::channel();
        scope.spawn(move || {
            for vec in chains_receiver.iter() {
                chains.extend(vec);
            }
        });

        zone.leaves.par_iter().for_each(|leaf| {
            if task.is_cancelled() {
                return;
            }

            let (chain_starts, chains) = partial_search(
                leaf,
                db.mem_leaf_data(leaf),
                initial_state,
                non_special_states,
                transition_table,
                &dfa.accept_states,
            );

            task.advance(1);

            if !chain_starts.is_empty() {
                chain_starts_sender.send(chain_starts).unwrap();
            }
            if !chains.is_empty() {
                chains_sender.send(chains).unwrap();
            }
        });
    });

    if task.is_cancelled() {
        return Vec::new();
    }

    ordered_chains.par_sort_unstable_by_key(Chain::key);

    let (sender, receiver) = mpsc::channel();
    rayon::scope(|scope| {
        for chain in chain_starts {
            scope.spawn(|scope| {
                chain_task(scope, chain, &ordered_chains, &sender, task);
            });
        }
    });
    drop(sender);
    receiver.into_iter().collect()
}

fn chain_task<'scope>(
    scope: &Scope<'scope>,
    mut half: ChainHalf,
    ordered_chains: &'scope [Chain],
    result_sender: &'scope Sender<SearchMatch>,
    task: &'scope Task,
) {
    loop {
        if task.is_cancelled() {
            break;
        }
        match half.to {
            Handle::Tip => {
                let search_match = SearchMatch {
                    addr_min: half.addr_range.min,
                    addr_max: half.addr_range.max,
                    time_min: half.time_range.min,
                    time_max: half.time_range.max,
                };
                result_sender.send(search_match).unwrap();
                break;
            }
            Handle::State(state) => {
                let addr_start = half.addr_range.max + 1;

                let start_key = ChainKey {
                    state,
                    addr_start,
                    time_start: 0,
                };

                let end_key = ChainKey {
                    state,
                    addr_start,
                    time_start: Time::MAX,
                };

                // the chains of this state and address, however many share a key
                let start_idx = ordered_chains.partition_point(|chain| chain.key() < start_key);
                let rest = &ordered_chains[start_idx..];
                let end_idx = rest.partition_point(|chain| chain.key() <= end_key);

                let mut chain_iter = rest[..end_idx]
                    .iter()
                    .filter_map(|next| half.connect(&next.half));

                let Some(first_next_half) = chain_iter.next() else {
                    // the chain stop here
                    break;
                };

                for next_chain in chain_iter {
                    // spawn another task on chain fork
                    scope.spawn(|scope| {
                        chain_task(scope, next_chain, ordered_chains, result_sender, task);
                    });
                }

                // loop on the same task
                half = first_next_half;
            }
        }
    }
}

/// Execute partial DFA search on memory leaf
fn partial_search(
    rect: &MemWriteLeaf,
    haystack: &[u8],
    initial_state: State,
    non_special_states: &[State],
    transition_table: &TransitionTable,
    accept_states: &FxHashSet<State>,
) -> (SmallVec<[ChainHalf; 1]>, SmallVec<[Chain; 1]>) {
    let mut chain_starts = SmallVec::new();
    let mut chains = SmallVec::new();

    assert!(!haystack.is_empty());

    // remember previous partial match, to prevent creating duplicate chains
    let mut match_states_from_initial = FxHashSet::default();

    // try starting at every position
    for start_idx in 0..haystack.len() {
        let exec_result = execute_dfa(
            &haystack[start_idx..],
            initial_state,
            transition_table,
            accept_states,
        );

        let Some((match_handle, relative_match_idx)) = exec_result else {
            // the execution has failed in the haystack
            continue;
        };

        let match_idx = start_idx + relative_match_idx;

        if let Handle::State(match_state) = match_handle {
            let is_new = match_states_from_initial.insert(match_state);
            if !is_new {
                continue;
            }
        }

        let start_addr = rect.node.addr.min + start_idx as Addr;
        let match_addr = rect.node.addr.min + match_idx as Addr;

        chain_starts.push(ChainHalf {
            to: match_handle,
            addr_range: IRange::new(start_addr, match_addr),
            time_range: rect.node.time,
        });
    }

    // try every non_special_state as start state
    for state in non_special_states {
        let exec_result = execute_dfa(haystack, *state, transition_table, accept_states);

        let Some((match_handle, match_idx)) = exec_result else {
            // the execution has failed in the haystack
            continue;
        };

        let match_addr = rect.node.addr.min + match_idx as Addr;

        chains.push(Chain {
            from: *state,
            half: ChainHalf {
                to: match_handle,
                addr_range: IRange::new(rect.node.addr.min, match_addr),
                time_range: rect.node.time,
            },
        });
    }

    (chain_starts, chains)
}

/// Execute DFA on haystack starting with a specific state
fn execute_dfa(
    haystack: &[u8],
    start_state: State,
    transition_table: &TransitionTable,
    accept_states: &FxHashSet<State>,
) -> Option<(Handle, usize)> {
    assert!(!haystack.is_empty());

    let mut state = start_state;
    for (idx, byte) in haystack.iter().copied().enumerate() {
        // find the next state using the transition table, if none => match failed
        state = *transition_table.get(&(state, byte))?;

        if accept_states.contains(&state) {
            return Some((Handle::Tip, idx));
        }
    }

    let last_idx = haystack.len() - 1;
    Some((Handle::State(state), last_idx))
}

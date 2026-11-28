use std::{
    fmt::Debug,
    hash::Hash,
    ops::{Deref, DerefMut},
};

use rustc_hash::{FxHashMap, FxHashSet};

use crate::*;

/// Create minimal DFA from NFA using Brzozowski's algorithm
pub fn determine_and_minimize_nfa<T>(mut nfa: Nfa<T>) -> Dfa<T>
where
    T: Eq + Hash + Clone + Debug,
{
    nfa.invert();
    let mut dfa = determine_nfa(&nfa);
    dfa.invert();
    let nfa2 = dfa.into_nfa();
    determine_nfa(&nfa2)
}

fn determine_nfa<T>(nfa: &Nfa<T>) -> Dfa<T>
where
    T: Eq + Hash + Clone + Debug,
{
    let mut dfa = Dfa::new();
    let counter = Counter::new(State::MIN);
    let mut state_mapping: FxHashMap<MultiState, State> = Default::default();

    /// Convert NFA MultiState to single DFA State
    macro_rules! multistate_to_dfa {
        ($multi_state:expr) => {
            *state_mapping
                .entry($multi_state.clone())
                .or_insert_with(|| {
                    let next = counter.next();
                    let is_accept = $multi_state
                        .iter()
                        .any(|state| nfa.accept_states.contains(state));
                    if is_accept {
                        dfa.accept_states.insert(next);
                    }
                    next
                })
        };
    }

    let initial_state = MultiState(nfa.initial_states.iter().copied().collect());
    let initial_state = normalize_multi_state(nfa, initial_state);
    dfa.initial_states.insert(multistate_to_dfa!(initial_state));

    let mut to_explore: FxHashSet<MultiState> = Default::default();
    let mut explored: FxHashSet<MultiState> = Default::default();

    to_explore.insert(initial_state.clone());
    explored.insert(initial_state);

    while !to_explore.is_empty() {
        for from in std::mem::take(&mut to_explore) {
            let mut to_by_symbol: FxHashMap<T, MultiState> = FxHashMap::default();

            for link in &nfa.links {
                if !from.contains(&link.from) {
                    continue;
                }

                let MaybeSymbol::Symbol(symbol) = &link.symbol else {
                    continue;
                };

                to_by_symbol
                    .entry(symbol.clone())
                    .or_default()
                    .push(link.to);
            }

            let dfa_from = multistate_to_dfa!(from);

            for (symbol, to) in to_by_symbol {
                let to = normalize_multi_state(nfa, to);
                let dfa_to = multistate_to_dfa!(to);

                dfa.link(dfa_from, dfa_to, symbol);

                if explored.contains(&to) {
                    continue;
                }
                explored.insert(to.clone());
                to_explore.insert(to.clone());
            }
        }
    }

    dfa
}

/// Normalize NFA multi state by following recursively epsilon links
fn normalize_multi_state<T>(nfa: &Nfa<T>, from: MultiState) -> MultiState {
    let mut to_explore = from.0;
    let mut explored = FxHashSet::default();
    let mut result = MultiState::default();

    while !to_explore.is_empty() {
        for state in std::mem::take(&mut to_explore) {
            if explored.contains(&state) {
                continue;
            }
            result.push(state);
            explored.insert(state);
            for link in nfa.links_from(state) {
                if let MaybeSymbol::Epsilon = &link.symbol {
                    to_explore.push(link.to);
                }
            }
        }
    }

    result.sort();
    result
}

/// A list of states, must be sorted before calling Eq or Hash
#[derive(Clone, Default)]
struct MultiState(Vec<State>);

impl MultiState {
    pub fn sort(&mut self) {
        self.0.sort();
    }
}

impl Hash for MultiState {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        assert!(self.0.is_sorted(), "MultiState is not sorted on hash");
        self.0.hash(state);
    }
}

impl Eq for MultiState {}

impl PartialEq for MultiState {
    fn eq(&self, other: &Self) -> bool {
        assert!(self.0.is_sorted(), "MultiState is not sorted on comparison");
        self.0 == other.0
    }
}

impl Deref for MultiState {
    type Target = Vec<State>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for MultiState {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

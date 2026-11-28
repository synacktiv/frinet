use std::cmp::Reverse;

use crate::db::ModuleInfo;
use crate::format::Addr;

/// Module ID
pub type ModuleId = u16;

pub const MODULE_MARKER_NONE: ModuleId = ModuleId::MAX;
pub const MODULE_MARKER_MIXED: ModuleId = ModuleId::MAX - 1;

/// Maximum number of supported modules
pub const MAX_MODULES: usize = ModuleId::MAX as usize - 1;

pub fn normalize_module_order(modules: &mut [ModuleInfo]) {
    modules.sort_by_key(module_order_key);
}

pub fn find_module_by_addr(modules: &[ModuleInfo], addr: Addr) -> Option<ModuleId> {
    debug_assert!(modules.is_sorted_by_key(module_order_key));
    let idx = modules.iter().position(|module| module.contains(addr))?;
    Some(idx as ModuleId)
}

fn module_order_key(module: &ModuleInfo) -> (Addr, Reverse<Addr>) {
    (module.end, Reverse(module.start))
}

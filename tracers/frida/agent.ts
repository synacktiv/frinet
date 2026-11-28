type TracedThread = {state: NativePointer; call: number};

type Tracer = {
    c_module: CModule;
    transform: NativePointer;
    new_state: NativeFunction<NativePointer, [number, number, NativePointer, number]>;
    finish: NativeFunction<void, [NativePointer]>;
    stop: NativeFunction<void, [NativePointer]>;
    flush: NativeFunction<void, [NativePointer]>;
    registers: string;
};

// A C array of (base, size) guint64 pairs, as read by `new_state`
type RangeArray = {pointer: NativePointer; count: number};

// The trace in progress on each thread
const traced_threads: Map<ThreadId, TracedThread> = new Map();
// Kept alive: Stalker may still run the CModule code after unfollow
let tracer: Tracer | null = null;
// Kept alive: the C states read them until the end of their trace
const range_arrays: RangeArray[] = [];

const HEX = /^0x[0-9a-f]+$/i;
const CALLOUT_GRACE_PERIOD_S = 0.1;

function getModuleByName(name: string): Module {
    const module = Process.findModuleByName(name);
    if (module !== null) {
        return module;
    }

    const found = Process.enumerateModules().map(m => m.name).sort().join(', ');
    throw new Error(`unable to find module ${name} (found: ${found})`);
}

// Excludes the untraced modules from Stalker, returns the traced names (null: every module)
function excludeUntracedModules(names: string[] | null): Set<string> | null {
    const modules = Process.enumerateModules();
    const traced = (names === null || names.includes('*')) ? modules : names.map(getModuleByName);
    const traced_names = new Set(traced.map(m => m.name));

    for (const module of modules.filter(m => !traced_names.has(m.name))) {
        Stalker.exclude({base: module.base, size: module.size});
    }

    console.log(`Tracing ${traced.length} of ${modules.length} modules: ` +
                [...traced_names].sort().join(', '));
    return traced.length == modules.length ? null : traced_names;
}

function allocTracedRanges(modules: Module[], traced_names: Set<string> | null): RangeArray {
    const traced = modules
        .filter(m => traced_names === null || traced_names.has(m.name))
        .flatMap(m => m.enumerateRanges('--x'));
    const pointer = Memory.alloc(Math.max(traced.length, 1) * 16);

    traced.forEach((r, i) => {
        pointer.add(i * 16).writeU64(uint64(r.base.toString()));
        pointer.add(i * 16 + 8).writeU64(r.size);
    });
    return {pointer, count: traced.length};
}

// `symbol`, `module!symbol`, `module!0xoffset` or `0xabsolute`
function resolveAddressSpec(spec: string): NativePointer {
    if (HEX.test(spec)) {
        return ptr(spec);
    }

    const bang = spec.indexOf('!');
    const has_bang = bang >= 0;
    if (has_bang && HEX.test(spec.slice(bang + 1))) {
        const name = spec.slice(0, bang)
        const offset = ptr(spec.slice(bang + 1));
        return getModuleByName(name).base.add(offset);
    }

    const pattern = has_bang ? `exports:${spec}` : `exports:*!${spec}`;
    const matches = new ApiResolver('module').enumerateMatches(pattern);
    const addrs = [...new Set(matches.map(m => m.address.toString()))];

    if (addrs.length == 0) {
        const function_name = has_bang ? spec.slice(bang + 1) : spec
        const module = has_bang ? getModuleByName(spec.slice(0, bang)) : null;
        const functions = [...new Set(DebugSymbol.findFunctionsNamed(function_name).map(a => a.toString()))]
            .filter(a => module === null || Process.findModuleByAddress(ptr(a))?.name === module.name);

        if (functions.length == 0) {
            throw new Error(`unable to find function '${spec}'`);
        } else if (functions.length > 1) {
            const all_matches = functions.map(a => DebugSymbol.fromAddress(ptr(a))).join(', ');
            throw new Error(`'${spec}' is ambiguous: ${all_matches}`);
        }
        return ptr(functions[0]);
    } else if (addrs.length == 1) {
        return ptr(addrs[0]);
    } else {
        const all_matches = matches.map(m => m.name).join(', ')
        throw new Error(`'${spec}' is ambiguous: ${all_matches}`);
    }

}

function loadTracer(c_src: string): Tracer {
    const c_module = new CModule(c_src, {
        send: new NativeCallback((tid, call, data, len) => {
            send({id: 'trace', tid, call}, data.readByteArray(len));
        }, 'void', ['uint', 'uint', 'pointer', 'uint']),
    });

    return {
        c_module,
        transform: c_module.transform,
        new_state: new NativeFunction(c_module.new_state, 'pointer', ['uint', 'uint', 'pointer', 'uint']),
        finish: new NativeFunction(c_module.finish, 'void', ['pointer']),
        stop: new NativeFunction(c_module.stop, 'void', ['pointer']),
        flush: new NativeFunction(c_module.flush, 'void', ['pointer']),
        registers: new NativeFunction(c_module.trace_registers, 'pointer', [])().readCString(),
    };
}

function endTrace(tid: ThreadId) {
    const {state, call} = traced_threads.get(tid);

    traced_threads.delete(tid);
    tracer.finish(state);
    send({id: 'end', tid, call});
}

function endAllTraces() {
    const tids = [...traced_threads.keys()];

    for (const tid of tids) {
        Stalker.unfollow(tid);
        tracer.stop(traced_threads.get(tid).state);
    }
    Thread.sleep(CALLOUT_GRACE_PERIOD_S);
    for (const tid of tids) {
        endTrace(tid);
    }
}

function trace(traced_modules: string[] | null, start_spec: string, oneshot: boolean, c_src: string) {
    const start_address = resolveAddressSpec(start_spec);

    const traced_names = excludeUntracedModules(traced_modules);

    console.log(`Starting at ${DebugSymbol.fromAddress(start_address)}`);

    tracer = loadTracer(c_src);

    Process.setExceptionHandler(details => {
        const traced = traced_threads.get(Process.getCurrentThreadId());
        if (traced === undefined) {
            return false;
        }

        console.log('Got exception: flushing trace');
        tracer.flush(traced.state);
        send({id: 'exception'});
        recv('exception_ack', () => {}).wait();
        return false;
    });

    let next_call = 0;
    const hook = Interceptor.attach(start_address, {
        onEnter() {
            const tid = Process.getCurrentThreadId();
            const is_thread_traced = traced_threads.has(tid);
            const is_oneshot_done = oneshot && next_call > 0;
            if (is_thread_traced || is_oneshot_done) {
                return;
            }

            this.call = next_call;
            next_call += 1;

            const process_modules = Process.enumerateModules();
            const ranges = allocTracedRanges(process_modules, traced_names);
            const state = tracer.new_state(tid, this.call, ranges.pointer, ranges.count);
            range_arrays.push(ranges);

            // List current active modules for the trace header
            const modules = process_modules.map(m => ({
                name: m.name,
                start: m.base.toString(),
                end: m.base.add(m.size).toString(),
            }));
            send({id: 'start', tid, call: this.call, registers: tracer.registers, modules});

            traced_threads.set(tid, {state, call: this.call});

            console.log(`Entering function (thread ${tid}, call ${this.call})`);
            Stalker.follow(tid, {transform: tracer.transform, data: state});
        },
        onLeave() {
            const tid = Process.getCurrentThreadId();
            if (this.call === undefined || !traced_threads.has(tid)) {
                return;
            }

            console.log(`Leaving function (thread ${tid}, call ${this.call})`);

            Stalker.unfollow(tid);
            endTrace(tid);

            if (oneshot) {
                hook.detach();
            }
            Stalker.garbageCollect();
        },
    });
}

rpc.exports = {
    arch: () => Process.arch,
    trace,
    end: endAllTraces,
};

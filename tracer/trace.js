var c_src;
var js_src;
var threadIds = []
var flushs = [];

function sendSrc(args) {
        if(args["is_c"])c_src = args["src"];
        else js_src = args["src"];
}

function removeItemOnce(arr, value) {
        var index = arr.indexOf(value);
        if (index > -1) {
                arr.splice(index, 1);
        }
        return arr;
}


function trace(args) {
        var module = args["module"];
        var traced_module = args["traced_module"];

        var addr = ptr(args["addr"]);
        var once = args["once"];
        var exclude = args["exclude"];
        var needmem = args["needmem"];
        var record_calls = !!args["calls"];

        var traced_base = traced_module == '*'? 0: -1;
        var traced_end = traced_module == '*'? Infinity: -1;
        var base = -1;
        var modules = Process.enumerateModules();
        modules.forEach(mod => {

                if(traced_module == '*')
                {
                        send({id: "module", name: mod.name,start: mod.base, end: mod.base.add(mod.size)});
                }
                else if (mod.name !== traced_module) {
                        if(exclude)
                        {
                                console.log(`Excluding '${mod.name}'.`);

                                // We're only interested in stalking our code
                                Stalker.exclude({
                                "base": mod.base,
                                "size": mod.size,
                                });
                        }
                }
                else if(traced_base == -1)
                {
                        traced_base = mod.base
                        traced_end = mod.base.add(mod.size);
                }

                if ((mod.name == module)) {
                        if(base != -1)
                                console.log("WARNING : The same module name is present twice ! ("+base+" vs "+mod.base+"). Keeping the first one...")
                        else base = mod.base;
                }
        });

        if ((base < 0) || (traced_base < 0) || (traced_end < 0)) {
                console.error(`Unable to find module. Module list :`);
                modules.forEach(mod => {console.log(mod.name)})
                return 1;
        }

        if(traced_module != '*')send({id: "slide", slide: traced_base});
        
        // ---- call recording: address -> readable name ----
        var symCache = {}
        var imageBases = {}
        function idaBase(mod) {
                // preferred ImageBase from the PE header, so names match IDA (sub_14000E424)
                if (mod.name in imageBases) return imageBases[mod.name]
                var ib = null
                try {
                        if (Process.platform === 'windows') {
                                var pe = mod.base.add(mod.base.add(0x3c).readU32())
                                var magic = pe.add(0x18).readU16()
                                ib = (magic === 0x20b) ? pe.add(0x30).readU64() : uint64(pe.add(0x34).readU32())
                        }
                } catch (e) { ib = null }
                imageBases[mod.name] = ib
                return ib
        }
        function symName(addrStr) {
                if (addrStr in symCache) return symCache[addrStr]
                var p = ptr(addrStr)
                var res = addrStr
                var mod = Process.findModuleByAddress(p)
                if (mod !== null) {
                        var off = p.sub(mod.base)
                        var sym = null
                        try { sym = DebugSymbol.fromAddress(p) } catch (e) {}
                        if (sym && sym.name && !/^0x[0-9a-f]+$/i.test(sym.name) && sym.address.equals(p))
                                res = mod.name + '!' + sym.name
                        else if (mod.name === traced_module && idaBase(mod) !== null)
                                res = 'sub_' + idaBase(mod).add(off).toString(16).toUpperCase()
                        else
                                res = mod.name + '+0x' + off.toString(16).toUpperCase()
                }
                symCache[addrStr] = res
                return res
        }
        function codeAddr(addrStr) {
                // address of the call instruction, in IDA terms when possible
                var p = ptr(addrStr)
                var mod = Process.findModuleByAddress(p)
                if (mod !== null && idaBase(mod) !== null)
                        return idaBase(mod).add(p.sub(mod.base)).toString(16).toUpperCase()
                return addrStr
        }

        var slow = args.slow
        var cmods = []
        var getstalker = (mytid) => {
                var transform
                
                var flush
                if(slow)
                {
                        //const mod = new Module(js_src)
                        var SlowMode = eval(js_src)(traced_base, traced_end, Process.arch, args.end_addr, args["swap_rw"])
                        transform = (iterator)=>SlowMode.transform(iterator)
                        flush = ()=>SlowMode.flush()
                }
                else
                {
                        if(args.end_addr) //Ensure flushing on end address
                        {
                                c_src = "#define END_ADDR "+(traced_base.add(args.end_addr))+"LL\n"+c_src
                        }
                        if(args.trace_addr) //Ensure flushing on trace address
                        {
                                c_src = "#define TRACE_ADDR "+(traced_base.add(args.trace_addr))+"LL\n"+c_src
                        }

                        let filter_func
                        if(traced_module == '*')
                                filter_func = new NativeCallback(addr => {
                                        return 0;
                                }, 'int', ['size_t'])
                        else
                                filter_func = new NativeCallback(addr => {
                                        return ((addr >= traced_base) && (addr < traced_end)) ? 0 : 1;
                                }, 'int', ['size_t'])

                        let cmod = new CModule(c_src, {
                                'state': Memory.alloc(Process.pointerSize),
                                'filter': filter_func,
                                'exclude': new NativeCallback(() => {
                                        return exclude ? 1 : 0;
                                }, 'bool', []),
                                'needmem': new NativeCallback(() => {
                                        return needmem ? 1 : 0;
                                }, 'bool', []),
                                'calls': new NativeCallback(() => {
                                        return record_calls ? 1 : 0;
                                }, 'bool', []),
                                'send_calls': new NativeCallback(ptr => {
                                        var lines = ptr.readCString().split('\n')
                                        var out = []
                                        for (var l of lines) {
                                                if (!l) continue
                                                var f = l.split(' ')   // time depth kind from to
                                                out.push([f[0], f[1], f[2], codeAddr(f[3]), symName(f[4])].join(' '))
                                        }
                                        send({ id: "calls", tid: mytid, data: out.join('\n') + '\n' });
                                }, 'void', ['pointer']),
                                'swap_rw': new NativeCallback(() => {
                                        return args["swap_rw"];
                                }, 'char', []),
                                'send': new NativeCallback(ptr => {
                                        var cstr = ptr.readCString();
                                        send({
                                                id: "trace",
                                                tid: mytid,
                                                data: cstr,
                                        });
                                }, 'void', ['pointer']),
                                'send_end': new NativeCallback(() => {
                                        Stalker.unfollow(this.threadId);
                                        Stalker.flush();
                                        flush()
                                        Stalker.garbageCollect();
                                }, 'void', []),
                        });
                        cmods.push(cmod)
                        transform = cmod.transform
                        flush = new NativeFunction(cmod.flush, 'void', []);
                }
                
                return [flush, transform]
        }
        
        Process.setExceptionHandler(function (details) {
                console.log(`Got exception : flushing Stalker`);
                Stalker.flush();
                for(let flush of flushs)
                        flush()
        })

        var hook
        var filter_tid = -1
        var onEnter = function(args) {
                this.inside = false
                let curpid = Process.getCurrentThreadId()
                if(threadIds.includes(curpid) || (filter_tid>=0 && filter_tid != curpid))return
                this.inside = true
                console.log(`Entering function`);
                threadIds.push(curpid)
                let stalk = getstalker(curpid)
                this.flush = stalk[0]
                flushs.push(this.flush)
                Stalker.follow(curpid, {transform: stalk[1]});
        }
        var onLeave = function(retval) {
                if(!this.inside || (args.end_addr != undefined))return
                removeItemOnce(threadIds, Process.getCurrentThreadId())
                console.log(`Leaving function`);
                removeItemOnce(flushs, this.flush)
                Stalker.unfollow(Process.getCurrentThreadId());
                Stalker.flush();
                this.flush()
                if (once) {
                        Stalker.garbageCollect();
                        hook.detach();
                }
        }

        hook = Interceptor.attach(base.add(addr), {
                onEnter: onEnter,
                onLeave: onLeave,
        });

        return 0;
}

function end()
{       
        for(let t of threadIds)
        {
                Stalker.unfollow(t);
        }
        Stalker.flush();
}

function arch()
{       
        return Process.arch
}

rpc.exports = {
        sendSrc: sendSrc,
        trace: trace,
        end: end,
        arch: arch
}


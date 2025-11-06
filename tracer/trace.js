var c_src;
var js_src;
var threadIds = new Set();
var flushMap = new Map();

function sendSrc(args) {
        if(args["is_c"])c_src = args["src"];
        else js_src = args["src"];
}


function trace(args) {
        var module = args["module"];
        var traced_module = args["traced_module"];

        var addr = ptr(args["addr"]);
        var once = args["once"];
        var exclude = args["exclude"];
        var needmem = args["needmem"];

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
                for (let flush of flushMap.values())
  		    flush();
        })

        var hook
        var filter_tid = -1
        var onEnter = function(args) {
                this.inside = false
                let curpid = Process.getCurrentThreadId();
		if (threadIds.has(curpid) || (filter_tid >= 0 && filter_tid != curpid)) return;
		this.inside = true;
		console.log(`Entering function`);
		threadIds.add(curpid);
		let stalk = getstalker(curpid);
		this.flush = stalk[0];
		flushMap.set(curpid, this.flush);
		Stalker.follow(curpid, { transform: stalk[1] });
        }
        var onLeave = function(retval) {
                if (!this.inside || (args.end_addr != undefined)) return;

		let curpid = Process.getCurrentThreadId();
		console.log(`Leaving function`);
		threadIds.delete(curpid);
		flushMap.get(curpid)?.();
		flushMap.delete(curpid);
		Stalker.unfollow(curpid);
		Stalker.flush();

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
        for (let t of threadIds) {
	    Stalker.unfollow(t);
	    flushMap.get(t)?.();
	}
	Stalker.flush();
	threadIds.clear();
	flushMap.clear();
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


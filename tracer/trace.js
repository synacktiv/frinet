var c_src;
var js_src;
var threadIds = []
var flushs = [];

function sendSrc(args) {
        if(args["is_c"])c_src = args["src"];
        else js_src = args["src"];
}


function trace(args) {
        var module = args["module"];
        var addr = ptr(args["addr"]);
        var once = args["once"];
        var exclude = args["exclude"];

        var base = -1;
        var end = -1;
        var modules = Process.enumerateModules();
        modules.forEach(mod => {
                
                if ((mod.name !== module)) {
                        if(exclude)
                        {
                                console.log(`Excluding '${mod.name}'.`);

                                // We're only interested in stalking our code
                                Stalker.exclude({
                                "base": mod.base,
                                "size": mod.size,
                                });
                        }
                } else {
                        base = mod.base;
                        end = mod.base.add(mod.size);
                }
        });

        if ((base < 0) || (end < 0)) {
                console.error(`Unable to find module '${module}'.`);
                return 1;
        }

        send({id: "slide", slide: base});
        
        var flush;
        var js_transform;
        var cmod;
        var hook;
        var slow = args.slow
        let mytid = 0
        if(slow)
        {
                //const mod = new Module(js_src)
                var SlowMode = eval(js_src)(base, end, Process.arch, args.end_addr, args["swap_rw"])
                js_transform = (iterator)=>SlowMode.transform(iterator)
                flush = ()=>SlowMode.flush()
        }
        else
        {
                if(args.end_addr) //Ensure flushing on end address
                {
                        c_src = "#define END_ADDR "+(base.add(args.end_addr))+"LL\n"+c_src
                }
                if(args.trace_addr) //Ensure flushing on trace address
                {
                        c_src = "#define TRACE_ADDR "+(base.add(args.trace_addr))+"LL\n"+c_src
                }

                cmod = new CModule(c_src, {
                        'state': Memory.alloc(Process.pointerSize),
                        'filter': new NativeCallback(addr => {
                                return ((addr >= base) && (addr < end)) ? 0 : 1;
                        }, 'int', ['size_t']),
                        'exclude': new NativeCallback(() => {
                                return exclude ? 1 : 0;
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
                flush = new NativeFunction(cmod.flush, 'void', []);
        }
        flushs.push(flush)

        var hooklock = false; //Not really safe, but good enough
        hook = Interceptor.attach(base.add(addr), {
                onEnter: function(args) {
                        this.inside = false
                        if(hooklock)return
                        hooklock=true
                        mytid = Process.getCurrentThreadId(),
                        this.inside = true
                        console.log(`Entering function`);
                        threadIds.push(this.threadId)
                        if(slow)Stalker.follow(this.threadId, {transform: js_transform});
                        else Stalker.follow(this.threadId, {transform: cmod.transform});
                },
                onLeave: function(retval) {
                        if(!this.inside || (args.end_addr != undefined))return
                        console.log(`Leaving function`);
                        Stalker.unfollow(this.threadId);
                        Stalker.flush();
                        flush()
                        if (once) {
                                Stalker.garbageCollect();
                                hook.detach();
                        }
                        mytid = 0
                        hooklock=false
                },
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


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

        var traced_base = -1;
        var traced_end = -1;
        var base = -1;
        var modules = Process.enumerateModules();
        modules.forEach(mod => {
                
                if ((mod.name !== traced_module)) {
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
                else
                {
                        traced_base = mod.base
                        traced_end = mod.base.add(mod.size);
                }

                if ((mod.name == module)) {
                        base = mod.base;
                }
        });

        if ((base < 0) || (traced_base < 0) || (traced_end < 0)) {
                console.error(`Unable to find module. Module list :`);
                modules.forEach(mod => {console.log(mod.name)})
                return 1;
        }

        send({id: "slide", slide: traced_base});
        
        var hook;
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

                        let cmod = new CModule(c_src, {
                                'state': Memory.alloc(Process.pointerSize),
                                'filter': new NativeCallback(addr => {
                                        return ((addr >= traced_base) && (addr < traced_end)) ? 0 : 1;
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

        hook = Interceptor.attach(base.add(addr), {
                onEnter: function(args) {
                        this.inside = false
                        if(threadIds.includes(Process.getCurrentThreadId()))return
                        this.inside = true
                        console.log(`Entering function`);
                        threadIds.push(Process.getCurrentThreadId())
                        let stalk = getstalker(Process.getCurrentThreadId())
                        this.flush = stalk[0]
                        flushs.push(this.flush)
                        Stalker.follow(Process.getCurrentThreadId(), {transform: stalk[1]});

                },
                onLeave: function(retval) {
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


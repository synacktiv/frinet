import logging
regs = []

def init_regs(arch):
    if len(regs):return
    if arch == "arm64":
        for i in range(29):
            regs.append("x"+str(i))
        regs.append("fp")
        regs.append("sp")
        regs.append("lr")
        regs.append("pc")
    elif arch == "arm":
        for i in range(13):
            regs.append("r"+str(i))
        regs.append("sp")
        regs.append("lr")
        regs.append("pc")
    elif arch == "x64":
        regs.append("rax")
        regs.append("rbx")
        regs.append("rcx")
        regs.append("rdx")
        regs.append("rbp")
        regs.append("rsp")
        regs.append("rsi")
        regs.append("rdi")
        for i in range(8,16):
            regs.append("r"+str(i))
        regs.append("rip")
    elif arch == "ia32":
        regs.append("eax")
        regs.append("ebx")
        regs.append("ecx")
        regs.append("edx")
        regs.append("ebp")
        regs.append("esp")
        regs.append("esi")
        regs.append("edi")
        regs.append("eip")
    else:
        logging.error("No such arch !")
        exit(1)

def do_slowmode_output(payload, arch):
    init_regs(arch)

    lastctx = None
    lines = []
    for ctx in payload:
        line = []
        for k in regs:
            if k in ctx and (not lastctx or not k in lastctx or lastctx[k]!=ctx[k]):
                line.append(k+"="+ctx[k])
        
        for k in ["mw", "mr"]:
            if not k in ctx:continue
            addr,val = ctx[k].split(":")
            line.append(k+"="+addr+":"+val)
        
        lastctx=ctx
        lines.append(",".join(line))
    return {'id':'trace', 'tid':0, 'data':"\n".join(lines)+"\n"}
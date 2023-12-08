(binbase, binend, arch, END_ADDR, swap_rw)=>
{
class Slowmode
{
    FLUSH_THRESHOLD = 8000;
    allctx = []
    regs = []
    lastwrite = null
    nomem = []
    realcontext

    constructor(arch) {
        this.nomem = new Set()
        if(arch=="arm64")
        {
            for(let i=0;i<29;i++)this.regs.push("x"+i)
            this.regs.push("fp")
            this.regs.push("sp")
            this.regs.push("lr")
            this.regs.push("pc")
            this.realcontext = (c,r)=>this.realcontext_arm64(c,r)
        }
        else if(arch=="arm")
        {
            for(let i=0;i<13;i++)this.regs.push("r"+i)
            this.regs.push("sp")
            this.regs.push("lr")
            this.regs.push("pc")
            this.realcontext = (c,r)=>this.realcontext_arm(c,r)
        }
        else if(arch=="x64")
        {
            this.regs.push("rax")
            this.regs.push("rbx")
            this.regs.push("rcx")
            this.regs.push("rdx")
            this.regs.push("rbp")
            this.regs.push("rsp")
            this.regs.push("rsi")
            this.regs.push("rdi")
            for(let i=8;i<16;i++)this.regs.push("r"+i)
            this.regs.push("rip")

            this.realcontext = (c,r)=>this.realcontext_x64(c,r)

            this.nomem.add("lea")
            this.nomem.add("nop")
        }
        else if(arch=="ia32")
        {
            this.regs.push("eax")
            this.regs.push("ebx")
            this.regs.push("ecx")
            this.regs.push("edx")
            this.regs.push("ebp")
            this.regs.push("esp")
            this.regs.push("esi")
            this.regs.push("edi")
            this.regs.push("eip")

            this.realcontext = (c,r)=>this.realcontext_x86(c,r)

            this.nomem.add("lea")
            this.nomem.add("nop")
        }
        this.op_access = "w"
        if(swap_rw)this.op_access = "r"

    }
    
    //var instrs = INSTRSJSON
    
    buf2hex(buffer) {
        var u = new Uint8Array(buffer),
            a = new Array(u.length),
            i = u.length;
        while (i--) // map to hex
            a[i] = (u[i] < 16 ? '0' : '') + u[i].toString(16);
        u = null; // free memory
        return a.join('');
    };

    realcontext_x86(context, r)
    {
        if(context[r])return context[r]
        else send("CONTEXT MISMATCH : "+r)
    }

    realcontext_x64(context, r)
    {
        if(context[r])return context[r]
        else send("CONTEXT MISMATCH : "+r)
    }

    realcontext_arm64(context, r)
    {
        if(context[r])return context[r]
        let r2 = 'x'+r.substr(1)
        if(context[r2])return context[r2]
        else send("CONTEXT MISMATCH : "+r2)

    }
    
    regtranslate_arm = {"fp":"r11","ip":"r12"}
    realcontext_arm(context, r)
    {
        if(context[r])return context[r]
        let r2 = this.regtranslate_arm[r]
        if(context[r2])return context[r2]
        else send("CONTEXT MISMATCH : "+r)

    }
    
    testcb(context, readval, writeval)
    {   
        let addr = context.pc.sub(binbase)
    
        let contx = {}
        for(let reg of this.regs)
        {
            contx[reg] = this.realcontext(context, reg)
        }
        
        if(this.lastwrite)
        {
            contx.mw = this.lastwrite.ptr+":"+this.buf2hex(this.lastwrite.ptr.readByteArray(this.lastwrite.siz))
            this.lastwrite=null
        }
        if(writeval)
        {
            this.lastwrite={}
            let siz = 8
            
            let ptr = (new NativePointer(this.realcontext(context, writeval[0].base))).add(writeval[0].disp)
            if(writeval[0].index)ptr = ptr.add(new NativePointer(this.realcontext(context, writeval[0].index)))
            this.lastwrite.ptr = ptr
            this.lastwrite.siz = siz
        }
    
        if(readval)
        {
            let siz = 8
            let ptr = (new NativePointer(this.realcontext(context, readval[0].base))).add(readval[0].disp)
            if(readval[0].index)
            {
                let dst = this.realcontext(context, readval[0].index)
                
                ptr = ptr.add(new NativePointer(dst))
            }
            contx.mr = ptr+":"+this.buf2hex(ptr.readByteArray(siz))
        }
    
        this.allctx.push(contx)
    
        if(this.allctx.length>=this.FLUSH_THRESHOLD)flush()
        if(END_ADDR && addr.toInt32() == END_ADDR)
        {
            send("Reached end address !")
            flush()
            send("SENT "+this.allctx.length)
            Stalker.unfollow(Process.getCurrentThreadId());
            Stalker.flush()
        }
    }

    flush()
    {
        send(this.allctx)
        this.allctx = []
    }
    
    transform(iterator)
    {
        let instruction = iterator.next()
        let self = this
        do{
            if(instruction.address < binend && instruction.address >= binbase)
            {
                let read = null;
                let write = null;
                for(let op of instruction.operands)
                {
                    if(op.type=="mem" && op.value.base && !this.nomem.has(instruction.mnemonic))
                    {
                        if(op.access==this.op_access)
                        {
                            write = [op.value, instruction.mnemonic, instruction.opStr]
                        }
                        else
                        {
                            read = [op.value, instruction.mnemonic, instruction.opStr]
                        }
                    }
                }
                iterator.putCallout(function(context)
                {
                    self.testcb(context,read,write)
                });
            }
            iterator.keep();
            
            
        } while ((instruction = iterator.next()) !== null)
    
    }
    
    
}
return new Slowmode(arch)
}
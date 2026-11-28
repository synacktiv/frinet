#include <capstone.h>
#include <glib.h>
#include <gum/gumstalker.h>
#include <string.h>


/* architecture specific part of the tracer, followed by common.c (see tracer.py) */

#define TRACE_REGISTERS \
    "reg rip 8\n" \
    "reg rax 8\n" \
    "reg rbx 8\n" \
    "reg rcx 8\n" \
    "reg rdx 8\n" \
    "reg rbp 8\n" \
    "reg rsp 8\n" \
    "reg rsi 8\n" \
    "reg rdi 8\n" \
    "reg r8 8\n" \
    "reg r9 8\n" \
    "reg r10 8\n" \
    "reg r11 8\n" \
    "reg r12 8\n" \
    "reg r13 8\n" \
    "reg r14 8\n" \
    "reg r15 8\n"

#define CTX_INSN_MEMS_MAX       2


struct ctx_insn_mem {
    x86_op_mem      op;             /* operand */
    cs_ac_type      ac;             /* access type */
    gsize           size;           /* access size */
    const guint8    *ptr;           /* resolved pointer */
    gboolean         stackreg;      /* stack register for push/pop */
};

/* register indices in the trace header, the first one is the PC */
enum trace_reg {
    REG_NONE = -1,
    REG_PC,
    REG_RAX,
    REG_RBX,
    REG_RCX,
    REG_RDX,
    REG_RBP,
    REG_RSP,
    REG_RSI,
    REG_RDI,
    REG_R8,
    REG_R9,
    REG_R10,
    REG_R11,
    REG_R12,
    REG_R13,
    REG_R14,
    REG_R15,
    REG_COUNT,
};


static gint reg_index(x86_reg reg) {
    switch (reg) {
        case X86_REG_AL:
        case X86_REG_AH:
        case X86_REG_AX:
        case X86_REG_EAX:
        case X86_REG_RAX:
            return REG_RAX;
        case X86_REG_BL:
        case X86_REG_BH:
        case X86_REG_BX:
        case X86_REG_EBX:
        case X86_REG_RBX:
            return REG_RBX;
        case X86_REG_CL:
        case X86_REG_CH:
        case X86_REG_CX:
        case X86_REG_ECX:
        case X86_REG_RCX:
            return REG_RCX;
        case X86_REG_DL:
        case X86_REG_DH:
        case X86_REG_DX:
        case X86_REG_EDX:
        case X86_REG_RDX:
            return REG_RDX;
        case X86_REG_SPL:
        case X86_REG_SP:
        case X86_REG_ESP:
        case X86_REG_RSP:
            return REG_RSP;
        case X86_REG_BPL:
        case X86_REG_BP:
        case X86_REG_EBP:
        case X86_REG_RBP:
            return REG_RBP;
        case X86_REG_SIL:
        case X86_REG_SI:
        case X86_REG_ESI:
        case X86_REG_RSI:
            return REG_RSI;
        case X86_REG_DIL:
        case X86_REG_DI:
        case X86_REG_EDI:
        case X86_REG_RDI:
            return REG_RDI;
        case X86_REG_R8B:
        case X86_REG_R8W:
        case X86_REG_R8D:
        case X86_REG_R8:
            return REG_R8;
        case X86_REG_R9B:
        case X86_REG_R9W:
        case X86_REG_R9D:
        case X86_REG_R9:
            return REG_R9;
        case X86_REG_R10B:
        case X86_REG_R10W:
        case X86_REG_R10D:
        case X86_REG_R10:
            return REG_R10;
        case X86_REG_R11B:
        case X86_REG_R11W:
        case X86_REG_R11D:
        case X86_REG_R11:
            return REG_R11;
        case X86_REG_R12B:
        case X86_REG_R12W:
        case X86_REG_R12D:
        case X86_REG_R12:
            return REG_R12;
        case X86_REG_R13B:
        case X86_REG_R13W:
        case X86_REG_R13D:
        case X86_REG_R13:
            return REG_R13;
        case X86_REG_R14B:
        case X86_REG_R14W:
        case X86_REG_R14D:
        case X86_REG_R14:
            return REG_R14;
        case X86_REG_R15B:
        case X86_REG_R15W:
        case X86_REG_R15D:
        case X86_REG_R15:
            return REG_R15;
        /* only as a memory operand base (rip-relative addressing) */
        case X86_REG_RIP:
            return REG_PC;
        default:
            return REG_NONE;
    }
}

static guint64 ctx_reg_read(const GumCpuContext *ctx, enum trace_reg reg) {
    switch (reg) {
        case REG_PC:
            return ctx->rip;
        case REG_RAX:
            return ctx->rax;
        case REG_RBX:
            return ctx->rbx;
        case REG_RCX:
            return ctx->rcx;
        case REG_RDX:
            return ctx->rdx;
        case REG_RBP:
            return ctx->rbp;
        case REG_RSP:
            return ctx->rsp;
        case REG_RSI:
            return ctx->rsi;
        case REG_RDI:
            return ctx->rdi;
        case REG_R8:
            return ctx->r8;
        case REG_R9:
            return ctx->r9;
        case REG_R10:
            return ctx->r10;
        case REG_R11:
            return ctx->r11;
        case REG_R12:
            return ctx->r12;
        case REG_R13:
            return ctx->r13;
        case REG_R14:
            return ctx->r14;
        case REG_R15:
            return ctx->r15;
        default:
            return 0;
    }
}

static gsize ctx_reg_bytes(const GumCpuContext *ctx, enum trace_reg reg, guint8 *value) {
    guint64 gpr = ctx_reg_read(ctx, reg);

    memcpy(value, &gpr, sizeof(gpr));
    return sizeof(gpr);
}

static const guint8 * mem_address(const GumCpuContext *cpu_ctx, const struct ctx_insn_mem *mem) {
    const x86_op_mem *mem_op = &mem->op;
    guint64 addr = 0;

    if (mem->stackreg) {
        addr += ctx_reg_read(cpu_ctx, REG_RSP);
        if (mem->ac & CS_AC_WRITE) {
            /* TODO: operand size */
            addr -= 0x8;
        }
    } else {
        if (mem_op->base != X86_REG_INVALID) {
            addr += ctx_reg_read(cpu_ctx, reg_index(mem_op->base));
        }
        if (mem_op->index != X86_REG_INVALID) {
            addr += mem_op->scale * ctx_reg_read(cpu_ctx, reg_index(mem_op->index));
        }
        addr += mem_op->disp;
    }

    return (const guint8 *)addr;
}

/* memory accesses of an instruction, their address is resolved at run time by `mem_address` */
static gsize decode_mems(const cs_insn *insn, struct ctx_insn_mem *mems) {
    const cs_x86 *insn_x86 = &(insn->detail->x86);
    gsize n_mems = 0;
    gsize i;

    if ((insn->id == X86_INS_PUSH) || (insn->id == X86_INS_POP)) {
        const cs_x86_op *op = &insn_x86->operands[0];

        /* TODO: push immediate */
        if (op->type == X86_OP_REG) {
            if (op->access & CS_AC_READ) {
                mems[n_mems].ac = CS_AC_WRITE;
            } else {
                mems[n_mems].ac = CS_AC_READ;
            }
            mems[n_mems].size = op->size;
            mems[n_mems].stackreg = 1;
            ++n_mems;
        }
    }

    for (i = 0; i < insn_x86->op_count; ++i) {
        const cs_x86_op *op = &insn_x86->operands[i];

        switch (op->type) {
        case X86_OP_MEM:
            /* TODO: lea */
            if (insn->id == X86_INS_LEA)
                    break;
            /* ignore awful n-bytes nop */
            if (insn->id == X86_INS_NOP)
                    break;
            /* TODO: x86 segments */
            if (op->mem.segment != X86_REG_INVALID)
                    break;
            mems[n_mems].op = op->mem;
            if (op->mem.base == X86_REG_RIP || op->mem.base == X86_REG_EIP) {
                    mems[n_mems].op.disp += insn->size;
            }
            mems[n_mems].ac = op->access;
            mems[n_mems].size = op->size;
            mems[n_mems].stackreg = 0;
            ++n_mems;

            break;
        default:
            break;
        }
    }

    return n_mems;
}

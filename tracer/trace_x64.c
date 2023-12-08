#include <capstone.h>
#include <glib.h>
#include <gum/gumstalker.h>
#include <string.h>


#define TRACE_FLUSH_SIZE        (1 << 20)

#define CTX_INSN_REGS_MAX       32
#define CTX_INSN_MEMS_MAX       2


struct ctx_insn_mem {
        x86_op_mem      op;             /* operand */
        cs_ac_type      ac;             /* access type */
        gsize           size;           /* access size */
        const guint8    *ptr;           /* resolved pointer */
        gboolean         stackreg;      /* stack register for push/pop */
};

struct ctx_insn {
        x86_reg                 regs[CTX_INSN_REGS_MAX];
        gsize                   n_regs;
        struct ctx_insn_mem     mems[CTX_INSN_MEMS_MAX];
        gsize                   n_mems;
        char call_instruction;
        bool enable_regs;
};

struct ctx_trace {
        gboolean init;
        guint64 rip;
        struct ctx_insn ctx_insn;
};

struct state {
        struct ctx_trace last_ctx_trace;
        GString *trace;
        GumCpuContext *old_cpu_ctx;
        char dump_all_regs;
        bool exclude;
};


extern struct state *state;
extern int filter(guintptr addr);
extern bool exclude();
extern char swap_rw();
extern void send(gchar *str);


void init(void);
void finalize(void);
void flush(void);
void send_end(void);
void transform(GumStalkerIterator *iterator, GumStalkerOutput *output,
               gpointer user_data);


static gsize
reg_size(x86_reg reg)
{
        switch (reg) {
        case X86_REG_AL:
        case X86_REG_BL:
        case X86_REG_CL:
        case X86_REG_DL:
        case X86_REG_SPL:
        case X86_REG_BPL:
        case X86_REG_SIL:
        case X86_REG_DIL:
        case X86_REG_R8B:
        case X86_REG_R9B:
        case X86_REG_R10B:
        case X86_REG_R11B:
        case X86_REG_R12B:
        case X86_REG_R13B:
        case X86_REG_R14B:
        case X86_REG_R15B:
        case X86_REG_AH:
        case X86_REG_BH:
        case X86_REG_CH:
        case X86_REG_DH:
                return 1;
        case X86_REG_AX:
        case X86_REG_BX:
        case X86_REG_CX:
        case X86_REG_DX:
        case X86_REG_SP:
        case X86_REG_BP:
        case X86_REG_SI:
        case X86_REG_DI:
        case X86_REG_R8W:
        case X86_REG_R9W:
        case X86_REG_R10W:
        case X86_REG_R11W:
        case X86_REG_R12W:
        case X86_REG_R13W:
        case X86_REG_R14W:
        case X86_REG_R15W:
                return 2;
        case X86_REG_EAX:
        case X86_REG_EBX:
        case X86_REG_ECX:
        case X86_REG_EDX:
        case X86_REG_ESP:
        case X86_REG_EBP:
        case X86_REG_ESI:
        case X86_REG_EDI:
        case X86_REG_R8D:
        case X86_REG_R9D:
        case X86_REG_R10D:
        case X86_REG_R11D:
        case X86_REG_R12D:
        case X86_REG_R13D:
        case X86_REG_R14D:
        case X86_REG_R15D:
                return 4;
        default:
                return 8;
        }
}

static const gchar *
reg_name(x86_reg reg)
{
        switch (reg) {
        case X86_REG_AL:
        case X86_REG_AH:
        case X86_REG_AX:
        case X86_REG_EAX:
        case X86_REG_RAX:
                return "rax";
        case X86_REG_BL:
        case X86_REG_BH:
        case X86_REG_BX:
        case X86_REG_EBX:
        case X86_REG_RBX:
                return "rbx";
        case X86_REG_CL:
        case X86_REG_CH:
        case X86_REG_CX:
        case X86_REG_ECX:
        case X86_REG_RCX:
                return "rcx";
        case X86_REG_DL:
        case X86_REG_DH:
        case X86_REG_DX:
        case X86_REG_EDX:
        case X86_REG_RDX:
                return "rdx";
        case X86_REG_SPL:
        case X86_REG_SP:
        case X86_REG_ESP:
        case X86_REG_RSP:
                return "rsp";
        case X86_REG_BPL:
        case X86_REG_BP:
        case X86_REG_EBP:
        case X86_REG_RBP:
                return "rbp";
        case X86_REG_SIL:
        case X86_REG_SI:
        case X86_REG_ESI:
        case X86_REG_RSI:
                return "rsi";
        case X86_REG_DIL:
        case X86_REG_DI:
        case X86_REG_EDI:
        case X86_REG_RDI:
                return "rdi";
        case X86_REG_R8B:
        case X86_REG_R8W:
        case X86_REG_R8D:
        case X86_REG_R8:
                return "r8";
        case X86_REG_R9B:
        case X86_REG_R9W:
        case X86_REG_R9D:
        case X86_REG_R9:
                return "r9";
        case X86_REG_R10B:
        case X86_REG_R10W:
        case X86_REG_R10D:
        case X86_REG_R10:
                return "r10";
        case X86_REG_R11B:
        case X86_REG_R11W:
        case X86_REG_R11D:
        case X86_REG_R11:
                return "r11";
        case X86_REG_R12B:
        case X86_REG_R12W:
        case X86_REG_R12D:
        case X86_REG_R12:
                return "r12";
        case X86_REG_R13B:
        case X86_REG_R13W:
        case X86_REG_R13D:
        case X86_REG_R13:
                return "r13";
        case X86_REG_R14B:
        case X86_REG_R14W:
        case X86_REG_R14D:
        case X86_REG_R14:
                return "r14";
        case X86_REG_R15B:
        case X86_REG_R15W:
        case X86_REG_R15D:
        case X86_REG_R15:
                return "r15";
        default:
                return NULL;
        }
}

static guint64
ctx_reg_read(const GumCpuContext *ctx, x86_reg reg)
{
        switch (reg) {
        case X86_REG_AL:
        case X86_REG_AH:
        case X86_REG_AX:
        case X86_REG_EAX:
        case X86_REG_RAX:
                return ctx->rax;
        case X86_REG_BL:
        case X86_REG_BH:
        case X86_REG_BX:
        case X86_REG_EBX:
        case X86_REG_RBX:
                return ctx->rbx;
        case X86_REG_CL:
        case X86_REG_CH:
        case X86_REG_CX:
        case X86_REG_ECX:
        case X86_REG_RCX:
                return ctx->rcx;
        case X86_REG_DL:
        case X86_REG_DH:
        case X86_REG_DX:
        case X86_REG_EDX:
        case X86_REG_RDX:
                return ctx->rdx;
        case X86_REG_SPL:
        case X86_REG_SP:
        case X86_REG_ESP:
        case X86_REG_RSP:
                return ctx->rsp;
        case X86_REG_BPL:
        case X86_REG_BP:
        case X86_REG_EBP:
        case X86_REG_RBP:
                return ctx->rbp;
        case X86_REG_SIL:
        case X86_REG_SI:
        case X86_REG_ESI:
        case X86_REG_RSI:
                return ctx->rsi;
        case X86_REG_DIL:
        case X86_REG_DI:
        case X86_REG_EDI:
        case X86_REG_RDI:
                return ctx->rdi;
        case X86_REG_R8B:
        case X86_REG_R8W:
        case X86_REG_R8D:
        case X86_REG_R8:
                return ctx->r8;
        case X86_REG_R9B:
        case X86_REG_R9W:
        case X86_REG_R9D:
        case X86_REG_R9:
                return ctx->r9;
        case X86_REG_R10B:
        case X86_REG_R10W:
        case X86_REG_R10D:
        case X86_REG_R10:
                return ctx->r10;
        case X86_REG_R11B:
        case X86_REG_R11W:
        case X86_REG_R11D:
        case X86_REG_R11:
                return ctx->r11;
        case X86_REG_R12B:
        case X86_REG_R12W:
        case X86_REG_R12D:
        case X86_REG_R12:
                return ctx->r12;
        case X86_REG_R13B:
        case X86_REG_R13W:
        case X86_REG_R13D:
        case X86_REG_R13:
                return ctx->r13;
        case X86_REG_R14B:
        case X86_REG_R14W:
        case X86_REG_R14D:
        case X86_REG_R14:
                return ctx->r14;
        case X86_REG_R15B:
        case X86_REG_R15W:
        case X86_REG_R15D:
        case X86_REG_R15:
                return ctx->r15;
        /* handle x86 cs segment */
        case X86_REG_RIP:
                return ctx->rip;
        default:
                return 0;
        }

}

static inline void print_trace_line(GumCpuContext *cpu_ctx, x86_reg reg)
{
        const gchar *r_name = reg_name(reg);
        if (r_name)
        {
                guint64 r_val = ctx_reg_read(cpu_ctx, reg);
                g_string_append_printf(state->trace, ",%s=0x%zx", r_name, r_val);
        }
}

static inline void print_trace_line_cmp(GumCpuContext *cpu_ctx, x86_reg reg)
{
        const gchar *r_name = reg_name(reg);
        if (r_name)
        {
                guint64 r_val = ctx_reg_read(cpu_ctx, reg);
                bool ok = r_val != ctx_reg_read(state->old_cpu_ctx, reg);
                if(ok)g_string_append_printf(state->trace, ",%s=0x%zx", r_name, r_val);
        }
}

static void
on_insn(GumCpuContext *cpu_ctx, gpointer user_data)
{
        const struct ctx_insn *ctx_insn = user_data;
        struct ctx_trace *last_ctx_trace = &state->last_ctx_trace;
        struct ctx_insn *last_ctx_insn = &last_ctx_trace->ctx_insn;
        gsize i, j;

        /* trace generation phase */

        if (last_ctx_trace->init) {
                if(last_ctx_insn->enable_regs)
                {
                        g_string_append_printf(state->trace, ",rip=0x%zx", last_ctx_trace->rip);

                        if(state->dump_all_regs)
                        {
                                print_trace_line_cmp(cpu_ctx, X86_REG_RAX);
                                print_trace_line_cmp(cpu_ctx, X86_REG_RBX);
                                print_trace_line_cmp(cpu_ctx, X86_REG_RCX);
                                print_trace_line_cmp(cpu_ctx, X86_REG_RDX);
                                print_trace_line_cmp(cpu_ctx, X86_REG_RSP);
                                print_trace_line_cmp(cpu_ctx, X86_REG_RBP);
                                print_trace_line_cmp(cpu_ctx, X86_REG_RSI);
                                print_trace_line_cmp(cpu_ctx, X86_REG_RDI);
                                print_trace_line_cmp(cpu_ctx, X86_REG_R8);
                                print_trace_line_cmp(cpu_ctx, X86_REG_R9);
                                print_trace_line_cmp(cpu_ctx, X86_REG_R10);
                                print_trace_line_cmp(cpu_ctx, X86_REG_R11);
                                print_trace_line_cmp(cpu_ctx, X86_REG_R12);
                                print_trace_line_cmp(cpu_ctx, X86_REG_R13);
                                print_trace_line_cmp(cpu_ctx, X86_REG_R14);
                                print_trace_line_cmp(cpu_ctx, X86_REG_R15);
                                state->dump_all_regs = 0;
                        }
                        else
                        {
                                for (i = 0; i < last_ctx_insn->n_regs; ++i) {
                                        x86_reg reg = last_ctx_insn->regs[i];
                                        print_trace_line(cpu_ctx, reg);
                                }
                        }
                }


                for (i = 0; i < last_ctx_insn->n_mems; ++i) {
                        const struct ctx_insn_mem *mem = &last_ctx_insn->mems[i];

                        /* capstone memory operand read access is wrong */
                        g_string_append_printf(state->trace, ",m%s=0x%zx:",
                                               (mem->ac & CS_AC_WRITE) ? "w" : "r",
                                               (guint64)mem->ptr);

                        for (j = 0; j < mem->size; ++j)
                               g_string_append_printf(state->trace, "%02x",
                                                      mem->ptr[j] & 0xff);
                }

                if(last_ctx_insn->enable_regs)g_string_append_c(state->trace, '\n');
        }

        /* trace context phase */
        if(state->dump_all_regs<2)
        {
                if(!ctx_insn->enable_regs) 
                {
                        state->dump_all_regs = 2;
                        memcpy(state->old_cpu_ctx, cpu_ctx, sizeof(GumCpuContext));
                }

                else
                {
                        state->dump_all_regs = ctx_insn->call_instruction;
                        if(state->dump_all_regs)
                        {
                                memcpy(state->old_cpu_ctx, cpu_ctx, sizeof(GumCpuContext));
                        }
                }
        }

        last_ctx_trace->rip = cpu_ctx->rip;

        memcpy(last_ctx_insn->regs, ctx_insn->regs,
               ctx_insn->n_regs * sizeof(x86_reg));
        last_ctx_insn->n_regs = ctx_insn->n_regs;

        last_ctx_insn->enable_regs = ctx_insn->enable_regs;
        last_ctx_trace->init = TRUE;

        for (i = 0; i < ctx_insn->n_mems; ++i) {
                const struct ctx_insn_mem *mem = &ctx_insn->mems[i];
                const x86_op_mem *mem_op = &mem->op;
                struct ctx_insn_mem *last_mem = &last_ctx_insn->mems[i];
                guint64 r_val;

                memcpy(last_mem, mem, sizeof(*last_mem));

                last_mem->ptr = 0;
                if (mem->stackreg) {
                        last_mem->ptr += ctx_reg_read(cpu_ctx, X86_REG_RSP);
                        if (mem->ac & CS_AC_WRITE)
                                /* TODO: operand size */
                                last_mem->ptr -= 0x8;
                } else {
                        if (mem_op->base != X86_REG_INVALID) {
                                r_val = ctx_reg_read(cpu_ctx, mem_op->base);
                                last_mem->ptr += r_val;
                        }
                        if (mem_op->index != X86_REG_INVALID) {
                                r_val = ctx_reg_read(cpu_ctx, mem_op->index);
                                last_mem->ptr += mem_op->scale * r_val;
                        }
                        last_mem->ptr += mem_op->disp;
                }
        }
        last_ctx_insn->n_mems = ctx_insn->n_mems;

        /* trace flush phase */

        if (state->trace->len >= TRACE_FLUSH_SIZE)
                flush();

        #ifdef END_ADDR
                if (cpu_ctx->rip == END_ADDR)
                {
                        flush();
                        send_end();
                }
        #endif

        #ifdef TRACE_ADDR
                if (cpu_ctx->rip == TRACE_ADDR)
                {
                        flush();
                }
        #endif

}


void
init(void)
{
        state = g_malloc0(sizeof(*state));
        state->old_cpu_ctx = g_malloc0(sizeof(GumCpuContext));
        memset((void*)state->old_cpu_ctx, 0, sizeof(GumCpuContext));
        state->trace = g_string_new(NULL);
        state->dump_all_regs = 2;
        state->exclude = exclude();
}

void
finalize(void)
{
        g_string_free(state->trace, TRUE);
        g_free(state);
}

void
flush(void)
{
        gchar *trace = g_string_free(state->trace, FALSE);

        send(trace);
        g_free(trace);
        state->trace = g_string_new(NULL);
}

void
transform(GumStalkerIterator *iterator, GumStalkerOutput *output,
          gpointer user_data)
{
        cs_insn *insn;
        gsize insn_cnt = 0;
        gboolean enable_regs;
        enable_regs = true;
        while (gum_stalker_iterator_next(iterator, &insn)) {
                cs_x86 *insn_x86;
                struct ctx_insn *ctx_insn;
                gsize i;

                if (insn_cnt == 0)
                {
                        if (filter(insn->address)) {
                                if(exclude())
                                {
                                        gum_stalker_iterator_keep(iterator);
                                        continue;
                                }
                                else
                                {
                                        enable_regs = false;
                                }
                        }
                }

                insn_x86 = &(insn->detail->x86);

                ctx_insn = g_malloc(sizeof(struct ctx_insn));
                ctx_insn->n_regs = 0;
                ctx_insn->n_mems = 0;

                if ((insn->id == X86_INS_PUSH) || (insn->id == X86_INS_POP)) {
                        cs_x86_op *op = &insn_x86->operands[0];

                        ctx_insn->regs[ctx_insn->n_regs++] = X86_REG_RSP;

                        /* TODO: push immediate */
                        if (op->type == X86_OP_REG) {
                                if (op->access & CS_AC_READ)
                                        ctx_insn->mems[ctx_insn->n_mems].ac = CS_AC_WRITE;
                                else
                                        ctx_insn->mems[ctx_insn->n_mems].ac = CS_AC_READ;
                                ctx_insn->mems[ctx_insn->n_mems].size = op->size;
                                ctx_insn->mems[ctx_insn->n_mems].stackreg = 1;
                                ++ctx_insn->n_mems;
                        }
                }

                for (i = 0; i < insn_x86->op_count; ++i) {
                        cs_x86_op *op = &insn_x86->operands[i];

                        switch (op->type) {
                        case X86_OP_REG:
                                if (!enable_regs)
                                        break;
                                if (op->access & CS_AC_WRITE)
                                        ctx_insn->regs[ctx_insn->n_regs++] = op->reg;
                                break;
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
                                ctx_insn->mems[ctx_insn->n_mems].op = op->mem;
                                ctx_insn->mems[ctx_insn->n_mems].ac = op->access;
                                ctx_insn->mems[ctx_insn->n_mems].size = op->size;
                                ctx_insn->mems[ctx_insn->n_mems].stackreg = 0;
                                ++ctx_insn->n_mems;
                                break;
                        default:
                                break;
                        }
                }
                ctx_insn->call_instruction=0;
                ctx_insn->enable_regs = enable_regs;
                //if(insn->detail->groups[1] || insn->detail->groups[2] || insn->detail->groups[4] // ARM64_GRP_JMP|CALL|INT (does not work for BR?)
                // TODO
                /*
                if(insn->id == ARM64_INS_BR || insn->id == ARM64_INS_BLR) //Check if exhaustive for branchs outside of program
                {
                        ctx_insn->call_instruction=1; 
                }
                */
                gum_stalker_iterator_put_callout(iterator, on_insn, ctx_insn, g_free);
                gum_stalker_iterator_keep(iterator);
                ++insn_cnt;
        }
}


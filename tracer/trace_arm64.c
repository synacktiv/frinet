#include <capstone.h>
#include <glib.h>
#include <gum/gumstalker.h>
#include <string.h>


#define TRACE_FLUSH_SIZE        (1 << 20)

#define CTX_INSN_REGS_MAX       32
#define CTX_INSN_MEMS_MAX       1


struct ctx_insn_mem {
        arm64_op_mem    op;     /* operand */
        cs_ac_type      ac;     /* access type */
        gsize           size;   /* access size */
        const guint8    *ptr;   /* resolved pointer */
};

struct ctx_insn {
        arm64_reg               regs[CTX_INSN_REGS_MAX];
        gsize                   n_regs;
        struct ctx_insn_mem     mems[CTX_INSN_MEMS_MAX];
        gsize                   n_mems;
        char call_instruction;
        bool enable_regs;
};

struct ctx_trace {
        gboolean init;
        guint64 pc;
        struct ctx_insn ctx_insn;
};

struct state {
        struct ctx_trace last_ctx_trace;
        GString *trace;
        GumCpuContext *old_cpu_ctx;
        guint32 mflag;
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
reg_size(arm64_reg reg)
{
        switch (reg) {
        case ARM64_REG_B0 ... ARM64_REG_B31:
                return 1;
        case ARM64_REG_H0 ... ARM64_REG_H31:
                return 2;
        case ARM64_REG_W0 ... ARM64_REG_W30:
                return 4;
        default:
                return 8;
        }
}

static const gchar *
reg_name(arm64_reg reg)
{
        switch (reg) {
        case ARM64_REG_SP:
                return "sp";
        case ARM64_REG_B0:
        case ARM64_REG_H0:
        case ARM64_REG_W0:
        case ARM64_REG_X0:
                return "x0";
        case ARM64_REG_B1:
        case ARM64_REG_H1:
        case ARM64_REG_W1:
        case ARM64_REG_X1:
                return "x1";
        case ARM64_REG_B2:
        case ARM64_REG_H2:
        case ARM64_REG_W2:
        case ARM64_REG_X2:
                return "x2";
        case ARM64_REG_B3:
        case ARM64_REG_H3:
        case ARM64_REG_W3:
        case ARM64_REG_X3:
                return "x3";
        case ARM64_REG_B4:
        case ARM64_REG_H4:
        case ARM64_REG_W4:
        case ARM64_REG_X4:
                return "x4";
        case ARM64_REG_B5:
        case ARM64_REG_H5:
        case ARM64_REG_W5:
        case ARM64_REG_X5:
                return "x5";
        case ARM64_REG_B6:
        case ARM64_REG_H6:
        case ARM64_REG_W6:
        case ARM64_REG_X6:
                return "x6";
        case ARM64_REG_B7:
        case ARM64_REG_H7:
        case ARM64_REG_W7:
        case ARM64_REG_X7:
                return "x7";
        case ARM64_REG_B8:
        case ARM64_REG_H8:
        case ARM64_REG_W8:
        case ARM64_REG_X8:
                return "x8";
        case ARM64_REG_B9:
        case ARM64_REG_H9:
        case ARM64_REG_W9:
        case ARM64_REG_X9:
                return "x9";
        case ARM64_REG_B10:
        case ARM64_REG_H10:
        case ARM64_REG_W10:
        case ARM64_REG_X10:
                return "x10";
        case ARM64_REG_B11:
        case ARM64_REG_H11:
        case ARM64_REG_W11:
        case ARM64_REG_X11:
                return "x11";
        case ARM64_REG_B12:
        case ARM64_REG_H12:
        case ARM64_REG_W12:
        case ARM64_REG_X12:
                return "x12";
        case ARM64_REG_B13:
        case ARM64_REG_H13:
        case ARM64_REG_W13:
        case ARM64_REG_X13:
                return "x13";
        case ARM64_REG_B14:
        case ARM64_REG_H14:
        case ARM64_REG_W14:
        case ARM64_REG_X14:
                return "x14";
        case ARM64_REG_B15:
        case ARM64_REG_H15:
        case ARM64_REG_W15:
        case ARM64_REG_X15:
                return "x15";
        case ARM64_REG_B16:
        case ARM64_REG_H16:
        case ARM64_REG_W16:
        case ARM64_REG_X16:
                return "x16";
        case ARM64_REG_B17:
        case ARM64_REG_H17:
        case ARM64_REG_W17:
        case ARM64_REG_X17:
                return "x17";
        case ARM64_REG_B18:
        case ARM64_REG_H18:
        case ARM64_REG_W18:
        case ARM64_REG_X18:
                return "x18";
        case ARM64_REG_B19:
        case ARM64_REG_H19:
        case ARM64_REG_W19:
        case ARM64_REG_X19:
                return "x19";
        case ARM64_REG_B20:
        case ARM64_REG_H20:
        case ARM64_REG_W20:
        case ARM64_REG_X20:
                return "x20";
        case ARM64_REG_B21:
        case ARM64_REG_H21:
        case ARM64_REG_W21:
        case ARM64_REG_X21:
                return "x21";
        case ARM64_REG_B22:
        case ARM64_REG_H22:
        case ARM64_REG_W22:
        case ARM64_REG_X22:
                return "x22";
        case ARM64_REG_B23:
        case ARM64_REG_H23:
        case ARM64_REG_W23:
        case ARM64_REG_X23:
                return "x23";
        case ARM64_REG_B24:
        case ARM64_REG_H24:
        case ARM64_REG_W24:
        case ARM64_REG_X24:
                return "x24";
        case ARM64_REG_B25:
        case ARM64_REG_H25:
        case ARM64_REG_W25:
        case ARM64_REG_X25:
                return "x25";
        case ARM64_REG_B26:
        case ARM64_REG_H26:
        case ARM64_REG_W26:
        case ARM64_REG_X26:
                return "x26";
        case ARM64_REG_B27:
        case ARM64_REG_H27:
        case ARM64_REG_W27:
        case ARM64_REG_X27:
                return "x27";
        case ARM64_REG_B28:
        case ARM64_REG_H28:
        case ARM64_REG_W28:
        case ARM64_REG_X28:
                return "x28";
        case ARM64_REG_FP:
                return "fp";
        case ARM64_REG_LR:
                return "lr";
        default:
                return NULL;
        }
}

/* from afl++ */
static gsize
mem_size(const cs_insn *insn, cs_arm64_op *op)
{
        gsize regs;
        gsize mnemonic_len;

        switch (insn->id) {
        case ARM64_INS_STP:
        case ARM64_INS_STXP:
        case ARM64_INS_STNP:
        case ARM64_INS_STLXP:
        case ARM64_INS_LDP:
        case ARM64_INS_LDXP:
        case ARM64_INS_LDNP:
                regs = 2;
                break;
        default:
                regs = 1;
                break;
        }

        mnemonic_len = strlen(insn->mnemonic);
        if (mnemonic_len == 0)
                return 0;

        char last = insn->mnemonic[mnemonic_len - 1];
        switch (last) {
        case 'b':
                return 1;
        case 'h':
                return 2;
        case 'w':
                return 4 * regs;
        }

        if (op->vas != ARM64_VAS_INVALID)
                return 0;

        if (op->type != ARM64_OP_REG)
                return 8 * regs;

        switch (op->reg) {
        case ARM64_REG_W0 ... ARM64_REG_W30:
        case ARM64_REG_S0 ... ARM64_REG_S31:
                return 4 * regs;
        case ARM64_REG_D0 ... ARM64_REG_D31:
                return 8 * regs;
        case ARM64_REG_Q0 ... ARM64_REG_Q31:
                return 16;
        default:
                return 8 * regs;
        }
}

static guint64
ctx_reg_read(const GumCpuContext *ctx, arm64_reg reg)
{
        switch (reg) {
        case ARM64_REG_SP:
                return ctx->sp;
        case ARM64_REG_B0:
        case ARM64_REG_H0:
        case ARM64_REG_W0:
        case ARM64_REG_X0:
                return ctx->x[0];
        case ARM64_REG_B1:
        case ARM64_REG_H1:
        case ARM64_REG_W1:
        case ARM64_REG_X1:
                return ctx->x[1];
        case ARM64_REG_B2:
        case ARM64_REG_H2:
        case ARM64_REG_W2:
        case ARM64_REG_X2:
                return ctx->x[2];
        case ARM64_REG_B3:
        case ARM64_REG_H3:
        case ARM64_REG_W3:
        case ARM64_REG_X3:
                return ctx->x[3];
        case ARM64_REG_B4:
        case ARM64_REG_H4:
        case ARM64_REG_W4:
        case ARM64_REG_X4:
                return ctx->x[4];
        case ARM64_REG_B5:
        case ARM64_REG_H5:
        case ARM64_REG_W5:
        case ARM64_REG_X5:
                return ctx->x[5];
        case ARM64_REG_B6:
        case ARM64_REG_H6:
        case ARM64_REG_W6:
        case ARM64_REG_X6:
                return ctx->x[6];
        case ARM64_REG_B7:
        case ARM64_REG_H7:
        case ARM64_REG_W7:
        case ARM64_REG_X7:
                return ctx->x[7];
        case ARM64_REG_B8:
        case ARM64_REG_H8:
        case ARM64_REG_W8:
        case ARM64_REG_X8:
                return ctx->x[8];
        case ARM64_REG_B9:
        case ARM64_REG_H9:
        case ARM64_REG_W9:
        case ARM64_REG_X9:
                return ctx->x[9];
        case ARM64_REG_B10:
        case ARM64_REG_H10:
        case ARM64_REG_W10:
        case ARM64_REG_X10:
                return ctx->x[10];
        case ARM64_REG_B11:
        case ARM64_REG_H11:
        case ARM64_REG_W11:
        case ARM64_REG_X11:
                return ctx->x[11];
        case ARM64_REG_B12:
        case ARM64_REG_H12:
        case ARM64_REG_W12:
        case ARM64_REG_X12:
                return ctx->x[12];
        case ARM64_REG_B13:
        case ARM64_REG_H13:
        case ARM64_REG_W13:
        case ARM64_REG_X13:
                return ctx->x[13];
        case ARM64_REG_B14:
        case ARM64_REG_H14:
        case ARM64_REG_W14:
        case ARM64_REG_X14:
                return ctx->x[14];
        case ARM64_REG_B15:
        case ARM64_REG_H15:
        case ARM64_REG_W15:
        case ARM64_REG_X15:
                return ctx->x[15];
        case ARM64_REG_B16:
        case ARM64_REG_H16:
        case ARM64_REG_W16:
        case ARM64_REG_X16:
                return ctx->x[16];
        case ARM64_REG_B17:
        case ARM64_REG_H17:
        case ARM64_REG_W17:
        case ARM64_REG_X17:
                return ctx->x[17];
        case ARM64_REG_B18:
        case ARM64_REG_H18:
        case ARM64_REG_W18:
        case ARM64_REG_X18:
                return ctx->x[18];
        case ARM64_REG_B19:
        case ARM64_REG_H19:
        case ARM64_REG_W19:
        case ARM64_REG_X19:
                return ctx->x[19];
        case ARM64_REG_B20:
        case ARM64_REG_H20:
        case ARM64_REG_W20:
        case ARM64_REG_X20:
                return ctx->x[20];
        case ARM64_REG_B21:
        case ARM64_REG_H21:
        case ARM64_REG_W21:
        case ARM64_REG_X21:
                return ctx->x[21];
        case ARM64_REG_B22:
        case ARM64_REG_H22:
        case ARM64_REG_W22:
        case ARM64_REG_X22:
                return ctx->x[22];
        case ARM64_REG_B23:
        case ARM64_REG_H23:
        case ARM64_REG_W23:
        case ARM64_REG_X23:
                return ctx->x[23];
        case ARM64_REG_B24:
        case ARM64_REG_H24:
        case ARM64_REG_W24:
        case ARM64_REG_X24:
                return ctx->x[24];
        case ARM64_REG_B25:
        case ARM64_REG_H25:
        case ARM64_REG_W25:
        case ARM64_REG_X25:
                return ctx->x[25];
        case ARM64_REG_B26:
        case ARM64_REG_H26:
        case ARM64_REG_W26:
        case ARM64_REG_X26:
                return ctx->x[26];
        case ARM64_REG_B27:
        case ARM64_REG_H27:
        case ARM64_REG_W27:
        case ARM64_REG_X27:
                return ctx->x[27];
        case ARM64_REG_B28:
        case ARM64_REG_H28:
        case ARM64_REG_W28:
        case ARM64_REG_X28:
                return ctx->x[28];
        case ARM64_REG_FP:
                return ctx->fp;
        case ARM64_REG_LR:
                return ctx->lr;
        default:
                return 0;
        }

}

static inline void print_trace_line(GumCpuContext *cpu_ctx, arm64_reg reg)
{
        const gchar *r_name = reg_name(reg);
        if (r_name)
        {
                guint64 r_val = ctx_reg_read(cpu_ctx, reg);
                g_string_append_printf(state->trace, ",%s=0x%zx", r_name, r_val);
        }
        
}

static inline void print_trace_line_cmp(GumCpuContext *cpu_ctx, arm64_reg reg)
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
                        g_string_append_printf(state->trace, ",pc=0x%zx", last_ctx_trace->pc);

                        if(state->dump_all_regs)
                        {
                                arm64_reg reg;
                                for (reg = ARM64_REG_X0; reg < ARM64_REG_X28+1; ++reg) {
                                        print_trace_line_cmp(cpu_ctx, reg);
                                }
                                print_trace_line_cmp(cpu_ctx, ARM64_REG_FP);
                                print_trace_line_cmp(cpu_ctx, ARM64_REG_SP);
                                print_trace_line_cmp(cpu_ctx, ARM64_REG_LR);
                                state->dump_all_regs = 0;
                        }
                        else
                        {
                                for (i = 0; i < last_ctx_insn->n_regs; ++i) {
                                        arm64_reg reg = last_ctx_insn->regs[i];
                                        print_trace_line(cpu_ctx, reg);
                                }
                        }
                }


                for (i = 0; i < last_ctx_insn->n_mems; ++i) {
                        const struct ctx_insn_mem *mem = &last_ctx_insn->mems[i];

                        /* capstone memory operand read access is wrong */
                        g_string_append_printf(state->trace, ",m%s=0x%zx:",
                                               (mem->ac & state->mflag) ? "w" : "r",
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

        last_ctx_trace->pc = cpu_ctx->pc;

        memcpy(last_ctx_insn->regs, ctx_insn->regs,
               ctx_insn->n_regs * sizeof(arm64_reg));
        last_ctx_insn->n_regs = ctx_insn->n_regs;

        last_ctx_insn->enable_regs = ctx_insn->enable_regs;
        last_ctx_trace->init = TRUE;

        

        for (i = 0; i < ctx_insn->n_mems; ++i) {
                const struct ctx_insn_mem *mem = &ctx_insn->mems[i];
                const arm64_op_mem *mem_op = &mem->op;
                struct ctx_insn_mem *last_mem = &last_ctx_insn->mems[i];
                gsize r_size;
                guint64 r_val;

                memcpy(last_mem, mem, sizeof(*last_mem));

                last_mem->ptr = 0;
                if (mem_op->base != ARM64_REG_INVALID) {
                        r_size = reg_size(mem_op->base);
                        r_val = ctx_reg_read(cpu_ctx, mem_op->base);
                        if ((r_size > 0) && (r_size < sizeof(guint64)))
                                last_mem->ptr += (r_val & ((1 << (8 * r_size)) - 1));
                        else
                                last_mem->ptr += r_val;
                }
                if (mem_op->index != ARM64_REG_INVALID) {
                        r_size = reg_size(mem_op->index);
                        r_val = ctx_reg_read(cpu_ctx, mem_op->index);
                        if ((r_size > 0) && (r_size < sizeof(guint64)))
                                last_mem->ptr += (r_val & ((1 << (8 * r_size)) - 1));
                        else
                                last_mem->ptr += r_val;
                }
                last_mem->ptr += mem_op->disp;
        }
        last_ctx_insn->n_mems = ctx_insn->n_mems;

        /* trace flush phase */

        if (state->trace->len >= TRACE_FLUSH_SIZE)
                flush();

        #ifdef END_ADDR
                if (cpu_ctx->pc == END_ADDR)
                {
                        flush();
                        send_end();
                }
        #endif
        #ifdef TRACE_ADDR
                if (cpu_ctx->pc == TRACE_ADDR)
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
        if(swap_rw())state->mflag = CS_AC_READ;
        else state->mflag = CS_AC_WRITE;
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
                cs_arm64 *insn_arm64;
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
                
                
                insn_arm64 = &(insn->detail->arm64);

                ctx_insn = g_malloc(sizeof(struct ctx_insn));
                ctx_insn->n_regs = 0;
                ctx_insn->n_mems = 0;

                for (i = 0; i < insn_arm64->op_count; ++i) {
                        cs_arm64_op *op = &insn_arm64->operands[i];

                        switch (op->type) {
                        case ARM64_OP_REG:
                                if (enable_regs && op->access & CS_AC_WRITE)
                                        ctx_insn->regs[ctx_insn->n_regs++] = op->reg;
                                break;
                        case ARM64_OP_MEM:
                                ctx_insn->mems[ctx_insn->n_mems].op = op->mem;
                                ctx_insn->mems[ctx_insn->n_mems].ac = op->access;
                                ctx_insn->mems[ctx_insn->n_mems].size = mem_size(insn, &(insn_arm64->operands[0]));
                                ++ctx_insn->n_mems;
                                break;
                        default:
                                break;
                        }
                }
                ctx_insn->call_instruction=0;
                ctx_insn->enable_regs = enable_regs;
                //if(insn->detail->groups[1] || insn->detail->groups[2] || insn->detail->groups[4] // ARM64_GRP_JMP|CALL|INT (does not work for BR?)
                if(insn->id == ARM64_INS_BR || insn->id == ARM64_INS_BLR) //Check if exhaustive for branchs outside of program
                {
                        ctx_insn->call_instruction=1; 
                }
                gum_stalker_iterator_put_callout(iterator, on_insn, ctx_insn, g_free);
                gum_stalker_iterator_keep(iterator);
                ++insn_cnt;
        }
}


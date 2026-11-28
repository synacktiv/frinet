/*
 * Architecture independent part of the tracer, compiled after <arch>.c (see tracer.py)
 * which defines:
 * - TRACE_REGISTERS: the trace header registers, the first one is the PC
 * - enum trace_reg: their indices, from REG_PC (0) to REG_COUNT
 * - struct ctx_insn_mem and CTX_INSN_MEMS_MAX
 * - ctx_reg_read(), ctx_reg_bytes(), decode_mems() and mem_address()
 */


#define TRACE_FLUSH_SIZE        (1 << 20)
#define REG_SIZE_MAX            16

/* FRINET-TRACE binary stream tags (see crates/index/src/parser/file.rs) */
#define TAG_STEP                0x00
#define TAG_MEM_READ            0x01
#define TAG_MEM_WRITE           0x02
#define TAG_MEM_READ_WRITE      0x03
#define TAG_REG_BASE            0x10


struct state;

struct ctx_insn {
    struct state            *state;
    struct ctx_insn_mem     mems[CTX_INSN_MEMS_MAX];
    gsize                   n_mems;
};

struct ctx_trace {
    gboolean init;
    guint64 pc;
    struct ctx_insn ctx_insn;
};

struct state {
    guint tid;
    guint call;
    const guint64 *ranges;
    guint n_ranges;
    volatile gboolean stopped;
    struct ctx_trace last_ctx_trace;
    GString *trace;
    guint8 last_regs[REG_COUNT][REG_SIZE_MAX];  /* last emitted value of each register */
    gboolean regs_emitted;          /* FALSE until the first step */
};


extern void send(guint tid, guint call, const gchar *data, guint len);


struct state * new_state(guint tid, guint call, const guint64 *ranges, guint n_ranges);
void stop(struct state *state);
void flush(struct state *state);
void finish(struct state *state);
const gchar * trace_registers(void);
void transform(GumStalkerIterator *iterator, GumStalkerOutput *output, gpointer user_data);


/* values are emitted raw: the host is little-endian (x64/arm64) */
static inline void emit_step(struct state *state) {
    g_string_append_c(state->trace, TAG_STEP);
}

static inline void emit_reg(struct state *state, gint idx, const guint8 *value, gsize size) {
    g_string_append_c(state->trace, TAG_REG_BASE + idx);
    g_string_append_len(state->trace, (const gchar *)value, size);
}

static gboolean bytes_equal(const guint8 *a, const guint8 *b, gsize size) {
    gsize i;

    for (i = 0; i < size; ++i) {
        if (a[i] != b[i]) {
            return FALSE;
        }
    }
    return TRUE;
}

static inline void emit_mem(struct state *state, guint8 tag, guint64 addr, const guint8 *ptr, gsize size) {
    guint16 len = size;

    if (len == 0) {
        return;
    }
    g_string_append_c(state->trace, tag);
    g_string_append_len(state->trace, (const gchar *)&addr, sizeof(addr));
    g_string_append_len(state->trace, (const gchar *)&len, sizeof(len));
    g_string_append_len(state->trace, (const gchar *)ptr, len);
}

static guint8 mem_tag(cs_ac_type ac) {
    switch (ac) {
        case CS_AC_READ | CS_AC_WRITE:
            return TAG_MEM_READ_WRITE;
        case CS_AC_WRITE:
            return TAG_MEM_WRITE;
        default:
            return TAG_MEM_READ;
    }
}

/* the PC at every step, the other registers only when they change (implicit writes included) */
static void emit_regs(struct state *state, const GumCpuContext *cpu_ctx, guint64 pc) {
    gint idx;

    emit_reg(state, REG_PC, (const guint8 *)&pc, sizeof(pc));

    for (idx = REG_PC + 1; idx < REG_COUNT; ++idx) {
        guint8 value[REG_SIZE_MAX];
        gsize size = ctx_reg_bytes(cpu_ctx, idx, value);

        if (!state->regs_emitted || !bytes_equal(value, state->last_regs[idx], size)) {
            emit_reg(state, idx, value, size);
            memcpy(state->last_regs[idx], value, size);
        }
    }
    state->regs_emitted = TRUE;
}

static void emit_last_insn(struct state *state) {
    const struct ctx_insn *last_ctx_insn = &state->last_ctx_trace.ctx_insn;
    gsize i;

    for (i = 0; i < last_ctx_insn->n_mems; ++i) {
        const struct ctx_insn_mem *mem = &last_ctx_insn->mems[i];

        emit_mem(state, mem_tag(mem->ac), (guint64)mem->ptr, mem->ptr, mem->size);
    }

    emit_step(state);
}

static void on_insn(GumCpuContext *cpu_ctx, gpointer user_data) {
    const struct ctx_insn *ctx_insn = user_data;
    struct state *state = ctx_insn->state;
    struct ctx_trace *last_ctx_trace = &state->last_ctx_trace;
    struct ctx_insn *last_ctx_insn = &last_ctx_trace->ctx_insn;
    gsize i;

    if (state->stopped) {
        return;
    }

    /* trace generation phase */

    if (last_ctx_trace->init) {
        emit_regs(state, cpu_ctx, last_ctx_trace->pc);
        emit_last_insn(state);
    }

    /* trace context phase */

    last_ctx_trace->pc = ctx_reg_read(cpu_ctx, REG_PC);
    last_ctx_trace->init = TRUE;

    for (i = 0; i < ctx_insn->n_mems; ++i) {
        struct ctx_insn_mem *last_mem = &last_ctx_insn->mems[i];

        memcpy(last_mem, &ctx_insn->mems[i], sizeof(*last_mem));
        last_mem->ptr = mem_address(cpu_ctx, last_mem);
    }

    last_ctx_insn->n_mems = ctx_insn->n_mems;

    /* trace flush phase */

    if (state->trace->len >= TRACE_FLUSH_SIZE) {
        flush(state);
    }
}


struct state * new_state(guint tid, guint call, const guint64 *ranges, guint n_ranges) {
    struct state *state = g_malloc0(sizeof(*state));

    state->tid = tid;
    state->call = call;
    state->ranges = ranges;
    state->n_ranges = n_ranges;
    state->trace = g_string_new(NULL);
    return state;
}

void stop(struct state *state) {
    state->stopped = TRUE;
}

void flush(struct state *state) {
    if (state->trace->len == 0) {
        return;
    }
    send(state->tid, state->call, state->trace->str, state->trace->len);
    g_string_truncate(state->trace, 0);
}

void finish(struct state *state) {
    stop(state);
    if (state->last_ctx_trace.init) {
        emit_reg(state, REG_PC, (const guint8 *)&state->last_ctx_trace.pc, sizeof(state->last_ctx_trace.pc));
        emit_last_insn(state);
        state->last_ctx_trace.init = FALSE;
    }
    flush(state);
}

const gchar * trace_registers(void) {
    return TRACE_REGISTERS;
}

static gboolean is_traced(const struct state *state, guint64 address) {
    guint i;

    for (i = 0; i < state->n_ranges; ++i) {
        if (address - state->ranges[2 * i] < state->ranges[2 * i + 1]) {
            return TRUE;
        }
    }
    return FALSE;
}

void transform(GumStalkerIterator *iterator, GumStalkerOutput *output, gpointer user_data) {
    struct state *state = user_data;
    cs_insn *insn;

    while (gum_stalker_iterator_next(iterator, &insn)) {
        if (is_traced(state, insn->address)) {
            struct ctx_insn *ctx_insn = g_malloc(sizeof(struct ctx_insn));

            ctx_insn->state = state;
            ctx_insn->n_mems = decode_mems(insn, ctx_insn->mems);

            gum_stalker_iterator_put_callout(iterator, on_insn, ctx_insn, g_free);
        }
        gum_stalker_iterator_keep(iterator);
    }
}

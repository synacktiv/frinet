#include <capstone.h>
#include <glib.h>
#include <gum/gumstalker.h>
#include <string.h>


/* architecture specific part of the tracer, followed by common.c (see tracer.py) */

#define TRACE_REGISTERS \
    "reg pc 8\n" \
    "reg sp 8\n" \
    "reg lr 8\n" \
    "reg fp 8\n" \
    "reg x0 8\n" \
    "reg x1 8\n" \
    "reg x2 8\n" \
    "reg x3 8\n" \
    "reg x4 8\n" \
    "reg x5 8\n" \
    "reg x6 8\n" \
    "reg x7 8\n" \
    "reg x8 8\n" \
    "reg x9 8\n" \
    "reg x10 8\n" \
    "reg x11 8\n" \
    "reg x12 8\n" \
    "reg x13 8\n" \
    "reg x14 8\n" \
    "reg x15 8\n" \
    "reg x16 8\n" \
    "reg x17 8\n" \
    "reg x18 8\n" \
    "reg x19 8\n" \
    "reg x20 8\n" \
    "reg x21 8\n" \
    "reg x22 8\n" \
    "reg x23 8\n" \
    "reg x24 8\n" \
    "reg x25 8\n" \
    "reg x26 8\n" \
    "reg x27 8\n" \
    "reg x28 8\n" \
    "reg v0 16\n" \
    "reg v1 16\n" \
    "reg v2 16\n" \
    "reg v3 16\n" \
    "reg v4 16\n" \
    "reg v5 16\n" \
    "reg v6 16\n" \
    "reg v7 16\n" \
    "reg v8 16\n" \
    "reg v9 16\n" \
    "reg v10 16\n" \
    "reg v11 16\n" \
    "reg v12 16\n" \
    "reg v13 16\n" \
    "reg v14 16\n" \
    "reg v15 16\n" \
    "reg v16 16\n" \
    "reg v17 16\n" \
    "reg v18 16\n" \
    "reg v19 16\n" \
    "reg v20 16\n" \
    "reg v21 16\n" \
    "reg v22 16\n" \
    "reg v23 16\n" \
    "reg v24 16\n" \
    "reg v25 16\n" \
    "reg v26 16\n" \
    "reg v27 16\n" \
    "reg v28 16\n" \
    "reg v29 16\n" \
    "reg v30 16\n" \
    "reg v31 16\n"

#define CTX_INSN_MEMS_MAX       1


struct ctx_insn_mem {
    arm64_op_mem    op;         /* operand */
    arm64_extender  ext;        /* extend applied to the index register */
    guint8          shift;      /* left shift applied to the extended index register */
    gboolean        pac_base;   /* the base register holds a signed pointer */
    cs_ac_type      ac;         /* access type */
    gsize           size;       /* access size */
    const guint8    *ptr;       /* resolved pointer */
};


/* register indices in the trace header, the first one is the PC */
enum trace_reg {
    REG_NONE = -1,
    REG_PC,
    REG_SP,
    REG_LR,
    REG_FP,
    REG_X0,
    REG_X1,
    REG_X2,
    REG_X3,
    REG_X4,
    REG_X5,
    REG_X6,
    REG_X7,
    REG_X8,
    REG_X9,
    REG_X10,
    REG_X11,
    REG_X12,
    REG_X13,
    REG_X14,
    REG_X15,
    REG_X16,
    REG_X17,
    REG_X18,
    REG_X19,
    REG_X20,
    REG_X21,
    REG_X22,
    REG_X23,
    REG_X24,
    REG_X25,
    REG_X26,
    REG_X27,
    REG_X28,
    REG_V0,
    REG_V31 = REG_V0 + 31,
    REG_COUNT,
};

static gint reg_index(arm64_reg reg) {
    switch (reg) {
        case ARM64_REG_WSP:
        case ARM64_REG_SP:
            return REG_SP;
        case ARM64_REG_B0:
        case ARM64_REG_H0:
        case ARM64_REG_W0:
        case ARM64_REG_X0:
            return REG_X0;
        case ARM64_REG_B1:
        case ARM64_REG_H1:
        case ARM64_REG_W1:
        case ARM64_REG_X1:
            return REG_X1;
        case ARM64_REG_B2:
        case ARM64_REG_H2:
        case ARM64_REG_W2:
        case ARM64_REG_X2:
            return REG_X2;
        case ARM64_REG_B3:
        case ARM64_REG_H3:
        case ARM64_REG_W3:
        case ARM64_REG_X3:
            return REG_X3;
        case ARM64_REG_B4:
        case ARM64_REG_H4:
        case ARM64_REG_W4:
        case ARM64_REG_X4:
            return REG_X4;
        case ARM64_REG_B5:
        case ARM64_REG_H5:
        case ARM64_REG_W5:
        case ARM64_REG_X5:
            return REG_X5;
        case ARM64_REG_B6:
        case ARM64_REG_H6:
        case ARM64_REG_W6:
        case ARM64_REG_X6:
            return REG_X6;
        case ARM64_REG_B7:
        case ARM64_REG_H7:
        case ARM64_REG_W7:
        case ARM64_REG_X7:
            return REG_X7;
        case ARM64_REG_B8:
        case ARM64_REG_H8:
        case ARM64_REG_W8:
        case ARM64_REG_X8:
            return REG_X8;
        case ARM64_REG_B9:
        case ARM64_REG_H9:
        case ARM64_REG_W9:
        case ARM64_REG_X9:
            return REG_X9;
        case ARM64_REG_B10:
        case ARM64_REG_H10:
        case ARM64_REG_W10:
        case ARM64_REG_X10:
            return REG_X10;
        case ARM64_REG_B11:
        case ARM64_REG_H11:
        case ARM64_REG_W11:
        case ARM64_REG_X11:
            return REG_X11;
        case ARM64_REG_B12:
        case ARM64_REG_H12:
        case ARM64_REG_W12:
        case ARM64_REG_X12:
            return REG_X12;
        case ARM64_REG_B13:
        case ARM64_REG_H13:
        case ARM64_REG_W13:
        case ARM64_REG_X13:
            return REG_X13;
        case ARM64_REG_B14:
        case ARM64_REG_H14:
        case ARM64_REG_W14:
        case ARM64_REG_X14:
            return REG_X14;
        case ARM64_REG_B15:
        case ARM64_REG_H15:
        case ARM64_REG_W15:
        case ARM64_REG_X15:
            return REG_X15;
        case ARM64_REG_B16:
        case ARM64_REG_H16:
        case ARM64_REG_W16:
        case ARM64_REG_X16:
            return REG_X16;
        case ARM64_REG_B17:
        case ARM64_REG_H17:
        case ARM64_REG_W17:
        case ARM64_REG_X17:
            return REG_X17;
        case ARM64_REG_B18:
        case ARM64_REG_H18:
        case ARM64_REG_W18:
        case ARM64_REG_X18:
            return REG_X18;
        case ARM64_REG_B19:
        case ARM64_REG_H19:
        case ARM64_REG_W19:
        case ARM64_REG_X19:
            return REG_X19;
        case ARM64_REG_B20:
        case ARM64_REG_H20:
        case ARM64_REG_W20:
        case ARM64_REG_X20:
            return REG_X20;
        case ARM64_REG_B21:
        case ARM64_REG_H21:
        case ARM64_REG_W21:
        case ARM64_REG_X21:
            return REG_X21;
        case ARM64_REG_B22:
        case ARM64_REG_H22:
        case ARM64_REG_W22:
        case ARM64_REG_X22:
            return REG_X22;
        case ARM64_REG_B23:
        case ARM64_REG_H23:
        case ARM64_REG_W23:
        case ARM64_REG_X23:
            return REG_X23;
        case ARM64_REG_B24:
        case ARM64_REG_H24:
        case ARM64_REG_W24:
        case ARM64_REG_X24:
            return REG_X24;
        case ARM64_REG_B25:
        case ARM64_REG_H25:
        case ARM64_REG_W25:
        case ARM64_REG_X25:
            return REG_X25;
        case ARM64_REG_B26:
        case ARM64_REG_H26:
        case ARM64_REG_W26:
        case ARM64_REG_X26:
            return REG_X26;
        case ARM64_REG_B27:
        case ARM64_REG_H27:
        case ARM64_REG_W27:
        case ARM64_REG_X27:
            return REG_X27;
        case ARM64_REG_B28:
        case ARM64_REG_H28:
        case ARM64_REG_W28:
        case ARM64_REG_X28:
            return REG_X28;
        case ARM64_REG_W29:
        case ARM64_REG_FP:
            return REG_FP;
        case ARM64_REG_W30:
        case ARM64_REG_LR:
            return REG_LR;
        default:
            return REG_NONE;
    }
}

static gsize reg_size(arm64_reg reg) {
    switch (reg) {
        case ARM64_REG_B0 ... ARM64_REG_B31:
            return 1;
        case ARM64_REG_H0 ... ARM64_REG_H31:
            return 2;
        case ARM64_REG_WZR:
        case ARM64_REG_W0 ... ARM64_REG_W30:
        case ARM64_REG_S0 ... ARM64_REG_S31:
            return 4;
        case ARM64_REG_Q0 ... ARM64_REG_Q31:
            return 16;
        default:
            return 8;
    }
}

static gsize vector_size(arm64_vas vas) {
    switch (vas) {
        case ARM64_VAS_1B:
            return 1;
        case ARM64_VAS_1H:
            return 2;
        case ARM64_VAS_4B:
        case ARM64_VAS_2H:
        case ARM64_VAS_1S:
            return 4;
        case ARM64_VAS_8B:
        case ARM64_VAS_4H:
        case ARM64_VAS_2S:
        case ARM64_VAS_1D:
            return 8;
        default:
            return 16;
    }
}

static gsize element_size(arm64_vas vas) {
    switch (vas) {
        case ARM64_VAS_16B:
        case ARM64_VAS_8B:
        case ARM64_VAS_4B:
        case ARM64_VAS_1B:
            return 1;
        case ARM64_VAS_8H:
        case ARM64_VAS_4H:
        case ARM64_VAS_2H:
        case ARM64_VAS_1H:
            return 2;
        case ARM64_VAS_4S:
        case ARM64_VAS_2S:
        case ARM64_VAS_1S:
            return 4;
        case ARM64_VAS_2D:
        case ARM64_VAS_1D:
            return 8;
        default:
            return 16;
    }
}

static gsize vector_list_size(const cs_insn *insn) {
    const cs_arm64 *insn_arm64 = &(insn->detail->arm64);
    gboolean replicate = (insn->id == ARM64_INS_LD1R) || (insn->id == ARM64_INS_LD2R) ||
                         (insn->id == ARM64_INS_LD3R) || (insn->id == ARM64_INS_LD4R);
    gsize size = 0;
    gsize i;

    for (i = 0; i < insn_arm64->op_count && insn_arm64->operands[i].type == ARM64_OP_REG; ++i) {
        arm64_vas vas = insn_arm64->operands[i].vas;
        size += replicate ? element_size(vas) : vector_size(vas);
    }

    return size;
}

static gsize transfer_regs(const cs_insn *insn) {
    switch (insn->id) {
        case ARM64_INS_LDP:
        case ARM64_INS_STP:
        case ARM64_INS_LDNP:
        case ARM64_INS_STNP:
        case ARM64_INS_LDPSW:
        case ARM64_INS_LDXP:
        case ARM64_INS_LDAXP:
        case ARM64_INS_STXP:
        case ARM64_INS_STLXP:
        case ARM64_INS_STGP:
        case ARM64_INS_CASP:
        case ARM64_INS_CASPA:
        case ARM64_INS_CASPL:
        case ARM64_INS_CASPAL:
            return 2;
        default:
            return 1;
    }
}

static gsize first_data_operand(const cs_insn *insn) {
    switch (insn->id) {
        case ARM64_INS_STXR:
        case ARM64_INS_STXRB:
        case ARM64_INS_STXRH:
        case ARM64_INS_STLXR:
        case ARM64_INS_STLXRB:
        case ARM64_INS_STLXRH:
        case ARM64_INS_STXP:
        case ARM64_INS_STLXP:
            return 1;
        default:
            return 0;
    }
}

static gsize mem_size(const cs_insn *insn) {
    const cs_arm64_op *data = &(insn->detail->arm64.operands[first_data_operand(insn)]);
    gsize regs = transfer_regs(insn);
    gsize mnemonic_len = strlen(insn->mnemonic);

    switch (insn->id) {
        /* both load a doubleword: their trailing a or b selects the key, it is not a size suffix */
        case ARM64_INS_LDRAA:
        case ARM64_INS_LDRAB:
            return 8;
        case ARM64_INS_STZG:
            return 16;
        case ARM64_INS_STZ2G:
            return 32;
        case ARM64_INS_LD64B:
        case ARM64_INS_ST64B:
        case ARM64_INS_ST64BV:
        case ARM64_INS_ST64BV0:
            return 64;
    }

    switch (insn->mnemonic[mnemonic_len - 1]) {
        case 'b':
            return 1 * regs;
        case 'h':
            return 2 * regs;
        case 'w':
            return 4 * regs;
    }

    if (data->type != ARM64_OP_REG) {
        return 0;
    }
    if (data->vas != ARM64_VAS_INVALID) {
        return vector_list_size(insn);
    }
    return reg_size(data->reg) * regs;
}

static cs_ac_type mem_access(const cs_insn *insn) {
    static const gchar *atomic_prefixes[] = {
        "ldadd", "ldclr", "ldeor", "ldset", "ldsmax", "ldsmin", "ldumax", "ldumin",
        "stadd", "stclr", "steor", "stset", "stsmax", "stsmin", "stumax", "stumin",
        "swp", "cas",
    };
    gsize i;

    for (i = 0; i < G_N_ELEMENTS(atomic_prefixes); ++i) {
        if (g_str_has_prefix(insn->mnemonic, atomic_prefixes[i])) {
            return CS_AC_READ | CS_AC_WRITE;
        }
    }
    if (g_str_has_prefix(insn->mnemonic, "st")) {
        return CS_AC_WRITE;
    }
    return CS_AC_READ;
}

static gboolean is_scalable_operand(const cs_arm64_op *op) {
    if (op->type == ARM64_OP_SME_INDEX) {
        return TRUE;
    }
    if (op->type != ARM64_OP_REG) {
        return FALSE;
    }
    switch (op->reg) {
        case ARM64_REG_FFR:
        case ARM64_REG_ZA:
        case ARM64_REG_P0 ... ARM64_REG_P15:
        case ARM64_REG_Z0 ... ARM64_REG_Z31:
        case ARM64_REG_ZAB0 ... ARM64_REG_ZAS3:
            return TRUE;
        default:
            return FALSE;
    }
}

static gboolean has_data_access(const cs_insn *insn) {
    const cs_arm64 *insn_arm64 = &(insn->detail->arm64);
    gsize i;

    switch (insn->id) {
        /* a prefetch never faults: its operand may point to unmapped memory, never dereference it */
        case ARM64_INS_PRFM:
        case ARM64_INS_PRFUM:
        case ARM64_INS_PRFB:
        case ARM64_INS_PRFH:
        case ARM64_INS_PRFW:
        case ARM64_INS_PRFD:
        case ARM64_INS_LDG:
        case ARM64_INS_LDGM:
        case ARM64_INS_STG:
        case ARM64_INS_ST2G:
        case ARM64_INS_STGM:
        case ARM64_INS_STZGM:
            return FALSE;
    }

    for (i = 0; i < insn_arm64->op_count; ++i) {
        if (is_scalable_operand(&insn_arm64->operands[i])) {
            return FALSE;
        }
    }
    return TRUE;
}

static guint64 ctx_reg_read(const GumCpuContext *ctx, enum trace_reg reg) {
    switch (reg) {
        case REG_PC:
            return ctx->pc;
        case REG_SP:
            return ctx->sp;
        case REG_LR:
            return ctx->lr;
        case REG_FP:
            return ctx->fp;
        case REG_X0 ... REG_X28:
            return ctx->x[reg - REG_X0];
        default:
            return 0;
    }
}

static gsize ctx_reg_bytes(const GumCpuContext *ctx, enum trace_reg reg, guint8 *value) {
    guint64 gpr;

    if (reg >= REG_V0 && reg <= REG_V31) {
        memcpy(value, ctx->v[reg - REG_V0].q, sizeof(ctx->v[0].q));
        return sizeof(ctx->v[0].q);
    }
    gpr = ctx_reg_read(ctx, reg);
    memcpy(value, &gpr, sizeof(gpr));
    return sizeof(gpr);
}

static inline guint64 extend_index(arm64_extender ext, guint64 r_val) {
    switch (ext) {
        case ARM64_EXT_UXTW:
            return (guint32)r_val;
        case ARM64_EXT_SXTW:
            return (guint64)(gint64)(gint32)r_val;
        default:
            return r_val;
    }
}

static const guint8 * mem_address(const GumCpuContext *cpu_ctx, const struct ctx_insn_mem *mem) {
    const arm64_op_mem *mem_op = &mem->op;
    guint64 addr = 0;

    if (mem_op->base != ARM64_REG_INVALID) {
        guint64 base = ctx_reg_read(cpu_ctx, reg_index(mem_op->base));

        /* the signature sits above the address, the instruction accesses it stripped */
        if (mem->pac_base) {
            base = GPOINTER_TO_SIZE(gum_strip_code_pointer(GSIZE_TO_POINTER(base)));
        }
        addr += base;
    }
    if (mem_op->index != ARM64_REG_INVALID) {
        addr += extend_index(mem->ext, ctx_reg_read(cpu_ctx, reg_index(mem_op->index)))
                << mem->shift;
    }
    addr += mem_op->disp;

    return (const guint8 *)addr;
}

/* memory accesses of an instruction, their address is resolved at run time by `mem_address` */
static gsize decode_mems(const cs_insn *insn, struct ctx_insn_mem *mems) {
    const cs_arm64 *insn_arm64 = &(insn->detail->arm64);
    gboolean pac_base = (insn->id == ARM64_INS_LDRAA) || (insn->id == ARM64_INS_LDRAB);
    gsize n_mems = 0;
    gsize i;

    if (!has_data_access(insn)) {
        return 0;
    }

    for (i = 0; i < insn_arm64->op_count && n_mems < CTX_INSN_MEMS_MAX; ++i) {
        const cs_arm64_op *op = &insn_arm64->operands[i];

        switch (op->type) {
        case ARM64_OP_MEM:
            mems[n_mems].op = op->mem;
            mems[n_mems].ext = op->ext;
            mems[n_mems].shift = (op->shift.type == ARM64_SFT_LSL) ? op->shift.value : 0;
            mems[n_mems].pac_base = pac_base;
            mems[n_mems].ac = mem_access(insn);
            mems[n_mems].size = mem_size(insn);
            ++n_mems;
            break;
        default:
            break;
        }
    }

    return n_mems;
}

/* Capstone Disassembly Engine */
/* MOS65XX Backend by Sebastian Macke <sebastian@macke.de> 2018 */

#include "capstone/mos65xx.h"
#include "MOS65XXDisassembler.h"
#include "MOS65XXDisassemblerInternals.h"

typedef struct OpInfo {
	mos65xx_insn ins;
	mos65xx_address_mode am;
} OpInfo;


#include "m6502.inc"

static const char* RegNames[] = {
	"invalid", "A", "X", "Y", "P", "SP"
};

#ifndef CAPSTONE_DIET
static const char* GroupNames[] = {
	NULL,
	"jump",
	"call",
	"ret",
	NULL,
	"iret",
	"branch_relative"
};

typedef struct InstructionInfo {
	const char* name;
	mos65xx_group_type group_type;
	mos65xx_reg write, read;
	bool modifies_status;
} InstructionInfo;

static const struct InstructionInfo InstructionInfoTable[]= {
	{ "invalid", MOS65XX_GRP_INVALID,         MOS65XX_REG_INVALID, MOS65XX_REG_INVALID, false },
	{ "adc",     MOS65XX_GRP_INVALID,         MOS65XX_REG_ACC,     MOS65XX_REG_INVALID, true },
	{ "and",     MOS65XX_GRP_INVALID,         MOS65XX_REG_ACC,     MOS65XX_REG_INVALID, true },
	{ "asl",     MOS65XX_GRP_INVALID,         MOS65XX_REG_INVALID, MOS65XX_REG_INVALID, true },
	{ "bcc",     MOS65XX_GRP_BRANCH_RELATIVE, MOS65XX_REG_INVALID, MOS65XX_REG_P,       false },
	{ "bcs",     MOS65XX_GRP_BRANCH_RELATIVE, MOS65XX_REG_INVALID, MOS65XX_REG_P,       false },
	{ "beq",     MOS65XX_GRP_BRANCH_RELATIVE, MOS65XX_REG_INVALID, MOS65XX_REG_P,       false },
	{ "bit",     MOS65XX_GRP_INVALID,         MOS65XX_REG_INVALID, MOS65XX_REG_INVALID, true },
	{ "bmi",     MOS65XX_GRP_BRANCH_RELATIVE, MOS65XX_REG_INVALID, MOS65XX_REG_P,       false },
	{ "bne",     MOS65XX_GRP_BRANCH_RELATIVE, MOS65XX_REG_INVALID, MOS65XX_REG_P,       false },
	{ "bpl",     MOS65XX_GRP_BRANCH_RELATIVE, MOS65XX_REG_INVALID, MOS65XX_REG_P,       false },
	{ "brk",     MOS65XX_GRP_INVALID,         MOS65XX_REG_SP,      MOS65XX_REG_INVALID, false },
	{ "bvc",     MOS65XX_GRP_BRANCH_RELATIVE, MOS65XX_REG_INVALID, MOS65XX_REG_P,       false },
	{ "bvs",     MOS65XX_GRP_BRANCH_RELATIVE, MOS65XX_REG_INVALID, MOS65XX_REG_P,       false },
	{ "clc",     MOS65XX_GRP_INVALID,         MOS65XX_REG_INVALID, MOS65XX_REG_INVALID, true },
	{ "cld",     MOS65XX_GRP_INVALID,         MOS65XX_REG_INVALID, MOS65XX_REG_INVALID, true },
	{ "cli",     MOS65XX_GRP_INVALID,         MOS65XX_REG_INVALID, MOS65XX_REG_INVALID, true },
	{ "clv",     MOS65XX_GRP_INVALID,         MOS65XX_REG_INVALID, MOS65XX_REG_INVALID, true },
	{ "cmp",     MOS65XX_GRP_INVALID,         MOS65XX_REG_INVALID, MOS65XX_REG_ACC,     true },
	{ "cpx",     MOS65XX_GRP_INVALID,         MOS65XX_REG_INVALID, MOS65XX_REG_X,       true },
	{ "cpy",     MOS65XX_GRP_INVALID,         MOS65XX_REG_INVALID, MOS65XX_REG_Y,       true },
	{ "dec",     MOS65XX_GRP_INVALID,         MOS65XX_REG_INVALID, MOS65XX_REG_INVALID, true },
	{ "dex",     MOS65XX_GRP_INVALID,         MOS65XX_REG_X,       MOS65XX_REG_X,       true },
	{ "dey",     MOS65XX_GRP_INVALID,         MOS65XX_REG_Y,       MOS65XX_REG_Y,       true },
	{ "eor",     MOS65XX_GRP_INVALID,         MOS65XX_REG_INVALID, MOS65XX_REG_INVALID, true },
	{ "inc",     MOS65XX_GRP_INVALID,         MOS65XX_REG_INVALID, MOS65XX_REG_INVALID, true },
	{ "inx",     MOS65XX_GRP_INVALID,         MOS65XX_REG_X,       MOS65XX_REG_X,       true },
	{ "iny",     MOS65XX_GRP_INVALID,         MOS65XX_REG_Y,       MOS65XX_REG_Y,       true },
	{ "jmp",     MOS65XX_GRP_JUMP,            MOS65XX_REG_INVALID, MOS65XX_REG_INVALID, false },
	{ "jsr",     MOS65XX_GRP_CALL,            MOS65XX_REG_INVALID, MOS65XX_REG_INVALID, false },
	{ "lda",     MOS65XX_GRP_INVALID,         MOS65XX_REG_ACC,     MOS65XX_REG_INVALID, true },
	{ "ldx",     MOS65XX_GRP_INVALID,         MOS65XX_REG_X,       MOS65XX_REG_INVALID, true },
	{ "ldy",     MOS65XX_GRP_INVALID,         MOS65XX_REG_Y,       MOS65XX_REG_INVALID, true },
	{ "lsr",     MOS65XX_GRP_INVALID,         MOS65XX_REG_INVALID, MOS65XX_REG_INVALID, true },
	{ "nop",     MOS65XX_GRP_INVALID,         MOS65XX_REG_INVALID, MOS65XX_REG_INVALID, false },
	{ "ora",     MOS65XX_GRP_INVALID,         MOS65XX_REG_ACC,     MOS65XX_REG_INVALID, true },
	{ "pha",     MOS65XX_GRP_INVALID,         MOS65XX_REG_SP,      MOS65XX_REG_ACC,     false },
	{ "pla",     MOS65XX_GRP_INVALID,         MOS65XX_REG_ACC,     MOS65XX_REG_SP,      true },
	{ "php",     MOS65XX_GRP_INVALID,         MOS65XX_REG_SP,      MOS65XX_REG_P,       false },
	{ "plp",     MOS65XX_GRP_INVALID,         MOS65XX_REG_INVALID, MOS65XX_REG_SP,      true },
	{ "rol",     MOS65XX_GRP_INVALID,         MOS65XX_REG_INVALID, MOS65XX_REG_INVALID, true },
	{ "ror",     MOS65XX_GRP_INVALID,         MOS65XX_REG_INVALID, MOS65XX_REG_INVALID, true },
	{ "rti",     MOS65XX_GRP_IRET,            MOS65XX_REG_SP,      MOS65XX_REG_INVALID, true },
	{ "rts",     MOS65XX_GRP_RET,             MOS65XX_REG_SP,      MOS65XX_REG_INVALID, false },
	{ "sbc",     MOS65XX_GRP_INVALID,         MOS65XX_REG_ACC,     MOS65XX_REG_INVALID, true },
	{ "sec",     MOS65XX_GRP_INVALID,         MOS65XX_REG_INVALID, MOS65XX_REG_INVALID, true },
	{ "sed",     MOS65XX_GRP_INVALID,         MOS65XX_REG_INVALID, MOS65XX_REG_INVALID, true },
	{ "sei",     MOS65XX_GRP_INVALID,         MOS65XX_REG_INVALID, MOS65XX_REG_INVALID, true },
	{ "sta",     MOS65XX_GRP_INVALID,         MOS65XX_REG_INVALID, MOS65XX_REG_ACC,     false },
	{ "stx",     MOS65XX_GRP_INVALID,         MOS65XX_REG_INVALID, MOS65XX_REG_X,       false },
	{ "sty",     MOS65XX_GRP_INVALID,         MOS65XX_REG_INVALID, MOS65XX_REG_Y,       false },
	{ "tax",     MOS65XX_GRP_INVALID,         MOS65XX_REG_X,       MOS65XX_REG_ACC,     true },
	{ "tay",     MOS65XX_GRP_INVALID,         MOS65XX_REG_Y,       MOS65XX_REG_ACC,     true },
	{ "tsx",     MOS65XX_GRP_INVALID,         MOS65XX_REG_X,       MOS65XX_REG_SP,      true },
	{ "txa",     MOS65XX_GRP_INVALID,         MOS65XX_REG_ACC,     MOS65XX_REG_X,       true },
	{ "txs",     MOS65XX_GRP_INVALID,         MOS65XX_REG_SP,      MOS65XX_REG_X,       true },
	{ "tya",     MOS65XX_GRP_INVALID,         MOS65XX_REG_ACC,     MOS65XX_REG_Y,       true },
};
#endif

static int getInstructionLength(mos65xx_address_mode am)
{
	switch(am) {
		case MOS65XX_AM_NONE:
		case MOS65XX_AM_ACC:
		case MOS65XX_AM_IMP:
			return 1;

		case MOS65XX_AM_IMM:
		case MOS65XX_AM_ZPX:
		case MOS65XX_AM_ZPY:
		case MOS65XX_AM_ZP:
		case MOS65XX_AM_REL:
		case MOS65XX_AM_INDX:
		case MOS65XX_AM_INDY:
			return 2;

		case MOS65XX_AM_ABS:
		case MOS65XX_AM_ABSX:
		case MOS65XX_AM_ABSY:
		case MOS65XX_AM_IND:
			return 3;
		default:
			return 1;
	}
}

#ifndef CAPSTONE_DIET
static void fillDetails(MCInst *MI, unsigned char opcode)
{
	cs_detail *detail = MI->flat_insn->detail;
	mos65xx_insn ins = OpInfoTable[opcode].ins;
	mos65xx_address_mode am = OpInfoTable[opcode].am;

	detail->mos65xx.am = am;
	detail->mos65xx.modifies_flags = InstructionInfoTable[ins].modifies_status;
	detail->groups_count = 0;
	detail->regs_read_count = 0;
	detail->regs_write_count = 0;
	detail->mos65xx.op_count = 0;

	if (InstructionInfoTable[ins].group_type != MOS65XX_GRP_INVALID) {
		detail->groups[0] = InstructionInfoTable[ins].group_type;
		detail->groups_count++;
	}

	if (InstructionInfoTable[ins].read != MOS65XX_REG_INVALID) {
		detail->regs_read[detail->regs_read_count++] = InstructionInfoTable[ins].read;
	} else if (OpInfoTable[opcode].am == MOS65XX_AM_ACC) {
		detail->regs_read[detail->regs_read_count++] = MOS65XX_REG_ACC;
	} else if (OpInfoTable[opcode].am == MOS65XX_AM_INDY || OpInfoTable[opcode].am == MOS65XX_AM_ABSY || OpInfoTable[opcode].am == MOS65XX_AM_ZPY) {
		detail->regs_read[detail->regs_read_count++] = MOS65XX_REG_Y;
	} else if (OpInfoTable[opcode].am == MOS65XX_AM_INDX || OpInfoTable[opcode].am == MOS65XX_AM_ABSX || OpInfoTable[opcode].am == MOS65XX_AM_ZPX) {
		detail->regs_read[detail->regs_read_count++] = MOS65XX_REG_X;
	}

	if (InstructionInfoTable[ins].write != MOS65XX_REG_INVALID) {
		detail->regs_write[detail->regs_write_count++] = InstructionInfoTable[ins].write;
	} else if (OpInfoTable[opcode].am == MOS65XX_AM_ACC) {
		detail->regs_write[detail->regs_write_count++] = MOS65XX_REG_ACC;
	}

	if (InstructionInfoTable[ins].modifies_status) {
		detail->regs_write[detail->regs_write_count++] = MOS65XX_REG_P;
	}

	switch(am) {
		case MOS65XX_AM_IMP:
		case MOS65XX_AM_REL:
			break;
		case MOS65XX_AM_IMM:
			detail->mos65xx.operands[detail->mos65xx.op_count].type = MOS65XX_OP_IMM;
			detail->mos65xx.operands[detail->mos65xx.op_count].mem = MI->Operands[0].ImmVal;
			detail->mos65xx.op_count++;
			break;
		case MOS65XX_AM_ACC:
			detail->mos65xx.operands[detail->mos65xx.op_count].type = MOS65XX_OP_REG;
			detail->mos65xx.operands[detail->mos65xx.op_count].reg = MOS65XX_REG_ACC;
			detail->mos65xx.op_count++;
			break;
		default:
			detail->mos65xx.operands[detail->mos65xx.op_count].type = MOS65XX_OP_MEM;
			detail->mos65xx.operands[detail->mos65xx.op_count].mem = MI->Operands[0].ImmVal;
			detail->mos65xx.op_count++;
			break;
	}
}
#endif

void MOS65XX_printInst(MCInst *MI, struct SStream *O, void *PrinterInfo)
{
#ifndef CAPSTONE_DIET
	unsigned char opcode = MI->Opcode;
	mos65xx_info *info = (mos65xx_info *)PrinterInfo;

	const char *prefix = info->hex_prefix ? info->hex_prefix : "0x";

	SStream_concat0(O, InstructionInfoTable[OpInfoTable[MI->Opcode].ins].name);
	unsigned int value = MI->Operands[0].ImmVal;

	switch (OpInfoTable[opcode].am) {
		default:
			break;

		case MOS65XX_AM_IMP:
			break;

		case MOS65XX_AM_ACC:
			SStream_concat(O, " a");
			break;

		case MOS65XX_AM_ABS:
			SStream_concat(O, " %s%04x", prefix, value);
			break;

		case MOS65XX_AM_IMM:
			SStream_concat(O, " #%s%02x", prefix, value);
			break;

		case MOS65XX_AM_ZP:
			SStream_concat(O, " %s%02x", prefix, value);
			break;

		case MOS65XX_AM_ABSX:
			SStream_concat(O, " %s%04x, x", prefix, value);
			break;

		case MOS65XX_AM_ABSY:
			SStream_concat(O, " %s%04x, y", prefix, value);
			break;

		case MOS65XX_AM_ZPX:
			SStream_concat(O, " %s%02x, x", prefix, value);
			break;

		case MOS65XX_AM_ZPY:
			SStream_concat(O, " %s%02x, y", prefix, value);
			break;

		case MOS65XX_AM_REL:
			SStream_concat(O, " %s%04x", prefix, 
				(MI->address + (signed char) value + 2) & 0xffff);
			break;

		case MOS65XX_AM_IND:
			SStream_concat(O, " (%s%04x)", prefix, value);
			break;

		case MOS65XX_AM_INDX:
			SStream_concat(O, " (%s%02x, x)", prefix, value);
			break;

		case MOS65XX_AM_INDY:
			SStream_concat(O, " (%s%02x), y", prefix, value);
			break;
	}
#endif
}

bool MOS65XX_getInstruction(csh ud, const uint8_t *code, size_t code_len,
							MCInst *MI, uint16_t *size, uint64_t address, void *inst_info)
{
	unsigned char opcode;
	unsigned char len;
	mos65xx_insn ins;
	int cpu_type = MOS65XX_CPU_TYPE_6502;
	cs_struct* handle = MI->csh;
	mos65xx_info *info = (mos65xx_info *)handle->printer_info;

	if (code_len == 0) {
		*size = 1;
		return false;
	}

	if (handle->mode & CS_MODE_MOS65XX_65C02)
		cpu_type = MOS65XX_CPU_TYPE_6502;
	info->cpu_type = cpu_type;

	opcode = code[0];
	ins = OpInfoTable[opcode].ins;
	if (ins == MOS65XX_INS_INVALID) {
		*size = 1;
		return false;
	}

	len = getInstructionLength(OpInfoTable[opcode].am);
	if (code_len < len) {
		*size = 1;
		return false;
	}

	MI->address = address;
	MI->Opcode = opcode;
	MI->OpcodePub = ins;
	MI->size = 0;

	*size = len;
	if (len == 2) {
		MCOperand_CreateImm0(MI, code[1]);
	} else
	if (len == 3) {
		MCOperand_CreateImm0(MI, (code[2]<<8) | code[1]);
	}
#ifndef CAPSTONE_DIET
	if (MI->flat_insn->detail) {
		fillDetails(MI, opcode);
	}
#endif

	return true;
}

const char *MOS65XX_insn_name(csh handle, unsigned int id)
{
#ifdef CAPSTONE_DIET
	return NULL;
#else
	if (id >= ARR_SIZE(InstructionInfoTable)) {
		return NULL;
	}
	return InstructionInfoTable[id].name;
#endif
}

const char* MOS65XX_reg_name(csh handle, unsigned int reg)
{
#ifdef CAPSTONE_DIET
	return NULL;
#else
	if (reg >= ARR_SIZE(RegNames)) {
		return NULL;
	}
	return RegNames[(int)reg];
#endif
}

void MOS65XX_get_insn_id(cs_struct *h, cs_insn *insn, unsigned int id)
{
	if (id < 256) {
		insn->id = OpInfoTable[id].ins;
	}
}

const char *MOS65XX_group_name(csh handle, unsigned int id)
{
#ifdef CAPSTONE_DIET
	return NULL;
#else
	if (id >= ARR_SIZE(GroupNames)) {
		return NULL;
	}
	return GroupNames[(int)id];
#endif
}

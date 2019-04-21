/* Capstone Disassembly Engine */
/* MOS65XX Backend by Sebastian Macke <sebastian@macke.de> 2018 */

#ifdef CAPSTONE_HAS_MOS65XX

#include "../../utils.h"
#include "../../MCRegisterInfo.h"
#include "MOS65XXDisassembler.h"
#include "MOS65XXDisassemblerInternals.h"
#include "MOS65XXModule.h"

cs_err MOS65XX_global_init(cs_struct *ud)
{
	mos65xx_info *info;
	// verify if requested mode is valid
	if (ud->mode)
		return CS_ERR_MODE;

	info = cs_mem_malloc(sizeof(*info));
	info->hex_prefix = NULL;
	info->cpu_type = MOS65XX_CPU_TYPE_6502;

	ud->printer = MOS65XX_printInst;
	ud->printer_info = info;
	ud->insn_id = MOS65XX_get_insn_id;
	ud->insn_name = MOS65XX_insn_name;
	ud->group_name = MOS65XX_group_name;
	ud->disasm = MOS65XX_getInstruction;
	ud->reg_name = MOS65XX_reg_name;

	return CS_ERR_OK;
}

cs_err MOS65XX_option(cs_struct *handle, cs_opt_type type, size_t value)
{
	mos65xx_info *info = (mos65xx_info *)handle->printer_info;
	switch(type) {
		default:
			break;
		case CS_OPT_MODE:
			handle->mode = (cs_mode)value;
			break;
		case CS_OPT_SYNTAX:
			switch(value) {
				default:
					// wrong syntax value
					handle->errnum = CS_ERR_OPTION;
					return CS_ERR_OPTION;
				case CS_OPT_SYNTAX_DEFAULT:
					info->hex_prefix = NULL;
					break;
				case CS_OPT_SYNTAX_MOTOROLA:
					info->hex_prefix = "$";
					break;
			}
			handle->syntax = (int)value;
			break;
	}
	return CS_ERR_OK;
}

#endif

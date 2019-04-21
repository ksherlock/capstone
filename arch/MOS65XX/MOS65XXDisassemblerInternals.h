#ifndef CS_MOS65XXDISASSEMBLERINTERNALS_H
#define CS_MOS65XXDISASSEMBLERINTERNALS_H

#include "capstone/mos65xx.h"

enum {
	MOS65XX_CPU_TYPE_6502,
	MOS65XX_CPU_TYPE_65C02
};

typedef struct mos65xx_info {

	char *hex_prefix;
	unsigned cpu_type;

} mos65xx_info;


#endif

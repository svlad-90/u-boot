# SPDX-License-Identifier: GPL-2.0+

obj-y += \
	avb_preloaded.o \
	boot.o \
	generate_fdt.o \
	lowlevel_init.o \
	next_stage_fdt.o \
	pvmfw-arm64.o \

$(obj)/next_stage_fdt.c: $(obj)/platform.dtb
	$(call cmd,bin2c,next_stage_fdt_template)
$(obj)/platform.dtb: $(src)/platform.dts
	$(call cmd,dtc)

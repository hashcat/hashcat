##
## Author......: Jens Steube <jens.steube@gmail.com>
## License.....: MIT
##

##
## Detect number of processors
##

NPROCS   := $(shell grep -c ^processor /proc/cpuinfo)
OS       := $(shell uname)

##
## Makefile flags
##

MAKEFLAGS += -l -j $(NPROCS) -rR --no-print-directory

ifneq ($(findstring clean,$(MAKECMDGOALS)),)
MAKEFLAGS += -j 1
endif

##
## Installation paths (Linux only)
##

INSTALL_FOLDER           ?= /opt/test/usr/bin
SHARED_FOLDER            ?= /opt/test/usr/share/oclHashcat
DOCUMENT_FOLDER          ?= /opt/test/usr/share/doc/oclHashcat

#INSTALL_FOLDER           ?= /usr/bin
#SHARED_FOLDER            ?= /usr/share/oclHashcat
#DOCUMENT_FOLDER          ?= /usr/share/doc/oclHashcat

##
## Library paths
##

OCL                      := deps/amd-app-sdk
OCLLIBPATH32             := $(OCL)/lib/x86
OCLLIBPATH64             := $(OCL)/lib/x86_64

CUDA                     := deps/cuda-7.5
CUDALIBPATH32            := deps/NVIDIA-Linux-x86_64-352.21/32
CUDALIBPATH64            := deps/NVIDIA-Linux-x86_64-352.21

ADL                      := deps/adl-sdk

GDK                      := deps/nvidia-gdk
NVAPI                    := deps/R352-developer

NVMLINCPATH              := $(GDK)/usr/include/nvidia/gdk/
NVMLLIBPATH32            := $(CUDALIBPATH32)
NVMLLIBPATH64            := $(CUDALIBPATH64)

CLCOMPILE_PATH           := tools/clcompile
RULES_OPTIMIZE_PATH      := tools/rules_optimize

##
## Compiler paths
##

CC_LINUX_32              := gcc
CC_LINUX_64              := gcc

CC_WIN_32                := i686-w64-mingw32-gcc
CC_WIN_64                := x86_64-w64-mingw32-gcc

DLL_WIN_32               := i686-w64-mingw32-dlltool
DLL_WIN_64               := x86_64-w64-mingw32-dlltool

NVCC                     := $(CUDA)/bin/nvcc
CLCOMPILE                := $(CLCOMPILE_PATH)/clcompile.bin

BIN                      := .

INSTALL                  := install
CP                       := cp

##
## Misc stuff
##

NOW                      := $(shell perl -e 'print time')

##
## Compiler flags
##

CFLAGS                   := -O2 -s -pipe -W -Wall -Iinclude/ -std=c99
#CFLAGS                   := -g -pipe -W -Wall -Iinclude/ -std=c99

CFLAGS_32                := -m32
CFLAGS_64                := -m64

CFLAGS_LINUX             := -D_POSIX -DLINUX
CFLAGS_WIN               := -D_WIN   -DWIN -D__MSVCRT__ -D__USE_MINGW_ANSI_STDIO=1

CFLAGS_OCL_LINUX         := -D_OCL  -I$(OCL)/include/ -I$(ADL)/include/
CFLAGS_OCL_WIN           := -D_OCL  -I$(OCL)/include/ -I$(ADL)/include/
CFLAGS_CUDA_LINUX        := -D_CUDA -I$(CUDA)/include/ -I$(GDK)/usr/include/nvidia/gdk/
CFLAGS_CUDA_WIN          := -D_CUDA -I$(CUDA)/include/ -I$(NVAPI)/

LFLAGS_OCL_LINUX         := -lpthread -lOpenCL -ldl
LFLAGS_OCL_WIN           := -lpsapi -L./lib
LFLAGS_CUDA_LINUX        := -lpthread -lnvidia-ml -lcuda
LFLAGS_CUDA_WIN          := -lpsapi -L./lib

##
## Kernels
##

AMD_IN                   := amd
AMD_OUT                  := kernels/4098

NV_IN                    := nv
NV_OUT                   := kernels/4318

KERNELS_MODE_ALL         := m00400 m00500 m01600 m01800 m02100 m02500 m03200 m05200 m05800 m06211 m06212 m06213 m06221 m06222 m06223 m06231 m06232 m06233 m06300 m06400 m06500 m06600 m06700 m06800 m07100 m07400 m07900 m08200 m08800 m08900 m09000 m09100 m09400 m09500 m09600 m10300 m10500 m10700 m10900 m11300 m11600 m11900 m12000 m12200 m12300 m12400 m12500 m12700 m12800 m00000_a0 m00000_a1 m00000_a3 m00010_a0 m00010_a1 m00010_a3 m00020_a0 m00020_a1 m00020_a3 m00030_a0 m00030_a1 m00030_a3 m00040_a0 m00040_a1 m00040_a3 m00050_a0 m00050_a1 m00050_a3 m00060_a0 m00060_a1 m00060_a3 m00100_a0 m00100_a1 m00100_a3 m00110_a0 m00110_a1 m00110_a3 m00120_a0 m00120_a1 m00120_a3 m00130_a0 m00130_a1 m00130_a3 m00140_a0 m00140_a1 m00140_a3 m00150_a0 m00150_a1 m00150_a3 m00160_a0 m00160_a1 m00160_a3 m00190_a0 m00190_a1 m00190_a3 m00200_a0 m00200_a1 m00200_a3 m00300_a0 m00300_a1 m00300_a3 m00900_a0 m00900_a1 m00900_a3 m01000_a0 m01000_a1 m01000_a3 m01100_a0 m01100_a1 m01100_a3 m01400_a0 m01400_a1 m01400_a3 m01410_a0 m01410_a1 m01410_a3 m01420_a0 m01420_a1 m01420_a3 m01430_a0 m01430_a1 m01430_a3 m01440_a0 m01440_a1 m01440_a3 m01450_a0 m01450_a1 m01450_a3 m01460_a0 m01460_a1 m01460_a3 m01500_a0 m01500_a1 m01500_a3 m01700_a0 m01700_a1 m01700_a3 m01710_a0 m01710_a1 m01710_a3 m01720_a0 m01720_a1 m01720_a3 m01730_a0 m01730_a1 m01730_a3 m01740_a0 m01740_a1 m01740_a3 m01750_a0 m01750_a1 m01750_a3 m01760_a0 m01760_a1 m01760_a3 m02400_a0 m02400_a1 m02400_a3 m02410_a0 m02410_a1 m02410_a3 m02610_a0 m02610_a1 m02610_a3 m02710_a0 m02710_a1 m02710_a3 m02810_a0 m02810_a1 m02810_a3 m03000_a0 m03000_a1 m03000_a3 m03100_a0 m03100_a1 m03100_a3 m03710_a0 m03710_a1 m03710_a3 m03800_a0 m03800_a1 m03800_a3 m04310_a0 m04310_a1 m04310_a3 m04400_a0 m04400_a1 m04400_a3 m04500_a0 m04500_a1 m04500_a3 m04700_a0 m04700_a1 m04700_a3 m04800_a0 m04800_a1 m04800_a3 m04900_a0 m04900_a1 m04900_a3 m05000_a0 m05000_a1 m05000_a3 m05100_a0 m05100_a1 m05100_a3 m05300_a0 m05300_a1 m05300_a3 m05400_a0 m05400_a1 m05400_a3 m05500_a0 m05500_a1 m05500_a3 m05600_a0 m05600_a1 m05600_a3 m06000_a0 m06000_a1 m06000_a3 m06100_a0 m06100_a1 m06100_a3 m06900_a0 m06900_a1 m06900_a3 m07300_a0 m07300_a1 m07300_a3 m07500_a0 m07500_a1 m07500_a3 m07600_a0 m07600_a1 m07600_a3 m07700_a0 m07700_a1 m07700_a3 m07800_a0 m07800_a1 m07800_a3 m08000_a0 m08000_a1 m08000_a3 m08100_a0 m08100_a1 m08100_a3 m08300_a0 m08300_a1 m08300_a3 m08400_a0 m08400_a1 m08400_a3 m08500_a0 m08500_a1 m08500_a3 m08600_a0 m08600_a1 m08600_a3 m08700_a0 m08700_a1 m08700_a3 m09700_a0 m09700_a1 m09700_a3 m09710_a0 m09710_a1 m09710_a3 m09720_a0 m09720_a1 m09720_a3 m09800_a0 m09800_a1 m09800_a3 m09810_a0 m09810_a1 m09810_a3 m09820_a0 m09820_a1 m09820_a3 m09900_a0 m09900_a1 m09900_a3 m10100_a0 m10100_a1 m10100_a3 m10400_a0 m10400_a1 m10400_a3 m10410_a0 m10410_a1 m10410_a3 m10420_a0 m10420_a1 m10420_a3 m10800_a0 m10800_a1 m10800_a3 m11000_a0 m11000_a1 m11000_a3 m11100_a0 m11100_a1 m11100_a3 m11200_a0 m11200_a1 m11200_a3 m11400_a0 m11400_a1 m11400_a3 m11500_a0 m11500_a1 m11500_a3 m11700_a0 m11700_a1 m11700_a3 m11800_a0 m11800_a1 m11800_a3 m12600_a0 m12600_a1 m12600_a3
KERNELS_MASK_ALL         := markov_le_v1 markov_le_v2 markov_le_v4 markov_be_v1 markov_be_v2 markov_be_v4
KERNELS_AMP_ALL          := amp_a0_v1 amp_a0_v2 amp_a0_v4 amp_a1_v1 amp_a1_v2 amp_a1_v4 amp_a3_v1 amp_a3_v2 amp_a3_v4
AMD_DEVICES_ALL          := VLIW1 VLIW4 VLIW5
NV_DEVICES_ALL           := sm_20 sm_21 sm_30 sm_35 sm_37 sm_50 sm_52
NV_BITNESS_ALL           := 32 64

##
## Targets for scrypt
##

SCRYPT_N_ALL             := 1024 16384
SCRYPT_R_ALL             := 1
SCRYPT_P_ALL             := 1
SCRYPT_TMTO_ALL          := 2 4 8 16 32 64 128 256 512 1024

##
## Targets: Global
##

all: binaries_all kernels_all

binaries_all: linux32 linux64 win32 win64 rules_optimize

kernels_all: amd_all nv_all

release: binaries

linux: linux32 linux64 rules_optimize

windows: win32 win64 rules_optimize

clean: clean_bin

clean_all: clean_bin clean_kernel clean_clcompile

clean_bin:
	rm -f obj/*.o lib/*.a $(BIN)/*.bin $(BIN)/*.exe $(BIN)/*.app *.restore *.out *.pot *.dictstat *.log
	rm -rf *Hashcat.induct
	rm -rf *Hashcat.outfiles
	$(MAKE) -C $(RULES_OPTIMIZE_PATH) clean

clean_kernel:
	rm -f $(AMD_OUT)/* $(NV_OUT)/*

clean_clcompile:
	rm -f ${CLCOMPILE_PATH}/clcompile.bin

${CLCOMPILE}: ${CLCOMPILE_PATH}/clcompile.c
	$(CC_LINUX_64) $(CFLAGS) -o $@ -I$(CFLAGS_OCL_LINUX) $< -L$(OCLLIBPATH64) $(LFLAGS_OCL_LINUX)

rules_optimize:
	$(MAKE) -C $(RULES_OPTIMIZE_PATH)

linux32:        oclHashcat32.bin cudaHashcat32.bin
linux64:        oclHashcat64.bin cudaHashcat64.bin

win32:          oclHashcat32.exe cudaHashcat32.exe
win64:          oclHashcat64.exe cudaHashcat64.exe

amd_all:        $(foreach KERNEL,$(KERNELS_MODE_ALL),$(foreach DEVICE,$(AMD_DEVICES_ALL),$(AMD_OUT)/$(KERNEL).$(DEVICE).llvmir)) \
		$(AMD_OUT)/markov_le_v1.llvmir $(AMD_OUT)/markov_le_v2.llvmir $(AMD_OUT)/markov_le_v4.llvmir \
		$(AMD_OUT)/markov_be_v1.llvmir $(AMD_OUT)/markov_be_v2.llvmir $(AMD_OUT)/markov_be_v4.llvmir \
		$(AMD_OUT)/amp_a0_v1.llvmir $(AMD_OUT)/amp_a0_v2.llvmir $(AMD_OUT)/amp_a0_v4.llvmir \
		$(AMD_OUT)/amp_a1_v1.llvmir $(AMD_OUT)/amp_a1_v2.llvmir $(AMD_OUT)/amp_a1_v4.llvmir \
		$(AMD_OUT)/amp_a3_v1.llvmir $(AMD_OUT)/amp_a3_v2.llvmir $(AMD_OUT)/amp_a3_v4.llvmir

nv_all:         $(foreach KERNEL,$(KERNELS_MODE_ALL),$(foreach DEVICE,$(NV_DEVICES_ALL),$(foreach BITNESS,$(NV_BITNESS_ALL),$(NV_OUT)/$(KERNEL).$(DEVICE).$(BITNESS).cubin))) \
		$(foreach DEVICE,$(NV_DEVICES_ALL),$(foreach BITNESS,$(NV_BITNESS_ALL),$(NV_OUT)/markov_le_v1.$(DEVICE).$(BITNESS).cubin)) $(foreach DEVICE,$(NV_DEVICES_ALL),$(foreach BITNESS,$(NV_BITNESS_ALL),$(NV_OUT)/markov_le_v2.$(DEVICE).$(BITNESS).cubin)) $(foreach DEVICE,$(NV_DEVICES_ALL),$(foreach BITNESS,$(NV_BITNESS_ALL),$(NV_OUT)/markov_le_v4.$(DEVICE).$(BITNESS).cubin)) \
		$(foreach DEVICE,$(NV_DEVICES_ALL),$(foreach BITNESS,$(NV_BITNESS_ALL),$(NV_OUT)/markov_be_v1.$(DEVICE).$(BITNESS).cubin)) $(foreach DEVICE,$(NV_DEVICES_ALL),$(foreach BITNESS,$(NV_BITNESS_ALL),$(NV_OUT)/markov_be_v2.$(DEVICE).$(BITNESS).cubin)) $(foreach DEVICE,$(NV_DEVICES_ALL),$(foreach BITNESS,$(NV_BITNESS_ALL),$(NV_OUT)/markov_be_v4.$(DEVICE).$(BITNESS).cubin)) \
		$(foreach DEVICE,$(NV_DEVICES_ALL),$(foreach BITNESS,$(NV_BITNESS_ALL),$(NV_OUT)/amp_a0_v1.$(DEVICE).$(BITNESS).cubin))    $(foreach DEVICE,$(NV_DEVICES_ALL),$(foreach BITNESS,$(NV_BITNESS_ALL),$(NV_OUT)/amp_a0_v2.$(DEVICE).$(BITNESS).cubin))    $(foreach DEVICE,$(NV_DEVICES_ALL),$(foreach BITNESS,$(NV_BITNESS_ALL),$(NV_OUT)/amp_a0_v4.$(DEVICE).$(BITNESS).cubin)) \
		$(foreach DEVICE,$(NV_DEVICES_ALL),$(foreach BITNESS,$(NV_BITNESS_ALL),$(NV_OUT)/amp_a1_v1.$(DEVICE).$(BITNESS).cubin))    $(foreach DEVICE,$(NV_DEVICES_ALL),$(foreach BITNESS,$(NV_BITNESS_ALL),$(NV_OUT)/amp_a1_v2.$(DEVICE).$(BITNESS).cubin))    $(foreach DEVICE,$(NV_DEVICES_ALL),$(foreach BITNESS,$(NV_BITNESS_ALL),$(NV_OUT)/amp_a1_v4.$(DEVICE).$(BITNESS).cubin)) \
		$(foreach DEVICE,$(NV_DEVICES_ALL),$(foreach BITNESS,$(NV_BITNESS_ALL),$(NV_OUT)/amp_a3_v1.$(DEVICE).$(BITNESS).cubin))    $(foreach DEVICE,$(NV_DEVICES_ALL),$(foreach BITNESS,$(NV_BITNESS_ALL),$(NV_OUT)/amp_a3_v2.$(DEVICE).$(BITNESS).cubin))    $(foreach DEVICE,$(NV_DEVICES_ALL),$(foreach BITNESS,$(NV_BITNESS_ALL),$(NV_OUT)/amp_a3_v4.$(DEVICE).$(BITNESS).cubin))

##
## Targets: Linux install
## We need some better native compilation logic here, fixing it to 64 bit for now and AMD kernels
## How to make /usr/bin/install doing recursive??
##

install: linux64 amd_all
	$(INSTALL) -m 755 -d                     $(DOCUMENT_FOLDER)
	$(CP) -a docs/*                          $(DOCUMENT_FOLDER)/
	$(INSTALL) -m 755 -d                     $(DOCUMENT_FOLDER)/extra
	$(CP) -a extra/*                         $(DOCUMENT_FOLDER)/extra/
	$(INSTALL) -m 755 -d                     $(SHARED_FOLDER)
	$(INSTALL) -m 755 -d                     $(SHARED_FOLDER)/charsets
	$(CP) -a charsets/*                      $(SHARED_FOLDER)/charsets/
	$(INSTALL) -m 755 -d                     $(SHARED_FOLDER)/kernels
	$(CP) -a kernels/*                       $(SHARED_FOLDER)/kernels/
	$(INSTALL) -m 755 -d                     $(SHARED_FOLDER)/masks
	$(CP) -a masks/*                         $(SHARED_FOLDER)/masks/
	$(INSTALL) -m 755 -d                     $(SHARED_FOLDER)/rules
	$(CP) -a rules/*                         $(SHARED_FOLDER)/rules/
	$(INSTALL) -m 755    -T hashcat.hcstat   $(SHARED_FOLDER)/hashcat.hcstat
	$(INSTALL) -m 755 -s -T oclHashcat64.bin $(INSTALL_FOLDER)/oclHashcat


uninstall:
	$(RM) -f  $(INSTALL_FOLDER)/oclHashcat
	$(RM) -rf $(SHARED_FOLDER)
	$(RM) -rf $(DOCUMENT_FOLDER)

##
## Targets: AMD Kernel (oclHashcat)
##

# general kernels

$(AMD_OUT)/markov_%.llvmir: $(AMD_IN)/markov_%.cl ${CLCOMPILE}
	@rm -f $(subst .llvmir,*.kernel,$@)
	$(CLCOMPILE) "-D VLIW1 -I $(AMD_IN)/" $< $@

$(AMD_OUT)/amp_%_v1.llvmir: $(AMD_IN)/amp_%_v1.cl ${CLCOMPILE}
	@rm -f $(subst .llvmir,*.kernel,$@)
	$(CLCOMPILE) "-D VLIW1 -I $(AMD_IN)/" $< $@

$(AMD_OUT)/amp_%_v2.llvmir: $(AMD_IN)/amp_%_v2.cl ${CLCOMPILE}
	@rm -f $(subst .llvmir,*.kernel,$@)
	$(CLCOMPILE) "-D VLIW1 -I $(AMD_IN)/" $< $@

$(AMD_OUT)/amp_%_v4.llvmir: $(AMD_IN)/amp_%_v4.cl ${CLCOMPILE}
	@rm -f $(subst .llvmir,*.kernel,$@)
	$(CLCOMPILE) "-D VLIW1 -I $(AMD_IN)/" $< $@

$(AMD_OUT)/%.VLIW1.llvmir: $(AMD_IN)/%.cl ${CLCOMPILE}
	@rm -f $(subst VLIW1.llvmir,*.kernel,$@)
	$(CLCOMPILE) "-D VLIW1 -I $(AMD_IN)/" $< $@

$(AMD_OUT)/%.VLIW4.llvmir: $(AMD_IN)/%.cl ${CLCOMPILE}
	@rm -f $(subst VLIW4.llvmir,*.kernel,$@)
	$(CLCOMPILE) "-D VLIW4 -I $(AMD_IN)/" $< $@

$(AMD_OUT)/%.VLIW5.llvmir: $(AMD_IN)/%.cl ${CLCOMPILE}
	@rm -f $(subst VLIW5.llvmir,*.kernel,$@)
	$(CLCOMPILE) "-D VLIW5 -I $(AMD_IN)/" $< $@

# scrypt specific kernels

.PHONY : $(AMD_OUT)/m08900.VLIW1.llvmir $(AMD_OUT)/m08900.VLIW4.llvmir $(AMD_OUT)/m08900.VLIW5.llvmir

$(AMD_OUT)/m08900.VLIW1.llvmir: $(foreach N,$(SCRYPT_N_ALL),$(foreach R,$(SCRYPT_R_ALL),$(foreach P,$(SCRYPT_P_ALL),$(foreach TMTO,$(SCRYPT_TMTO_ALL),$(AMD_OUT)/m08900_$(N)_$(R)_$(P)_$(TMTO).VLIW1.llvmir)))) ${CLCOMPILE}

$(AMD_OUT)/m08900.VLIW4.llvmir: $(foreach N,$(SCRYPT_N_ALL),$(foreach R,$(SCRYPT_R_ALL),$(foreach P,$(SCRYPT_P_ALL),$(foreach TMTO,$(SCRYPT_TMTO_ALL),$(AMD_OUT)/m08900_$(N)_$(R)_$(P)_$(TMTO).VLIW4.llvmir)))) ${CLCOMPILE}

$(AMD_OUT)/m08900.VLIW5.llvmir: $(foreach N,$(SCRYPT_N_ALL),$(foreach R,$(SCRYPT_R_ALL),$(foreach P,$(SCRYPT_P_ALL),$(foreach TMTO,$(SCRYPT_TMTO_ALL),$(AMD_OUT)/m08900_$(N)_$(R)_$(P)_$(TMTO).VLIW5.llvmir)))) ${CLCOMPILE}

$(AMD_OUT)/m08900_%.llvmir: $(AMD_IN)/m08900.cl ${CLCOMPILE}
	@rm -f $(subst .llvmir,*.kernel,$@)
	$(eval splitted := $(subst ., ,$(subst _, ,$@)))
	$(eval n_val    := $(wordlist 2, 2, $(splitted)))
	$(eval r_val    := $(wordlist 3, 3, $(splitted)))
	$(eval p_val    := $(wordlist 4, 4, $(splitted)))
	$(eval tmto_val := $(wordlist 5, 5, $(splitted)))
	$(eval vliw_val := $(wordlist 6, 6, $(splitted)))
	$(CLCOMPILE) "-D $(vliw_val) -I $(AMD_IN)/ -DSCRYPT_N=$(n_val) -DSCRYPT_R=$(r_val) -DSCRYPT_P=$(p_val) -DSCRYPT_TMTO=$(tmto_val)" $< $@

##
## Targets: NV Kernels 32 bit (oclHashcat)
##

# general kernels

$(NV_OUT)/%.sm_20.32.cubin: $(NV_IN)/%.cu
	${NVCC} -ccbin $(CC_LINUX_32) -cubin --machine 32 -o $@ -arch sm_20 -I . -I $(NV_IN)/ $< -Dsm_20 -DNV32

$(NV_OUT)/%.sm_21.32.cubin: $(NV_IN)/%.cu
	${NVCC} -ccbin $(CC_LINUX_32) -cubin --machine 32 -o $@ -arch sm_21 -I . -I $(NV_IN)/ $< -Dsm_21 -DNV32

$(NV_OUT)/%.sm_30.32.cubin: $(NV_IN)/%.cu
	${NVCC} -ccbin $(CC_LINUX_32) -cubin --machine 32 -o $@ -arch sm_30 -I . -I $(NV_IN)/ $< -Dsm_30 -DNV32

$(NV_OUT)/%.sm_35.32.cubin: $(NV_IN)/%.cu
	${NVCC} -ccbin $(CC_LINUX_32) -cubin --machine 32 -o $@ -arch sm_35 -I . -I $(NV_IN)/ $< -Dsm_35 -DNV32

$(NV_OUT)/%.sm_37.32.cubin: $(NV_IN)/%.cu
	${NVCC} -ccbin $(CC_LINUX_32) -cubin --machine 32 -o $@ -arch sm_37 -I . -I $(NV_IN)/ $< -Dsm_37 -DNV32

$(NV_OUT)/%.sm_50.32.cubin: $(NV_IN)/%.cu
	${NVCC} -ccbin $(CC_LINUX_32) -cubin --machine 32 -o $@ -arch sm_50 -I . -I $(NV_IN)/ $< -Dsm_50 -DNV32

$(NV_OUT)/%.sm_52.32.cubin: $(NV_IN)/%.cu
	${NVCC} -ccbin $(CC_LINUX_32) -cubin --machine 32 -o $@ -arch sm_52 -I . -I $(NV_IN)/ $< -Dsm_52 -DNV32

# scrypt specific kernels

.PHONY : $(NV_OUT)/m08900.sm_20.32.cubin $(NV_OUT)/m08900.sm_21.32.cubin $(NV_OUT)/m08900.sm_30.32.cubin $(NV_OUT)/m08900.sm_35.32.cubin $(NV_OUT)/m08900.sm_37.32.cubin $(NV_OUT)/m08900.sm_50.32.cubin $(NV_OUT)/m08900.sm_52.32.cubin

$(NV_OUT)/m08900.sm_20.32.cubin:$(foreach N,$(SCRYPT_N_ALL),$(foreach R,$(SCRYPT_R_ALL),$(foreach P,$(SCRYPT_P_ALL),$(foreach TMTO,$(SCRYPT_TMTO_ALL),$(NV_OUT)/m08900_$(N)_$(R)_$(P)_$(TMTO).sm_20.32.cubin))))

$(NV_OUT)/m08900.sm_21.32.cubin:$(foreach N,$(SCRYPT_N_ALL),$(foreach R,$(SCRYPT_R_ALL),$(foreach P,$(SCRYPT_P_ALL),$(foreach TMTO,$(SCRYPT_TMTO_ALL),$(NV_OUT)/m08900_$(N)_$(R)_$(P)_$(TMTO).sm_21.32.cubin))))

$(NV_OUT)/m08900.sm_30.32.cubin:$(foreach N,$(SCRYPT_N_ALL),$(foreach R,$(SCRYPT_R_ALL),$(foreach P,$(SCRYPT_P_ALL),$(foreach TMTO,$(SCRYPT_TMTO_ALL),$(NV_OUT)/m08900_$(N)_$(R)_$(P)_$(TMTO).sm_30.32.cubin))))

$(NV_OUT)/m08900.sm_35.32.cubin:$(foreach N,$(SCRYPT_N_ALL),$(foreach R,$(SCRYPT_R_ALL),$(foreach P,$(SCRYPT_P_ALL),$(foreach TMTO,$(SCRYPT_TMTO_ALL),$(NV_OUT)/m08900_$(N)_$(R)_$(P)_$(TMTO).sm_35.32.cubin))))

$(NV_OUT)/m08900.sm_37.32.cubin:$(foreach N,$(SCRYPT_N_ALL),$(foreach R,$(SCRYPT_R_ALL),$(foreach P,$(SCRYPT_P_ALL),$(foreach TMTO,$(SCRYPT_TMTO_ALL),$(NV_OUT)/m08900_$(N)_$(R)_$(P)_$(TMTO).sm_37.32.cubin))))

$(NV_OUT)/m08900.sm_50.32.cubin:$(foreach N,$(SCRYPT_N_ALL),$(foreach R,$(SCRYPT_R_ALL),$(foreach P,$(SCRYPT_P_ALL),$(foreach TMTO,$(SCRYPT_TMTO_ALL),$(NV_OUT)/m08900_$(N)_$(R)_$(P)_$(TMTO).sm_50.32.cubin))))

$(NV_OUT)/m08900.sm_52.32.cubin:$(foreach N,$(SCRYPT_N_ALL),$(foreach R,$(SCRYPT_R_ALL),$(foreach P,$(SCRYPT_P_ALL),$(foreach TMTO,$(SCRYPT_TMTO_ALL),$(NV_OUT)/m08900_$(N)_$(R)_$(P)_$(TMTO).sm_52.32.cubin))))

$(NV_OUT)/m08900_%.32.cubin: $(NV_IN)/m08900.cu
	$(eval splitted := $(subst ., ,$(subst _, ,$@)))
	$(eval n_val    := $(wordlist 2, 2, $(splitted)))
	$(eval r_val    := $(wordlist 3, 3, $(splitted)))
	$(eval p_val    := $(wordlist 4, 4, $(splitted)))
	$(eval tmto_val := $(wordlist 5, 5, $(splitted)))
	$(eval cubin_val  := $(wordlist 7, 7, $(splitted)))
	${NVCC} -ccbin $(CC_LINUX_32) -cubin --machine 32 -o $@ -arch sm_$(cubin_val) -I . -I $(NV_IN)/ $< -Dsm_$(cubin_val) -DSCRYPT_N=$(n_val) -DSCRYPT_R=$(r_val) -DSCRYPT_P=$(p_val) -DSCRYPT_TMTO=$(tmto_val)

##
## Targets: NV Kernels 64 bit (oclHashcat)
##

# general kernels

$(NV_OUT)/%.sm_20.64.cubin: $(NV_IN)/%.cu
	${NVCC} -ccbin $(CC_LINUX_64) -cubin --machine 64 -o $@ -arch sm_20 -I . -I $(NV_IN)/ $< -Dsm_20 -DNV64

$(NV_OUT)/%.sm_21.64.cubin: $(NV_IN)/%.cu
	${NVCC} -ccbin $(CC_LINUX_64) -cubin --machine 64 -o $@ -arch sm_21 -I . -I $(NV_IN)/ $< -Dsm_21 -DNV64

$(NV_OUT)/%.sm_30.64.cubin: $(NV_IN)/%.cu
	${NVCC} -ccbin $(CC_LINUX_64) -cubin --machine 64 -o $@ -arch sm_30 -I . -I $(NV_IN)/ $< -Dsm_30 -DNV64

$(NV_OUT)/%.sm_35.64.cubin: $(NV_IN)/%.cu
	${NVCC} -ccbin $(CC_LINUX_64) -cubin --machine 64 -o $@ -arch sm_35 -I . -I $(NV_IN)/ $< -Dsm_35 -DNV64

$(NV_OUT)/%.sm_37.64.cubin: $(NV_IN)/%.cu
	${NVCC} -ccbin $(CC_LINUX_64) -cubin --machine 64 -o $@ -arch sm_37 -I . -I $(NV_IN)/ $< -Dsm_37 -DNV64

$(NV_OUT)/%.sm_50.64.cubin: $(NV_IN)/%.cu
	${NVCC} -ccbin $(CC_LINUX_64) -cubin --machine 64 -o $@ -arch sm_50 -I . -I $(NV_IN)/ $< -Dsm_50 -DNV64

$(NV_OUT)/%.sm_52.64.cubin: $(NV_IN)/%.cu
	${NVCC} -ccbin $(CC_LINUX_64) -cubin --machine 64 -o $@ -arch sm_52 -I . -I $(NV_IN)/ $< -Dsm_52 -DNV64

# scrypt specific kernels

.PHONY : $(NV_OUT)/m08900.sm_20.64.cubin $(NV_OUT)/m08900.sm_21.64.cubin $(NV_OUT)/m08900.sm_30.64.cubin $(NV_OUT)/m08900.sm_35.64.cubin $(NV_OUT)/m08900.sm_37.64.cubin $(NV_OUT)/m08900.sm_50.64.cubin $(NV_OUT)/m08900.sm_52.64.cubin

$(NV_OUT)/m08900.sm_20.64.cubin:$(foreach N,$(SCRYPT_N_ALL),$(foreach R,$(SCRYPT_R_ALL),$(foreach P,$(SCRYPT_P_ALL),$(foreach TMTO,$(SCRYPT_TMTO_ALL),$(NV_OUT)/m08900_$(N)_$(R)_$(P)_$(TMTO).sm_20.64.cubin))))

$(NV_OUT)/m08900.sm_21.64.cubin:$(foreach N,$(SCRYPT_N_ALL),$(foreach R,$(SCRYPT_R_ALL),$(foreach P,$(SCRYPT_P_ALL),$(foreach TMTO,$(SCRYPT_TMTO_ALL),$(NV_OUT)/m08900_$(N)_$(R)_$(P)_$(TMTO).sm_21.64.cubin))))

$(NV_OUT)/m08900.sm_30.64.cubin:$(foreach N,$(SCRYPT_N_ALL),$(foreach R,$(SCRYPT_R_ALL),$(foreach P,$(SCRYPT_P_ALL),$(foreach TMTO,$(SCRYPT_TMTO_ALL),$(NV_OUT)/m08900_$(N)_$(R)_$(P)_$(TMTO).sm_30.64.cubin))))

$(NV_OUT)/m08900.sm_35.64.cubin:$(foreach N,$(SCRYPT_N_ALL),$(foreach R,$(SCRYPT_R_ALL),$(foreach P,$(SCRYPT_P_ALL),$(foreach TMTO,$(SCRYPT_TMTO_ALL),$(NV_OUT)/m08900_$(N)_$(R)_$(P)_$(TMTO).sm_35.64.cubin))))

$(NV_OUT)/m08900.sm_37.64.cubin:$(foreach N,$(SCRYPT_N_ALL),$(foreach R,$(SCRYPT_R_ALL),$(foreach P,$(SCRYPT_P_ALL),$(foreach TMTO,$(SCRYPT_TMTO_ALL),$(NV_OUT)/m08900_$(N)_$(R)_$(P)_$(TMTO).sm_37.64.cubin))))

$(NV_OUT)/m08900.sm_50.64.cubin:$(foreach N,$(SCRYPT_N_ALL),$(foreach R,$(SCRYPT_R_ALL),$(foreach P,$(SCRYPT_P_ALL),$(foreach TMTO,$(SCRYPT_TMTO_ALL),$(NV_OUT)/m08900_$(N)_$(R)_$(P)_$(TMTO).sm_50.64.cubin))))

$(NV_OUT)/m08900.sm_52.64.cubin:$(foreach N,$(SCRYPT_N_ALL),$(foreach R,$(SCRYPT_R_ALL),$(foreach P,$(SCRYPT_P_ALL),$(foreach TMTO,$(SCRYPT_TMTO_ALL),$(NV_OUT)/m08900_$(N)_$(R)_$(P)_$(TMTO).sm_52.64.cubin))))

$(NV_OUT)/m08900_%.64.cubin: $(NV_IN)/m08900.cu
	$(eval splitted := $(subst ., ,$(subst _, ,$@)))
	$(eval n_val    := $(wordlist 2, 2, $(splitted)))
	$(eval r_val    := $(wordlist 3, 3, $(splitted)))
	$(eval p_val    := $(wordlist 4, 4, $(splitted)))
	$(eval tmto_val := $(wordlist 5, 5, $(splitted)))
	$(eval cubin_val  := $(wordlist 7, 7, $(splitted)))
	${NVCC} -ccbin $(CC_LINUX_64) -cubin --machine 64 -o $@ -arch sm_$(cubin_val) -I . -I $(NV_IN)/ $< -Dsm_$(cubin_val) -DNV64 -DSCRYPT_N=$(n_val) -DSCRYPT_R=$(r_val) -DSCRYPT_P=$(p_val) -DSCRYPT_TMTO=$(tmto_val)

##
## Targets: Libraries
##

lib/libOpenCL.a:
	${DLL_WIN_32} -A -k -l lib/libOpenCL.a   -d lib/OpenCL.def

lib/libOpenCL64.a:
	${DLL_WIN_64} -A -k -l lib/libOpenCL64.a -d lib/OpenCL64.def

lib/libcuda.a:
	${DLL_WIN_32} -A -k -l lib/libcuda.a     -d lib/cuda.def

lib/libcuda64.a:
	${DLL_WIN_64} -A -k -l lib/libcuda64.a   -d lib/cuda64.def

##
## oclHashcat
##

obj/%.oclHashcat.LINUX.32.o:  src/%.c
	$(CC_LINUX_32) $(CFLAGS) $(CFLAGS_LINUX) $(CFLAGS_32) $(CFLAGS_OCL_LINUX)  -c -o $@ $<

obj/%.oclHashcat.LINUX.64.o:  src/%.c
	$(CC_LINUX_64) $(CFLAGS) $(CFLAGS_LINUX) $(CFLAGS_64) $(CFLAGS_OCL_LINUX)  -c -o $@ $<

obj/%.oclHashcat.WIN.32.o:    src/%.c
	$(CC_WIN_32)   $(CFLAGS) $(CFLAGS_WIN)   $(CFLAGS_32) $(CFLAGS_OCL_WIN)    -c -o $@ $<

obj/%.oclHashcat.WIN.64.o:    src/%.c
	$(CC_WIN_64)   $(CFLAGS) $(CFLAGS_WIN)   $(CFLAGS_64) $(CFLAGS_OCL_WIN)    -c -o $@ $<

obj/%.cudaHashcat.LINUX.32.o: src/%.c
	$(CC_LINUX_32) $(CFLAGS) $(CFLAGS_LINUX) $(CFLAGS_32) $(CFLAGS_CUDA_LINUX) -c -o $@ $<

obj/%.cudaHashcat.LINUX.64.o: src/%.c
	$(CC_LINUX_64) $(CFLAGS) $(CFLAGS_LINUX) $(CFLAGS_64) $(CFLAGS_CUDA_LINUX) -c -o $@ $<

obj/%.cudaHashcat.WIN.32.o:   src/%.c
	$(CC_WIN_32)   $(CFLAGS) $(CFLAGS_WIN)   $(CFLAGS_32) $(CFLAGS_CUDA_WIN)   -c -o $@ $<

obj/%.cudaHashcat.WIN.64.o:   src/%.c
	$(CC_WIN_64)   $(CFLAGS) $(CFLAGS_WIN)   $(CFLAGS_64) $(CFLAGS_CUDA_WIN)   -c -o $@ $<

oclHashcat32.bin:  src/oclHashcat.c obj/ext_OpenCL.oclHashcat.LINUX.32.o obj/ext_ADL.oclHashcat.LINUX.32.o    obj/shared.oclHashcat.LINUX.32.o  obj/rp_gpu_on_cpu.oclHashcat.LINUX.32.o
	$(CC_LINUX_32) $(CFLAGS) $(CFLAGS_LINUX) $(CFLAGS_32) $(CFLAGS_OCL_LINUX)  -o $@ -DCOMPTIME=$(NOW) $^ -L$(OCLLIBPATH32)  $(LFLAGS_OCL_LINUX) -DINSTALL_FOLDER=\"$(INSTALL_FOLDER)\" -DSHARED_FOLDER=\"$(SHARED_FOLDER)\" -DDOCUMENT_FOLDER=\"$(DOCUMENT_FOLDER)\"

oclHashcat64.bin:  src/oclHashcat.c obj/ext_OpenCL.oclHashcat.LINUX.64.o obj/ext_ADL.oclHashcat.LINUX.64.o    obj/shared.oclHashcat.LINUX.64.o  obj/rp_gpu_on_cpu.oclHashcat.LINUX.64.o
	$(CC_LINUX_64) $(CFLAGS) $(CFLAGS_LINUX) $(CFLAGS_64) $(CFLAGS_OCL_LINUX)  -o $@ -DCOMPTIME=$(NOW) $^ -L$(OCLLIBPATH64)  $(LFLAGS_OCL_LINUX) -DINSTALL_FOLDER=\"$(INSTALL_FOLDER)\" -DSHARED_FOLDER=\"$(SHARED_FOLDER)\" -DDOCUMENT_FOLDER=\"$(DOCUMENT_FOLDER)\"

oclHashcat32.exe:  src/oclHashcat.c obj/ext_OpenCL.oclHashcat.WIN.32.o   obj/ext_ADL.oclHashcat.WIN.32.o      obj/shared.oclHashcat.WIN.32.o    obj/rp_gpu_on_cpu.oclHashcat.WIN.32.o      lib/libOpenCL.a   /usr/i686-w64-mingw32/lib/CRT_glob.o
	$(CC_WIN_32)   $(CFLAGS) $(CFLAGS_WIN)   $(CFLAGS_32) $(CFLAGS_OCL_WIN)    -o $@ -DCOMPTIME=$(NOW) $^ -L$(OCLLIBPATH32)  $(LFLAGS_OCL_WIN) -static-libgcc

oclHashcat64.exe:  src/oclHashcat.c obj/ext_OpenCL.oclHashcat.WIN.64.o   obj/ext_ADL.oclHashcat.WIN.64.o      obj/shared.oclHashcat.WIN.64.o    obj/rp_gpu_on_cpu.oclHashcat.WIN.64.o      lib/libOpenCL64.a /usr/x86_64-w64-mingw32/lib/CRT_glob.o
	$(CC_WIN_64)   $(CFLAGS) $(CFLAGS_WIN)   $(CFLAGS_64) $(CFLAGS_OCL_WIN)    -o $@ -DCOMPTIME=$(NOW) $^ -L$(OCLLIBPATH64)  $(LFLAGS_OCL_WIN) -static-libgcc

cudaHashcat32.bin: src/oclHashcat.c obj/ext_cuda.cudaHashcat.LINUX.32.o  obj/ext_nvml.cudaHashcat.LINUX.32.o  obj/shared.cudaHashcat.LINUX.32.o obj/rp_gpu_on_cpu.cudaHashcat.LINUX.32.o
	$(CC_LINUX_32) $(CFLAGS) $(CFLAGS_LINUX) $(CFLAGS_32) $(CFLAGS_CUDA_LINUX) -o $@ -DCOMPTIME=$(NOW) $^ -L$(CUDALIBPATH32) $(LFLAGS_CUDA_LINUX) -L$(NVMLLIBPATH32) -DINSTALL_FOLDER=\"$(INSTALL_FOLDER)\" -DSHARED_FOLDER=\"$(SHARED_FOLDER)\" -DDOCUMENT_FOLDER=\"$(DOCUMENT_FOLDER)\"

cudaHashcat64.bin: src/oclHashcat.c obj/ext_cuda.cudaHashcat.LINUX.64.o  obj/ext_nvml.cudaHashcat.LINUX.64.o  obj/shared.cudaHashcat.LINUX.64.o obj/rp_gpu_on_cpu.cudaHashcat.LINUX.64.o
	$(CC_LINUX_64) $(CFLAGS) $(CFLAGS_LINUX) $(CFLAGS_64) $(CFLAGS_CUDA_LINUX) -o $@ -DCOMPTIME=$(NOW) $^ -L$(CUDALIBPATH64) $(LFLAGS_CUDA_LINUX) -L$(NVMLLIBPATH64) -DINSTALL_FOLDER=\"$(INSTALL_FOLDER)\" -DSHARED_FOLDER=\"$(SHARED_FOLDER)\" -DDOCUMENT_FOLDER=\"$(DOCUMENT_FOLDER)\"

cudaHashcat32.exe: src/oclHashcat.c obj/ext_cuda.cudaHashcat.WIN.32.o    obj/ext_nvapi.cudaHashcat.WIN.32.o    obj/shared.cudaHashcat.WIN.32.o  obj/rp_gpu_on_cpu.cudaHashcat.WIN.32.o   lib/libcuda.a   /usr/i686-w64-mingw32/lib/CRT_glob.o
	$(CC_WIN_32)   $(CFLAGS) $(CFLAGS_WIN)   $(CFLAGS_32) $(CFLAGS_CUDA_WIN)   -o $@ -DCOMPTIME=$(NOW) $^ -L$(CUDALIBPATH32) $(LFLAGS_CUDA_WIN) -static-libgcc $(NVAPI)/x86/nvapi.lib

cudaHashcat64.exe: src/oclHashcat.c obj/ext_cuda.cudaHashcat.WIN.64.o    obj/ext_nvapi.cudaHashcat.WIN.64.o    obj/shared.cudaHashcat.WIN.64.o  obj/rp_gpu_on_cpu.cudaHashcat.WIN.64.o   lib/libcuda64.a /usr/x86_64-w64-mingw32/lib/CRT_glob.o
	$(CC_WIN_64)   $(CFLAGS) $(CFLAGS_WIN)   $(CFLAGS_64) $(CFLAGS_CUDA_WIN)   -o $@ -DCOMPTIME=$(NOW) $^ -L$(CUDALIBPATH64) $(LFLAGS_CUDA_WIN) -static-libgcc $(NVAPI)/amd64/nvapi64.lib

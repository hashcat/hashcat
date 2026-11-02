##
## Author......: See docs/credits.txt
## License.....: MIT
##

ALGO            ?= bcrypt

BOARD           ?= zc706

FLOW_ztex213    := usb

FLOW_artyz7     := ps

FLOW            = $(or $(FLOW_$(BOARD)),dma)

CORES_ypcb      := 760
CLK_ypcb        := 115

CORES_zc706     := 240
CLK_zc706       := 160

CORES_enigmax1  := 32
CLK_enigmax1    := 125

CORES_ztex213   := 24
CLK_ztex213     := 105

CORES_artyz7    := 68
CLK_artyz7      := 91

CORES           ?= $(or $(CORES_$(BOARD)),240)
CLK             ?= $(or $(CLK_$(BOARD)),155)

LANES_ypcb      := 1
LANES_zc706     := 1
PCIE_LANES      ?= $(LANES_$(BOARD))

STARTUPCLK      ?= Cclk

N               ?= 0
R               ?= 0

UNROLL          ?= 1

TARGET          := $(ALGO)/$(ALGO)_$(BOARD)_$(FLOW).py

board_shape = $(shell sed -n '/^BOARD_SHAPE = {/,/^}/p' $(TARGET) 2>/dev/null | sed -n 's/^ *"$(1)": *\([0-9][0-9]*\),.*/\1/p')

HAS_SHAPE       := $(call board_shape,din_bits)

DIN_BITS        ?= $(call board_shape,din_bits)
FEED_GROUP      ?= $(call board_shape,feed_group)
FEED_SHARD      ?= $(call board_shape,feed_shard)
COLLECT_GROUP   ?= $(call board_shape,collect_group)
NUM_CORES_DIST  ?= $(call board_shape,num_cores_dist)
INIT_BATCH      ?= $(call board_shape,init_batch)

NO_DUMP         ?= $(or $(call board_shape,no_dump),0)

NO_CMP          ?= $(or $(call board_shape,no_cmp),0)

CSLOW           ?= $(or $(call board_shape,cslow),1)

RELEASES_DEF    := ../bridges/fpga/fpga_releases.def

THREADS         ?= $(shell n=$$(nproc); [ $$n -gt 32 ] && echo 32 || echo $$n)

ABI             := $(shell awk '/#define FPGA_ABI_CURRENT/ { print $$3 }' ../bridges/fpga/hcfpga.h)

SET             := $(shell awk '/#define FPGA_SET_CURRENT/ { print $$3 }' ../bridges/fpga/hcfpga.h)

STARTUP_SUFFIX  := _$(shell echo $(STARTUPCLK) | tr 'A-Z' 'a-z')

SHAPE_SUFFIX    := $(if $(filter-out 0,$(FEED_GROUP)),_fg$(FEED_GROUP),)$(if $(filter-out 0,$(NO_DUMP)),_nodump,)$(if $(filter-out 0,$(NO_CMP)),_nocmp,)$(if $(filter-out 8,$(DIN_BITS)),_din$(DIN_BITS),)$(if $(filter-out 0,$(NUM_CORES_DIST)),_d$(NUM_CORES_DIST),)$(if $(filter-out 0,$(FEED_SHARD)),_fs$(FEED_SHARD),)$(if $(filter-out 0,$(COLLECT_GROUP)),_cg$(COLLECT_GROUP),)$(if $(filter-out 0,$(INIT_BATCH)),_ib$(INIT_BATCH),)

LANES_SUFFIX    := $(if $(PCIE_LANES),_x$(PCIE_LANES),)

PLACE_DEFAULT   = $(shell sed -n 's/.*"--place-directive".*default *= *"\([^"]*\)".*/\1/p' $(TARGET) 2>/dev/null)
PLACE_SUFFIX    = $(if $(PLACE_DIRECTIVE),$(if $(filter-out $(PLACE_DEFAULT),$(PLACE_DIRECTIVE)),_p$(PLACE_DIRECTIVE),),)

CSLOW_SUFFIX    = $(if $(filter-out 1,$(CSLOW)),_cs$(CSLOW),)

BUILD_NAME      = $(ALGO)_$(BOARD)_$(FLOW)_c$(CORES)_$(CLK)mhz$(if $(filter-out 0,$(N)),_n$(N)_r$(R)_u$(UNROLL),)$(STARTUP_SUFFIX)$(LANES_SUFFIX)$(SHAPE_SUFFIX)$(PLACE_SUFFIX)$(CSLOW_SUFFIX)
BITSTREAM_EXT   := $(or $(shell awk -F'[(,)]' '/^FPGA_RELEASE/ { gsub(/[" ]/,""); if ($$2 == "$(ALGO)" && $$3 == "$(BOARD)") print $$6 }' $(RELEASES_DEF) 2>/dev/null | head -1),bit)

BITSTREAM       := $(ALGO)/build/$(BUILD_NAME)/gateware/$(BUILD_NAME).$(BITSTREAM_EXT)

PARAM_SUFFIX    := $(if $(filter-out 0,$(N)),-n$(N)-r$(R),)

IDENT_PARAMS    := $(if $(filter-out 0,$(N)),;n=$(N);r=$(R),)
DIST_NAME       := $(ALGO)-$(BOARD)$(PARAM_SUFFIX)
DIST_DIR        := dist

HOST_DIR        := $(ALGO)/software/user
DRIVER_DIR      := driver
GENERATED       := $(ALGO)/build/$(BUILD_NAME)/software/include/generated

ALGOS           := $(sort $(shell sed -n 's/^FPGA_RELEASE[^"]*"\([a-z0-9_]*\)".*/\1/p' $(RELEASES_DEF)))

.PHONY: all $(ALGOS) build load headers check-headers driver tools sim verify dist clean help releases check-release check-published check-docs check-ps-app check

all: help

$(ALGOS):
	@$(MAKE) --no-print-directory build ALGO=$@

releases:
	@awk -F'[(,)]' '/^FPGA_RELEASE/ { gsub(/[" ]/,""); printf "  %-8s %-8s N=%-6s R=%s\n", $$2, $$3, $$4, $$5 }' $(RELEASES_DEF)

CHECKS          := check-docs check-headers check-ps-app

check:
	@bad=""; \
	 for c in $(CHECKS); do \
	   echo "== $$c"; \
	   $(MAKE) --no-print-directory $$c || bad="$$bad $$c"; \
	 done; \
	 echo; \
	 if [ -n "$$bad" ]; then \
	   echo "  FAILED:$$bad"; \
	   exit 1; \
	 fi; \
	 echo "  all offline checks pass"; \
	 echo; \
	 echo "  not run here, and each needs something this target deliberately does not assume:"; \
	 echo "    make sim               the merge gate, 55 testbench configurations, needs iverilog"; \
	 echo "    make check-published   fetches every declared release, needs the network"; \
	 echo "    make check-release     answers for one ALGO and BOARD, so build already runs it"

BOARDS_DEF      := ../bridges/fpga/fpga_boards.def
FPGA_DOC        := ../../docs/hashcat-fpga-setup.md

PS_APP_DIR      := $(ALGO)/ps_app
PS_APP_HEADER   := ../bridges/fpga/artyz7_ps_app.h
PS_APP_CROSS    ?= arm-none-eabi-

check-ps-app:
	@if [ ! -d $(PS_APP_DIR) ]; then \
	   echo "  $(ALGO) has no ps_app, nothing to check"; \
	 elif ! command -v $(PS_APP_CROSS)gcc >/dev/null 2>&1; then \
	   echo "  skipped: $(PS_APP_CROSS)gcc is not on the path"; \
	   echo "  install it with 'apt install gcc-arm-none-eabi', or pass PS_APP_CROSS=/path/to/prefix-"; \
	 else \
	   work=$$(mktemp -d) || exit 1; \
	   trap 'rm -rf "$$work"' EXIT INT TERM; \
	   cp $(PS_APP_DIR)/* "$$work"/ 2>/dev/null; \
	   rm -f "$$work"/app.elf "$$work"/app.bin; \
	   ( cd "$$work" && $(MAKE) --no-print-directory CROSS=$(PS_APP_CROSS) AEAD_DIR=$(abspath ../bridges/fpga) >/dev/null 2>&1 ) \
	     || { echo "  the application did not build with $(PS_APP_CROSS)gcc"; exit 1; }; \
	   ( cd "$$work" && ./gen_ps_app.py app.bin fresh.h "$$($(PS_APP_CROSS)gcc --version | head -1)" >/dev/null ) \
	     || { echo "  gen_ps_app.py refused the image"; exit 1; }; \
	   have=$$(sed -n 's|^// Built by: ||p' $(PS_APP_HEADER)); \
	   mine=$$(sed -n 's|^// Built by: ||p' "$$work"/fresh.h); \
	   hsz=$$(sed -n 's|^#define ARTYZ7_PS_APP_SIZE ||p' $(PS_APP_HEADER)); \
	   msz=$$(sed -n 's|^#define ARTYZ7_PS_APP_SIZE ||p' "$$work"/fresh.h); \
	   grep -vE '^  0x|^// Built by: |^#define ARTYZ7_PS_APP_(SIZE|CRC32) ' $(PS_APP_HEADER) > "$$work"/prose.have; \
	   grep -vE '^  0x|^// Built by: |^#define ARTYZ7_PS_APP_(SIZE|CRC32) ' "$$work"/fresh.h > "$$work"/prose.mine; \
	   if ! diff -q "$$work"/prose.have "$$work"/prose.mine >/dev/null; then \
	     echo "  the committed header is not shaped like a generated one any more, so it has been edited by hand"; \
	     exit 1; \
	   fi; \
	   if [ "$$have" = "$$mine" ]; then \
	     if diff -q $(PS_APP_HEADER) "$$work"/fresh.h >/dev/null; then \
	       echo "  $(notdir $(PS_APP_HEADER)) is $$hsz bytes and matches a fresh build, same compiler"; \
	     else \
	       echo "  STALE: $(notdir $(PS_APP_HEADER)) is $$hsz bytes, a fresh build of ps_app/ is $$msz"; \
	       echo "  Same compiler, so the sources have moved since the header was generated."; \
	       echo "  Regenerate it with: make -C $(PS_APP_DIR) header"; \
	       exit 1; \
	     fi; \
	   else \
	     echo "  $(notdir $(PS_APP_HEADER)) is $$hsz bytes, this compiler builds $$msz, and the prose agrees"; \
	     echo "  committed by: $$have"; \
	     echo "  yours:        $$mine"; \
	     echo "  A size difference between compilers is expected. To compare the bytes, use the one above."; \
	   fi; \
	 fi

check-docs:
	@fail=0; \
	 sed -n 's/^FPGA_BOARD (.*, *"\([^"]*\)")$$/\1/p' $(BOARDS_DEF) | while read -r sec; do \
	   if grep -q "^## $$sec$$" $(FPGA_DOC); then \
	     printf "  ok        %s\n" "$$sec"; \
	   else \
	     printf "  MISSING   %s   named in %s, no such heading in %s\n" "$$sec" "$(BOARDS_DEF)" "$(FPGA_DOC)"; \
	     echo x >> /tmp/hcfpga-docfail.$$$$; \
	   fi; \
	 done; \
	 if [ -f /tmp/hcfpga-docfail.$$$$ ]; then rm -f /tmp/hcfpga-docfail.$$$$; echo; echo "  a board names a section the guide does not have"; exit 1; fi
	@echo "  every board's diagnostic points at a section that exists"

check-release:
	@awk -F'[(,)]' -v a="$(ALGO)" -v b="$(BOARD)" -v n="$(N)" -v r="$(R)" \
	  '/^FPGA_RELEASE/ { gsub(/[" ]/,""); if ($$2==a && $$3==b && $$4==n && $$5==r) found=1 } \
	   END { if (found != 1) { printf "  %s/%s N=%s R=%s is not in %s\n", a, b, n, r, "$(RELEASES_DEF)"; exit 1 } }' $(RELEASES_DEF)

BITSTREAM_URL_BASE ?= https://hashcat.net/bitstreams

check-published:
	@echo "  checking $(RELEASES_DEF) against $(BITSTREAM_URL_BASE)"
	@curl -sS -o /tmp/hcfpga-manifest.json $(BITSTREAM_URL_BASE)/manifest.json || { echo "  cannot reach the manifest"; exit 1; }
	@rm -f /tmp/hcfpga-missing.txt
	@awk -F'[(,)]' '/^FPGA_RELEASE/ { gsub(/[" ]/,""); \
	   if ($$7 == "FPGA_DIST_REDISTRIBUTED") next; \
	   name = $$2 "-" $$3; if ($$4 != "0") name = name "-n" $$4 "-r" $$5; \
	   ext = ($$6 == "") ? "bit" : $$6; print "v$(SET)/" name "." ext ".xz", name }' $(RELEASES_DEF) \
	 > /tmp/hcfpga-declared.txt
	@
	@
	@
	@
	@printf '%s\n' 'ztex/inouttraffic.ihx.xz ztex/inouttraffic.ihx' \
	  'ztex/ztex115y_bcrypt.bit.xz ztex/ztex115y_bcrypt.bit' \
	 >> /tmp/hcfpga-declared.txt
	@while read -r path name; do \
	    if grep -q "\"$$name\"" /tmp/hcfpga-manifest.json; then :; else \
	      echo "    NO ENTRY  $$name   declared here, not in manifest.json"; \
	      echo "$$name" >> /tmp/hcfpga-missing.txt; continue; \
	    fi; \
	    url=$(BITSTREAM_URL_BASE)/$$path; \
	    if curl -sSfL -o /tmp/hcfpga-file.xz "$$url"; then :; else \
	      echo "    NO FILE   $$name   in manifest.json, but $$url does not fetch"; \
	      echo "$$name" >> /tmp/hcfpga-missing.txt; continue; \
	    fi; \
	    want=$$(python3 -c "import json;print(json.load(open('/tmp/hcfpga-manifest.json'))['$$name']['sha256'])"); \
	    have=$$(sha256sum /tmp/hcfpga-file.xz | cut -d' ' -f1); \
	    if [ "$$want" = "$$have" ]; then \
	      echo "    ok        $$name"; \
	    else \
	      echo "    CORRUPT   $$name   the published file does not match its own manifest sha256"; \
	      echo "$$name" >> /tmp/hcfpga-missing.txt; \
	    fi; \
	  done < /tmp/hcfpga-declared.txt
	@
	@
	@for path in v$(SET)/LICENSES.txt ztex/COPYING ztex/inouttraffic.c ztex/inouttraffic.README ztex/ztex115y_bcrypt-source.tar.xz; do \
	    if curl -sSfL -o /dev/null "$(BITSTREAM_URL_BASE)/$$path"; then \
	      echo "    ok        $$path"; \
	    else \
	      echo "    NO FILE   $$path   a licence companion that has to be published"; \
	      echo "$$path" >> /tmp/hcfpga-missing.txt; \
	    fi; \
	  done
	@rm -f /tmp/hcfpga-file.xz
	@echo
	@test ! -s /tmp/hcfpga-missing.txt || { \
	   echo "  Any line above that is not 'ok' means the bridge prints a curl command that fails."; \
	   echo "  Either fix the upload or take the release out of $(RELEASES_DEF)."; \
	   exit 1; }
	@echo "  every declared release is in the manifest, fetches, and matches its published sha256,"
	@echo "  and every licence companion is published."

PARAM_ARGS      :=

PLACE_ARGS      := $(if $(PLACE_DIRECTIVE),--place-directive $(PLACE_DIRECTIVE),)

LANES_ARGS      := $(if $(PCIE_LANES),--pcie-lanes $(PCIE_LANES),)

EXTRA_ARGS      ?=

FEED_ARGS       := $(if $(HAS_SHAPE),--din-bits $(DIN_BITS) --feed-group $(FEED_GROUP) --feed-shard $(FEED_SHARD) --collect-group $(COLLECT_GROUP) --num-cores-dist $(NUM_CORES_DIST) --init-batch $(INIT_BATCH),)$(if $(filter-out 0,$(NO_DUMP)), --no-dump,)$(if $(filter-out 0,$(NO_CMP)), --no-cmp,)$(if $(filter-out 1,$(CSLOW)), --cslow $(CSLOW),)

build: check-release
	@command -v vivado >/dev/null 2>&1 || { echo "vivado not on PATH, source settings64.sh first"; exit 1; }
	cd $(ALGO) && python3 $(notdir $(TARGET)) --build \
	  --cores $(CORES) $(PARAM_ARGS) $(FEED_ARGS) \
	  --startup-clk $(STARTUPCLK) $(LANES_ARGS) \
	  --abi $(ABI) $(PLACE_ARGS) $(EXTRA_ARGS) \
	  --sys-clk-freq $(CLK)e6 --threads $(THREADS)

LOAD_NOTE_DEFAULT := Programmed. REBOOT now. The PCIe endpoint does not re-enumerate without it. Then: sudo make -C src/fpga/driver dkms-install
LOAD_NOTE_ztex213 := Nothing was programmed and nothing needed to be. See above.
LOAD_NOTE_artyz7  := Nothing was programmed and nothing needed to be. hashcat loads the fabric AND the PS application over JTAG at the start of a run that uses the board, unless the board already runs them.

LOAD_NOTE        = $(if $(LOAD_NOTE_$(BOARD)),$(LOAD_NOTE_$(BOARD)),$(LOAD_NOTE_DEFAULT))

load:
	cd $(ALGO) && python3 $(notdir $(TARGET)) --load \
	  --cores $(CORES) $(PARAM_ARGS) $(FEED_ARGS) \
	  --startup-clk $(STARTUPCLK) $(LANES_ARGS) \
	  $(PLACE_ARGS) \
	  --sys-clk-freq $(CLK)e6
	@echo
	@echo "  $(LOAD_NOTE)"

HEADER_DIRS     := $(sort $(wildcard $(ALGO)/software/kernel/*))
HEADER_SRC      := $(firstword $(HEADER_DIRS))

check-headers:
	@if [ -z "$(strip $(HEADER_DIRS))" ]; then \
	   echo "  check-headers: skipped, no LiteX build output under $(ALGO)/software/kernel/"; \
	   echo "  A LiteX board build writes its register map there, and this check then compares them."; \
	   exit 0; \
	 fi; \
	 bad=0; ref=$(HEADER_SRC); \
	 refsum=`grep -E '^#define' $$ref/csr.h | sort | md5sum`; \
	 for d in $(HEADER_DIRS); do \
	   dsum=`grep -E '^#define' $$d/csr.h | sort | md5sum`; \
	   if [ "$$refsum" != "$$dsum" ]; then \
	     echo "  DIVERGED: $$d/csr.h does not agree with $$ref/csr.h"; \
	     bad=1; \
	   fi; \
	 done; \
	 if [ $$bad -ne 0 ]; then \
	   echo; \
	   echo "  One shared module and one set of tools serve every board, which is true only while every"; \
	   echo "  board's map agrees. One no longer does, so this is a real fork and not a formatting"; \
	   echo "  difference: diff the two csr.h files and find what moved. A design that adds a CPU, which"; \
	   echo "  a DRAM controller needs for calibration, relocates the SoC level registers the driver"; \
	   echo "  reads, and that is the usual cause."; \
	   exit 1; \
	 fi
	@test -z "$(strip $(HEADER_DIRS))" || echo "  register map for $(ALGO) agrees across every board: $(notdir $(HEADER_DIRS))"

headers: check-headers
	@test -n "$(strip $(HEADER_DIRS))" || { echo "  no register map under $(ALGO)/software/kernel/, build $(ALGO) on a LiteX board first"; exit 1; }
	cp $(HEADER_SRC)/csr.h $(DRIVER_DIR)/
	@awk 'NR == 4 { print "// The register map every LiteX board in this tree shares. The board name, the clock and the"; print "// identity are left out, because they differ per board and the driver reads none of them." } \
	   /^
	@echo "  driver headers refreshed. Every board above agrees, so this map drives all of them,"
	@echo "  including several different boards in the same host."
	@echo "  now rebuild the module: sudo make -C src/fpga/driver dkms-install"

driver:
	$(MAKE) -C $(DRIVER_DIR)
	@echo
	@echo "  for a driver that survives kernel upgrades and is signed for Secure Boot:"
	@echo "    sudo make -C src/fpga/driver dkms-install"

tools:
	$(MAKE) -C $(DRIVER_DIR) prepare
	$(MAKE) -C $(HOST_DIR)
	@echo
	@echo "  built for $(ALGO), against the register map currently in $(DRIVER_DIR)."
	@echo "  That map is set by 'make headers ALGO=...' and there is only one of it, so the tools for"
	@echo "  one algorithm at a time are what you can have. It covers every BOARD of that algorithm,"
	@echo "  so there is nothing per board to rebuild."

IVERILOG        ?= iverilog

SIM_SCRIPT_bcrypt := bcrypt/gateware/bcrypt/run_iverilog_sim.sh bcrypt/gateware/ztex_fx2/run_iverilog_sim.sh

SIM_SCRIPT      := $(SIM_SCRIPT_$(ALGO))

sim: check-headers
	@test -n "$(SIM_SCRIPT)" || { echo "  no simulation gate for ALGO=$(ALGO), add SIM_SCRIPT_$(ALGO) in $(firstword $(MAKEFILE_LIST))"; exit 1; }
	@command -v $(IVERILOG) >/dev/null 2>&1 || { echo "  $(IVERILOG) not on PATH. Debian and Ubuntu: apt install iverilog"; exit 1; }
	@rc=0; for s in $(SIM_SCRIPT); do ./$$s || rc=1; done; \
	 if [ $$rc -ne 0 ]; then echo; echo "  SIM *** FAIL ***  at least one gate failed, see above"; fi; \
	 exit $$rc

NODE              ?=

VERIFY_CMD_bcrypt := ./dma_ek_test 5 8 --board=$(BOARD) $(NODE)

VERIFY_CMD        := $(VERIFY_CMD_$(ALGO))

verify:
	@test "$(FLOW)" = dma || { echo "  make verify drives a LitePCIe card over /dev/litepcieN, and BOARD=$(BOARD) (FLOW=$(FLOW)) is not one."; echo "  Test that board with hashcat itself: tools/test.py with HCFPGA_TEST=1."; exit 1; }
	@test -n "$(VERIFY_CMD)" || { echo "  no verify command defined for ALGO=$(ALGO), add VERIFY_CMD_$(ALGO)"; exit 1; }
	$(MAKE) -C $(DRIVER_DIR) prepare
	$(MAKE) -C $(HOST_DIR)
	@echo "=== self test: distinct inputs, identity, per-core histogram (must be 0 bad) ==="
	cd $(HOST_DIR) && $(VERIFY_CMD)

dist: $(BITSTREAM)
	@mkdir -p $(DIST_DIR)
	xz -9 -c $(BITSTREAM) > $(DIST_DIR)/$(DIST_NAME).$(BITSTREAM_EXT).xz
	@printf '{\n  "%s": {\n    "sha256": "%s",\n    "size_raw": %s,\n    "size_xz": %s,\n    "ident": "hcfpga/1;board=%s;algo=%s;cores=%s;clk=%s%s;abi=$(ABI)"\n  }\n}\n' \
	  "$(DIST_NAME)" \
	  "$$(sha256sum $(DIST_DIR)/$(DIST_NAME).$(BITSTREAM_EXT).xz | cut -d' ' -f1)" \
	  "$$(stat -c %s $(BITSTREAM))" \
	  "$$(stat -c %s $(DIST_DIR)/$(DIST_NAME).$(BITSTREAM_EXT).xz)" \
	  "$(BOARD)" "$(ALGO)" "$(CORES)" "$(CLK)" "$(IDENT_PARAMS)" > $(DIST_DIR)/$(DIST_NAME).json
	@echo
	@echo "  $(DIST_DIR)/$(DIST_NAME).$(BITSTREAM_EXT).xz"
	@echo "  Upload with its .json entry merged into manifest.json. Do NOT publish a bitstream"
	@echo "  that has not passed 'make verify' on real hardware, or for a USB or Ethernet board"
	@echo "  a hashcat run on the board with HCFPGA_TEST=1 tools/test.py."

clean:
	$(RM) -rf $(ALGO)/build $(DIST_DIR)
	$(MAKE) -C $(HOST_DIR) clean 2>/dev/null || true

help:
	@echo "hashcat FPGA synthesis tree (not part of the hashcat build)"
	@echo
	@echo "  algorithms: $(ALGOS)"
	@echo
	@echo "  make <algo> [CLK=155] [CORES=240]                         build a bitstream"
	@echo "  make <algo> BOARD=ypcb                                    ... for the xc7k480t card"
	@echo "  make <algo> FEED_SHARD=96 COLLECT_GROUP=34                ... override the board's declared array shape"
	@echo "  make releases                                             list what we publish"
	@echo "  make load                                                 program it (then reboot)"
	@echo "  make driver                                               build the litepcie kernel module"
	@echo "  make headers ALGO=<algo>                                  refresh the driver's register map"
	@echo "  make tools ALGO=<algo>                                    build that algorithm's host tools"
	@echo "  make sim                                                  simulate under iverilog, the merge gate"
	@echo "  make verify                                               stress test on hardware"
	@echo "  make dist                                                 compress + manifest entry"
	@echo "  make check-published                                      are the declared releases actually downloadable"
	@echo "  make check-ps-app                                         is the embedded Arty Z7 application current"
	@echo "  make check                                                every check that needs no network and no board"
	@echo
	@echo "  current: $(ALGO) on $(BOARD), $(CORES) cores @ $(CLK) MHz$(if $(PCIE_LANES), PCIe x$(PCIE_LANES),), dist name $(DIST_NAME)"
	@echo "  shape:   din_bits=$(DIN_BITS) feed_group=$(FEED_GROUP) feed_shard=$(FEED_SHARD) collect_group=$(COLLECT_GROUP) num_cores_dist=$(NUM_CORES_DIST) init_batch=$(INIT_BATCH)"
	@echo "           no_dump=$(NO_DUMP) no_cmp=$(NO_CMP) cslow=$(CSLOW)"
	@echo "  bitstream: $(BITSTREAM)"

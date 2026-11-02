##
## Author......: See docs/credits.txt
## License.....: MIT
##

LITEPCIE_VERSION ?= 2026.08

TOP        := ../../..
VENDOR     := $(TOP)/deps/litepcie-$(LITEPCIE_VERSION)/software/kernel
PATCHES    := $(sort $(wildcard patches/*.patch))
BUILD      := build

VENDOR_SRCS := $(sort $(notdir $(wildcard $(VENDOR)/*.c) $(wildcard $(VENDOR)/*.h)))

KERNEL_VERSION := $(shell uname -r)
KERNEL_PATH    ?= /lib/modules/$(KERNEL_VERSION)/build

ARCH_ARG := $(if $(ARCH),ARCH=$(ARCH))

.PHONY: all prepare check clean load refresh-patches dkms-install dkms-remove dkms-status

all: prepare
	$(MAKE) -C $(KERNEL_PATH) $(ARCH_ARG) M=$(CURDIR)/$(BUILD) modules
	@echo
	@echo "  built $(BUILD)/litepcie.ko for $$(modinfo $(BUILD)/litepcie.ko 2>/dev/null | awk '/^vermagic/{print $$2}')"
	@echo "  litepcie $(LITEPCIE_VERSION) plus $(words $(PATCHES)) local patches"
	@echo "  register map: the one every LiteX board shares, so this module drives all of them, in"
	@echo "  the same host if you have several"
	@echo
	@echo "  load it with: sudo make -C src/fpga/driver load"

prepare: check
	@rm -rf $(BUILD)
	@mkdir -p $(BUILD)
	@cp $(VENDOR)/*.c $(VENDOR)/*.h $(BUILD)/
	@for p in $(PATCHES); do \
	  printf '  applying %s\n' "$$p"; \
	  patch -d $(BUILD) -p1 --batch --forward --fuzz=0 < "$$p" || { \
	    echo; \
	    echo "  $$p did not apply to litepcie $(LITEPCIE_VERSION)."; \
	    echo "  Either upstream moved under it, or the series is out of order."; \
	    exit 1; }; \
	done
	@cp csr.h soc.h $(BUILD)/
	@printf 'obj-m := litepcie.o\nlitepcie-objs := main.o\n' > $(BUILD)/Kbuild
	@
	@
	@if [ -n "$(SUDO_UID)" ]; then chown -R $(SUDO_UID):$(SUDO_GID) $(BUILD); fi

check:
	@command -v patch >/dev/null 2>&1 || { \
	  echo "  'patch' is not installed, and the driver sources are assembled with it"; \
	  echo "    Debian/Ubuntu   sudo apt install patch"; \
	  echo "    Fedora/RHEL     sudo dnf install patch"; \
	  exit 1; }
	@test -d "$(VENDOR)" || { \
	  echo "  no vendored litepcie at $(VENDOR)"; \
	  echo "  set LITEPCIE_VERSION to a version present in deps/"; \
	  exit 1; }
	@test -d "$(KERNEL_PATH)" || { \
	  echo "  no kernel build tree at $(KERNEL_PATH)"; \
	  echo; \
	  echo "  install the headers for the kernel you are running:"; \
	  echo "    Debian/Ubuntu   sudo apt install linux-headers-$(KERNEL_VERSION)"; \
	  echo "    Fedora/RHEL     sudo dnf install kernel-devel-$(KERNEL_VERSION)"; \
	  echo "    Arch            sudo pacman -S linux-headers"; \
	  echo; \
	  echo "  or point KERNEL_PATH at a tree you already have"; \
	  exit 1; }
	@test -f csr.h -a -f soc.h || { \
	  echo "  csr.h or soc.h missing. These describe the register map this module is built against, and"; \
	  echo "  it is one map for every board of an algorithm rather than one per board. They are tracked,"; \
	  echo "  so a clean checkout has them. After building your own bitstream, refresh with:"; \
	  echo "    make -C src/fpga headers ALGO=<algo>"; \
	  exit 1; }

load:
	@test -f $(BUILD)/litepcie.ko || { echo "  nothing built yet, run: make -C src/fpga/driver"; exit 1; }
	rmmod litepcie 2>/dev/null || true
	insmod $(BUILD)/litepcie.ko
	@echo "  loaded. The card's identity is in dmesg. Check it matches the bitstream you flashed."

DKMS_NAME    := litepcie-hashcat
DKMS_VERSION := $(LITEPCIE_VERSION)
DKMS_SRC     := /usr/src/$(DKMS_NAME)-$(DKMS_VERSION)

MOK_UBUNTU := $(shell . /etc/os-release 2>/dev/null; case "$$ID:$$ID_LIKE" in ubuntu:*|*:*ubuntu*) echo 1;; esac)
MOK_CONF   := $(shell sed -n 's/^[[:space:]]*mok_certificate=//p' /etc/dkms/framework.conf /etc/dkms/framework.conf.d/*.conf 2>/dev/null | tr -d '"' | tail -n 1)
MOK_CERT   := $(if $(MOK_CONF),$(MOK_CONF),$(if $(MOK_UBUNTU),/var/lib/shim-signed/mok/MOK.der,/var/lib/dkms/mok.pub))

SB_NEEDS_MOK := command -v mokutil >/dev/null 2>&1 && mokutil --sb-state 2>/dev/null | grep -q "SecureBoot enabled" && { [ ! -f $(MOK_CERT) ] || mokutil --test-key $(MOK_CERT) 2>/dev/null | grep -q "is not enrolled"; }

dkms-install: prepare
	@command -v dkms >/dev/null 2>&1 || { \
	  echo "  dkms is not installed"; \
	  echo "    Debian/Ubuntu   sudo apt install dkms"; \
	  echo "    Fedora/RHEL     sudo dnf install dkms"; \
	  echo "  or skip dkms and use: make -C src/fpga/driver && sudo make -C src/fpga/driver load"; \
	  exit 1; }
	@if [ -n "$(MOK_UBUNTU)" ] && $(SB_NEEDS_MOK); then \
	  echo "  Secure Boot is ON and no MOK is enrolled yet."; \
	  echo; \
	  echo "  dkms will ask you to choose a Secure Boot password, then you must confirm the same"; \
	  echo "  password in MokManager on the NEXT BOOT, at the physical console. It cannot be done"; \
	  echo "  over ssh, and an unattended run will hang on the prompt rather than fail."; \
	  echo; \
	  echo "  So run this from a real terminal on the machine, or turn Secure Boot off in your BIOS."; \
	  echo "  Set HCFPGA_SB_ACK=1 to proceed anyway once you know which of those you are doing."; \
	  echo; \
	  [ -n "$(HCFPGA_SB_ACK)" ] || exit 1; \
	fi
	rm -rf $(DKMS_SRC)
	mkdir -p $(DKMS_SRC)
	cp $(BUILD)/*.c $(BUILD)/*.h $(BUILD)/Kbuild $(DKMS_SRC)/
	sed 's|@VERSION@|$(DKMS_VERSION)|g' dkms.conf.in > $(DKMS_SRC)/dkms.conf
	@
	@
	@
	@
	@
	@
	@
	@
	@
	@for v in $$(dkms status -m $(DKMS_NAME) 2>/dev/null | sed -nE 's|^[^/,]+[/,] ?([^,:]+)[,:].*|\1|p' | sort -u); do \
	  if [ "$$v" != "$(DKMS_VERSION)" ]; then \
	    echo "  removing $(DKMS_NAME) $$v, which $(DKMS_VERSION) replaces"; \
	    dkms remove -m $(DKMS_NAME) -v $$v --all >/dev/null 2>&1 || true; \
	    rm -rf /usr/src/$(DKMS_NAME)-$$v; \
	  fi; \
	done
	@if dkms status -m $(DKMS_NAME) -v $(DKMS_VERSION) 2>/dev/null | grep -q .; then \
	  echo "  replacing the previous $(DKMS_NAME) $(DKMS_VERSION) registration"; \
	  dkms remove -m $(DKMS_NAME) -v $(DKMS_VERSION) --all >/dev/null 2>&1 || true; \
	fi
	dkms add     -m $(DKMS_NAME) -v $(DKMS_VERSION)
	dkms build   -m $(DKMS_NAME) -v $(DKMS_VERSION)
	dkms install -m $(DKMS_NAME) -v $(DKMS_VERSION)
	@
	@
	@for k in $$(ls /lib/modules); do \
	  [ "$$k" = "$$(uname -r)" ] && continue; \
	  [ -e /lib/modules/$$k/build/include ] || continue; \
	  dkms install -m $(DKMS_NAME) -v $(DKMS_VERSION) -k $$k >/dev/null 2>&1 && echo "  also built for kernel $$k" || echo "  could not build litepcie for kernel $$k"; \
	done

	@
	@
	@
	@
	@
	@
	@
	@
	@
	@
	@
	@
	@
	@
	@
	@if command -v update-initramfs >/dev/null 2>&1; then \
	  echo "  refreshing the initramfs, which keeps its own copy of the module"; \
	  update-initramfs -u -k all || echo "  update-initramfs failed, so THIS BOX WILL BOOT THE OLD MODULE"; \
	elif command -v dracut >/dev/null 2>&1; then \
	  echo "  refreshing the initramfs, which keeps its own copy of the module"; \
	  dracut --force --regenerate-all || echo "  dracut failed, so THIS BOX WILL BOOT THE OLD MODULE"; \
	fi

	@
	@
	@
	@
	@if lsmod | grep -q "^litepcie "; then \
	  echo "  litepcie already loaded, reloading it so the new build takes effect"; \
	  modprobe -r litepcie || { \
	    echo "  litepcie is in use, so the new build is installed but the OLD module is still running."; \
	    echo "  Stop hashcat and anything else holding /dev/litepcie*, then run:"; \
	    echo "    sudo modprobe -r litepcie && sudo modprobe litepcie"; \
	    exit 1; }; \
	fi
	@modprobe litepcie && echo "  loaded litepcie" || { \
	  echo "  built and registered, but modprobe failed. Check 'dmesg | tail'."; \
	  if $(SB_NEEDS_MOK); then \
	    echo "  The signing key $(MOK_CERT) is not enrolled, which is the likely cause."; \
	    if [ -z "$(MOK_UBUNTU)" ]; then echo "  Enrol it with: sudo mokutil --import $(MOK_CERT)"; fi; \
	    echo "  Then reboot and complete the enrolment in MokManager at the console."; \
	  fi; \
	  exit 1; }

	@echo
	@echo "  registered with dkms. It will rebuild itself on kernel upgrades."
	@echo "  With Secure Boot on, dkms signs it with $(MOK_CERT)."
	@if $(SB_NEEDS_MOK); then \
	  echo; \
	  echo "  NOT DONE YET: the signing key is NOT enrolled, so the module will be refused with"; \
	  echo "  'Key was rejected by service' even though everything above succeeded."; \
	  if [ -z "$(MOK_UBUNTU)" ]; then echo "  Enrol it with: sudo mokutil --import $(MOK_CERT)"; fi; \
	  echo "  Then reboot and complete the enrolment in MokManager at the console."; \
	fi

dkms-remove:
	-dkms remove -m $(DKMS_NAME) -v $(DKMS_VERSION) --all
	rm -rf $(DKMS_SRC)

dkms-status:
	@dkms status -m $(DKMS_NAME) 2>/dev/null || echo "  not registered with dkms"

refresh-patches:
	@test -n "$(VENDOR_SRCS)" || { echo "  no vendored litepcie at $(VENDOR)"; exit 1; }
	@test -d $(BUILD) || { echo "  nothing to diff, run: make -C src/fpga/driver prepare"; exit 1; }
	@for f in $(VENDOR_SRCS); do \
	  diff -u --label "a/$$f" --label "b/$$f" \
	    $(VENDOR)/$$f $(BUILD)/$$f > /tmp/refresh-$$f.diff || true; \
	  printf '  %s: %s changed lines\n' "$$f" "$$(grep -cE '^[+-][^+-]' /tmp/refresh-$$f.diff || true)"; \
	done
	@echo "  diffs written to /tmp/refresh-*.diff, split them into patches/ by hand"

clean:
	rm -rf $(BUILD)

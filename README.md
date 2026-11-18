# GarminGLO2Updater

A native, Apple Silicon replacement for **Garmin WebUpdater** that updates a
**Garmin GLO 2** Bluetooth GPS. Garmin's own tool hangs forever on this unit.

Tested end to end: GLO 2 (part 006-B3206-00), software **2.10 → 2.30**, on
macOS 26.5 (arm64) with the system `python3`.

## TL;DR

- **Symptom.** WebUpdater 2.2.1 (Intel-only, runs under Rosetta) sends the first
  "erase region" command and then waits forever. The GLO looks frozen until you
  pull its battery.
- **Bug.** The GLO's USB updater has a "transfer in progress" flag. When the
  normal firmware hands control to the updater, that flag is already set. While
  it is set, the updater **silently drops every erase command**: no reply and no
  error. WebUpdater waits for the erase reply with an infinite timeout, so it
  hangs.
- **Fix.** Send a deliberately too-short data packet first (Pid 36 with 2 bytes).
  The updater rejects it with status 4 before touching flash, and that error path
  clears the flag. The next erase is accepted.
- This tool also follows the USB re-enumeration that the hand-off causes, resets
  the USB port on every open (works around a macOS reopen quirk), and puts a
  timeout on every wait.

## Quick start

```bash
brew install libusb
python3 -m pip install --user pyusb
```

```bash
python3 garmin_update.py info                # model, part number, version, protocols
python3 garmin_update.py check               # ask Garmin's server for newer software
python3 garmin_update.py update --dry-run    # verify unit, file and plan; sends nothing
caffeinate -is python3 -u garmin_update.py -v update   # download (MD5-checked) and flash
```

Other commands: `status`, `download`, `inspect FILE.rgn`, and `flash FILE.rgn`.
Downloads are cached in `~/Library/Caches/garmin-update/`.

> **While it flashes, do not touch the GLO.** It looks frozen for a few minutes.
> Regions 12 and 14 must both be written with no power cycle in between (see
> [Firmware layout](#firmware-layout)). If a step fails, the tool tells you
> whether a battery pull is safe.

Run with `/usr/bin/python3`, or any interpreter that can see your user
site-packages. `python3 -I` hides pyusb.

## How WebUpdater hangs

The Mac WebUpdater 2.2.1 binary is x86_64-only and ships with C++ symbols
intact. It is built from BaseCamp's `iou` (USB), `iol` (link), and `ioa`
(application) libraries. A stack sample of the hung process shows exactly where
it is stuck:

```
ioa::FileSender_t::WaitForResponse
  iol::Link_t::GetPacket
    iou::Session_t::WaitForFrameWithTimeout
```

Decompiled, `FileSender_t::WaitForResponse` waits for Pid `0x4A` (erase status)
with a timeout of `0xFFFFFFFF`. It has no retry and no reconnect. By then the
GLO has dropped off USB and come back as a different device. Even if
WebUpdater re-opened it, the updater would ignore the erase (see below).

## Protocol (recovered from WebUpdater)

| Item | Detail |
|---|---|
| USB | VID `091E`, PID `0003`; bulk OUT; interrupt IN; bulk IN read until a zero-length packet |
| Packet header | 12 bytes `<u8 layer, 3 pad, u16 pid, 2 pad, u32 size>`; layer 0 = USB, layer 20 = application |
| Session | `0/5` → `0/6` (u32 unit id); max packet `0/16` → `0/17` (u32, payload limit = value − 12) |
| Product | `20/254` → `20/255` (product id, version ×100, strings) + `20/253` (protocol array) |
| Erase | `20/75` s16 region → `20/74` s16 status (0 = OK) |
| Data | `20/36` u32 offset + data; chunk = `(max_packet − 4) & ~1`; never crosses a 64 KiB boundary |
| Complete | `20/45` s16 region |
| Update server | `POST https://www.garmin.com/support/WUSoftwareUpdate.jsp`, form `req=<UnitSoftwareUpdate/v3 XML>` |
| RGN file | `"KpGr" u16 100`, then `<u32 len, u8 type, payload>` records; `R` = u16 region, u32 delay_ms, u32 size, data |

## What the GLO 2 does

### Two personalities, both reporting "Software Version 2.10"

| Mode | Protocols | Max packet | Behaviour |
|---|---|---|---|
| App (normal) | 24 (A010 … A1011) | 4084 | Answers everything |
| USB updater | 4 (`P000 L001 A010 T001`) | 1012 | Looks frozen; only a battery pull exits it |

In app mode, an erase of **region 12** doesn't erase anything. The app
(`FUN_b00b98b4`) calls `FUN_b0071efc()`, which ends in a jump to `0xB0000000`,
the boot path into the updater. The USB pipe stalls, and the unit re-enumerates
about 2 seconds later in updater mode. The app's region table also refuses
region 14, so every update has to go through the updater.

### Root cause: the updater's busy flag

The updater's Pid handler is `FUN_00002998` in region 12. Its state lives at
`0x1197C`, where byte 0 is the busy flag. Paraphrased:

```c
case 75: /* erase */
    if (state.busy) return;          // dropped: no ack, no status, nothing
    state.busy = 1;
    status = erase(region);
    reply(74, status);
    if (status != 0) state.busy = 0;
    break;

case 36: /* data */
    status = (len < 4) ? 4 : write(offset, data);
    if (status == 0) return;         // busy stays set while the region is open
    reply(74, status);
    state.busy = 0;                  // ← every error clears the flag
    break;

case 45: /* complete */
    ...                              // closes the region; does not clear busy
```

The updater's init routine (`FUN_00002b3e`) zeroes the flag. Even so, every
time the app handed over to the updater, the flag was already set. We did not
pin down which code path leaves it set. What matters is that it is set, and
nothing in WebUpdater's sequence clears it.

The workaround uses the error path. A Pid 36 with only 2 payload bytes fails
the length check (status 4) **before any flash access**, and the error path
resets the flag. Live results:

| Mode | `TX 20/36 [00 00]` reply | Effect |
|---|---|---|
| App | `20/74 status 4` | Harmless; nothing written |
| Updater | `20/74 status 4` | Flag cleared; the next erase returns status 0 |

The static analysis is of the **2.30** updater, taken from `GLO2_230.rgn`.
Garmin doesn't publish the 2.10 image. The live 2.10 updater behaved exactly as
the 2.30 code predicts.

Other findings:

- The 2.10 updater doesn't implement upload (Pid 96).
- Command 57 returns Pid 252 (a baud-rate table).
- Command 118 returns Pid 305.

### macOS USB quirk

After the interface is closed and re-opened, the GLO silently drops its bulk
replies (a data-toggle desync), and it rejects `CLEAR_FEATURE(HALT)`. A USB
port reset on every open fixes this. The one exception is right after the
unit restarts: a fresh enumeration already has clean pipes, so the tool skips
the reset there.

## Firmware layout

| Region | Size | Load address | Contents |
|---|---|---|---|
| 12 | 68,328 B (5000 ms delay) | `0x00001000` (ITCM) | USB updater **plus a shared library** |
| 14 | 1,146,368 B | `0xB0040000` | Main application |

The CPU is an ARM946 (ARMv5TE, MPU). The app calls into region 12's library at
fixed addresses (for example `0xB1EC` memcpy and `0xE24C` delay). A 2.30
updater with a 2.10 app, or the reverse, is a mismatched pair. That's why both
regions are written in one session, and a power cycle between them is the one
real brick risk.

## How this tool flashes it

For each region (12, then 14):

1. **Clear the busy flag** with the 2-byte Pid 36.
2. **Erase.** If the unit stalls or drops off USB (the app handing over to the
   updater), reopen within about 2 s, confirm it's the same unit ID, clear the
   flag again, and resend the erase. In updater mode the erase must be answered
   within 30 s, or the tool stops: nothing has been erased, and a battery pull
   is safe.
3. **Recompute the chunk size.** The max packet changes across restarts:
   4084 → 1012 → 804.
4. **Send the data.** Watch for an abort status every 8 packets.
5. **Send Complete**, wait the delay the RGN asks for, then reconnect.

Finally, it waits for the restart and checks the version. The unit ID is
checked on every reconnect.

Trimmed log of the successful run (unit ID removed):

```
Region 12: erasing (the unit can take a minute or two)…
  TX L20/36 [2] 00 00          RX L20/74 [2] 04 00     busy-flag reset -> status 4
  TX L20/75 [2] 0c 00          GPS disconnected ([Errno 5] Input/Output Error)
Region 12: the unit restarted (update mode); reconnecting…  back after 2.3s
Region 12: reconnected (max packet 1012); erasing again…
  TX L20/36 [2] 00 00          RX L20/74 [2] 04 00     busy-flag reset -> status 4
  TX L20/75 [2] 0c 00          RX L20/74 [2] 00 00     erase OK
Region 12: 68,328 bytes sent, completion signalled.
  (reconnect: max packet now 816-12 = 804, i.e. the new 2.30 updater is running)
Region 14: erasing…
  TX L20/36 [2] 00 00          RX L20/74 [2] 04 00     busy-flag reset -> status 4
  TX L20/75 [2] 0e 00          RX L20/74 [2] 00 00     erase OK
Region 14: 1,146,368 bytes sent, completion signalled.
All regions sent. Waiting for the unit to restart…
Unit now reports software v2.30.
```

## Why this works where WebUpdater doesn't

| | WebUpdater 2.2.1 (Mac) | This tool |
|---|---|---|
| Architecture | x86_64 under Rosetta | Native arm64 Python + libusb |
| Busy flag after hand-off | Never cleared, so the erase is dropped | Cleared before every erase |
| Re-enumeration after erase(12) | Keeps waiting on the dead pipe | Detects the stall or detach, reconnects, re-erases |
| Erase-status wait | `0xFFFFFFFF` (forever) | Bounded, with a clear message about what's safe |
| macOS reopen desync | Not handled | USB port reset on open |
| Packet size after restart | n/a | Re-queried each time |

## Reproducing the reverse engineering

You'll need Ghidra 12.x (`brew install ghidra`). The helper scripts are in
[`re/ghidra/`](re/ghidra):

| Script | Purpose |
|---|---|
| `Decomp.java` | Decompile functions by demangled-name regex or `@addr` (used on the WebUpdater binary) |
| `PidHandlers.java` | Find functions that compare against given Pids and decompile them |
| `DecAddr.java` | Decompile the functions at the given addresses, listing callers |
| `PoolRefs.java` | Find functions that load a given literal-pool value (for example `0x1197C`) |
| `Disasm.java` | Raw disassembly at given addresses |

```bash
python3 garmin_update.py download                      # fetch GLO2_230.rgn (cached)
python3 re/extract_regions.py ~/Library/Caches/garmin-update/GLO2_230.rgn fw/
```

```bash
GH=$(brew --prefix ghidra)/libexec/support/analyzeHeadless; mkdir -p proj
$GH proj glo -import fw/r12.bin -processor ARM:LE:32:v5t -loader BinaryLoader \
    -loader-baseAddr 0x1000 -scriptPath re/ghidra \
    -postScript PidHandlers.java r12_pids.c 0x4b,0x4a,0x2d,0x24
$GH proj glo -import fw/r14.bin -processor ARM:LE:32:v5t -loader BinaryLoader \
    -loader-baseAddr 0xb0040000 -scriptPath re/ghidra \
    -postScript PidHandlers.java r14_pids.c 0x4b,0x4a,0x2d
```

Firmware and decompiler output aren't committed (they're Garmin's code).
`.gitignore` excludes `*.rgn` and `*.bin`.

## Tests

```bash
python3 -m unittest -v test_garmin_update.py
```

There are 19 offline tests. They run against a simulated GPS that enforces the
recovered protocol, and they cover these cases:

- 64 KiB splitting
- restart into the updater on the first erase
- an updater that ignores erase (the tool must fail fast)
- the busy-flag updater across regions 12 and 14
- abort status, model mismatch, dry run, and RGN and server-XML parsing

## Caveats

- This has been tested on **one** GLO 2 only. The transport and RGN code follow
  WebUpdater's generic legacy-USB path (GPSMAP 60/76/96, eTrex HCx, and similar
  units), but the busy-flag workaround is only proven on the GLO 2.
- If WebUpdater already hung on your unit, it never got past the erase, so
  pulling the battery returns it to its old firmware. Then run this tool.
- Firmware comes from Garmin's update server. By flashing, you accept
  [Garmin's license](http://www8.garmin.com/gcdfiles/license.txt).
- Not affiliated with or endorsed by Garmin. Use at your own risk.

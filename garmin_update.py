#!/usr/bin/env python3
"""
garmin_update.py - native replacement for "Garmin WebUpdater" (2.2.1, x86_64-only)

Targets Garmin units that speak the legacy Garmin USB protocol (USB VID 0x091E,
PID 0x0003: GPSMAP 60/76/96 series, eTrex Vista/Legend/Summit HCx, Quest, etc.).
Runs natively on Apple Silicon through libusb, so it needs no Rosetta.
Tested end to end on a Garmin GLO 2 (006-B3206-00), 2.10 -> 2.30; see README.md
for the updater "busy flag" bug that makes WebUpdater hang on that unit.

Everything below was recovered from the WebUpdater binary (symbols intact):

  USB framing (iou::MakeUsbPacket / Session_t)
      12-byte header <u8 layer, 3 pad, u16 id, 2 pad, u32 size> + payload
      layer 0 = USB protocol layer, layer 20 = application layer
      host->device on bulk OUT, ZLP after any write that is a multiple of
      wMaxPacketSize; device->host on interrupt IN, and when the device sends
      Pid_Data_Available (layer 0, id 2) the host reads bulk IN until a ZLP.
  Session (iou::Session_t ctor)
      Start Session (0/5) repeated every 500 ms -> Session Started (0/6, u32 unit id)
      Max-packet query (0/16) -> (0/17, u32) ; payload limit = value - 12, default 255
  Part number (ioa::GarminPartNumberString)
      "006-B%04u-00" % product_id ; system software lives in region 14
  Update server (upd::GetFirmwareUpdates)
      POST https://www.garmin.com/support/WUSoftwareUpdate.jsp
      form field req=<UnitSoftwareUpdate/v3 Requests XML>
  RGN file (-[GarminDevicePrivate readRgnHeader:], -[GarminUsbDevice transferRgnPkgFile:])
      "KpGr" u16(100), then records <u32 len, u8 type, payload[len]>
      first record 'D' u16(100); 'R' records = u16 region, u32 delay_ms, u32 size, data
  Region transfer (ioa::FileSender_t)
      Pid 75  host->dev  s16 region                 (erase / prepare)
      Pid 74  dev->host  s16 status, 0 = OK         (WebUpdater waits FOREVER here)
      Pid 36  host->dev  u32 offset + data          chunk = (max_packet - 4) & ~1,
                                                    never crossing a 64 KiB boundary
      Pid 45  host->dev  s16 region                 (complete)
      A Pid 74 arriving during the data phase means the unit aborted.

Usage
      python3 garmin_update.py status
      python3 garmin_update.py info
      python3 garmin_update.py check
      python3 garmin_update.py update            # check -> download -> flash
      python3 garmin_update.py download
      python3 garmin_update.py inspect FILE.rgn
      python3 garmin_update.py flash FILE.rgn [--dry-run]

Requires: pyusb (pip install pyusb) and libusb (brew install libusb).
"""
from __future__ import annotations

import argparse
import hashlib
import html
import json
import os
import re
import struct
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterator, List, Optional, Tuple

__version__ = "1.0.0"

GARMIN_VID = 0x091E
GARMIN_USB_PID = 0x0003

LAYER_USB = 0
LAYER_APP = 20

PID_DATA_AVAILABLE = 2
PID_START_SESSION = 5
PID_SESSION_STARTED = 6
PID_REQ_MAX_PACKET = 16
PID_MAX_PACKET = 17

PID_EXT_PRODUCT_DATA = 248
PID_PROTOCOL_ARRAY = 253
PID_PRODUCT_RQST = 254
PID_PRODUCT_DATA = 255

PID_RGN_DATA = 36
PID_RGN_COMPLETE = 45
PID_RGN_STATUS = 74
PID_RGN_ERASE = 75

SYSTEM_REGION = 14
UPDATER_ERASE_TIMEOUT_S = 30.0   # an updater that answers at all does so within seconds
DEFAULT_MAX_PACKET = 255

UPDATE_URL = "https://www.garmin.com/support/WUSoftwareUpdate.jsp"
USER_AGENT = f"garmin-update.py/{__version__}"
NS_UNIT_SW = "http://www.garmin.com/xmlschemas/UnitSoftwareUpdate/v3"

CACHE_DIR = (Path.home() / "Library" / "Caches" / "garmin-update") if sys.platform == "darwin" \
    else (Path.home() / ".cache" / "garmin-update")


# --------------------------------------------------------------------------- errors

class GarminError(Exception):
    """Any failure the user should see as a one-line message."""


class DeviceBusy(GarminError):
    pass


class DeviceGone(GarminError):
    pass


class FlashError(GarminError):
    pass


# --------------------------------------------------------------------------- packets

HDR = struct.Struct("<B3xH2xI")


@dataclass
class Packet:
    layer: int
    pid: int
    data: bytes = b""

    def encode(self) -> bytes:
        return HDR.pack(self.layer, self.pid, len(self.data)) + self.data

    def __str__(self) -> str:
        d = self.data
        tail = d[:24].hex(" ") + (" …" if len(d) > 24 else "")
        return f"L{self.layer}/{self.pid} [{len(d)}] {tail}"


def take_packets(buf: bytearray) -> List[Packet]:
    """Pop every complete packet from the front of buf (in place)."""
    out = []
    while len(buf) >= HDR.size:
        layer, pid, size = HDR.unpack_from(buf, 0)
        if layer not in (LAYER_USB, LAYER_APP) or size > 1 << 20:
            # Out of sync: WebUpdater discards the whole transfer in this case.
            del buf[:]
            break
        if len(buf) < HDR.size + size:
            break
        out.append(Packet(layer, pid, bytes(buf[HDR.size:HDR.size + size])))
        del buf[:HDR.size + size]
    return out


# --------------------------------------------------------------------------- USB transport

def _is_timeout(exc: Exception) -> bool:
    import usb.core
    if hasattr(usb.core, "USBTimeoutError") and isinstance(exc, usb.core.USBTimeoutError):
        return True
    return getattr(exc, "errno", None) in (60, 110) or getattr(exc, "backend_error_code", None) == -7


def _is_gone(exc: Exception) -> bool:
    return getattr(exc, "errno", None) in (19, 5, 6) or getattr(exc, "backend_error_code", None) in (-4, -1)


def _is_stall(exc: Exception) -> bool:
    # A GLO 2 stalls its pipes as it drops off the bus to restart into its loader.
    return getattr(exc, "errno", None) == 32 or getattr(exc, "backend_error_code", None) == -9


def _libusb_backend():
    try:
        import usb.backend.libusb1 as libusb1
    except ImportError:
        raise GarminError("pyusb is not installed: python3 -m pip install --user pyusb")
    candidates = [os.environ.get("LIBUSB_PATH"),
                  "/opt/homebrew/lib/libusb-1.0.0.dylib",
                  "/usr/local/lib/libusb-1.0.0.dylib"]
    for c in candidates:
        if c and os.path.exists(c):
            be = libusb1.get_backend(find_library=lambda _n, c=c: c)
            if be:
                return be
    be = libusb1.get_backend()
    if be:
        return be
    raise GarminError("libusb-1.0 not found: brew install libusb (or set LIBUSB_PATH)")


def usb_owner_hint() -> str:
    """macOS: name the process that holds the Garmin interface exclusively."""
    if sys.platform != "darwin":
        return ""
    try:
        out = subprocess.run(["ioreg", "-r", "-c", "IOUSBHostInterface", "-l", "-w0"],
                             capture_output=True, text=True, timeout=10).stdout
    except Exception:
        return ""
    for block in out.split("+-o IOUSBHostInterface"):
        if f'"idVendor" = {GARMIN_VID}' in block:
            m = re.search(r'"UsbExclusiveOwner" = "([^"]+)"', block)
            if m:
                return m.group(1)
    return ""


class UsbTransport:
    """Garmin USB pipe handling, mirroring iou::InPipe_t / OutPipe_t."""

    BULK_READ = 0x4000

    def __init__(self, dev, log: Callable[[str], None]):
        import usb.util
        self.dev = dev
        self.log = log
        try:
            cfg = dev.get_active_configuration()
        except Exception:
            dev.set_configuration(1)
            cfg = dev.get_active_configuration()
        intf = cfg[(0, 0)]
        self.intf_num = intf.bInterfaceNumber
        try:
            usb.util.claim_interface(dev, self.intf_num)
        except Exception as e:
            owner = usb_owner_hint()
            msg = f"Cannot claim the GPS USB interface ({e})."
            if owner:
                msg += f"\nIt is held exclusively by: {owner}. Quit that program (or kill it) and retry."
            raise DeviceBusy(msg)
        eps = list(intf)

        def pick(direction, kind):
            for ep in eps:
                if usb.util.endpoint_direction(ep.bEndpointAddress) == direction and \
                        usb.util.endpoint_type(ep.bmAttributes) == kind:
                    return ep
            raise GarminError("Unexpected USB descriptor: missing endpoint")

        self.ep_intr = pick(usb.util.ENDPOINT_IN, usb.util.ENDPOINT_TYPE_INTR)
        self.ep_bulk_in = pick(usb.util.ENDPOINT_IN, usb.util.ENDPOINT_TYPE_BULK)
        self.ep_bulk_out = pick(usb.util.ENDPOINT_OUT, usb.util.ENDPOINT_TYPE_BULK)
        self._bulk_mode = False
        self._bulk_deadline = 0.0
        self._intr_buf = bytearray()
        self._bulk_buf = bytearray()
        self._queue: List[Packet] = []

    @classmethod
    def open(cls, log: Callable[[str], None], reset: bool = True,
             not_at: Optional[Tuple[int, int]] = None) -> "UsbTransport":
        """not_at=(bus, address): ignore the unit's previous enumeration (wait for the new one)."""
        import usb.core
        import usb.util
        backend = _libusb_backend()

        def find():
            for d in usb.core.find(find_all=True, idVendor=GARMIN_VID, idProduct=GARMIN_USB_PID,
                                   backend=backend):
                if not_at is None or (d.bus, d.address) != not_at:
                    return d
            return None

        dev = find()
        if dev is None:
            raise DeviceGone("No Garmin USB-protocol GPS (091e:0003) found. Is it connected and switched on?")
        if reset:
            # After macOS closes and reopens the pipes, a GLO 2 silently drops its
            # replies (data-toggle desync; it rejects CLEAR_FEATURE(HALT)). A port
            # reset puts both ends back in a known state. The unit re-enumerates.
            log("  USB port reset")
            try:
                dev.reset()
            except Exception as e:
                log(f"  USB reset failed ({e}); continuing without it")
            usb.util.dispose_resources(dev)
            deadline = time.monotonic() + 10.0
            dev = None
            while dev is None and time.monotonic() < deadline:
                time.sleep(0.5)
                dev = find()
            if dev is None:
                raise DeviceGone("GPS did not come back after a USB port reset")
            time.sleep(1.0)
        return cls(dev, log)

    def write(self, pkt: Packet, timeout_ms: int = 6000) -> None:
        raw = pkt.encode()
        self.log(f"  TX {pkt}")
        try:
            self.ep_bulk_out.write(raw, timeout_ms)
            if raw and len(raw) % self.ep_bulk_out.wMaxPacketSize == 0:
                self.ep_bulk_out.write(b"", timeout_ms)
        except Exception as e:
            if _is_gone(e):
                raise DeviceGone(f"GPS disconnected during write ({e})")
            if _is_timeout(e):
                raise GarminError(f"Timed out sending {pkt}")
            raise

    def read_packet(self, timeout_ms: int) -> Optional[Packet]:
        """Return one packet, or None if nothing arrived within timeout_ms."""
        deadline = time.monotonic() + timeout_ms / 1000.0
        while True:
            if self._queue:
                p = self._queue.pop(0)
                self.log(f"  RX {p}")
                return p
            remaining = int((deadline - time.monotonic()) * 1000)
            if remaining <= 0:
                return None
            self._read_once(max(1, min(remaining, 250)))

    def _read_once(self, timeout_ms: int) -> None:
        try:
            if self._bulk_mode:
                data = self.ep_bulk_in.read(self.BULK_READ, timeout_ms)
                if len(data) == 0:          # ZLP: end of bulk burst
                    self._bulk_mode = False
                    return
                self._bulk_buf += bytes(data)
                self._queue += take_packets(self._bulk_buf)
                self._bulk_deadline = time.monotonic() + 2.0
                return
            data = self.ep_intr.read(self.ep_intr.wMaxPacketSize, timeout_ms)
        except Exception as e:
            if _is_timeout(e):
                # Stay in bulk mode across short polls; give up only if the
                # announced burst (or its ZLP) never shows up.
                if self._bulk_mode and time.monotonic() > self._bulk_deadline:
                    self._bulk_mode = False
                return
            if _is_gone(e):
                raise DeviceGone(f"GPS disconnected ({e})")
            if _is_stall(e):
                self._bulk_mode = False
                self.log(f"  USB pipe stalled ({e})")
                raise DeviceGone(f"GPS USB pipe stalled; the unit is probably restarting ({e})")
            raise
        self._intr_buf += bytes(data)
        for p in take_packets(self._intr_buf):
            if p.layer == LAYER_USB and p.pid == PID_DATA_AVAILABLE:
                self.log("  RX L0/2 (data available)")
                self._bulk_mode = True
                self._bulk_deadline = time.monotonic() + 2.0
            else:
                self._queue.append(p)

    def still_attached(self) -> bool:
        """False once the unit has dropped off the bus or re-enumerated (new address)."""
        import usb.core
        try:
            found = usb.core.find(find_all=True, idVendor=GARMIN_VID, idProduct=GARMIN_USB_PID,
                                  backend=_libusb_backend())
            return any(d.bus == self.dev.bus and d.address == self.dev.address for d in found)
        except Exception:
            return True

    def close(self) -> None:
        try:
            import usb.util
            usb.util.release_interface(self.dev, self.intf_num)
            usb.util.dispose_resources(self.dev)
        except Exception:
            pass


# --------------------------------------------------------------------------- device

@dataclass
class ProductInfo:
    unit_id: int
    product_id: int
    sw_version: int                       # hundredths, e.g. 420 = 4.20
    descriptions: List[str]
    ext_data: List[str] = field(default_factory=list)
    protocols: List[str] = field(default_factory=list)
    max_packet: int = DEFAULT_MAX_PACKET

    @property
    def part_number(self) -> str:
        return f"006-B{self.product_id:04d}-00"

    @property
    def version(self) -> Tuple[int, int]:
        return divmod(self.sw_version, 100)

    @property
    def version_str(self) -> str:
        return "%d.%02d" % self.version

    @property
    def model(self) -> str:
        return self.descriptions[0] if self.descriptions else f"product {self.product_id}"


def parse_product_data(data: bytes) -> Tuple[int, int, List[str]]:
    if len(data) < 4:
        raise GarminError("Short product data packet")
    pid, ver = struct.unpack_from("<Hh", data, 0)
    strings = [s.decode("latin-1").strip() for s in data[4:].split(b"\0")]
    return pid, ver, [s for s in strings if s]


def parse_protocol_array(data: bytes) -> List[str]:
    return ["%s%03d" % (chr(data[i]), struct.unpack_from("<H", data, i + 1)[0])
            for i in range(0, len(data) - 2, 3)]


class GarminDevice:
    def __init__(self, transport, log: Callable[[str], None] = lambda s: None,
                 opener: Optional[Callable[[], object]] = None):
        self.t = transport
        self.log = log
        self.opener = opener
        self.unit_id: Optional[int] = None
        self.max_packet = DEFAULT_MAX_PACKET
        self.in_updater = False   # set once the unit has restarted into its update loader

    # -- generic I/O
    def send(self, layer: int, pid: int, data: bytes = b"", timeout_ms: int = 6000) -> None:
        self.t.write(Packet(layer, pid, data), timeout_ms)

    def recv(self, timeout_s: float, layer: int, pid: int) -> Optional[Packet]:
        """Wait for a specific packet; others are logged and dropped (as iol::Link_t does)."""
        deadline = time.monotonic() + timeout_s
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return None
            p = self.t.read_packet(max(1, int(remaining * 1000)))
            if p is None:
                return None
            if p.layer == layer and p.pid == pid:
                return p
            self.log(f"  (ignored {p})")

    # -- session
    def start_session(self, timeout_s: float = 8.0) -> int:
        deadline = time.monotonic() + timeout_s
        while time.monotonic() < deadline:
            self.send(LAYER_USB, PID_START_SESSION)
            p = self.recv(0.5, LAYER_USB, PID_SESSION_STARTED)
            if p and len(p.data) == 4:
                self.unit_id = struct.unpack("<I", p.data)[0]
                break
        else:
            raise GarminError("GPS did not answer Start Session (is it in mass-storage mode or off?)")
        self.send(LAYER_USB, PID_REQ_MAX_PACKET)
        p = self.recv(1.5, LAYER_USB, PID_MAX_PACKET)
        mp = struct.unpack("<I", p.data)[0] - 12 if p and len(p.data) == 4 else 0
        self.max_packet = mp if 16 <= mp <= 0x10000 else DEFAULT_MAX_PACKET
        return self.unit_id

    def product_info(self) -> ProductInfo:
        self.send(LAYER_APP, PID_PRODUCT_RQST)
        prod = None
        ext: List[str] = []
        protos: List[str] = []
        deadline = time.monotonic() + 4.0
        while time.monotonic() < deadline:
            wait = 1.5 if prod else max(0.05, deadline - time.monotonic())
            p = self.t.read_packet(int(wait * 1000))
            if p is None:
                if prod:
                    break
                continue
            if p.layer != LAYER_APP:
                continue
            if p.pid == PID_PRODUCT_DATA:
                prod = parse_product_data(p.data)
            elif p.pid == PID_EXT_PRODUCT_DATA:
                ext += [s.decode("latin-1") for s in p.data.split(b"\0") if s]
            elif p.pid == PID_PROTOCOL_ARRAY:
                protos = parse_protocol_array(p.data)
        if not prod:
            raise GarminError("GPS did not return product data")
        return ProductInfo(self.unit_id or 0, prod[0], prod[1], prod[2], ext, protos, self.max_packet)

    def reconnect(self, expect_unit: Optional[int], attempts: int = 10, delay_s: float = 3.0) -> None:
        """Mirror -[GarminDevice waitForAvailability]: the unit may reboot between regions."""
        last = None
        for _ in range(attempts):
            try:
                if self.opener:
                    try:
                        self.t.close()
                    except Exception:
                        pass
                    self.t = self.opener()
                uid = self.start_session(timeout_s=4.0)
                if expect_unit is not None and uid != expect_unit:
                    raise GarminError(f"A different GPS answered (unit id {uid}, expected {expect_unit})")
                return
            except (DeviceGone, GarminError) as e:
                if isinstance(e, GarminError) and "different GPS" in str(e):
                    raise
                last = e
                time.sleep(delay_s)
        raise DeviceGone(f"GPS did not come back after reboot ({last})")

    def reconnect_after_restart(self, expect_unit: Optional[int], timeout_s: float = 45.0) -> None:
        """The unit just dropped off the bus to restart into its update loader. The loader
        only waits briefly for the host (a GLO 2 gives up and restarts again), so grab the
        new enumeration at once, without a port reset: a fresh enumeration has clean pipes."""
        old = None
        dev = getattr(self.t, "dev", None)
        if dev is not None:
            old = (dev.bus, dev.address)
        try:
            self.t.close()
        except Exception:
            pass
        if not self.opener:                      # tests: same simulated transport
            self.start_session(timeout_s=4.0)
            return
        t0 = time.monotonic()
        last = None
        while time.monotonic() - t0 < timeout_s:
            try:
                self.t = self.opener(reset=False, not_at=old)
            except DeviceGone as e:
                last = e
                time.sleep(0.1)
                continue
            try:
                uid = self.start_session(timeout_s=4.0)
            except (DeviceGone, GarminError) as e:
                last = e
                self.log(f"  new enumeration did not answer yet ({e})")
                try:
                    self.t.close()
                except Exception:
                    pass
                time.sleep(0.2)
                continue
            if expect_unit is not None and uid != expect_unit:
                raise GarminError(f"A different GPS answered (unit id {uid}, expected {expect_unit})")
            self.log(f"  back after {time.monotonic() - t0:.1f}s at address {self.t.dev.address}")
            return
        self.log(f"  no fresh enumeration answered ({last}); falling back to port resets")
        self.reconnect(expect_unit, attempts=10, delay_s=3.0)

    def clear_busy(self, notice: Callable[[str], None] = print) -> Optional[int]:
        """Reset a stuck region-transfer state. After the app hands over to the GLO 2
        updater, the updater's "region open" flag is already set, so it silently ignores
        erase requests (this is why WebUpdater hangs). A data packet too short to hold an
        offset is rejected with status 4 before any flash access, and that error path clears
        the flag. Harmless in app mode too (same reply, nothing written)."""
        self.send(LAYER_APP, PID_RGN_DATA, b"\0\0")
        p = self.recv(3.0, LAYER_APP, PID_RGN_STATUS)
        code = struct.unpack_from("<h", p.data)[0] if p is not None and len(p.data) >= 2 else None
        self.log(f"  busy-flag reset -> status {code}")
        return code

    # -- firmware region transfer (ioa::FileSender_t)
    def write_region(self, region: int, data: bytes, erase_timeout_s: float,
                     progress: Callable[[str, int, int], None],
                     notice: Callable[[str], None] = print, max_restarts: int = 2) -> None:
        # Some units (GLO 2) answer the first erase by restarting into their update
        # loader. WebUpdater then waits forever on a dead link; we reconnect to the
        # same unit and repeat the erase, which the loader acknowledges.
        restarts = 0
        self.clear_busy(notice)
        self.send(LAYER_APP, PID_RGN_ERASE, struct.pack("<h", region), timeout_ms=60000)
        t0 = time.monotonic()
        next_check = t0 + 1.0
        status = None
        while status is None:
            elapsed = time.monotonic() - t0
            limit = min(erase_timeout_s, UPDATER_ERASE_TIMEOUT_S) if restarts else erase_timeout_s
            if elapsed > limit:
                if restarts:
                    raise FlashError(
                        f"The unit restarted into its updater but the updater ignored the erase for "
                        f"region {region} ({limit:.0f}s).\nNothing was erased (the app switches to the "
                        "updater before erasing). The unit stays frozen in update mode: disconnect "
                        "its battery/power to restart it.\nKnown on GLO 2 software 2.10: its updater "
                        "does not accept firmware transfers over USB.")
                raise FlashError(
                    f"No erase acknowledgement for region {region} after {limit:.0f}s.\n"
                    "The unit may have erased that region. Do not power it off; unplug/replug USB, "
                    "run `info`, then repeat the same `flash`.")
            progress("erase", int(elapsed), int(erase_timeout_s))
            try:
                p = self.recv(1.0, LAYER_APP, PID_RGN_STATUS)
                gone = False
                if time.monotonic() >= next_check:
                    next_check = time.monotonic() + 1.0
                    attached = getattr(self.t, "still_attached", None)
                    gone = attached is not None and not attached()
            except DeviceGone as e:
                p, gone = None, True
                self.log(f"  {e}")
            if gone:
                if restarts >= max_restarts:
                    raise FlashError(f"Unit kept restarting instead of erasing region {region}.")
                restarts += 1
                notice(f"\nRegion {region}: the unit restarted (update mode); reconnecting…")
                self.reconnect_after_restart(self.unit_id)
                self.in_updater = True
                notice(f"Region {region}: reconnected (max packet {self.max_packet}); erasing again…")
                self.clear_busy(notice)
                self.send(LAYER_APP, PID_RGN_ERASE, struct.pack("<h", region), timeout_ms=60000)
                t0 = time.monotonic()
                next_check = t0 + 1.0
                continue
            if p is not None:
                if len(p.data) < 2:
                    raise FlashError("Malformed erase status packet")
                status = struct.unpack_from("<h", p.data)[0]
        if status != 0:
            raise FlashError(f"Unit refused region {region} (status {status}); nothing was written.")

        # The packet size can change across the restart, so size chunks now.
        chunk = (self.max_packet - 4) & ~1
        if chunk < 16:
            raise FlashError(f"Bad max packet size {self.max_packet}")
        total = len(data)
        sent = 0
        mv = memoryview(data)
        n_pkts = 0
        while sent < total:
            n = min(chunk, total - sent)
            for off, piece in split_64k(sent, mv[sent:sent + n]):
                self.send(LAYER_APP, PID_RGN_DATA, struct.pack("<I", off) + bytes(piece))
            sent += n
            n_pkts += 1
            if n_pkts % 8 == 0 or sent == total:
                p = self.t.read_packet(1)
                if p is not None and p.layer == LAYER_APP and p.pid == PID_RGN_STATUS:
                    code = struct.unpack_from("<h", p.data)[0] if len(p.data) >= 2 else -1
                    raise FlashError(f"Unit aborted region {region} at offset {sent} (status {code}).")
                progress("write", sent, total)
        self.send(LAYER_APP, PID_RGN_COMPLETE, struct.pack("<h", region))


def split_64k(offset: int, buf) -> Iterator[Tuple[int, memoryview]]:
    """ioa::FileSender_t::SendData: a data packet never straddles a 64 KiB boundary."""
    n = len(buf)
    if n == 0:
        return
    end = offset + n - 1
    if (end ^ offset) < 0x10000:
        yield offset, buf
    else:
        cut = (end & 0xFFFF0000) - offset
        yield offset, buf[:cut]
        yield end & 0xFFFF0000, buf[cut:]


# --------------------------------------------------------------------------- RGN files

@dataclass
class RgnRegion:
    region: int
    delay_ms: int
    size: int
    data_offset: int


@dataclass
class RgnFile:
    path: Path
    raw: bytes
    regions: List[RgnRegion]
    info: List[str]

    def region_bytes(self, r: RgnRegion) -> bytes:
        return self.raw[r.data_offset:r.data_offset + r.size]


def parse_rgn(path: Path) -> RgnFile:
    raw = Path(path).read_bytes()
    if len(raw) < 6 or raw[:4] != b"KpGr":
        raise GarminError(f"{path}: not a Garmin RGN file (missing KpGr header)")
    if struct.unpack_from("<H", raw, 4)[0] != 100:
        raise GarminError(f"{path}: unsupported RGN version")
    pos = 6
    regions: List[RgnRegion] = []
    info: List[str] = []
    first = True
    while pos < len(raw):
        if pos + 5 > len(raw):
            raise GarminError(f"{path}: truncated record header at {pos}")
        length, rtype = struct.unpack_from("<IB", raw, pos)
        start, end = pos + 5, pos + 5 + length
        if end > len(raw):
            raise GarminError(f"{path}: record at {pos} runs past end of file (corrupt download?)")
        payload = raw[start:end]
        t = chr(rtype)
        if first:
            if t != "D" or len(payload) < 2 or struct.unpack_from("<H", payload)[0] != 100:
                raise GarminError(f"{path}: first record must be data-version 'D' 100")
            first = False
        elif t == "R":
            if len(payload) < 10:
                raise GarminError(f"{path}: short region record at {pos}")
            region, delay, size = struct.unpack_from("<HII", payload)
            if size != length - 10:
                raise GarminError(f"{path}: region {region} size {size} != record length {length - 10}")
            regions.append(RgnRegion(region, delay, size, start + 10))
        elif t == "A":
            ver = struct.unpack_from("<H", payload)[0] if len(payload) >= 2 else 0
            strs = [s.decode("latin-1") for s in payload[2:].split(b"\0") if s.strip()]
            info.append(f"app record v{ver}: " + " | ".join(strs))
        pos = end
    if not regions:
        raise GarminError(f"{path}: no region records")
    return RgnFile(Path(path), raw, regions, info)


# --------------------------------------------------------------------------- update server

@dataclass
class UpdateInfo:
    part_number: str
    region: int
    description: str
    version: Tuple[int, int]
    build_type: str
    url: str
    size_kb: int
    md5: Optional[str]
    license_url: str
    changes: str
    notes: str
    more_info: str

    @property
    def version_str(self) -> str:
        return "%d.%02d" % self.version


def build_request_xml(part_number: str, regions: List[Tuple[int, int, int]]) -> str:
    region_xml = "".join(
        f"<Region><RegionId>{rid}</RegionId><Version><VersionMajor>{maj}</VersionMajor>"
        f"<VersionMinor>{mn}</VersionMinor><BuildType>Release</BuildType></Version></Region>"
        for rid, maj, mn in regions)
    return ('<?xml version="1.0" encoding="UTF-8" standalone="no" ?>'
            f'<Requests xmlns="{NS_UNIT_SW}"><Request><PartNumber>{part_number}</PartNumber>'
            f"<TransferType>USB</TransferType>{region_xml}</Request></Requests>")


def _html_to_text(s: str) -> str:
    s = urllib.parse.unquote_plus(s or "")
    s = re.sub(r"<li>", "\n  - ", s, flags=re.I)
    s = re.sub(r"<br\s*/?>|</?strong>", "\n", s, flags=re.I)
    s = html.unescape(re.sub(r"<[^>]+>", "", s))
    return re.sub(r"\n\s*\n+", "\n", s).strip()


def parse_response_xml(text: str) -> List[UpdateInfo]:
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        raise GarminError(f"Update server error: {text.strip()[:200]}")
    ns = {"u": NS_UNIT_SW}
    out = []
    for resp in root.findall("u:Response", ns):
        pn = resp.findtext("u:RequestedPartNumber", "", ns)
        lic = resp.findtext("u:LicenseLocation", "", ns)
        for up in resp.findall("u:Update", ns):
            f = up.find("u:UpdateFile", ns)
            out.append(UpdateInfo(
                part_number=pn,
                region=int(up.findtext("u:RequestedRegionId", "0", ns)),
                description=up.findtext("u:Description", "", ns),
                version=(int(up.findtext("u:Version/u:VersionMajor", "0", ns)),
                         int(up.findtext("u:Version/u:VersionMinor", "0", ns))),
                build_type=up.findtext("u:Version/u:BuildType", "", ns),
                url=f.findtext("u:Location", "", ns) if f is not None else "",
                size_kb=int(f.findtext("u:Size", "0", ns)) if f is not None else 0,
                md5=(f.findtext("u:MD5Sum", "", ns) or None) if f is not None else None,
                license_url=lic,
                changes=_html_to_text(up.findtext("u:ChangeDescription", "", ns)),
                notes=_html_to_text(up.findtext("u:Notes", "", ns)),
                more_info=up.findtext("u:AdditionalInfo", "", ns)))
    return out


def query_updates(part_number: str, version: Tuple[int, int]) -> List[UpdateInfo]:
    xml = build_request_xml(part_number, [(SYSTEM_REGION, version[0], version[1])])
    body = urllib.parse.urlencode({"req": xml}).encode()
    req = urllib.request.Request(UPDATE_URL, data=body, headers={
        "Content-Type": "application/x-www-form-urlencoded", "User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            text = r.read().decode("utf-8", "replace")
    except urllib.error.URLError as e:
        raise GarminError(f"Could not reach Garmin update server: {e}")
    return parse_response_xml(text)


def download_update(u: UpdateInfo, dest_dir: Path, say: Callable[[str], None]) -> Path:
    dest_dir.mkdir(parents=True, exist_ok=True)
    name = os.path.basename(urllib.parse.urlparse(u.url).path) or "update.rgn"
    dest = dest_dir / name
    if dest.exists() and u.md5 and hashlib.md5(dest.read_bytes()).hexdigest() == u.md5.lower():
        say(f"Using cached {dest}")
        _write_sidecar(dest, u)
        return dest
    urls = [u.url]
    if u.url.startswith("http://"):
        urls.insert(0, "https://" + u.url[len("http://"):])
    last = None
    for url in urls:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
            with urllib.request.urlopen(req, timeout=60) as r:
                total = int(r.headers.get("Content-Length") or 0)
                h = hashlib.md5()
                tmp = dest.with_suffix(dest.suffix + ".part")
                got = 0
                with open(tmp, "wb") as f:
                    while True:
                        block = r.read(65536)
                        if not block:
                            break
                        f.write(block)
                        h.update(block)
                        got += len(block)
                        _bar("download", got, total or u.size_kb * 1024)
                sys.stderr.write("\n")
            if u.md5 and h.hexdigest() != u.md5.lower():
                tmp.unlink(missing_ok=True)
                raise GarminError(f"MD5 mismatch for {url}: got {h.hexdigest()}, expected {u.md5}")
            tmp.replace(dest)
            _write_sidecar(dest, u)
            say(f"Saved {dest} ({got} bytes, MD5 verified)" if u.md5 else f"Saved {dest} ({got} bytes)")
            return dest
        except GarminError:
            raise
        except Exception as e:
            last = e
    raise GarminError(f"Download failed: {last}")


def _write_sidecar(rgn: Path, u: UpdateInfo) -> None:
    meta = {"part_number": u.part_number, "description": u.description,
            "version": u.version_str, "md5": u.md5, "url": u.url}
    rgn.with_suffix(rgn.suffix + ".json").write_text(json.dumps(meta, indent=2))


def _read_sidecar(rgn: Path) -> Optional[dict]:
    p = rgn.with_suffix(rgn.suffix + ".json")
    try:
        return json.loads(p.read_text())
    except Exception:
        return None


# --------------------------------------------------------------------------- UI helpers

def _bar(label: str, done: int, total: int, unit: str = "B") -> None:
    if not sys.stderr.isatty():
        return
    width = 32
    frac = (done / total) if total else 0
    fill = int(frac * width)
    if unit == "s":
        txt = f"{done}s (limit {total}s)"
    else:
        txt = f"{done / 1024:,.0f}/{total / 1024:,.0f} KiB"
    sys.stderr.write(f"\r  {label:<9} [{'#' * fill}{'.' * (width - fill)}] {frac * 100:5.1f}%  {txt}   ")
    sys.stderr.flush()


def _confirm(prompt: str, assume_yes: bool) -> bool:
    if assume_yes:
        return True
    if not sys.stdin.isatty():
        raise GarminError("Refusing to flash without a terminal; pass --yes to confirm non-interactively.")
    return input(prompt).strip().lower() == "yes"


def print_info(info: ProductInfo) -> None:
    print(f"Model          : {info.model}")
    for extra in info.descriptions[1:]:
        print(f"                 {extra}")
    print(f"Product ID     : {info.product_id}  (part number {info.part_number})")
    print(f"Software       : {info.version_str}")
    print(f"Unit ID        : {info.unit_id}")
    print(f"USB max packet : {info.max_packet} bytes")
    if info.protocols:
        print(f"Protocols      : {' '.join(info.protocols)}")
    for e in info.ext_data:
        print(f"Ext data       : {e}")


# --------------------------------------------------------------------------- commands

class Session:
    """Opens the GPS and guarantees the USB interface is released."""

    def __init__(self, verbose: bool):
        self.log = (lambda s: print(s, file=sys.stderr)) if verbose else (lambda s: None)
        self.dev: Optional[GarminDevice] = None

    def __enter__(self) -> GarminDevice:
        opener = lambda **kw: UsbTransport.open(self.log, **kw)
        self.dev = GarminDevice(opener(), self.log, opener)
        try:
            self.dev.start_session()
        except BaseException:
            self.dev.t.close()
            raise
        return self.dev

    def __exit__(self, *exc):
        if self.dev:
            self.dev.t.close()
        return False


def cmd_status(args) -> int:
    backend = _libusb_backend()
    import usb.core
    found = list(usb.core.find(find_all=True, idVendor=GARMIN_VID, backend=backend))
    if not found:
        print("No Garmin USB devices attached.")
        return 1
    for d in found:
        kind = "Garmin USB protocol (this tool)" if d.idProduct == GARMIN_USB_PID else \
            "mass-storage / MTP device (use Garmin Express; not handled here)"
        print(f"091e:{d.idProduct:04x} bus {d.bus} addr {d.address}  {kind}")
    owner = usb_owner_hint()
    if owner:
        print(f"Interface currently held by: {owner}")
    return 0


def cmd_info(args) -> int:
    with Session(args.verbose) as dev:
        print_info(dev.product_info())
    return 0


def _pick_update(info: ProductInfo, updates: List[UpdateInfo]) -> Optional[UpdateInfo]:
    sys_updates = [u for u in updates if u.region == SYSTEM_REGION and u.url]
    return max(sys_updates, key=lambda u: u.version) if sys_updates else None


def _show_update(info: ProductInfo, u: Optional[UpdateInfo], verbose_changes: bool) -> None:
    if not u:
        print(f"Garmin's server lists no system software for {info.part_number}.")
        return
    print(f"Server offers  : {u.description} v{u.version_str} ({u.build_type}), {u.size_kb} KB")
    print(f"File           : {u.url}")
    if u.more_info:
        print(f"Details        : {u.more_info}")
    if u.license_url:
        print(f"License        : {u.license_url}")
    if u.notes:
        print("Notes          :\n  " + u.notes.replace("\n", "\n  "))
    if verbose_changes and u.changes:
        print("Changes:\n" + u.changes)


def cmd_check(args) -> int:
    with Session(args.verbose) as dev:
        info = dev.product_info()
    print_info(info)
    u = _pick_update(info, query_updates(info.part_number, info.version))
    print()
    _show_update(info, u, args.changes)
    if u:
        newer = u.version > info.version
        print(f"\n{'UPDATE AVAILABLE' if newer else 'Up to date'}: unit {info.version_str}, "
              f"server {u.version_str}")
    return 0


def cmd_download(args) -> int:
    with Session(args.verbose) as dev:
        info = dev.product_info()
    u = _pick_update(info, query_updates(info.part_number, info.version))
    _show_update(info, u, False)
    if not u:
        return 1
    download_update(u, Path(args.dir or CACHE_DIR), print)
    return 0


def cmd_inspect(args) -> int:
    rgn = parse_rgn(Path(args.rgn))
    print(f"{rgn.path}  ({len(rgn.raw):,} bytes, MD5 {hashlib.md5(rgn.raw).hexdigest()})")
    for line in rgn.info:
        print(f"  {line}")
    for r in rgn.regions:
        print(f"  region {r.region:>3}: {r.size:>10,} bytes  delay {r.delay_ms} ms  @ file offset {r.data_offset}")
    meta = _read_sidecar(rgn.path)
    if meta:
        print(f"  downloaded for {meta.get('part_number')} ({meta.get('description')}) v{meta.get('version')}")
    return 0


def flash(dev: GarminDevice, info: ProductInfo, rgn: RgnFile, args,
          expected_part: Optional[str]) -> int:
    meta = _read_sidecar(rgn.path)
    file_part = meta.get("part_number") if meta else expected_part
    print(f"\nUnit           : {info.model}  {info.part_number}  v{info.version_str}  (unit id {info.unit_id})")
    print(f"Firmware file  : {rgn.path.name}  ({len(rgn.raw):,} bytes)")
    for line in rgn.info:
        print(f"                 {line}")
    chunk = (dev.max_packet - 4) & ~1
    for r in rgn.regions:
        print(f"  region {r.region:>3}: {r.size:>10,} bytes in ~{-(-r.size // chunk):,} packets"
              + (f", then wait {r.delay_ms} ms" if r.delay_ms else ""))
    if file_part and file_part != info.part_number:
        raise GarminError(f"This RGN was fetched for {file_part}, but the connected unit is "
                          f"{info.part_number}. Refusing to flash.")
    if not file_part:
        print("\n  WARNING: no record of which model this RGN is for. Flashing firmware for a different\n"
              "  model can brick the unit. Prefer `update`, which fetches the file for this exact unit.")
        if not args.force_unverified:
            raise GarminError("Pass --force-unverified to flash an RGN of unknown origin.")
    if args.dry_run:
        print("\nDry run: device, file and plan verified. Nothing was sent to the GPS.")
        return 0
    print("\nBefore continuing: fresh batteries or external power, keep the cable still, and do not")
    print("let the Mac sleep. If a region fails, do NOT power the GPS off; re-run the same command.")
    if not _confirm('Type "yes" to flash: ', args.yes):
        print("Cancelled.")
        return 1

    region = None
    todo = [r for r in rgn.regions if r.region != 0]
    try:
        for i, r in enumerate(todo):
            region = r.region
            print(f"\nRegion {r.region}: erasing (the unit can take a minute or two)…")

            def progress(phase, done, total):
                _bar(phase, done, total, "s" if phase == "erase" else "B")

            dev.write_region(r.region, rgn.region_bytes(r), args.erase_timeout, progress)
            sys.stderr.write("\n")
            print(f"Region {r.region}: {r.size:,} bytes sent, completion signalled.")
            # Leave the bus alone while the unit commits the region, then open a fresh,
            # reset session and check it is still the same unit (WebUpdater's
            # waitForAvailability). The final region is handled by the restart wait below.
            if r.delay_ms:
                print(f"Region {r.region}: waiting {r.delay_ms} ms as the RGN requests.")
                time.sleep(r.delay_ms / 1000.0)
            if i + 1 < len(todo):
                dev.reconnect(info.unit_id)
    except KeyboardInterrupt:
        sys.stderr.write("\n")
        print(f"Interrupted during region {region}. Do NOT power off the GPS; re-run the same "
              "flash command to finish.")
        return 130
    except FlashError:
        sys.stderr.write("\n")
        raise

    print("\nAll regions sent. Waiting for the unit to restart…")
    try:
        dev.reconnect(info.unit_id, attempts=20, delay_s=3.0)
        after = dev.product_info()
        print(f"Unit now reports software v{after.version_str}.")
    except GarminError as e:
        print(f"Could not re-query the unit ({e}). Check its About screen once it finishes booting.")
    return 0


def cmd_flash(args) -> int:
    rgn = parse_rgn(Path(args.rgn))
    with Session(args.verbose) as dev:
        info = dev.product_info()
        return flash(dev, info, rgn, args, None)


def cmd_update(args) -> int:
    with Session(args.verbose) as dev:
        info = dev.product_info()
        print_info(info)
        u = _pick_update(info, query_updates(info.part_number, info.version))
        print()
        _show_update(info, u, args.changes)
        if not u:
            return 1
        if u.version <= info.version and not args.reinstall:
            print(f"\nAlready at v{info.version_str}; nothing to do (use --reinstall to flash anyway).")
            return 0
        path = download_update(u, Path(args.dir or CACHE_DIR), print)
        rgn = parse_rgn(path)
        if u.license_url:
            print(f"\nBy flashing you accept Garmin's license: {u.license_url}")
        return flash(dev, info, rgn, args, u.part_number)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Native Garmin USB firmware updater (WebUpdater replacement)")
    ap.add_argument("-v", "--verbose", action="store_true", help="trace every USB packet")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("status", help="list attached Garmin USB devices")
    sub.add_parser("info", help="show model, part number, software version")
    p = sub.add_parser("check", help="ask Garmin's server for newer system software")
    p.add_argument("--changes", action="store_true", help="print the change log")
    p = sub.add_parser("download", help="download the firmware for the attached unit")
    p.add_argument("--dir", help=f"destination (default {CACHE_DIR})")
    p = sub.add_parser("inspect", help="list the regions inside an RGN file")
    p.add_argument("rgn")
    for name in ("flash", "update"):
        p = sub.add_parser(name, help="flash an RGN file" if name == "flash"
                           else "check, download and flash the latest firmware")
        if name == "flash":
            p.add_argument("rgn")
            p.add_argument("--force-unverified", action="store_true",
                           help="allow an RGN not downloaded by this tool for this unit")
        else:
            p.add_argument("--dir", help=f"download directory (default {CACHE_DIR})")
            p.add_argument("--reinstall", action="store_true", help="flash even if not newer")
            p.add_argument("--changes", action="store_true", help="print the change log")
            p.set_defaults(force_unverified=False)
        p.add_argument("--dry-run", action="store_true", help="verify everything, send nothing")
        p.add_argument("--yes", action="store_true", help="do not prompt")
        p.add_argument("--erase-timeout", type=float, default=300.0,
                       help="seconds to wait for each region erase (default 300; WebUpdater waits forever)")
    args = ap.parse_args(argv)
    handlers = {"status": cmd_status, "info": cmd_info, "check": cmd_check, "download": cmd_download,
                "inspect": cmd_inspect, "flash": cmd_flash, "update": cmd_update}
    try:
        return handlers[args.cmd](args)
    except GarminError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())

"""Offline tests: a simulated GPS that enforces the protocol recovered from WebUpdater."""
import argparse
import io
import os
import struct
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import garmin_update as gu  # noqa: E402


def make_rgn(regions, app_strings=("SQA", "Jan 01 2010", "12:00:00")):
    out = b"KpGr" + struct.pack("<H", 100)
    rec = lambda t, p: struct.pack("<IB", len(p), ord(t)) + p
    out += rec("D", struct.pack("<H", 100))
    out += rec("A", struct.pack("<H", 420) + b"\0".join(s.encode() for s in app_strings) + b"\0")
    for region, delay, data in regions:
        out += rec("R", struct.pack("<HII", region, delay, len(data)) + data)
    return out


class FakeGps:
    """Implements the transport interface and plays the device side."""

    def __init__(self, max_packet_raw=4096 + 12, product_id=291, sw=410, unit_id=0x1234ABCD,
                 erase_reply=True, abort_after=None, erase_status=0, restart_on_erase=None,
                 busy_updater=False):
        self.q = []
        # restart_on_erase=N: the first erase makes the unit drop off the bus and come
        # back as its update loader with max packet N (what a GLO 2 does).
        self.restart_on_erase = restart_on_erase
        self.restarting = False
        # busy_updater: like the GLO 2 updater, it starts with its region-open flag set,
        # ignores erases while set, sets it again on every successful erase, and only a
        # too-short data packet (status 4) clears it.
        self.busy_updater = busy_updater
        self.in_updater = False
        self.busy = False
        self.max_packet_raw = max_packet_raw
        self.product_id, self.sw, self.unit_id = product_id, sw, unit_id
        self.erase_reply, self.abort_after, self.erase_status = erase_reply, abort_after, erase_status
        self.active = None
        self.written = {}
        self.completed = []
        self.data_pkts = 0
        self.sent = []

    def write(self, pkt, timeout_ms=6000):
        self.sent.append(pkt)
        L, P, d = pkt.layer, pkt.pid, pkt.data
        if (L, P) == (0, gu.PID_START_SESSION):
            self.q.append(gu.Packet(0, gu.PID_SESSION_STARTED, struct.pack("<I", self.unit_id)))
        elif (L, P) == (0, gu.PID_REQ_MAX_PACKET):
            if self.max_packet_raw:          # 0 = old firmware that ignores the query
                self.q.append(gu.Packet(0, gu.PID_MAX_PACKET, struct.pack("<I", self.max_packet_raw)))
        elif (L, P) == (20, gu.PID_PRODUCT_RQST):
            self.q.append(gu.Packet(20, gu.PID_PRODUCT_DATA,
                                    struct.pack("<Hh", self.product_id, self.sw) + b"GPSMAP 60CSx Software Version 4.10\0VERBMAP Americas Highway 4.00\0"))
            self.q.append(gu.Packet(20, gu.PID_PROTOCOL_ARRAY, b"P\x00\x00L\x01\x00A\x0a\x00"))
        elif (L, P) == (20, gu.PID_RGN_ERASE):
            assert len(d) == 2
            region = struct.unpack("<h", d)[0]
            assert self.active is None, "erase while another region open"
            if self.restart_on_erase:
                self.max_packet_raw, self.restart_on_erase = self.restart_on_erase, None
                self.restarting = True
                self.in_updater = True
                self.busy = self.busy_updater
                return
            if self.busy:
                return                       # silently ignored, like the real updater
            if self.in_updater and self.busy_updater:
                self.busy = True
            self.active = region
            self.written[region] = bytearray()
            if self.erase_reply:
                self.q.append(gu.Packet(20, gu.PID_RGN_STATUS, struct.pack("<h", self.erase_status)))
        elif (L, P) == (20, gu.PID_RGN_DATA) and len(d) < 4:
            self.busy = False
            self.q.append(gu.Packet(20, gu.PID_RGN_STATUS, struct.pack("<h", 4)))
        elif (L, P) == (20, gu.PID_RGN_DATA):
            assert self.active is not None, "data before erase"
            off = struct.unpack_from("<I", d)[0]
            payload = d[4:]
            limit = (self.max_packet_raw - 12) if self.max_packet_raw else gu.DEFAULT_MAX_PACKET
            assert len(d) <= limit, f"data packet {len(d)} > {limit}"
            assert (off >> 16) == ((off + len(payload) - 1) >> 16), "crosses 64 KiB boundary"
            buf = self.written[self.active]
            assert off == len(buf), f"non-contiguous offset {off} != {len(buf)}"
            buf += payload
            self.data_pkts += 1
            if self.abort_after and self.data_pkts == self.abort_after:
                self.q.append(gu.Packet(20, gu.PID_RGN_STATUS, struct.pack("<h", 3)))
        elif (L, P) == (20, gu.PID_RGN_COMPLETE):
            region = struct.unpack("<h", d)[0]
            assert region == self.active
            self.completed.append(region)
            self.active = None

    def read_packet(self, timeout_ms):
        if self.restarting:
            self.restarting = False
            self.q.clear()
            raise gu.DeviceGone("USB pipe stalled")
        return self.q.pop(0) if self.q else None

    def close(self):
        pass


def args(**kw):
    base = dict(dry_run=False, yes=True, erase_timeout=5.0, force_unverified=False)
    base.update(kw)
    return argparse.Namespace(**base)


class Tests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def write_rgn(self, regions, part="006-B0291-00"):
        p = self.dir / "fw.rgn"
        p.write_bytes(make_rgn(regions))
        if part:
            p.with_suffix(".rgn.json").write_text('{"part_number": "%s"}' % part)
        return p

    # ---- framing
    def test_packet_roundtrip_and_split_stream(self):
        a = gu.Packet(20, 255, b"hello")
        b = gu.Packet(0, 6, b"\x01\x02\x03\x04")
        raw = a.encode() + b.encode()
        buf = bytearray()
        got = []
        for i in range(0, len(raw), 7):
            buf += raw[i:i + 7]
            got += gu.take_packets(buf)
        self.assertEqual([(p.layer, p.pid, p.data) for p in got],
                         [(20, 255, b"hello"), (0, 6, b"\x01\x02\x03\x04")])

    def test_zlp_after_exact_multiple(self):
        class Ep:
            wMaxPacketSize = 64

            def __init__(s):
                s.writes = []

            def write(s, data, timeout):
                s.writes.append(len(data))
        t = object.__new__(gu.UsbTransport)
        t.log = lambda s: None
        t.ep_bulk_out = Ep()
        t.write(gu.Packet(20, 36, b"\0" * (64 - 12)))      # 64 bytes -> needs ZLP
        t.write(gu.Packet(20, 36, b"\0" * 10))             # 22 bytes -> no ZLP
        self.assertEqual(t.ep_bulk_out.writes, [64, 0, 22])

    def test_split_64k(self):
        self.assertEqual([(o, len(b)) for o, b in gu.split_64k(0, b"x" * 100)], [(0, 100)])
        self.assertEqual([(o, len(b)) for o, b in gu.split_64k(0xFFF0, b"x" * 0x20)],
                         [(0xFFF0, 0x10), (0x10000, 0x10)])
        self.assertEqual([(o, len(b)) for o, b in gu.split_64k(0xFFE0, b"x" * 0x20)], [(0xFFE0, 0x20)])

    # ---- RGN
    def test_parse_rgn(self):
        p = self.write_rgn([(14, 0, b"A" * 5000), (12, 250, b"B" * 10)])
        r = gu.parse_rgn(p)
        self.assertEqual([(x.region, x.delay_ms, x.size) for x in r.regions], [(14, 0, 5000), (12, 250, 10)])
        self.assertEqual(r.region_bytes(r.regions[1]), b"B" * 10)
        self.assertIn("SQA", r.info[0])

    def test_parse_rgn_rejects_truncated(self):
        p = self.dir / "bad.rgn"
        p.write_bytes(make_rgn([(14, 0, b"A" * 5000)])[:-100])
        with self.assertRaises(gu.GarminError):
            gu.parse_rgn(p)
        p.write_bytes(b"MZ" + b"\0" * 100)
        with self.assertRaises(gu.GarminError):
            gu.parse_rgn(p)

    # ---- device
    def test_session_and_product_info(self):
        dev = gu.GarminDevice(FakeGps())
        self.assertEqual(dev.start_session(), 0x1234ABCD)
        info = dev.product_info()
        self.assertEqual(info.part_number, "006-B0291-00")
        self.assertEqual(info.version_str, "4.10")
        self.assertEqual(info.max_packet, 4096)
        self.assertEqual(info.protocols, ["P000", "L001", "A010"])

    def flash_with(self, fake, regions, **kw):
        p = self.write_rgn(regions)
        dev = gu.GarminDevice(fake)
        dev.start_session()
        info = dev.product_info()
        with redirect_stdout(io.StringIO()):
            rc = gu.flash(dev, info, gu.parse_rgn(p), args(**kw), None)
        return rc

    def test_flash_multi_region_large(self):
        big = os.urandom(300_001)            # odd size, spans several 64 KiB boundaries
        small = os.urandom(777)
        fake = FakeGps()
        self.assertEqual(self.flash_with(fake, [(14, 0, big), (5, 0, small)]), 0)
        self.assertEqual(fake.completed, [14, 5])
        self.assertEqual(bytes(fake.written[14]), big)
        self.assertEqual(bytes(fake.written[5]), small)

    def test_flash_default_packet_size(self):
        fake = FakeGps(max_packet_raw=0)    # no max-packet answer -> 255 like WebUpdater
        data = os.urandom(10_000)
        self.assertEqual(self.flash_with(fake, [(14, 0, data)]), 0)
        self.assertEqual(bytes(fake.written[14]), data)
        sizes = {len(p.data) - 4 for p in fake.sent if p.pid == gu.PID_RGN_DATA}
        self.assertLessEqual(max(sizes), 250)

    def test_dry_run_sends_nothing(self):
        fake = FakeGps()
        self.assertEqual(self.flash_with(fake, [(14, 0, b"x" * 100)], dry_run=True), 0)
        self.assertFalse([p for p in fake.sent if p.pid in (gu.PID_RGN_ERASE, gu.PID_RGN_DATA)])

    def test_refuses_wrong_model(self):
        p = self.write_rgn([(14, 0, b"x" * 100)], part="006-B0694-00")
        dev = gu.GarminDevice(FakeGps())
        dev.start_session()
        with self.assertRaises(gu.GarminError), redirect_stdout(io.StringIO()):
            gu.flash(dev, dev.product_info(), gu.parse_rgn(p), args(), None)

    def test_refuses_unknown_origin_without_flag(self):
        p = self.write_rgn([(14, 0, b"x" * 100)], part=None)
        fake = FakeGps()
        dev = gu.GarminDevice(fake)
        dev.start_session()
        with self.assertRaises(gu.GarminError), redirect_stdout(io.StringIO()):
            gu.flash(dev, dev.product_info(), gu.parse_rgn(p), args(), None)
        self.assertFalse([p for p in fake.sent if p.pid == gu.PID_RGN_ERASE])

    def test_erase_timeout_is_bounded(self):
        fake = FakeGps(erase_reply=False)
        with self.assertRaises(gu.FlashError):
            self.flash_with(fake, [(14, 0, b"x" * 100)], erase_timeout=1.5)
        self.assertFalse([p for p in fake.sent if p.pid == gu.PID_RGN_DATA and len(p.data) >= 4])

    def test_restart_into_loader_on_first_erase(self):
        fake = FakeGps(restart_on_erase=1024)
        data = os.urandom(50_000)
        self.assertEqual(self.flash_with(fake, [(12, 0, data)]), 0)
        self.assertEqual(bytes(fake.written[12]), data)
        self.assertEqual(len([p for p in fake.sent if p.pid == gu.PID_RGN_ERASE]), 2)
        sizes = {len(p.data) for p in fake.sent if p.pid == gu.PID_RGN_DATA}
        self.assertLessEqual(max(sizes), 1024 - 12)     # re-sized for the loader

    def test_updater_that_ignores_erase_fails_fast(self):
        import garmin_update
        old = garmin_update.UPDATER_ERASE_TIMEOUT_S
        garmin_update.UPDATER_ERASE_TIMEOUT_S = 1.0
        try:
            fake = FakeGps(restart_on_erase=1024, erase_reply=False)
            with self.assertRaises(gu.FlashError) as cm:
                self.flash_with(fake, [(12, 0, b"x" * 100)], erase_timeout=60)
            self.assertIn("updater ignored the erase", str(cm.exception))
            self.assertFalse([p for p in fake.sent if p.pid == gu.PID_RGN_DATA and len(p.data) >= 4])
        finally:
            garmin_update.UPDATER_ERASE_TIMEOUT_S = old

    def test_busy_updater_two_regions(self):
        fake = FakeGps(restart_on_erase=1024, busy_updater=True)
        r12, r14 = os.urandom(68_328), os.urandom(200_001)
        self.assertEqual(self.flash_with(fake, [(12, 5, r12), (14, 0, r14)]), 0)
        self.assertEqual(fake.completed, [12, 14])
        self.assertEqual(bytes(fake.written[12]), r12)
        self.assertEqual(bytes(fake.written[14]), r14)
        self.assertTrue(all(len(p.data) <= 1024 - 12 for p in fake.sent if p.pid == gu.PID_RGN_DATA))

    def test_erase_refused(self):
        with self.assertRaises(gu.FlashError):
            self.flash_with(FakeGps(erase_status=2), [(14, 0, b"x" * 100)])

    def test_device_abort_mid_transfer(self):
        fake = FakeGps(abort_after=5)
        with self.assertRaises(gu.FlashError):
            self.flash_with(fake, [(14, 0, os.urandom(200_000))])
        self.assertNotIn(14, fake.completed)

    # ---- server XML
    def test_request_xml_shape(self):
        import xml.etree.ElementTree as ET
        x = gu.build_request_xml("006-B0291-00", [(14, 4, 10)])
        root = ET.fromstring(x)
        ns = {"u": gu.NS_UNIT_SW}
        self.assertEqual(root.findtext("u:Request/u:PartNumber", None, ns), "006-B0291-00")
        self.assertEqual(root.findtext("u:Request/u:TransferType", None, ns), "USB")
        self.assertEqual(root.findtext("u:Request/u:Region/u:Version/u:VersionMinor", None, ns), "10")

    def test_parse_response(self):
        xml = ('<?xml version="1.0" encoding="UTF-8"?><Responses xmlns="http://www.garmin.com/xmlschemas/UnitSoftwareUpdate/v3">'
               '<Response><RequestedPartNumber>006-B0291-00</RequestedPartNumber><LicenseLocation>http://x/license.txt</LicenseLocation>'
               '<Update><Description>GPSMAP 60C/60CS/76C/76CS</Description><RequestedRegionId>14</RequestedRegionId>'
               '<Version><VersionMajor>4</VersionMajor><VersionMinor>20</VersionMinor><BuildType>Release</BuildType></Version>'
               '<ChangeDescription>%3Cli%3EImproved+support+for+Macintosh+USB.%3C%2Fli%3E</ChangeDescription>'
               '<UpdateFile><Location>http://download.garmin.com/software/x_420.rgn</Location><Size>2718</Size>'
               '<MD5Sum>f08c922bf6a01947489020a9631fead1</MD5Sum></UpdateFile></Update></Response></Responses>')
        [u] = gu.parse_response_xml(xml)
        self.assertEqual((u.region, u.version, u.size_kb), (14, (4, 20), 2718))
        self.assertIn("Macintosh USB", u.changes)
        with self.assertRaises(gu.GarminError):
            gu.parse_response_xml("400: Invalid request (XML parsing error)")


if __name__ == "__main__":
    unittest.main(verbosity=2)

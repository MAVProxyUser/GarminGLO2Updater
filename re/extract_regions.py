#!/usr/bin/env python3
"""Write each region of a Garmin RGN file to OUTDIR/r<region>.bin (for loading into Ghidra).

    python3 re/extract_regions.py GLO2_230.rgn OUTDIR
"""
import os
import sys
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import garmin_update as gu  # noqa: E402


def main() -> int:
    if len(sys.argv) != 3:
        print(__doc__.strip())
        return 2
    rgn = gu.parse_rgn(Path(sys.argv[1]))
    out = Path(sys.argv[2])
    out.mkdir(parents=True, exist_ok=True)
    for r in rgn.regions:
        p = out / f"r{r.region}.bin"
        p.write_bytes(rgn.region_bytes(r))
        print(f"region {r.region:>3}: {r.size:>10,} bytes, delay {r.delay_ms} ms -> {p}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""A video of the connect window of the PR head 1d63c93 (outputs table, then validation, then commit), from a debug.log written with -debug=window.

    windowviz.py debug.log [--from H] [--to H] [--speed S] [-o window.mp4]

Each frame is the window at one moment of the node's own clock: the blocks in it, lowest height on the
left, each a box coloured by its phase then and as tall as its input count (log scale). Under it, the
number of blocks in the window over the whole range, with a cursor. Needs Pillow and ffmpeg.
"""
import argparse
import math
import re
import shutil
import subprocess
import sys

from PIL import Image, ImageDraw, ImageFont

LINE = re.compile(
    r"window-c h=(\d+) txs=(\d+) ins=(\d+) staged=(\d+) read=(\d+) task=(\d+) indexed=(\d+) claimed=(\d+) validate=(\d+) validated=(\d+) commit=(\d+) committed=(\d+) confirmed=(\d+)"
)
W, H, FPS = 1280, 720, 30
BG, FG, MUTE, GRID = (251, 251, 250), (29, 29, 27), (118, 116, 110), (226, 224, 219)
# Name, colour; phase k runs from time k to time k+1 of a block (staged, read, task, indexed, claimed,
# validate, validated, commit, committed, confirmed). Saturated: a worker is on the block. Pale: the block holds a slot and no
# core works on it.
QUEUED = (175, 172, 165)
PHASES = [
    ("reading from disk", (196, 184, 224)),
    ("queued for a worker", QUEUED),
    ("parsing, outputs into the window table", (20, 140, 130)),
    ("waiting for lower blocks' outputs", (160, 215, 205)),
    ("queued for a worker", QUEUED),
    ("validating", (47, 111, 179)),
    ("valid, waiting for its commit", (242, 201, 150)),
    ("committing to the coin store", (217, 120, 30)),
    ("committed, waiting to be published", (110, 170, 118)),
]
WORKING = (2, 5, 7)  # phases drawn with white labels
NP = len(PHASES)


def parse(path, lo, hi):
    """The blocks of the last run in the log (a log can hold several starts of the node)."""
    runs = [[]]
    with open(path, errors="replace") as f:
        for line in f:
            if "Bitcoin Core version" in line and runs[-1]:
                runs.append([])
            if "window-c h=" not in line:
                continue
            m = LINE.search(line)
            if m:
                v = list(map(int, m.groups()))
                if lo <= v[0] <= hi:
                    runs[-1].append(v)
    runs = [r for r in runs if r]
    if len(runs) > 1:
        print(f"{len(runs)} runs in the log, using the last", file=sys.stderr)
    return runs[-1] if runs else []


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("log")
    ap.add_argument("--from", dest="lo", type=int, default=0)
    ap.add_argument("--to", dest="hi", type=int, default=10**9)
    ap.add_argument("--speed", type=float, help="node seconds per video second (default: 0.05, 1/20 of real time)")
    ap.add_argument("-o", "--out", default="window.mp4")
    a = ap.parse_args()

    if not shutil.which("ffmpeg"):
        sys.exit("ffmpeg not found")
    rows = parse(a.log, a.lo, a.hi)
    if not rows:
        sys.exit("no 'window-c h=' lines in range (was the node run with -debug=window?)")
    t0 = min(r[3] for r in rows)
    # height, txs, inputs, a placeholder (the old PR head's deferred count), then the ten times in seconds from
    # the first staging, so that the layout is the PR head script's
    blocks = sorted(([r[0], r[1], r[2], 0] + [(t - t0) / 1e6 for t in r[3:]] for r in rows), key=lambda b: b[4])
    END = 4 + NP  # index of the publication time
    t_end = max(b[END] for b in blocks)
    speed = a.speed or 0.05
    frames = max(1, math.ceil(t_end / speed * FPS))

    # Blocks in the window over time, for the bottom chart.
    events = sorted([(b[4], 1) for b in blocks] + [(b[END], -1) for b in blocks])
    occ, n = [], 0
    for t, d in events:
        n += d
        occ.append((t, n))
    peak = max(v for _, v in occ)
    max_log_inputs = math.log10(max(b[2] for b in blocks) + 1)

    font = ImageFont.load_default(size=16)
    small = ImageFont.load_default(size=12)

    # The occupancy chart is the same in every frame: drawn once.
    cx0, cx1, cy0, cy1 = 60, W - 20, H - 150, H - 40
    base = Image.new("RGB", (W, H), BG)
    d = ImageDraw.Draw(base)
    X = lambda t: cx0 + t / t_end * (cx1 - cx0)
    Y = lambda v: cy1 - v / peak * (cy1 - cy0)
    pts, prev = [(cx0, Y(0))], 0
    for t, v in occ:
        pts += [(X(t), Y(prev)), (X(t), Y(v))]
        prev = v
    d.line(pts, fill=FG, width=1)
    d.rectangle([cx0, cy0, cx1, cy1], outline=GRID)
    d.text((cx0, cy0 - 18), "blocks in the window", fill=MUTE, font=small)
    d.text((cx0 - 30, cy0 - 6), str(peak), fill=MUTE, font=small)
    d.text((cx0 - 30, cy1 - 10), "0", fill=MUTE, font=small)
    d.text((cx1 - 60, cy1 + 6), f"{t_end:.3g} s", fill=MUTE, font=small)
    lx, ly = 60, 48
    for name, col in dict(PHASES).items():  # the legend names each colour once, on as many lines as it needs
        w = 20 + int(d.textlength(name, font=small)) + 24
        if lx + w > W - 20:
            lx, ly = 60, ly + 18
        d.rectangle([lx, ly + 4, lx + 14, ly + 14], fill=col)
        d.text((lx + 20, ly), name, fill=MUTE, font=small)
        lx += w
    d.text((60, ly + 22), f"box height: inputs (log scale), number above: inputs   speed: {speed:g} node s per video s", fill=MUTE, font=small)

    # Window strip geometry.
    sx0, sx1, sy_base, sy_top = 60, W - 20, cy0 - 50, ly + 62
    slot = (sx1 - sx0) / peak
    # The heights, big and centred in their boxes: the largest font whose widest height fits a box.
    widest = str(max(b[0] for b in blocks))
    label_font = None
    for size in range(64, 7, -2):
        f = ImageFont.load_default(size=size)
        if ImageDraw.Draw(base).textlength(widest, font=f) <= slot - 8:
            label_font = f
            break
    min_box = (label_font.size + 12) if label_font else 6

    ff = subprocess.Popen(
        ["ffmpeg", "-loglevel", "error", "-y", "-f", "rawvideo", "-pix_fmt", "rgb24", "-s", f"{W}x{H}", "-r", str(FPS),
         "-i", "-", "-c:v", "libx264", "-pix_fmt", "yuv420p", "-crf", "20", a.out],
        stdin=subprocess.PIPE,
    )
    nxt, live, published = 0, [], 0
    for i in range(frames + FPS):  # one still second at the end
        t = min(i * speed / FPS, t_end)
        while nxt < len(blocks) and blocks[nxt][4] <= t:
            live.append(blocks[nxt])
            nxt += 1
        before = len(live)
        live = [b for b in live if b[END] > t]
        published += before - len(live)
        live.sort(key=lambda b: b[0])

        img = base.copy()
        d = ImageDraw.Draw(img)
        d.text((60, 14), f"t = {t:8.3f} s", fill=FG, font=font)
        rng = f"heights {live[0][0]}-{live[-1][0]}" if live else "window empty"
        d.text((260, 14), f"{len(live):3d} in window   {rng}   published {published}/{len(blocks)}", fill=FG, font=font)
        d.line([X(t), cy0, X(t), cy1], fill=(200, 60, 60), width=2)
        for k, b in enumerate(live):
            phase = next(p for p in range(NP) if t < b[5 + p])
            frac = math.log10(b[2] + 1) / max_log_inputs if max_log_inputs else 1
            top = sy_base - max(min_box, frac * (sy_base - sy_top))
            x = sx0 + k * slot
            d.rectangle([x + 1, top, x + slot - 2, sy_base], fill=PHASES[phase][1])
            if label_font:
                d.text((x + slot / 2, (top + sy_base) / 2), str(b[0]), fill=(255, 255, 255) if phase in WORKING else FG, font=label_font, anchor="mm")
            if slot >= 44:
                d.text((x + 2, top - 15), f"{b[2]} in", fill=MUTE, font=small)
        ff.stdin.write(img.tobytes())
    ff.stdin.close()
    if ff.wait() != 0:
        sys.exit("ffmpeg failed")
    print(f"{len(blocks)} blocks, heights {min(b[0] for b in blocks)}-{max(b[0] for b in blocks)}, "
          f"{t_end:.2f} node s at {speed:g}x -> {frames / FPS:.0f} s video: {a.out}")


if __name__ == "__main__":
    main()

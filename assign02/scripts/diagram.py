"""Draw the Merkle tree for examples/txs5.txt with the proof path for one leaf.

Usage: python scripts/diagram.py [--index 2] [--out docs/proof_path_5tx.svg]
All hashes in the picture are computed live, so the diagram always matches the code.
"""

from __future__ import annotations

import argparse
import os
import sys
from html import escape

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))
from merklelab import MerkleTree, leaf_hash, node_hash  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
BOX_W, BOX_H = 150, 58
C = {
    "path": ("#dbeafe", "#1d4ed8"), "sib": ("#ffedd5", "#c2410c"),
    "other": ("#f4f4f5", "#a1a1aa"), "text": "#18181b", "muted": "#52525b",
}


def build(index: int, out: str) -> None:
    txs = [ln.encode() for ln in open(os.path.join(HERE, "..", "examples", "txs5.txt"), encoding="utf-8").read().splitlines()]
    t = MerkleTree(txs)
    proof = t.prove(index)
    top = len(t.levels) - 1

    # names and x positions
    names, xs = [], []
    names.append([f"L{i} = H(00‖tx{i})" for i in range(t.size)])
    xs.append([100 + i * 200 for i in range(t.size)])
    spans = [[(i, i) for i in range(t.size)]]
    for lvl in range(1, len(t.levels)):
        prev, pspan, px = t.levels[lvl - 1], spans[-1], xs[-1]
        nm, sp, xx = [], [], []
        for j in range(len(t.levels[lvl])):
            a = 2 * j
            if a + 1 < len(prev):
                lo, hi = pspan[a][0], pspan[a + 1][1]
                nm.append("ROOT" if lvl == top else f"N{lo}..{hi}" if hi - lo > 1 else f"N{lo}{hi}")
                xx.append((px[a] + px[a + 1]) / 2)
                sp.append((lo, hi))
            else:
                nm.append(("ROOT = " if lvl == top else "") + names[-1][a].split(" ")[0] + " ↑")
                xx.append(px[a])
                sp.append(pspan[a])
        names.append(nm); xs.append(xx); spans.append(sp)

    ys = {lvl: 70 + (top - lvl) * 130 for lvl in range(len(t.levels))}
    path = {(lvl, index >> lvl) for lvl in range(len(t.levels))}
    sib = {}
    i = index
    for lvl, level in enumerate(t.levels[:-1]):
        if i % 2:
            sib[(lvl, i - 1)] = len(sib) + 1
        elif i + 1 < len(level):
            sib[(lvl, i + 1)] = len(sib) + 1
        i //= 2

    W, H = 1000, ys[0] + 305
    s = [f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {W} {H}" width="{W}" height="{H}" '
         f'font-family="Helvetica, Arial, sans-serif">',
         f'<rect width="{W}" height="{H}" fill="#ffffff"/>',
         f'<text x="{W/2}" y="30" text-anchor="middle" font-size="20" font-weight="bold" fill="{C["text"]}">'
         f'Merkle inclusion proof for tx{index} in a tree of {t.size} transactions</text>']

    # edges
    for lvl in range(1, len(t.levels)):
        prev = t.levels[lvl - 1]
        for j in range(len(t.levels[lvl])):
            for a in (2 * j, 2 * j + 1):
                if a >= len(prev):
                    continue
                on = (lvl - 1, a) in path and (lvl, j) in path
                dashed = 2 * j + 1 >= len(prev)
                s.append(f'<line x1="{xs[lvl-1][a]}" y1="{ys[lvl-1] - BOX_H/2}" x2="{xs[lvl][j]}" y2="{ys[lvl] + BOX_H/2}" '
                         f'stroke="{C["path"][1] if on else "#d4d4d8"}" stroke-width="{4 if on else 2}"'
                         f'{" stroke-dasharray=\"6 5\"" if dashed else ""}/>')

    # nodes
    for lvl, level in enumerate(t.levels):
        for j, h in enumerate(level):
            kind = "path" if (lvl, j) in path else "sib" if (lvl, j) in sib else "other"
            fill, stroke = C[kind]
            x, y = xs[lvl][j], ys[lvl]
            s.append(f'<rect x="{x - BOX_W/2}" y="{y - BOX_H/2}" width="{BOX_W}" height="{BOX_H}" rx="9" '
                     f'fill="{fill}" stroke="{stroke}" stroke-width="{3 if kind != "other" else 1.5}"/>')
            s.append(f'<text x="{x}" y="{y - 6}" text-anchor="middle" font-size="13" font-weight="bold" '
                     f'fill="{C["text"]}">{escape(names[lvl][j])}</text>')
            s.append(f'<text x="{x}" y="{y + 15}" text-anchor="middle" font-size="13" font-family="Menlo, Consolas, monospace" '
                     f'fill="{C["muted"]}">{h.hex()[:12]}…</text>')
            if (lvl, j) in sib:
                bx, by = x + BOX_W / 2 - 4, y - BOX_H / 2 + 4
                s.append(f'<circle cx="{bx}" cy="{by}" r="13" fill="{C["sib"][1]}"/>')
                s.append(f'<text x="{bx}" y="{by + 5}" text-anchor="middle" font-size="14" font-weight="bold" fill="#fff">S{sib[(lvl, j)]}</text>')
        if lvl == 0:
            for j, tx in enumerate(txs):
                s.append(f'<text x="{xs[0][j]}" y="{ys[0] + BOX_H/2 + 22}" text-anchor="middle" font-size="13" '
                         f'fill="{C["text"] if (0, j) in path else C["muted"]}"'
                         f'{" font-weight=\"bold\"" if (0, j) in path else ""}>tx{j}: "{escape(tx.decode())}"</text>')

    # steps
    y0 = ys[0] + BOX_H / 2 + 62
    h = leaf_hash(txs[index])
    steps = [f'h0 = H(0x00 ‖ "{txs[index].decode()}") = {h.hex()[:16]}…']
    for k, sbl in enumerate(proof.siblings, 1):
        h = node_hash(sbl.hash, h) if sbl.side == "left" else node_hash(h, sbl.hash)
        expr = f"H(0x01 ‖ S{k} ‖ h{k-1})" if sbl.side == "left" else f"H(0x01 ‖ h{k-1} ‖ S{k})"
        steps.append(f"h{k} = {expr}   [S{k} is on the {sbl.side}]   = {h.hex()[:16]}…")
    steps.append(f"h{len(proof.siblings)} == published root {t.root.hex()[:16]}…  ⇒  VALID")
    s.append(f'<text x="40" y="{y0}" font-size="15" font-weight="bold" fill="{C["text"]}">'
             f'Verifier recomputes the root using only tx{index}, the {len(proof.siblings)} sibling hashes and their sides:</text>')
    for k, line in enumerate(steps):
        s.append(f'<text x="60" y="{y0 + 28 + k * 24}" font-size="14" font-family="Menlo, Consolas, monospace" '
                 f'fill="{C["text"]}">{escape(line)}</text>')

    # legend
    ly = y0 + 28 + len(steps) * 24 + 22
    for k, (kind, label) in enumerate([("path", "target leaf and nodes the verifier computes"),
                                       ("sib", "sibling hashes S1..Sn carried in the proof"),
                                       ("other", "not needed by the verifier")]):
        lx = 40 + k * 320
        s.append(f'<rect x="{lx}" y="{ly - 13}" width="22" height="16" rx="3" fill="{C[kind][0]}" stroke="{C[kind][1]}" stroke-width="2"/>')
        s.append(f'<text x="{lx + 30}" y="{ly}" font-size="13" fill="{C["muted"]}">{label}</text>')
    s.append(f'<text x="40" y="{ly + 26}" font-size="13" fill="{C["muted"]}">Dashed edge = unpaired node promoted '
             f'unchanged to the next level (not duplicated). ↑ marks a promoted node.</text>')
    s.append("</svg>")

    os.makedirs(os.path.dirname(out) or ".", exist_ok=True)
    with open(out, "w", encoding="utf-8") as f:
        f.write("\n".join(s))
    print(f"wrote {out}")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--index", type=int, default=2)
    ap.add_argument("--out", default=os.path.join(HERE, "..", "docs", "proof_path_5tx.svg"))
    a = ap.parse_args()
    build(a.index, a.out)

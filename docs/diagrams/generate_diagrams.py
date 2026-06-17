# /// script
# requires-python = ">=3.12"
# dependencies = ["matplotlib"]
# ///
"""Generate Pigeon architecture diagrams.

Renders sequence-style diagrams of how Pigeon connects clients, exchanges keys,
and moves messages — across each transport — so users and reviewers can see what
the relay does and does not learn, and where private keys live.

Run (no manual install needed; uv reads the header above):

    uv run docs/diagrams/generate_diagrams.py

Outputs PNGs next to this script. Re-run any time the protocol changes.
"""

from __future__ import annotations

import textwrap
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.lines import Line2D
from matplotlib.patches import FancyBboxPatch, Rectangle

# --- Palette -----------------------------------------------------------------
# Each colour encodes *what kind of material* a step touches, so the security
# story (what stays secret, what is shareable, what is opaque) reads at a glance.
COLORS = {
    "private": "#C0392B",  # secret key material — never leaves the device
    "public": "#1F6FEB",  # public/shareable material (identity bundle, signatures)
    "cipher": "#7D3C98",  # end-to-end ciphertext — opaque to any transport/relay
    "plain": "#1E8449",  # plaintext — exists only on-device, after decryption
    "action": "#566573",  # a local action / neutral note
    "ack": "#909497",  # control / acknowledgement
}
CLIENT_FILL = "#EAF2FB"
CLIENT_EDGE = "#1F6FEB"
SERVER_FILL = "#EFEFF2"
SERVER_EDGE = "#34495E"
LANE = 3.4  # horizontal spacing between actors

LEGEND = [
    ("private", "private key (stays on device)"),
    ("public", "public material"),
    ("cipher", "end-to-end ciphertext"),
    ("plain", "plaintext (on-device only)"),
]


# --- Step constructors -------------------------------------------------------
def msg(src, dst, text, kind="public", dashed=False):
    return ("msg", src, dst, text, kind, dashed)


def note(actor, text, kind="action"):
    return ("note", actor, text, kind)


def binote(left, right, text, kind="action"):
    return ("binote", left, right, text, kind)


def divider(text):
    return ("divider", text)


# --- Renderer ----------------------------------------------------------------
def _wrap(text, width):
    return textwrap.fill(text, width)


# Consistent vertical gap between the bottom of one element and the top of the next.
GAP = 0.42


def _note_metrics(text, wrapw):
    wrapped = _wrap(text, wrapw)
    half = 0.20 + 0.14 * (wrapped.count("\n") + 1)
    return wrapped, half


def _draw_note(ax, cx, cy, wrapped, half, edge, width):
    ax.add_patch(
        FancyBboxPatch(
            (cx - width / 2, cy - half),
            width,
            2 * half,
            boxstyle="round,pad=0.04,rounding_size=0.10",
            linewidth=1.3,
            edgecolor=edge,
            facecolor="white",
            zorder=4,
        )
    )
    ax.text(cx, cy, wrapped, ha="center", va="center", fontsize=8, zorder=5, color="#17202A")


def render(title, actors, steps, caption, outfile):
    xs = {a["key"]: i * LANE for i, a in enumerate(actors)}
    x_min, x_max = -1.85, (len(actors) - 1) * LANE + 1.85

    fig, ax = plt.subplots(figsize=(2.05 * len(actors) + 2.6, 0.66 * len(steps) + 3.0))
    ax.axis("off")

    header_top, header_bot = 0.55, -0.35
    for a in actors:
        x = xs[a["key"]]
        fill = SERVER_FILL if a.get("role") == "server" else CLIENT_FILL
        edge = SERVER_EDGE if a.get("role") == "server" else CLIENT_EDGE
        ax.add_patch(
            FancyBboxPatch(
                (x - 1.25, header_bot),
                2.5,
                header_top - header_bot,
                boxstyle="round,pad=0.02,rounding_size=0.10",
                linewidth=1.6,
                edgecolor=edge,
                facecolor=fill,
                zorder=4,
            )
        )
        ax.text(x, 0.30, a["name"], ha="center", va="center", fontsize=10.5, fontweight="bold", zorder=5)
        if a.get("sub"):
            ax.text(x, -0.02, a["sub"], ha="center", va="center", fontsize=7.5, color="#566573", zorder=5)

    # Lay out steps top-to-bottom. `y` tracks the *bottom* of the last element;
    # each new element's top sits exactly GAP below it, so nothing overlaps.
    y = header_bot - 0.2
    for step in steps:
        kind = step[0]
        if kind == "msg":
            _, s, d, text, mk, dashed = step
            x0, x1 = xs[s], xs[d]
            label = _wrap(text, 40)
            label_h = 0.17 * (label.count("\n") + 1)
            arrow_y = y - GAP - label_h - 0.06
            ax.annotate(
                "",
                xy=(x1, arrow_y),
                xytext=(x0, arrow_y),
                arrowprops=dict(
                    arrowstyle="-|>",
                    color=COLORS[mk],
                    lw=1.9,
                    linestyle=(0, (4, 3)) if dashed else "-",
                    shrinkA=3,
                    shrinkB=3,
                ),
                zorder=3,
            )
            ax.text(
                (x0 + x1) / 2, arrow_y + 0.11, label, ha="center", va="bottom", fontsize=8.3, color="#17202A", zorder=3
            )
            y = arrow_y - 0.12
        elif kind == "note":
            _, actor, text, nk = step
            wrapped, half = _note_metrics(text, 26)
            cy = y - GAP - half
            _draw_note(ax, xs[actor], cy, wrapped, half, COLORS[nk], width=3.0)
            y = cy - half
        elif kind == "binote":
            _, left, right, text, nk = step
            cx = (xs[left] + xs[right]) / 2
            width = abs(xs[right] - xs[left]) + 2.4
            wrapped, half = _note_metrics(text, 52)
            cy = y - GAP - half
            _draw_note(ax, cx, cy, wrapped, half, COLORS[nk], width=width)
            y = cy - half
        elif kind == "divider":
            _, text = step
            band = 0.5
            cy = y - GAP - band / 2
            ax.add_patch(
                Rectangle((x_min, cy - band / 2), x_max - x_min, band, facecolor="#F4F6F7", edgecolor="none", zorder=1)
            )
            ax.text(
                (x_min + x_max) / 2, cy, text, ha="center", va="center", style="italic", fontsize=9, color="#566573", zorder=2
            )
            y = cy - band / 2 - 0.04

    bottom = y - 0.4
    for a in actors:  # lifelines span the whole flow
        ax.plot([xs[a["key"]], xs[a["key"]]], [header_bot, bottom], color="#B3B6B7", lw=1.0, ls=(0, (2, 3)), zorder=0)

    ax.set_xlim(x_min, x_max)
    ax.set_ylim(bottom - 1.1, 1.3)

    ax.text((x_min + x_max) / 2, 1.05, title, ha="center", va="center", fontsize=14, fontweight="bold")

    handles = [Line2D([0], [0], color=COLORS[k], lw=3) for k, _ in LEGEND]
    labels = [lbl for _, lbl in LEGEND]
    ax.legend(
        handles,
        labels,
        loc="lower center",
        bbox_to_anchor=(0.5, -0.005),
        ncol=len(LEGEND),
        frameon=False,
        fontsize=8,
        handlelength=1.6,
        columnspacing=1.4,
    )
    fig.text(0.5, 0.012, caption, ha="center", va="bottom", fontsize=8.5, color="#34495E", wrap=True)

    fig.tight_layout(rect=(0, 0.06, 1, 1))
    fig.savefig(outfile, dpi=200, bbox_inches="tight", facecolor="white")
    plt.close(fig)
    print(f"wrote {outfile}")


# --- Diagrams ----------------------------------------------------------------
def diagram_identity(out):
    alice = {"key": "a", "name": "Alice", "sub": "phone", "role": "client"}
    bob = {"key": "b", "name": "Bob", "sub": "phone", "role": "client"}
    steps = [
        note("a", "Generate Ed25519 identity + X25519 static key. Private keys live in the Keychain.", "private"),
        note("b", "Generate Ed25519 identity + X25519 static key. Private keys live in the Keychain.", "private"),
        divider("In person"),
        msg("a", "b", "Show QR: ContactCard (public identity bundle + name + signed relay URLs)", "public"),
        msg("b", "a", "Show QR back (public ContactCard)", "public"),
        note("a", "Verify the bundle signature binds identity to the Noise static key.", "action"),
        binote("a", "b", "Compare the 60-digit safety number aloud — detects a man-in-the-middle.", "action"),
        note("a", "Bob is now a verified contact.", "plain"),
    ]
    render(
        "Identity & trust  ·  in-person setup",
        [alice, bob],
        steps,
        "Private keys never leave the device. Only public keys are exchanged — in person — and verified by safety number.",
        out,
    )


def diagram_ble(out):
    alice = {"key": "a", "name": "Alice", "sub": "phone", "role": "client"}
    bob = {"key": "b", "name": "Bob", "sub": "phone", "role": "client"}
    steps = [
        divider("In Bluetooth range — no server involved"),
        msg("a", "b", "Noise XX msg1 (ephemeral public key)", "public"),
        msg("b", "a", "Noise XX msg2 (ephemeral + static public keys)", "public"),
        msg("a", "b", "Noise XX msg3 (static public key)", "public"),
        note("a", "Check handshake static key == verified bundle (binding check).", "action"),
        note("a", "Derive shared secret → Double Ratchet session.", "private"),
        msg("a", "b", "Encrypted message", "cipher"),
        note("b", "Decrypt with the ratchet → show plaintext.", "plain"),
        msg("b", "a", "Encrypted delivery ack", "cipher"),
    ]
    render(
        "Bluetooth LE mesh  ·  in range",
        [alice, bob],
        steps,
        "BLE is a dumb pipe carrying only ciphertext. Each message ratchets forward, so a captured key can't decrypt past messages.",
        out,
    )


def diagram_relay(out):
    alice = {"key": "a", "name": "Alice", "sub": "phone", "role": "client"}
    relay = {"key": "r", "name": "Relay", "sub": "blind mailbox", "role": "server"}
    bob = {"key": "b", "name": "Bob", "sub": "phone", "role": "client"}
    steps = [
        note("r", "Stores opaque ciphertext keyed by recipient public key. Never sees plaintext or private keys.", "action"),
        divider("Bob is online; out of Bluetooth range"),
        msg("b", "r", "Subscribe to my mailbox (= my public key)", "public"),
        msg("r", "b", "Challenge nonce", "public"),
        note("b", "Sign the nonce with the identity private key (stays on device).", "private"),
        msg("b", "r", "Signature → proves mailbox ownership", "public"),
        msg("r", "b", "OK — authenticated", "public"),
        divider("Alice sends to Bob"),
        msg("a", "r", "Deposit ciphertext addressed to Bob's mailbox", "cipher"),
        note("r", "Store-and-forward: held until acked (7-day TTL).", "action"),
        msg("r", "b", "Deliver ciphertext", "cipher"),
        note("b", "Decrypt with the ratchet → plaintext.", "plain"),
        msg("b", "r", "Ack → relay deletes the envelope", "ack", dashed=True),
    ]
    render(
        "Federated relay  ·  out of range",
        [alice, relay, bob],
        steps,
        "The relay learns only public keys, ciphertext size, and timing — never content. Confidentiality and authentication are end-to-end.",
        out,
    )


def diagram_notifications(out):
    alice = {"key": "a", "name": "Alice", "sub": "phone", "role": "client"}
    relay = {"key": "r", "name": "Relay", "sub": "blind mailbox", "role": "server"}
    bob = {"key": "b", "name": "Bob", "sub": "locked phone", "role": "client"}
    steps = [
        divider("Bob's phone is locked; app relaunched in the background"),
        note("b", "Identity key readable (after first unlock) → can receive. Message vault stays locked behind Face ID.", "action"),
        msg("a", "r", "Deposit ciphertext for Bob", "cipher"),
        msg("r", "b", "Deliver ciphertext", "cipher"),
        note("b", "Can't open the vault → hold ciphertext in memory; do NOT ack.", "private"),
        note("b", "Post a content-free notification: “New message” (no preview).", "action"),
        divider("Bob unlocks with Face ID"),
        note("b", "Vault opens → decrypt buffered ciphertext → show message.", "plain"),
        msg("b", "r", "Ack → relay deletes the envelope", "ack", dashed=True),
    ]
    render(
        "Notifications while locked  ·  background",
        [alice, relay, bob],
        steps,
        "While locked Pigeon can be woken to notify you, but content stays encrypted (never previewed) until you unlock. The relay keeps the message until it is acked.",
        out,
    )


def main():
    here = Path(__file__).resolve().parent
    diagram_identity(here / "pigeon_01_identity.png")
    diagram_ble(here / "pigeon_02_bluetooth.png")
    diagram_relay(here / "pigeon_03_relay.png")
    diagram_notifications(here / "pigeon_04_notifications.png")


if __name__ == "__main__":
    main()

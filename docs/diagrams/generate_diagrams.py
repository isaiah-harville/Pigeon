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

# "Vault" badges sit under each actor and show what secret material the device
# holds and what each key is *for* — the role private keys play locally.
VAULT_CLIENT = {
    "kind": "private",
    "lines": [
        "Keychain · private keys",
        "Ed25519 identity → sign",
        "Curve25519 (Olm) → ECDH",
        "ratchet keys → decrypt",
    ],
}
VAULT_RELAY = {
    "kind": "none",
    "lines": ["Holds no keys", "ciphertext + public", "addresses only"],
}
VAULT_APNS = {
    "kind": "none",
    "lines": ["Apple push service", "token + timing", "never content"],
}
# A locked device: identity key is reachable (after first unlock) so it can
# authenticate and receive, but the message vault is sealed until Face ID.
VAULT_CLIENT_LOCKED = {
    "kind": "private",
    "lines": [
        "Keychain · after first unlock",
        "Ed25519 identity → sign",
        "Curve25519 (Olm) → ECDH",
        "message vault → locked",
    ],
}


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


def _vault_height(vault):
    return 0.24 + 0.17 * len(vault["lines"])


def _draw_vault(ax, x, top, vault):
    private = vault["kind"] == "private"
    edge = COLORS["private"] if private else "#7F8C8D"
    face = "#FCEEEE" if private else "#F1F3F4"
    height = _vault_height(vault)
    ax.add_patch(
        FancyBboxPatch(
            (x - 1.32, top - height),
            2.64,
            height,
            boxstyle="round,pad=0.03,rounding_size=0.08",
            linewidth=1.2,
            edgecolor=edge,
            facecolor=face,
            zorder=4,
        )
    )
    line_y = top - 0.20
    for i, line in enumerate(vault["lines"]):
        ax.text(
            x,
            line_y,
            line,
            ha="center",
            va="center",
            fontsize=7.2 if i == 0 else 7.0,
            fontweight="bold" if i == 0 else "normal",
            color=edge if i == 0 else "#34495E",
            zorder=5,
        )
        line_y -= 0.165


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
    ax.text(
        cx, cy, wrapped, ha="center", va="center", fontsize=8, zorder=5, color="#17202A"
    )


def render(title, actors, steps, caption, outfile):
    xs = {a["key"]: i * LANE for i, a in enumerate(actors)}
    x_min, x_max = -1.85, (len(actors) - 1) * LANE + 1.85

    # Reserve a band under the headers for the vault badges (tallest one wins).
    band = max(
        (_vault_height(a["vault"]) for a in actors if a.get("vault")), default=0.0
    )
    extra = band + 0.35 if band else 0.0

    fig, ax = plt.subplots(
        figsize=(2.15 * len(actors) + 2.6, 0.66 * len(steps) + 3.0 + extra)
    )
    ax.axis("off")

    header_top, header_bot = 0.55, -0.35
    vault_top = header_bot - 0.12
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
        ax.text(
            x,
            0.30,
            a["name"],
            ha="center",
            va="center",
            fontsize=10.5,
            fontweight="bold",
            zorder=5,
        )
        if a.get("sub"):
            ax.text(
                x,
                -0.02,
                a["sub"],
                ha="center",
                va="center",
                fontsize=7.5,
                color="#566573",
                zorder=5,
            )
        if a.get("vault"):
            _draw_vault(ax, x, vault_top, a["vault"])

    # Lay out steps top-to-bottom. `y` tracks the *bottom* of the last element;
    # each new element's top sits exactly GAP below it, so nothing overlaps.
    lifeline_top = (vault_top - band - 0.18) if band else (header_bot - 0.1)
    y = lifeline_top
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
                (x0 + x1) / 2,
                arrow_y + 0.11,
                label,
                ha="center",
                va="bottom",
                fontsize=8.3,
                color="#17202A",
                zorder=3,
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
                Rectangle(
                    (x_min, cy - band / 2),
                    x_max - x_min,
                    band,
                    facecolor="#F4F6F7",
                    edgecolor="none",
                    zorder=1,
                )
            )
            ax.text(
                (x_min + x_max) / 2,
                cy,
                text,
                ha="center",
                va="center",
                style="italic",
                fontsize=9,
                color="#566573",
                zorder=2,
            )
            y = cy - band / 2 - 0.04

    bottom = y - 0.4
    for a in actors:  # lifelines span the flow, from just below the vault badge
        ax.plot(
            [xs[a["key"]], xs[a["key"]]],
            [lifeline_top + 0.1, bottom],
            color="#B3B6B7",
            lw=1.0,
            ls=(0, (2, 3)),
            zorder=0,
        )

    ax.set_xlim(x_min, x_max)
    ax.set_ylim(bottom - 1.1, 1.3)

    ax.text(
        (x_min + x_max) / 2,
        1.05,
        title,
        ha="center",
        va="center",
        fontsize=14,
        fontweight="bold",
    )

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
    fig.text(
        0.5,
        0.012,
        caption,
        ha="center",
        va="bottom",
        fontsize=8.5,
        color="#34495E",
        wrap=True,
    )

    fig.tight_layout(rect=(0, 0.06, 1, 1))
    fig.savefig(outfile, dpi=200, bbox_inches="tight", facecolor="white")
    plt.close(fig)
    print(f"wrote {outfile}")


# --- Diagrams ----------------------------------------------------------------
def _client(key, name, sub="phone", vault=VAULT_CLIENT):
    return {"key": key, "name": name, "sub": sub, "role": "client", "vault": vault}


def _server(key, name, sub, vault):
    return {"key": key, "name": name, "sub": sub, "role": "server", "vault": vault}


def diagram_identity(out):
    steps = [
        note(
            "a",
            "Generate Ed25519 identity + Olm account (Curve25519 + prekeys). Private keys live in the Keychain.",
            "private",
        ),
        note(
            "b",
            "Generate Ed25519 identity + Olm account (Curve25519 + prekeys). Private keys live in the Keychain.",
            "private",
        ),
        divider("In person"),
        msg(
            "a",
            "b",
            "Show QR: ContactCard (public identity bundle + name + signed relay URLs)",
            "public",
        ),
        msg("b", "a", "Show QR back (public ContactCard)", "public"),
        note(
            "a",
            "Verify the bundle signature binds identity to the Olm Curve25519 key.",
            "action",
        ),
        binote(
            "a",
            "b",
            "Compare the 60-digit safety number aloud — detects a man-in-the-middle.",
            "action",
        ),
        note("a", "Bob is now a verified contact.", "plain"),
    ]
    render(
        "Identity & trust  ·  in-person setup",
        [_client("a", "Alice"), _client("b", "Bob")],
        steps,
        "Private keys never leave the device. Only public keys are exchanged — in person — and verified by safety number.",
        out,
    )


def _handshake_steps(transport):
    """The Olm async-first session setup shared by every direct (serverless) link."""
    return [
        divider(transport),
        note(
            "a",
            "Olm: ECDH against Bob's published prekeys → derive Double Ratchet session.",
            "private",
        ),
        msg(
            "a",
            "b",
            "Olm pre-key message (initiation: identity bundle + first ciphertext)",
            "cipher",
        ),
        note(
            "b",
            "Establish session from the pre-key message; check identity key == verified bundle (binding check).",
            "action",
        ),
        note("b", "Ratchet message key → decrypt → show plaintext.", "plain"),
        msg("b", "a", "Encrypted reply (normal Olm message)", "cipher"),
        note("a", "Ratchet message key → decrypt → show plaintext.", "plain"),
    ]


def diagram_ble(out):
    render(
        "Bluetooth LE mesh  ·  in range",
        [_client("a", "Alice"), _client("b", "Bob")],
        _handshake_steps("In Bluetooth range — no server involved"),
        "BLE is a dumb pipe carrying only ciphertext. Each message ratchets forward, so a captured key can't decrypt past messages.",
        out,
    )


def diagram_wifi(out):
    render(
        "Local Wi-Fi  ·  same network  (planned)",
        [_client("a", "Alice"), _client("b", "Bob")],
        _handshake_steps("On the same Wi-Fi / LAN — peer-to-peer, no server"),
        "Planned transport (Network.framework / Multipeer). Same end-to-end crypto as BLE — only the link layer changes; the LAN never sees plaintext.",
        out,
    )


def diagram_relay(out):
    relay = _server("r", "Relay", "blind mailbox", VAULT_RELAY)
    steps = [
        note(
            "r",
            "Stores opaque ciphertext keyed by recipient public key. Never sees plaintext or private keys.",
            "action",
        ),
        divider("Bob is online; out of Bluetooth range"),
        msg("b", "r", "Subscribe to my mailbox (= my public key)", "public"),
        msg("r", "b", "Challenge nonce", "public"),
        note(
            "b",
            "Sign the nonce with the identity private key (stays on device).",
            "private",
        ),
        msg("b", "r", "Signature → proves mailbox ownership", "public"),
        msg("r", "b", "OK — authenticated", "public"),
        divider("Alice sends to Bob"),
        msg("a", "r", "Deposit ciphertext addressed to Bob's mailbox", "cipher"),
        note("r", "Store-and-forward: held until acked (7-day TTL).", "action"),
        msg("r", "b", "Deliver ciphertext", "cipher"),
        note("b", "Ratchet message key → decrypt → plaintext.", "plain"),
        msg("b", "r", "Ack → relay deletes the envelope", "ack", dashed=True),
    ]
    render(
        "Federated relay  ·  out of range",
        [_client("a", "Alice"), relay, _client("b", "Bob")],
        steps,
        "The relay learns only public keys, ciphertext size, and timing — never content. Confidentiality and authentication are end-to-end.",
        out,
    )


def diagram_notifications(out):
    relay = _server("r", "Relay", "blind mailbox", VAULT_RELAY)
    bob = _client("b", "Bob", "locked phone", VAULT_CLIENT_LOCKED)
    steps = [
        divider("Bob's phone is locked; app relaunched in the background"),
        note(
            "b",
            "Identity key readable (after first unlock) → can receive. Message vault stays locked behind Face ID.",
            "action",
        ),
        msg("a", "r", "Deposit ciphertext for Bob", "cipher"),
        msg("r", "b", "Deliver ciphertext", "cipher"),
        note("b", "Vault locked → hold ciphertext in memory; do NOT ack.", "private"),
        note(
            "b",
            "Post a content-free notification: “New message” (no preview).",
            "action",
        ),
        divider("Bob unlocks with Face ID"),
        note(
            "b",
            "Vault opens → ratchet key decrypts buffered ciphertext → show message.",
            "plain",
        ),
        msg("b", "r", "Ack → relay deletes the envelope", "ack", dashed=True),
    ]
    render(
        "Notifications while locked  ·  background",
        [_client("a", "Alice"), relay, bob],
        steps,
        "While locked Pigeon can be woken to notify you, but content stays encrypted (never previewed) until you unlock. The relay keeps the message until it is acked.",
        out,
    )


def diagram_notifications_apns(out):
    relay = _server("r", "Relay", "blind mailbox + push", VAULT_RELAY)
    apns = _server("p", "APNs", "Apple push", VAULT_APNS)
    bob = _client("b", "Bob", "asleep phone", VAULT_CLIENT_LOCKED)
    steps = [
        divider("One-time: Bob opts in to push"),
        note(
            "b",
            "Register the opaque APNs device token with my official relay.",
            "action",
        ),
        msg("b", "r", "device token + mailbox (public key)", "public"),
        divider("Alice sends while Bob's phone is asleep"),
        msg("a", "r", "Deposit ciphertext for Bob", "cipher"),
        note(
            "r", "Has a token for this mailbox → ask APNs to wake the device.", "action"
        ),
        msg("r", "p", "Content-free push (device token, no content)", "public"),
        msg("p", "b", "Wake — “New message” (no preview)", "action"),
        note("b", "Wakes in background; message vault still locked.", "private"),
        msg("b", "r", "Authenticate + fetch mailbox", "public"),
        msg("r", "b", "Deliver ciphertext", "cipher"),
        divider("Bob unlocks with Face ID"),
        note("b", "Vault opens → ratchet key decrypts → show message.", "plain"),
        msg("b", "r", "Ack → relay deletes the envelope", "ack", dashed=True),
    ]
    render(
        "Notifications with push (APNs configured)  ·  planned",
        [_client("a", "Alice"), relay, apns, bob],
        steps,
        "Only the official relay can push (it holds the APNs key), so push is not federated. APNs and the gateway see the token, timing, and a content-free wake — never the message.",
        out,
    )


def main():
    here = Path(__file__).resolve().parent
    diagram_identity(here / "pigeon_01_identity.png")
    diagram_ble(here / "pigeon_02_bluetooth.png")
    diagram_wifi(here / "pigeon_03_wifi.png")
    diagram_relay(here / "pigeon_04_relay.png")
    diagram_notifications(here / "pigeon_05_notifications.png")
    diagram_notifications_apns(here / "pigeon_06_notifications_apns.png")


if __name__ == "__main__":
    main()

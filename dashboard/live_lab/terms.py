"""One vocabulary for everything the dashboard shows.

Internal ids (``mtl``, ``slh-dsa``, folder names, CSV columns, config keys) never change in code or files. They are
translated to display words only here, so a label has one source: tile headers, sidebars, chips, captions, the home
page glossary and the generated reports all read this module.

Each concept lists the PS-036 wording and the IETF / standards term next to the label shown on screen, so a newcomer can
map a word on the dashboard to the problem statement and to the drafts and RFCs.
"""

from __future__ import annotations

APP_NAME = "CipherOps"
APP_SUBTITLE = "MTL DNSSEC benchmark"
QUESTION = "Does MTL mode make post-quantum DNSSEC signatures practical in DNS?"
EVENT = "AIORI Hackathon 3 · PS-036"
TEAM = "Team A3-PS036-TC161"
LINKS = {
    "draft-harvey-cfrg-mtl-mode": "https://datatracker.ietf.org/doc/draft-harvey-cfrg-mtl-mode/",
    "draft-fregly-dnsop-slh-dsa-mtl-dnssec": "https://datatracker.ietf.org/doc/draft-fregly-dnsop-slh-dsa-mtl-dnssec/",
}
REPO_URL = "https://github.com/aiori-hackathon/A3-PS036-TC161"

# ─────────────────────────── algorithms ───────────────────────────
# Offline harness modes and live-lab scenarios name the same algorithms with different ids; both map here.

ALGORITHMS: dict[str, dict[str, str]] = {
    "slh-dsa-mtl": {
        "label": "SLH-DSA-MTL", "short": "SLH-DSA-MTL",
        "ps036": "MTL workload configuration",
        "ietf": "SLH-DSA-SHA2-128s with MTL mode (draft-harvey-cfrg-mtl-mode, draft-fregly-dnsop-slh-dsa-mtl-dnssec)",
    },
    "slh-dsa": {
        "label": "SLH-DSA", "short": "SLH-DSA",
        "ps036": "non-MTL workload configuration",
        "ietf": "SLH-DSA-SHA2-128s, one signature per RRset (FIPS 205)",
    },
    "ecdsa-p256": {
        "label": "ECDSAP256SHA256 (13)", "short": "ECDSA P-256",
        "ps036": "classical reference", "ietf": "DNSSEC algorithm 13 (RFC 6605)",
    },
    "ed25519": {
        "label": "ED25519 (15)", "short": "Ed25519",
        "ps036": "classical reference", "ietf": "DNSSEC algorithm 15 (RFC 8080)",
    },
    "rsa-2048": {
        "label": "RSASHA256 (8)", "short": "RSA-2048",
        "ps036": "classical reference", "ietf": "DNSSEC algorithm 8 (RFC 5702), 2048-bit key",
    },
    "mixed-mtl": {
        "label": "Mixed (ECDSA root and TLD, SLH-DSA-MTL SLD)", "short": "Mixed",
        "ps036": "MTL workload configuration (mixed hierarchy)",
        "ietf": "classical keys above the SLDs, SLH-DSA-MTL in the SLDs",
    },
}
# Live-lab scenario ids and the older short ids resolve to the entries above.
ALGORITHM_ALIASES = {"mtl": "slh-dsa-mtl", "ecdsa": "ecdsa-p256", "rsa": "rsa-2048"}


def _alg(alg_id: str) -> dict[str, str] | None:
    return ALGORITHMS.get(ALGORITHM_ALIASES.get(alg_id, alg_id))


def algorithm_label(alg_id: str, short: bool = False) -> str:
    """Display name of an algorithm id; an unknown id is returned unchanged so nothing disappears silently."""
    a = _alg(alg_id)
    return (a["short"] if short else a["label"]) if a else alg_id


def algorithm_help(alg_id: str) -> str:
    a = _alg(alg_id)
    return f"{a['ps036']}. {a['ietf']}." if a else ""


def known_algorithm_ids() -> list[str]:
    return list(ALGORITHMS) + list(ALGORITHM_ALIASES)


# ─────────────────────────── levels, stacks, dataset sizes ───────────────────────────

LEVELS = {"root": "Root", "tld": "TLD", "sld": "SLD"}


def level_label(level_id: str) -> str:
    return LEVELS.get(level_id.lower(), level_id)


# The two pinned software stacks. `latest` is not "experimental": it is the stack the primary offline numbers run on.
STACKS = {
    "draft06": {"label": "draft-06",
                "what": "follows draft-fregly-…-06: condensed signatures by default, full signature on request"},
    "latest": {"label": "latest",
               "what": "FIPS 205 SLH-DSA and the newest MTL commit pinned here; its Unbound cannot validate plain SLH-DSA"},
}


def stack_label(stack_id: str) -> str:
    return STACKS.get(stack_id, {}).get("label", stack_id)


def dataset_label(name: str, n_names: int | None = None, rrsets: int | None = None) -> str:
    """'Large · 5,000 names · 10,005 RRsets': always with the counts when they are known."""
    parts = [name.capitalize()]
    if n_names is not None:
        parts.append(f"{int(n_names):,} names")
    if rrsets is not None:
        parts.append(f"{int(rrsets):,} RRsets")
    return " · ".join(parts)


# ─────────────────────────── kinds of number ───────────────────────────

BADGES = {
    "measured": ":green-badge[Measured]",
    "estimated": ":blue-badge[Estimated]",
    "analytical": ":orange-badge[Analytical]",
    "derived": ":violet-badge[Derived]",
    "extrapolated": ":orange-badge[Extrapolated]",
    "primary": ":primary-badge[Primary · pinned core]",
    "indicative": ":orange-badge[Indicative · not core-pinned]",
}
BADGE_HELP = {
    "measured": "Read from timed library calls or counted packets.",
    "estimated": "Fitted from measured samples and applied to the whole dataset.",
    "analytical": "Computed from the draft's size formulas; never measured.",
    "derived": "Measured values combined with a stated assumption.",
    "extrapolated": "Scaled from a measured sample to the whole zone.",
    "primary": "Offline benchmark: one pinned CPU core, no network.",
    "indicative": "Live-lab benchmark: containers share all host CPUs.",
}


def badge(kind: str) -> str:
    return BADGES[kind]


# ─────────────────────────── the mtl-mode-full option ───────────────────────────

def edns_code_points() -> list[tuple[str, int, str]]:
    """The lab code point for the mtl-mode-full EDNS option on each path. They differ, and neither is an IANA value."""
    from cipherops.codepoints import EDNS_MTL_MODE_FULL
    from live_lab import driver

    return [("Offline benchmark (byte model)", EDNS_MTL_MODE_FULL, "used to size the full-signature request"),
            ("Live lab, draft-06 stack", driver.MTL_FULL, "sent by the resolver to ask for the full signature")]


# ─────────────────────────── tiles ───────────────────────────
# `id` is the navigation id (query parameter ?tile=...), unchanged. Everything else is display text.

TILES = {
    "offline": {
        "icon": ":material/memory:", "title": "Offline benchmark", "subtitle": "Pinned core · primary results",
        "pitch": "The primary measurement path: the MTL library, liboqs and OpenSSL on one pinned core, no network.",
        "use_when": "You need signing time, verification time, signature sizes and byte counts for the report.",
        "not_for": "Resolver behaviour such as truncation and cache counters; use the live-lab benchmark.",
        "needs": "Docker", "needs_chip": "Needs Docker", "cta": "Open Offline benchmark",
    },
    "setup": {
        "icon": ":material/build:", "title": "Setup", "subtitle": "Build the live lab",
        "pitch": "Build the live lab once: images, signed zones, running containers.",
        "use_when": "First visit, or after changing dataset size, algorithms or software stack.",
        "not_for": "Measuring anything.",
        "needs": "Docker", "needs_chip": "Needs Docker", "cta": "Open Setup",
    },
    "live": {
        "icon": ":material/podcasts:", "title": "Demonstrate", "subtitle": "One lookup · live packets",
        "pitch": "Send a real lookup and watch the packets it causes.",
        "use_when": "You present one lookup, its packets and the cold-versus-warm cache.",
        "not_for": "Collecting benchmark figures.",
        "needs": "Signed zones and a running lab", "needs_chip": "Needs signed zones and a running lab",
        "cta": "Open Demonstrate",
    },
    "benchmark": {
        "icon": ":material/speed:", "title": "Live-lab benchmark", "subtitle": "Real resolver · indicative timings",
        "pitch": "Three dataset sizes, repeated trials, measured through a real resolver.",
        "use_when": "You need resolver-level numbers: bytes per level, truncation, TCP retry, resolver cache.",
        "not_for": "Headline signing and verification times; use the offline benchmark for those.",
        "needs": "Images", "needs_chip": "Needs images", "cta": "Open Live-lab benchmark",
    },
    "compare": {
        "icon": ":material/compare_arrows:", "title": "Results", "subtitle": "Side by side · any run",
        "pitch": "Every algorithm side by side, and any run against any other.",
        "use_when": "You compare SLH-DSA-MTL with SLH-DSA and the classical algorithms from a finished run.",
        "not_for": "Running anything.",
        "needs": "A finished run", "needs_chip": "Needs a finished run", "cta": "Open Results",
    },
    "learn": {
        "icon": ":material/menu_book:", "title": "Learn", "subtitle": "Six short scenes",
        "pitch": "Why DNSSEC needs MTL, in six short animated scenes.",
        "use_when": "You want the background before touching any control.",
        "not_for": "Evidence.",
        "needs": "Nothing", "needs_chip": "Needs nothing", "cta": "Open Learn",
    },
    "reset": {
        "icon": ":material/cleaning_services:", "title": "Clean up", "subtitle": "Remove only what you pick",
        "pitch": "Clear exactly what you pick, and nothing else.",
        "use_when": "You free disk or start fresh.",
        "not_for": "Anything you may still need: saved runs are listed before you confirm.",
        "needs": "Nothing", "needs_chip": "Needs nothing", "cta": "Open Clean up",
    },
}
TILE_ORDER = ("offline", "benchmark", "compare", "setup", "live", "learn", "reset")


def tile_title(tile_id: str) -> str:
    return TILES[tile_id]["title"]


# ─────────────────────────── glossary ───────────────────────────
# (term shown, what it means, PS-036 wording, IETF / standards term). The home page table is generated from this list.

GLOSSARY: list[tuple[str, str, str, str]] = [
    ("CipherOps", "this project and its dashboard", "—", "—"),
    ("Algorithm", "the signature scheme used to sign a zone: SLH-DSA-MTL, SLH-DSA, ECDSAP256SHA256 (13), "
     "ED25519 (15), RSASHA256 (8) or Mixed", "MTL and non-MTL workload configurations",
     "DNSSEC algorithm (IANA registry); SLH-DSA-MTL (draft-fregly-dnsop-slh-dsa-mtl-dnssec)"),
    ("Dataset size", "Small, Medium or Large: how many names and RRsets a zone holds", "test three dataset sizes",
     "zone, owner name, RRset (RFC 9499)"),
    ("Level", "where a zone sits in the hierarchy: Root, TLD or SLD", "DNSSEC-related workloads",
     "root zone, TLD, SLD; parent and child zone; delegation (RFC 9499)"),
    ("Sign zones", "sign every zone of the hierarchy with the chosen algorithms", "benchmark configuration",
     "zone signing; DNSKEY, RRSIG, DS records; trust anchor (RFC 4033, 4034)"),
    ("Software stack", "the pinned set of software versions: draft-06 or latest", "pinned software environment",
     "draft revision followed"),
    ("Run", "one execution of the benchmark, with its settings and results saved together",
     "benchmark harness; repeated-trial measurements", "—"),
    ("Trial", "one repeat of a measurement; a warm-up trial is run first and discarded", "repeated trials", "—"),
    ("Cold cache · Warm cache", "the resolver has nothing cached · it already holds the answer or the ladder",
     "cache-use measurements", "resolver cache; cached ladder (draft-harvey-cfrg-mtl-mode)"),
    ("Condensed signature · signed ladder · full signature",
     "the short hash path in each answer · the one signed summary of the zone · both together",
     "transmitted-byte comparison", "same terms in draft-harvey-cfrg-mtl-mode"),
    ("mtl-mode-full option", "the EDNS option a resolver sends to ask for the full signature; the number is a lab "
     "code point, not IANA-assigned, and differs by path (see Known limits)", "—",
     "mtl-mode-full EDNS option (draft-fregly-dnsop-slh-dsa-mtl-dnssec)"),
    ("Measured · Estimated · Analytical", "counted or timed · fitted from samples · computed from the draft's "
     "formulas", "separate measured cache use from analytical estimates",
     "draft-harvey-cfrg-mtl-mode section 12 size formulas"),
    ("Offline benchmark", "the primary measurement path: the MTL library, liboqs and OpenSSL on one pinned core, with "
     "no network", "benchmark harness", "—"),
    ("Live-lab benchmark", "the same comparison through a real resolver (Unbound) and servers (NSD) in Docker",
     "DNSSEC-related workloads; cache-use measurements", "stub resolver, recursive resolver, authoritative server "
     "(RFC 9499)"),
    ("Primary · Indicative", "offline benchmark, one pinned core · live-lab benchmark, shared CPUs", "—", "—"),
    ("Demonstrate", "the live lookup and packet views", "technical demonstration",
     "stub resolver, recursive resolver, authoritative server, AD flag (RFC 9499, RFC 4035)"),
    ("Results", "the comparison pages for a finished run", "signing and verification results; transmitted-byte "
     "comparison", "—"),
    ("Clean up", "remove only what you pick", "—", "—"),
]


def glossary_rows() -> list[dict[str, str]]:
    return [{"Term": t, "Meaning": m, "PS-036 wording": p, "IETF / standards term": i} for t, m, p, i in GLOSSARY]

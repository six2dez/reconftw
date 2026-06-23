"""Layer registry — tiers, functions, modes, and LLM context."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

Tier = Literal["critical", "standard", "heavy"]


@dataclass(frozen=True)
class Layer:
    id: str
    name: str
    tier: Tier
    eta_minutes: int
    description: str
    usage: str
    functions: tuple[str, ...] = ()
    mode: str = ""  # reconftw CLI mode flag value: n, s, p, r, z
    config_profile: str = ""
    outputs: tuple[str, ...] = ()
    disables: tuple[str, ...] = ()  # heavy modules disabled in profile


def _layer(
    id: str,
    name: str,
    tier: Tier,
    eta: int,
    desc: str,
    usage: str,
    *,
    functions: tuple[str, ...] = (),
    mode: str = "",
    config_profile: str = "",
    outputs: tuple[str, ...] = (),
) -> Layer:
    return Layer(
        id=id,
        name=name,
        tier=tier,
        eta_minutes=eta,
        description=desc,
        usage=usage,
        functions=functions,
        mode=mode,
        config_profile=config_profile,
        outputs=outputs,
    )


# --- Critical: target <= 5 minutes ---
LAYERS: dict[str, Layer] = {
    "osint_quick": _layer(
        "osint_quick",
        "OSINT Quick",
        "critical",
        2,
        "WHOIS, reverse IP, and email harvesting.",
        "First-pass domain context. No GitHub cloning or heavy API modules.",
        functions=("domain_info", "ip_info", "emails"),
        outputs=("osint/domain_info.txt", "osint/ips.txt", "osint/emails.txt"),
    ),
    "osint_passive": _layer(
        "osint_passive",
        "OSINT Passive",
        "critical",
        4,
        "Quick OSINT plus Google/GitHub dorks (no repo cloning).",
        "Use after osint_quick when you need dork pivots without ghleaks runtime.",
        functions=("domain_info", "ip_info", "emails", "google_dorks", "github_dorks"),
        config_profile="osint_light.cfg",
        outputs=("osint/dorks.txt", "osint/gitdorks.txt"),
    ),
    "subs_passive": _layer(
        "subs_passive",
        "Subdomains Passive",
        "critical",
        5,
        "Passive subdomain discovery (subfinder, crt.sh, etc.).",
        "No DNS brute/permutation. Safe for home NAT (dnsx).",
        functions=("sub_passive", "sub_crt"),
        config_profile="subs_passive.cfg",
        outputs=("subdomains/subdomains.txt",),
    ),
    "web_probe": _layer(
        "web_probe",
        "Web Probe",
        "critical",
        4,
        "HTTP probing of discovered hosts (httpx).",
        "Run after subs_passive. Produces live web target list.",
        functions=("webprobe_full",),
        outputs=("webs/webs.txt", "webs/webs_all.txt"),
    ),
    "waf_scan": _layer(
        "waf_scan",
        "WAF Detection",
        "critical",
        2,
        "Detect WAF/CDN in front of live web targets.",
        "Requires webs/webs_all.txt from web_probe.",
        functions=("waf_checks",),
        outputs=("webs/waf.txt",),
    ),
    "ssl_scan": _layer(
        "ssl_scan",
        "SSL/TLS Check",
        "critical",
        3,
        "TLS misconfiguration scan (testssl.sh).",
        "Lightweight vuln signal; run on probed hosts.",
        functions=("test_ssl",),
        outputs=("vulns/testssl.txt",),
    ),
    # --- Standard: 5–20 minutes ---
    "osint_full": _layer(
        "osint_full",
        "OSINT Full",
        "standard",
        15,
        "Full OSINT module without the heaviest GitHub secret mining.",
        "Mode -n with mcp osint profile. Skips ghleaks interlace by default.",
        mode="n",
        config_profile="osint_light.cfg",
        outputs=("osint/",),
    ),
    "subs_standard": _layer(
        "subs_standard",
        "Subdomains Standard",
        "standard",
        12,
        "Passive + active subs, DNS records, TLS certs. No brute/permut.",
        "Mode -s with passive-oriented profile.",
        mode="s",
        config_profile="subs_passive.cfg",
        outputs=("subdomains/",),
    ),
    "web_detect": _layer(
        "web_detect",
        "Web Detection",
        "standard",
        15,
        "Probe, favicon tech, CDN detection, screenshots.",
        "Sequential web detection stack after subdomains exist.",
        functions=("webprobe_full", "favirecon_tech", "cdnprovider", "screenshot"),
        config_profile="web_detect.cfg",
        outputs=("webs/", "screenshots/"),
    ),
    "recon_passive": _layer(
        "recon_passive",
        "Recon Passive",
        "standard",
        20,
        "Passive recon pipeline: OSINT + passive subs + light web.",
        "Equivalent to ./reconftw.sh -p with MCP profile.",
        mode="p",
        config_profile="passive.cfg",
        outputs=("osint/", "subdomains/", "webs/"),
    ),
    "vulns_quick": _layer(
        "vulns_quick",
        "Vulns Quick",
        "standard",
        10,
        "CRLF, SSL, WAF — fast vulnerability signals.",
        "No fuzz/nuclei_dast/sqli. Good triage pass.",
        functions=("crlf_checks", "test_ssl", "waf_checks"),
        config_profile="vulns_quick.cfg",
        outputs=("vulns/",),
    ),
    # --- Heavy: 20+ minutes (agent should confirm) ---
    "subs_brute": _layer(
        "subs_brute",
        "Subdomains Brute",
        "heavy",
        45,
        "DNS brute + permutations (slow on home NAT).",
        "Only when passive subs insufficient. Expect long dnsx runs.",
        functions=("sub_brute", "sub_permut"),
        config_profile="subs_brute.cfg",
        outputs=("subdomains/subdomains.txt",),
    ),
    "web_analyze": _layer(
        "web_analyze",
        "Web Analysis",
        "heavy",
        60,
        "URL collection, JS analysis, nuclei, fuzz (very heavy).",
        "Requires webs from web_detect. Confirm time budget.",
        functions=("urlchecks", "js_extract", "jschecks", "spiderjs_scan", "nuclei_check", "wscan_check", "fuzz"),
        config_profile="web_analyze.cfg",
        outputs=("webs/", "js/", "vulns/nuclei.txt", "vulns/wscan.txt"),
    ),
    "vulns_full": _layer(
        "vulns_full",
        "Vulns Full",
        "heavy",
        90,
        "Full intrusive vulnerability module.",
        "Mode -a equivalent. Only with explicit authorization.",
        mode="a",
        config_profile="vulns_full.cfg",
        outputs=("vulns/",),
    ),
    "recon_full": _layer(
        "recon_full",
        "Recon Full",
        "heavy",
        120,
        "Complete recon without intrusive vuln attacks.",
        "Mode -r with balanced MCP profile.",
        mode="r",
        config_profile="recon_balanced.cfg",
        outputs=("osint/", "subdomains/", "webs/", "hosts/", "vulns/"),
    ),
}

CRITICAL_LAYER_IDS: tuple[str, ...] = tuple(
    lid for lid, layer in LAYERS.items() if layer.tier == "critical"
)


def get_layer(layer_id: str) -> Layer:
    if layer_id not in LAYERS:
        raise KeyError(f"Unknown layer: {layer_id}. Use list_layers.")
    return LAYERS[layer_id]


def list_layers(*, tier: str | None = None) -> list[Layer]:
    items = list(LAYERS.values())
    if tier:
        items = [layer for layer in items if layer.tier == tier]
    return sorted(items, key=lambda layer: (layer.tier, layer.eta_minutes, layer.id))


def layer_context_markdown(layer: Layer) -> str:
    """Pruned LLM context for a single layer (no large file contents)."""
    lines = [
        f"# Layer: {layer.name} (`{layer.id}`)",
        f"- **Tier:** {layer.tier} (~{layer.eta_minutes} min)",
        f"- **Description:** {layer.description}",
        f"- **When to use:** {layer.usage}",
    ]
    if layer.mode:
        lines.append(f"- **CLI mode:** `-{layer.mode}`")
    if layer.functions:
        lines.append(f"- **Functions:** {', '.join(layer.functions)}")
    if layer.config_profile:
        lines.append(f"- **Config profile:** `config/mcp/{layer.config_profile}`")
    if layer.outputs:
        lines.append("- **Key outputs:**")
        for out in layer.outputs:
            lines.append(f"  - `Recon/<domain>/{out}`")
    lines.append(
        "\nAfter running, call `get_result_paths` or `search_results` — do not read full scan dirs inline."
    )
    return "\n".join(lines)

"""Catalog of individual reconFTW shell functions exposed via run_function."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class RunnableFunction:
    name: str
    category: str
    eta_minutes: int
    description: str
    prerequisites: str = ""


# Main tools an LLM agent can invoke via run_function (matches modules/*.sh).
RUNNABLE_FUNCTIONS: dict[str, RunnableFunction] = {
    # OSINT
    "domain_info": RunnableFunction(
        "domain_info", "osint", 1, "WHOIS / registration metadata for the target domain."
    ),
    "ip_info": RunnableFunction("ip_info", "osint", 1, "Reverse IP and ASN context for resolved hosts."),
    "emails": RunnableFunction("emails", "osint", 1, "Harvest emails from public sources."),
    "google_dorks": RunnableFunction("google_dorks", "osint", 2, "Generate Google dork queries (no automated search)."),
    "github_dorks": RunnableFunction("github_dorks", "osint", 2, "Generate GitHub dork queries."),
    "github_repos": RunnableFunction(
        "github_repos", "osint", 10, "Enumerate GitHub repos related to the target.", "Heavy; needs tokens."
    ),
    "github_leaks": RunnableFunction("github_leaks", "osint", 15, "Search GitHub for leaked secrets.", "Heavy."),
    "metadata": RunnableFunction("metadata", "osint", 3, "Extract document metadata leaks."),
    "apileaks": RunnableFunction("apileaks", "osint", 5, "Postman/Swagger/API leak checks."),
    # Subdomains
    "sub_passive": RunnableFunction(
        "sub_passive", "subdomains", 4, "Passive subdomain enumeration (subfinder, APIs)."
    ),
    "sub_crt": RunnableFunction("sub_crt", "subdomains", 2, "Certificate transparency subdomain discovery."),
    "sub_active": RunnableFunction("sub_active", "subdomains", 8, "Active DNS/subdomain probing."),
    "sub_brute": RunnableFunction(
        "sub_brute", "subdomains", 20, "DNS brute force.", "Heavy; slow on home NAT."
    ),
    "sub_permut": RunnableFunction(
        "sub_permut", "subdomains", 30, "Permutation + resolve pipeline.", "Heavy; cap PERMUTATIONS_MAX_CANDIDATES."
    ),
    "sub_scraping": RunnableFunction("sub_scraping", "subdomains", 5, "Scrape subdomains from web pages."),
    "subtakeover": RunnableFunction("subtakeover", "subdomains", 3, "Subdomain takeover checks."),
    "zonetransfer": RunnableFunction("zonetransfer", "subdomains", 1, "Attempt DNS zone transfers."),
    # Web
    "webprobe_full": RunnableFunction(
        "webprobe_full", "web", 4, "HTTP probe live hosts (httpx).", "Best after sub_passive."
    ),
    "favirecon_tech": RunnableFunction("favirecon_tech", "web", 3, "Favicon / technology fingerprinting."),
    "cdnprovider": RunnableFunction("cdnprovider", "web", 2, "Detect CDN/WAF providers."),
    "screenshot": RunnableFunction("screenshot", "web", 5, "Capture web screenshots."),
    "waf_checks": RunnableFunction("waf_checks", "web", 2, "WAF detection on probed URLs.", "Requires webs/webs_all.txt"),
    "urlchecks": RunnableFunction("urlchecks", "web", 15, "Collect and probe URLs.", "Heavy."),
    "js_extract": RunnableFunction("js_extract", "web", 5, "getJS passive JS URL extraction.", "Light; capped hosts."),
    "jschecks": RunnableFunction("jschecks", "web", 10, "JavaScript file analysis.", "Heavy."),
    "spiderjs_scan": RunnableFunction("spiderjs_scan", "web", 8, "SpiderJS API/framework discovery.", "Capped; requires spiderjs_bin."),
    "wscan_check": RunnableFunction("wscan_check", "vulns", 25, "Wscan active web vulnerability scan.", "Heavy; DEEP or WSCAN=true."),
    # Vulns
    "test_ssl": RunnableFunction("test_ssl", "vulns", 3, "TLS misconfiguration scan (testssl)."),
    "crlf_checks": RunnableFunction("crlf_checks", "vulns", 3, "CRLF injection checks."),
    "nuclei_check": RunnableFunction("nuclei_check", "vulns", 20, "Nuclei template scan.", "Heavy."),
    "fuzz": RunnableFunction("fuzz", "vulns", 30, "Directory/content fuzzing.", "Heavy; intrusive."),
    # Reporting
    "generate_consolidated_report": RunnableFunction(
        "generate_consolidated_report",
        "report",
        1,
        "Build report/report.json and report/index.html from existing scan artifacts.",
        "Run after scan modules; then use read_report.",
    ),
}

FUNCTION_CATEGORIES: tuple[str, ...] = ("osint", "subdomains", "web", "vulns", "report")


def list_functions(*, category: str | None = None) -> list[RunnableFunction]:
    items = list(RUNNABLE_FUNCTIONS.values())
    if category:
        items = [fn for fn in items if fn.category == category]
    return sorted(items, key=lambda fn: (fn.category, fn.eta_minutes, fn.name))


def get_function(name: str) -> RunnableFunction:
    if name not in RUNNABLE_FUNCTIONS:
        raise KeyError(f"Unknown function: {name}. Use list_functions.")
    return RUNNABLE_FUNCTIONS[name]


def function_names() -> tuple[str, ...]:
    return tuple(sorted(RUNNABLE_FUNCTIONS))

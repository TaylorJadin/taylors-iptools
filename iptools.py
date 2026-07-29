#!/usr/bin/env python3

"""
Unified command-line tool for extracting, expanding, and summarizing IP
addresses, CIDR ranges, and ASNs from arguments, files, or stdin.

Examples:
  iptools info 8.8.8.8
  iptools expand 192.0.2.0/30
  iptools condense --cidr --short access.log
"""

import argparse
import ipaddress
import json
import os
import re
import socket
import sys
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter
from typing import Dict, List, NamedTuple, Optional, Set, Tuple, Union

BOLD = "\033[1m"
FAINT = "\033[2m"
RESET = "\033[0m"

IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b|\b[0-9a-fA-F:]+:[0-9a-fA-F:]*\b")
ASN_RE = re.compile(r"\bAS\d+\b", re.IGNORECASE)
TARGET_RE = re.compile(
    r"\bAS\d+\b|"
    r"\b(?:\d{1,3}\.){3}\d{1,3}/\d{1,2}\b|"
    r"\b(?:\d{1,3}\.){3}\d{1,3}\b|"
    r"\b[0-9a-fA-F:]+:[0-9a-fA-F:]*/\d{1,3}\b|"
    r"\b[0-9a-fA-F:]+:[0-9a-fA-F:]*\b"
)

INFO_URL = "https://ipinfo.io/{}/json"
PUBLIC_IP_URLS = (
    "https://api.ipify.org",
    "https://api64.ipify.org",
)
RIPESTAT_AS_OVERVIEW_URL = "https://stat.ripe.net/data/as-overview/data.json?resource={}"
RIPESTAT_WHOIS_URL = "https://stat.ripe.net/data/whois/data.json?resource={}"
ASN_DETAILS_URL = "https://asn.ipinfo.app/api/json/details/{}"
RIPESTAT_PREFIXES_URL = "https://stat.ripe.net/data/announced-prefixes/data.json?resource={}"
RIPESTAT_NETWORK_INFO_URL = "https://stat.ripe.net/data/network-info/data.json?resource={}"

Network = Union[ipaddress.IPv4Network, ipaddress.IPv6Network]
IPAddress = Union[ipaddress.IPv4Address, ipaddress.IPv6Address]
LookupResult = Tuple[str, str, str, str, str]

USER_AGENT = "iptools"


class Config(NamedTuple):
    skip_public_ip: bool
    skip_targets: List[str]


class SkipRules(NamedTuple):
    ips: Set[IPAddress]
    networks: List[Network]
    asns: Set[str]

    def any_rules(self):
        # type: () -> bool
        return bool(self.ips or self.networks or self.asns)

    def has_lookup_rules(self):
        # type: () -> bool
        return bool(self.networks or self.asns)


COMMANDS = {
    "info": "Show IP, BGP, ASN, and hostname lookup details.",
    "expand": "Expand CIDRs, ASNs, and IPs into individual IP addresses.",
    "condense": "Identify common IPs, ASNs, and CIDR prefixes.",
}

ALIASES = {
    "ipinfo": "info",
    "ipexpand": "expand",
    "ipcondense": "condense",
}


def is_valid_ip(value):
    # type: (str) -> bool
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def extract_ips(text):
    # type: (str) -> List[str]
    """Pull valid IP addresses out of an arbitrary blob of text."""
    return [match for match in IP_RE.findall(text) if is_valid_ip(match)]


def filter_ips(ips, include_ipv4, include_ipv6):
    # type: (List[str], bool, bool) -> List[str]
    """Filter IPs by address family."""
    filtered = []  # type: List[str]
    for ip in ips:
        parsed = ipaddress.ip_address(ip)
        if parsed.version == 4 and include_ipv4:
            filtered.append(ip)
        elif parsed.version == 6 and include_ipv6:
            filtered.append(ip)
    return filtered


def unique_items(items):
    # type: (List[str]) -> List[str]
    """Deduplicate while preserving order."""
    seen = set()
    unique = []  # type: List[str]
    for item in items:
        if item in seen:
            continue
        seen.add(item)
        unique.append(item)
    return unique


def include_families(ipv4, ipv6):
    # type: (bool, bool) -> Tuple[bool, bool]
    """Default to both families unless one or both explicit flags are passed."""
    return ipv4 or not ipv6, ipv6 or not ipv4


def default_config_paths():
    # type: () -> List[str]
    """Return config files to load, from bundled defaults to user overrides."""
    script_dir = os.path.dirname(os.path.realpath(__file__))
    xdg_home = os.environ.get("XDG_CONFIG_HOME") or os.path.expanduser("~/.config")
    paths = [
        os.path.join(script_dir, "iptools.conf"),
        os.path.join(xdg_home, "iptools", "config"),
    ]
    env_path = os.environ.get("IPTOOLS_CONFIG")
    if env_path:
        paths.append(os.path.expanduser(env_path))
    return paths


def parse_bool(value):
    # type: (str) -> Optional[bool]
    normalized = value.strip().lower()
    if normalized in ("1", "true", "yes", "on"):
        return True
    if normalized in ("0", "false", "no", "off"):
        return False
    return None


def strip_inline_comment(line):
    # type: (str) -> str
    in_quote = None  # type: Optional[str]
    escaped = False
    for index, char in enumerate(line):
        if escaped:
            escaped = False
            continue
        if char == "\\":
            escaped = True
            continue
        if in_quote:
            if char == in_quote:
                in_quote = None
            continue
        if char in ("'", '"'):
            in_quote = char
            continue
        if char in ("#", ";"):
            return line[:index].rstrip()
    return line.rstrip()


class _FileConfig(NamedTuple):
    # Per-file config; booleans are None when the file does not set them.
    skip_public_ip: Optional[bool]
    skip_targets: List[str]


def read_config_file(path):
    # type: (str) -> _FileConfig
    skip_public_ip = None  # type: Optional[bool]
    skip_targets = []  # type: List[str]
    section = "options"
    with open(path, "r") as handle:
        for number, raw_line in enumerate(handle, 1):
            line = strip_inline_comment(raw_line).strip()
            if not line:
                continue
            if line.startswith("[") and line.endswith("]"):
                section = line[1:-1].strip().lower()
                continue

            if section == "skip":
                skip_targets.append(line)
                continue

            if "=" not in line:
                print("warning: {}:{}: ignoring invalid config line".format(path, number), file=sys.stderr)
                continue
            key, value = [part.strip() for part in line.split("=", 1)]
            key = key.lower().replace("-", "_")
            if key == "skip_public_ip":
                parsed = parse_bool(value)
                if parsed is None:
                    print("warning: {}:{}: invalid boolean: {}".format(path, number, value), file=sys.stderr)
                    continue
                skip_public_ip = parsed
            else:
                print("warning: {}:{}: unknown config option: {}".format(path, number, key), file=sys.stderr)
    return _FileConfig(skip_public_ip, skip_targets)


def load_config(paths=None):
    # type: (Optional[List[str]]) -> Config
    skip_public_ip = False
    skip_targets = []  # type: List[str]
    for path in paths or default_config_paths():
        if not path or not os.path.isfile(path):
            continue
        loaded = read_config_file(path)
        if loaded.skip_public_ip is not None:
            skip_public_ip = loaded.skip_public_ip
        skip_targets.extend(loaded.skip_targets)
    return Config(skip_public_ip, skip_targets)


def public_ips():
    # type: () -> List[str]
    ips = []  # type: List[str]
    for url in PUBLIC_IP_URLS:
        try:
            data = urllib.request.urlopen(url, timeout=10).read().decode("utf-8").strip()
        except (socket.timeout, OSError, urllib.error.URLError, ValueError):
            continue
        if is_valid_ip(data):
            ips.append(data)
    return unique_items(ips)


def skip_rules(config):
    # type: (Config) -> SkipRules
    ips = set()  # type: Set[IPAddress]
    networks = []  # type: List[Network]
    asns = set()  # type: Set[str]

    targets = list(config.skip_targets)
    if config.skip_public_ip:
        targets.extend(public_ips())

    for target in targets:
        value = clean_target(str(target))
        if not value:
            continue
        asn = normalize_asn(value)
        if asn:
            asns.add(asn)
            continue
        try:
            if "/" in value:
                networks.append(ipaddress.ip_network(value, strict=False))
            else:
                ips.add(ipaddress.ip_address(value))
        except ValueError:
            print("warning: ignoring invalid skip target: {}".format(value), file=sys.stderr)
    return SkipRules(ips, networks, asns)


def ip_is_skipped(ip, rules):
    # type: (str, SkipRules) -> bool
    parsed = ipaddress.ip_address(ip)
    if parsed in rules.ips:
        return True
    return any(parsed in network for network in rules.networks)


def asn_is_skipped(asn, rules):
    # type: (str, SkipRules) -> bool
    # A Team Cymru ASN field may list multiple origin ASNs (e.g. "701 1239");
    # the result is skipped if any of them is configured to be skipped.
    for token in asn.split():
        normalized = normalize_asn(token)
        if normalized and normalized in rules.asns:
            return True
    return False


def network_is_skipped(prefix, rules):
    # type: (str, SkipRules) -> bool
    """A network is skipped when it is contained within a skip network."""
    net = ipaddress.ip_network(prefix, strict=False)
    for skipped in rules.networks:
        if (
            net.version == skipped.version
            and net.network_address in skipped
            and net.broadcast_address in skipped
        ):
            return True
    return False


def info_asns(data):
    # type: (Dict) -> List[str]
    """Extract ASNs from an IP lookup payload."""
    return unique_items(extract_asns(json.dumps(data, sort_keys=True)))


def lookup_info_is_skipped(data, bgp_range, rules):
    # type: (Dict, str, SkipRules) -> bool
    if any(asn_is_skipped(asn, rules) for asn in info_asns(data)):
        return True
    if bgp_range:
        try:
            return network_is_skipped(bgp_range, rules)
        except ValueError:
            return False
    return False


def lookup_result_is_skipped(result, rules):
    # type: (LookupResult, SkipRules) -> bool
    _ip, asn, prefix, _cc, _name = result
    if asn_is_skipped(asn, rules):
        return True
    try:
        return network_is_skipped(prefix, rules)
    except ValueError:
        return False


def filter_skipped_ips(ips, rules):
    # type: (List[str], SkipRules) -> List[str]
    return [ip for ip in ips if not ip_is_skipped(ip, rules)]


def filter_skipped_asns(asns, rules):
    # type: (List[str], SkipRules) -> List[str]
    return [asn for asn in asns if not asn_is_skipped(asn, rules)]


def json_lookup(url):
    # type: (str) -> Dict
    """Fetch a JSON API response using the tool's shared HTTP settings."""
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=30) as response:
        return json.loads(response.read().decode("utf-8"))


def add_family_flags(parser):
    # type: (argparse.ArgumentParser) -> None
    parser.add_argument(
        "-4", "--ipv4",
        action="store_true",
        help="Include IPv4 addresses. Combine with -6 (or omit both) for all.",
    )
    parser.add_argument(
        "-6", "--ipv6",
        action="store_true",
        help="Include IPv6 addresses. Combine with -4 (or omit both) for all.",
    )


def stdin_text():
    # type: () -> str
    if sys.stdin.isatty():
        return ""
    return sys.stdin.read()


def read_text_file(path):
    # type: (str) -> str
    with open(path, "r") as handle:
        return handle.read()


def normalize_asn(value):
    # type: (str) -> Optional[str]
    """Return an AS-prefixed ASN, or None if the value is not ASN-shaped."""
    value = value.strip()
    if value.upper().startswith("AS"):
        number = value[2:]
    else:
        number = value
    if not number.isdigit():
        return None
    return "AS{}".format(int(number))


def extract_asns(text):
    # type: (str) -> List[str]
    """Pull AS-prefixed ASNs out of arbitrary text."""
    asns = []  # type: List[str]
    for match in ASN_RE.findall(text):
        asn = normalize_asn(match)
        if asn:
            asns.append(asn)
    return asns


def resolve_target(target):
    # type: (str) -> Optional[str]
    """Resolve a hostname to an IP address, or return None."""
    try:
        infos = socket.getaddrinfo(target, None)
    except socket.gaierror:
        return None

    for info in infos:
        ip = info[4][0]
        if is_valid_ip(ip):
            return ip
    return None


def collect_info_inputs(inputs):
    # type: (List[str]) -> Tuple[List[str], List[str], List[Tuple[str, str]]]
    """Build lists of IPs and ASNs from args, files, text, and stdin."""
    ips = []  # type: List[str]
    asns = []  # type: List[str]
    resolutions = []  # type: List[Tuple[str, str]]

    for item in inputs:
        if os.path.isfile(item):
            text = read_text_file(item)
            ips.extend(extract_ips(text))
            asns.extend(extract_asns(text))
            continue

        asn = normalize_asn(item)
        if asn:
            asns.append(asn)
            continue

        found = extract_ips(item)
        found_asns = extract_asns(item)
        if found or found_asns:
            ips.extend(found)
            asns.extend(found_asns)
            continue

        resolved = resolve_target(item)
        if resolved:
            ips.append(resolved)
            resolutions.append((item, resolved))
        else:
            print("error: {}: could not resolve".format(item), file=sys.stderr)

    text = stdin_text()
    if text:
        ips.extend(extract_ips(text))
        asns.extend(extract_asns(text))

    return ips, asns, resolutions


def ipinfo_lookup(ip):
    # type: (str) -> Dict
    url = INFO_URL.format(urllib.parse.quote(ip))
    return json_lookup(url)


def cymru_query(payload):
    # type: (str) -> List[str]
    """Send a query to the Team Cymru WHOIS service and return its lines."""
    with socket.create_connection(("whois.cymru.com", 43), timeout=1) as conn:
        conn.sendall(payload.encode("ascii"))
        chunks = []  # type: List[bytes]
        while True:
            chunk = conn.recv(4096)
            if not chunk:
                break
            chunks.append(chunk)
    return b"".join(chunks).decode("utf-8", "replace").splitlines()


def cymru_prefix_lookup(ip):
    # type: (str) -> str
    lines = cymru_query(" -p {}\n".format(ip))
    if len(lines) < 2:
        return ""

    parts = [part.strip() for part in lines[1].split("|")]
    if len(parts) >= 3 and parts[2] != "NA":
        return parts[2]
    return ""


def ripestat_network_info(ip):
    # type: (str) -> Dict
    """Fetch RIPEstat network-info data for an IP address."""
    url = RIPESTAT_NETWORK_INFO_URL.format(urllib.parse.quote(ip))
    return json_lookup(url).get("data", {})


def ripestat_prefix_lookup(ip):
    # type: (str) -> str
    return str(ripestat_network_info(ip).get("prefix") or "")


def bgp_range_lookup(ip):
    # type: (str) -> str
    try:
        return cymru_prefix_lookup(ip)
    except (socket.timeout, OSError):
        return ripestat_prefix_lookup(ip)


def asn_number(value):
    # type: (object) -> Optional[str]
    asn = normalize_asn(str(value))
    if asn:
        return asn[2:]
    return None


def asn_field_from_values(values):
    # type: (object) -> str
    if not isinstance(values, list):
        values = [values]
    numbers = []  # type: List[str]
    for value in values:
        number = asn_number(value)
        if number:
            numbers.append(number)
    return " ".join(numbers)


def ripestat_as_name(asn, cache):
    # type: (str, Dict[str, str]) -> str
    number = asn_number(asn)
    if number is None:
        return ""
    if number not in cache:
        try:
            url = RIPESTAT_AS_OVERVIEW_URL.format(urllib.parse.quote("AS{}".format(number)))
            cache[number] = str(json_lookup(url).get("data", {}).get("holder") or "")
        except (socket.timeout, OSError, urllib.error.URLError, ValueError):
            cache[number] = ""
    return cache[number]


def lookup_names(asn_field, cache):
    # type: (str, Dict[str, str]) -> str
    names = []  # type: List[str]
    for number in asn_field.split():
        name = ripestat_as_name(number, cache)
        if name and name not in names:
            names.append(name)
    return ", ".join(names)


def ripestat_lookup(ip, name_cache):
    # type: (str, Dict[str, str]) -> Optional[LookupResult]
    data = ripestat_network_info(ip)
    prefix = str(data.get("prefix") or "")
    asn = asn_field_from_values(data.get("asns") or [])
    if not prefix or not asn:
        return None
    return ip, asn, prefix, "", lookup_names(asn, name_cache)


def format_asn_field(asn):
    # type: (str) -> str
    """Render a Team Cymru ASN field (possibly multiple ASNs) as 'AS123 AS456'."""
    return " ".join("AS{}".format(token) for token in asn.split()) or "AS"


def format_value(value):
    # type: (object) -> str
    if isinstance(value, (dict, list)):
        return json.dumps(value, sort_keys=True)
    return str(value)


def format_number(value):
    # type: (object) -> str
    try:
        return "{:,}".format(int(value))
    except (TypeError, ValueError):
        return format_value(value)


def whois_first(records, key):
    # type: (List[List[Dict]], str) -> str
    key = key.lower()
    for record in records:
        for item in record:
            if item.get("key", "").lower() == key:
                return item.get("value", "")
    return ""


def asn_lookup(asn):
    # type: (str) -> Dict
    encoded = urllib.parse.quote(asn)
    overview = json_lookup(RIPESTAT_AS_OVERVIEW_URL.format(encoded))
    whois = json_lookup(RIPESTAT_WHOIS_URL.format(encoded))
    details = json_lookup(ASN_DETAILS_URL.format(encoded))
    return {
        "overview": overview.get("data", {}),
        "whois": whois.get("data", {}),
        "details": details,
    }


def print_info(ip, colors, data=None, bgp_range=None):
    # type: (str, Dict[str, str], Optional[Dict], Optional[str]) -> None
    bold, reset = colors["bold"], colors["reset"]
    if data is None:
        data = ipinfo_lookup(ip)
    if bgp_range is None:
        bgp_range = bgp_range_lookup(ip)
    for key in sorted(data.keys()):
        value = data[key]
        # ipinfo.io free responses include a "readme" pointer to
        # https://ipinfo.io/missingauth; skip that boilerplate field.
        if isinstance(value, str) and value.endswith("/missingauth"):
            continue
        print("{}{}:{} {}".format(bold, key, reset, format_value(value)))

    print("{}range:{} {}".format(bold, reset, bgp_range))
    print("{}more:{} https://ipinfo.io/{}".format(bold, reset, ip))


def print_asn_info(asn, colors):
    # type: (str, Dict[str, str]) -> None
    bold, reset = colors["bold"], colors["reset"]
    data = asn_lookup(asn)
    overview = data["overview"]
    whois = data["whois"]
    details = data["details"]
    records = whois.get("records", [])

    fields = [
        ("asn", asn),
        ("name", details.get("name") or whois_first(records, "as-name") or overview.get("holder")),
        ("description", whois_first(records, "descr")),
        ("registry", whois_first(records, "source") or ", ".join(whois.get("authorities", []))),
        ("status", whois_first(records, "status")),
        ("announced", overview.get("announced")),
        ("prefixes", details.get("iprec")),
        ("ipv4 addresses", details.get("v4size")),
        ("ipv6 /64s", details.get("v6size")),
    ]

    for key, value in fields:
        if value in (None, ""):
            continue
        if key in ("prefixes", "ipv4 addresses", "ipv6 /64s"):
            value = format_number(value)
        print("{}{}:{} {}".format(bold, key, reset, value))

    print("{}more:{} https://ipinfo.io/{}".format(bold, reset, asn))


def run_info(argv, config):
    # type: (List[str], Config) -> int
    parser = argparse.ArgumentParser(
        prog="iptools info",
        description="Show ipinfo.io, BGP, and ASN details for IPs and ASNs found in input.",
    )
    parser.add_argument(
        "inputs",
        nargs="*",
        help="IP addresses, ASNs, hostnames, file paths, or arbitrary text containing IPs/ASNs",
    )
    add_family_flags(parser)
    parser.add_argument(
        "--short",
        action="store_true",
        help="Only output discovered IPs and ASNs, one per line",
    )
    parser.add_argument(
        "--unique",
        action="store_true",
        help="Deduplicate discovered IPs and ASNs before output or lookup",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable colored output",
    )
    args = parser.parse_args(argv)

    include_ipv4, include_ipv6 = include_families(args.ipv4, args.ipv6)
    rules = skip_rules(config)
    ips, asns, resolutions = collect_info_inputs(args.inputs)
    ips = filter_ips(ips, include_ipv4, include_ipv6)
    found_count = len(ips) + len(asns)
    ips = filter_skipped_ips(ips, rules)
    asns = filter_skipped_asns(asns, rules)
    skipped_count = found_count - (len(ips) + len(asns))
    if args.unique:
        ips = unique_items(ips)
        asns = unique_items(asns)
    if not ips and not asns:
        if found_count and rules.any_rules():
            print("all IPs / ASNs were skipped")
            return 0
        parser.error("no IPs or ASNs provided; pass inputs/files/text as arguments or pipe via stdin")

    if args.short:
        for ip in ips:
            print(ip)
        for asn in asns:
            print(asn)
        return 0

    use_color = sys.stdout.isatty() and not args.no_color
    colors = {
        "bold": BOLD if use_color else "",
        "faint": FAINT if use_color else "",
        "reset": RESET if use_color else "",
    }
    sources_by_ip = {}  # type: Dict[str, List[str]]
    for source, resolved in resolutions:
        sources_by_ip.setdefault(resolved, []).append(source)

    exit_code = 0
    output_count = 0
    lookup_skipped_count = 0
    for ip in ips:
        try:
            data = ipinfo_lookup(ip)
            bgp_range = bgp_range_lookup(ip)
            if lookup_info_is_skipped(data, bgp_range, rules):
                lookup_skipped_count += 1
                continue
            if output_count:
                print("")
            for source in sources_by_ip.get(ip, []):
                print("{}{} -> {}{}".format(colors["faint"], source, ip, colors["reset"]))
            print_info(ip, colors, data=data, bgp_range=bgp_range)
            output_count += 1
        except (socket.timeout, OSError, urllib.error.URLError, ValueError) as exc:
            print("error: {}: {}".format(ip, exc), file=sys.stderr)
            exit_code = 1
    for asn in asns:
        try:
            if output_count:
                print("")
            print_asn_info(asn, colors)
            output_count += 1
        except (socket.timeout, OSError, urllib.error.URLError, ValueError) as exc:
            print("error: {}: {}".format(asn, exc), file=sys.stderr)
            exit_code = 1
    skipped_count += lookup_skipped_count
    if output_count == 0 and skipped_count > 0 and exit_code == 0:
        print("all IPs / ASNs were skipped")
        return exit_code
    print_summary(processed=output_count, skipped=skipped_count)
    return exit_code


def asn_prefixes(asn):
    # type: (str) -> List[str]
    """Fetch announced prefixes for an ASN from RIPEstat."""
    normalized = normalize_asn(asn)
    if normalized is None:
        raise ValueError("Invalid ASN: {}".format(asn))

    url = RIPESTAT_PREFIXES_URL.format(urllib.parse.quote(normalized))
    payload = json_lookup(url)
    return [p["prefix"] for p in payload["data"]["prefixes"]]


def classify_prefix(prefix):
    # type: (str) -> Optional[Network]
    """Return an ip_network for the prefix, or None if invalid."""
    try:
        return ipaddress.ip_network(prefix, strict=False)
    except ValueError:
        return None


def clean_target(raw):
    # type: (str) -> str
    """Strip whitespace, surrounding quotes, and trailing commas from an input line."""
    s = raw.strip()
    s = s.rstrip(",").strip()
    if len(s) >= 2 and s[0] == s[-1] and s[0] in ("'", '"'):
        s = s[1:-1].strip()
    return s


def extract_targets(text):
    # type: (str) -> List[str]
    """Pull ASNs, CIDRs, and bare IPs out of arbitrary text."""
    targets = []  # type: List[str]
    for match in TARGET_RE.findall(text):
        target = clean_target(match)
        if not target:
            continue
        if target.upper().startswith("AS"):
            targets.append(target)
            continue
        try:
            if "/" in target:
                ipaddress.ip_network(target, strict=False)
            else:
                ipaddress.ip_address(target)
            targets.append(target)
        except ValueError:
            continue
    return targets


def collect_expand_inputs(inputs):
    # type: (List[str]) -> List[str]
    """Build targets from args, files, arbitrary text, and stdin."""
    targets = []  # type: List[str]
    for item in inputs:
        if os.path.isfile(item):
            targets.extend(extract_targets(read_text_file(item)))
            continue

        extracted = extract_targets(item)
        if extracted:
            targets.extend(extracted)
            continue

        cleaned = clean_target(item)
        if cleaned:
            targets.append(cleaned)

    text = stdin_text()
    if text:
        targets.extend(extract_targets(text))

    return targets


def emit_network(net, include_all, rules):
    # type: (Network, bool, SkipRules) -> Tuple[int, int]
    """Print every address in a network, honoring the include_all flag for IPv4."""
    emitted = 0
    skipped = 0
    if include_all:
        iterator = net
    elif isinstance(net, ipaddress.IPv4Network) and net.prefixlen < 31:
        iterator = net.hosts()
    else:
        iterator = net
    for ip in iterator:
        if ip_is_skipped(str(ip), rules):
            skipped += 1
            continue
        print(ip)
        emitted += 1
    return emitted, skipped


def expand_target(target, include_ipv4, include_ipv6, include_all, rules):
    # type: (str, bool, bool, bool, SkipRules) -> Tuple[int, int]
    """Expand a single CIDR, ASN, or IP target to stdout."""
    if "/" in target:
        net = ipaddress.ip_network(target, strict=False)
        if isinstance(net, ipaddress.IPv4Network) and not include_ipv4:
            return 0, 0
        if isinstance(net, ipaddress.IPv6Network) and not include_ipv6:
            return 0, 0
        return emit_network(net, include_all, rules)

    try:
        ip = ipaddress.ip_address(target)
        if ip_is_skipped(str(ip), rules):
            return 0, 1
        if isinstance(ip, ipaddress.IPv4Address) and include_ipv4:
            print(ip)
            return 1, 0
        elif isinstance(ip, ipaddress.IPv6Address) and include_ipv6:
            print(ip)
            return 1, 0
        return 0, 0
    except ValueError:
        pass

    if asn_is_skipped(target, rules):
        return 0, 1
    emitted = 0
    skipped = 0
    for prefix in asn_prefixes(target):
        net = classify_prefix(prefix)
        if net is None:
            print("error: {}: invalid prefix".format(prefix), file=sys.stderr)
            continue
        if isinstance(net, ipaddress.IPv4Network) and not include_ipv4:
            continue
        if isinstance(net, ipaddress.IPv6Network) and not include_ipv6:
            continue
        net_emitted, net_skipped = emit_network(net, include_all, rules)
        emitted += net_emitted
        skipped += net_skipped
    return emitted, skipped


def run_expand(argv, config):
    # type: (List[str], Config) -> int
    parser = argparse.ArgumentParser(
        prog="iptools expand",
        description="Expand CIDRs, ASNs, and IPs found in input into individual IP addresses.",
    )
    parser.add_argument(
        "inputs",
        nargs="*",
        help="CIDRs, ASNs, IPs, file paths, or arbitrary text containing targets",
    )
    add_family_flags(parser)
    parser.add_argument(
        "--all",
        action="store_true",
        help="Include network/broadcast addresses for IPv4 CIDRs.",
    )
    parser.add_argument(
        "--short",
        action="store_true",
        help="Omit the summary line; output only the expanded IPs",
    )
    args = parser.parse_args(argv)

    include_ipv4, include_ipv6 = include_families(args.ipv4, args.ipv6)
    rules = skip_rules(config)
    targets = collect_expand_inputs(args.inputs)
    if not targets:
        parser.error("no targets provided; pass targets/files/text as arguments or pipe via stdin")

    exit_code = 0
    emitted_count = 0
    skipped_count = 0
    for target in targets:
        try:
            emitted, skipped = expand_target(
                target,
                include_ipv4=include_ipv4,
                include_ipv6=include_ipv6,
                include_all=args.all,
                rules=rules,
            )
            emitted_count += emitted
            skipped_count += skipped
        except (ValueError, urllib.error.URLError, KeyError) as exc:
            print("error: {}: {}".format(target, exc), file=sys.stderr)
            exit_code = 1
    if emitted_count == 0 and skipped_count > 0 and exit_code == 0:
        print("all IPs were skipped")
        return exit_code
    if not args.short:
        print_summary(processed=emitted_count, skipped=skipped_count)
    return exit_code


def collect_condense_inputs(inputs):
    # type: (List[str]) -> List[str]
    """Build a list of IPs from args, files, arbitrary text, and stdin."""
    ips = []  # type: List[str]

    for item in inputs:
        if os.path.isfile(item):
            ips.extend(extract_ips(read_text_file(item)))
            continue

        ips.extend(extract_ips(item))

    text = stdin_text()
    if text:
        ips.extend(extract_ips(text))

    return ips


def cymru_lookup_bulk(ips):
    # type: (List[str]) -> List[LookupResult]
    """Query Team Cymru bulk WHOIS."""
    query = "begin\nverbose\n" + "\n".join(ips) + "\nend\n"
    lines = cymru_query(query)

    results = []  # type: List[LookupResult]
    for line in lines[1:]:
        parts = [p.strip() for p in line.split("|")]
        if len(parts) >= 7:
            asn, _ip, prefix, cc, _, _, name = parts[:7]
            if asn == "NA" or prefix == "NA":
                continue
            results.append((_ip, asn, prefix, cc, name))
    return results


def ripestat_lookup_bulk(ips):
    # type: (List[str]) -> List[LookupResult]
    name_cache = {}  # type: Dict[str, str]
    results_by_ip = {}  # type: Dict[str, LookupResult]
    for ip in unique_items(ips):
        result = ripestat_lookup(ip, name_cache)
        if result:
            results_by_ip[ip] = result
    return [results_by_ip[ip] for ip in ips if ip in results_by_ip]


def lookup_bulk(ips):
    # type: (List[str]) -> List[LookupResult]
    try:
        return cymru_lookup_bulk(ips)
    except (socket.timeout, OSError):
        return ripestat_lookup_bulk(ips)


def selected_sections(args):
    # type: (argparse.Namespace) -> Tuple[bool, bool, bool]
    """Return whether to show IP, ASN, and CIDR sections."""
    show_all = not (args.ip or args.asn or args.cidr)
    return args.ip or show_all, args.asn or show_all, args.cidr or show_all


def print_summary(processed, skipped, leading_blank=True):
    # type: (int, int, bool) -> None
    parts = ["{} processed".format(processed)]
    if skipped:
        parts.append("{} skipped".format(skipped))
    prefix = "\n" if leading_blank else ""
    print("{}{}".format(prefix, ", ".join(parts)))


def run_condense(argv, config):
    # type: (List[str], Config) -> int
    parser = argparse.ArgumentParser(
        prog="iptools condense",
        description="Identify common IPs, ASNs, and CIDR prefixes from a set of IPs.",
    )
    parser.add_argument(
        "inputs",
        nargs="*",
        help="IP addresses, file paths, or arbitrary text containing IPs",
    )
    add_family_flags(parser)
    parser.add_argument(
        "-n", "--top",
        type=int,
        default=None,
        help="Show only the top N entries (default: show all)",
    )
    parser.add_argument(
        "-m", "--min-count",
        type=int,
        default=0,
        metavar="N",
        help="Only show entries with at least N IPs",
    )
    parser.add_argument(
        "--asn",
        action="store_true",
        help="Only output the ASN section",
    )
    parser.add_argument(
        "--ip",
        action="store_true",
        help="Only output the IP address section",
    )
    parser.add_argument(
        "--cidr",
        action="store_true",
        help="Only output the CIDR section",
    )
    parser.add_argument(
        "--short",
        action="store_true",
        help="Output only the IPs, ASNs, or CIDR ranges, one per line (no headers or counts)",
    )
    parser.add_argument(
        "--unique",
        action="store_true",
        help="Deduplicate discovered IPs before lookup",
    )
    args = parser.parse_args(argv)

    include_ipv4, include_ipv6 = include_families(args.ipv4, args.ipv6)
    rules = skip_rules(config)
    ips = collect_condense_inputs(args.inputs)
    ips = filter_ips(ips, include_ipv4, include_ipv6)
    found_count = len(ips)
    ips = filter_skipped_ips(ips, rules)
    skipped_count = found_count - len(ips)
    if args.unique:
        ips = unique_items(ips)
    if not ips:
        if found_count and rules.any_rules():
            print("all IPs were skipped")
            return 0
        parser.error("no IPs provided; pass IPs/files/text as arguments or pipe via stdin")

    show_ip, show_asn, show_cidr = selected_sections(args)

    threshold = args.min_count
    limit = args.top

    def filtered(counter):
        items = counter.most_common(None if limit is None else limit)
        if threshold > 0:
            items = [(k, c) for k, c in items if c >= threshold]
        return items

    results = []  # type: List[LookupResult]
    lookup_skipped_count = 0
    needs_lookup = show_asn or show_cidr or (show_ip and (not args.short or rules.has_lookup_rules()))
    if needs_lookup:
        try:
            lookup_results = lookup_bulk(ips)
        except (socket.timeout, OSError, urllib.error.URLError, ValueError) as exc:
            print("error: lookup: {}".format(exc), file=sys.stderr)
            return 1
        skipped_lookup_ips = set()  # type: Set[str]
        for result in lookup_results:
            if lookup_result_is_skipped(result, rules):
                skipped_lookup_ips.add(result[0])
                continue
            results.append(result)
        lookup_skipped_count = len(lookup_results) - len(results)
        if skipped_lookup_ips:
            before_lookup_skip_count = len(ips)
            ips = [ip for ip in ips if ip not in skipped_lookup_ips]
            skipped_count += before_lookup_skip_count - len(ips)
            if not ips:
                print("all IPs were skipped")
                return 0
        if not show_ip and lookup_skipped_count and not results:
            print("all lookup results were skipped")
            return 0

    ip_counter = Counter(ips)
    ip_lookup_details = {}  # type: Dict[str, Tuple[str, str]]
    for ip, asn, _prefix, _cc, name in results:
        ip_lookup_details[ip] = (asn, name)
    asn_counter = Counter((r[1], r[4]) for r in results)
    cidr_counter = Counter((r[2], r[1], r[4]) for r in results)

    if limit is None:
        scope_label = "all"
    else:
        scope_label = "top {}".format(limit)
    if threshold > 0:
        scope_label += ", >={} IPs".format(threshold)

    if args.short:
        if show_ip:
            for ip, _count in filtered(ip_counter):
                print(ip)
        if show_cidr:
            for (cidr, _asn, _name), _count in filtered(cidr_counter):
                print(cidr)
        if show_asn:
            for (asn, _name), _count in filtered(asn_counter):
                print(format_asn_field(asn))
        return 0

    if show_ip:
        print("\n=== IPs ({}) ===".format(scope_label))
        for ip, count in filtered(ip_counter):
            details = ip_lookup_details.get(ip)
            if details:
                asn, name = details
                print("  {:>5}  {:<20}  {:<10}  {}".format(count, ip, format_asn_field(asn), name))
            else:
                print("  {:>5}  {}".format(count, ip))

    if show_cidr:
        print("\n=== CIDR Prefixes ({}) ===".format(scope_label))
        for (cidr, asn, name), count in filtered(cidr_counter):
            print("  {:>5}  {:<20}  {:<10}  {}".format(count, cidr, format_asn_field(asn), name))

    if show_asn:
        print("\n=== ASNs ({}) ===".format(scope_label))
        for (asn, name), count in filtered(asn_counter):
            print("  {:>5}  {:<10}  {}".format(count, format_asn_field(asn), name))

    print_summary(processed=len(ips), skipped=skipped_count)

    return 0


def print_help():
    # type: () -> None
    print("usage: iptools [global options] <command> [options] [inputs...]")
    print("")
    print("Commands:")
    width = max(len(command) for command in COMMANDS)
    for command in sorted(COMMANDS):
        print("  {:{}}  {}".format(command, width, COMMANDS[command]))
    print("")
    print("Global options:")
    print("  --config PATH  Load this config file after the default config locations.")
    print("  --skip VALUE   Skip this IP, CIDR, or ASN for this run. Repeat as needed.")
    print("  --no-skip      Disable all configured and command-line skips for this run.")
    print("")
    print("Run 'iptools <command> --help' for command-specific options.")


def split_global_args(argv):
    # type: (List[str]) -> Tuple[Optional[str], List[str], bool, List[str]]
    config_path = None  # type: Optional[str]
    skip_targets = []  # type: List[str]
    no_skip = False
    remaining = []  # type: List[str]
    index = 0
    while index < len(argv):
        arg = argv[index]
        if arg == "--config":
            if index + 1 >= len(argv):
                parser = argparse.ArgumentParser(prog="iptools", add_help=False)
                parser.error("--config requires a path")
            config_path = argv[index + 1]
            index += 2
            continue
        if arg.startswith("--config="):
            config_path = arg.split("=", 1)[1]
            index += 1
            continue
        if arg == "--skip":
            if index + 1 >= len(argv):
                parser = argparse.ArgumentParser(prog="iptools", add_help=False)
                parser.error("--skip requires an IP, CIDR, or ASN")
            skip_targets.append(argv[index + 1])
            index += 2
            continue
        if arg.startswith("--skip="):
            skip_targets.append(arg.split("=", 1)[1])
            index += 1
            continue
        if arg == "--no-skip":
            no_skip = True
            index += 1
            continue
        remaining.append(arg)
        index += 1
    return config_path, skip_targets, no_skip, remaining


def main(argv=None):
    # type: (Optional[List[str]]) -> int
    argv = sys.argv[1:] if argv is None else argv
    config_path, cli_skip_targets, no_skip, argv = split_global_args(argv)
    if not argv or argv[0] in ("-h", "--help"):
        print_help()
        return 0
    if no_skip:
        config = Config(skip_public_ip=False, skip_targets=[])
    else:
        config = load_config(default_config_paths() + ([config_path] if config_path else []))
        config.skip_targets.extend(cli_skip_targets)

    command = ALIASES.get(argv[0], argv[0])
    command_args = argv[1:]
    if command == "info":
        return run_info(command_args, config)
    if command == "expand":
        return run_expand(command_args, config)
    if command == "condense":
        return run_condense(command_args, config)

    parser = argparse.ArgumentParser(prog="iptools", add_help=False)
    parser.error("unknown command: {}".format(argv[0]))
    return 2


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""
ftd_to_cp.py  --  Cisco Firepower Threat Defense (ASA-syntax) -> Check Point converter.

Parses a Cisco FTD `show running-config` (Firepower 2110 / FTD 7.2.x / FXOS 2.12.x,
which emits ASA-style configuration) using ciscoconfparse2 and emits one YAML "vars"
file per category, consumed by the matching Ansible playbook:

    vars/1_objects.yml       -> playbooks/1_objects.yml        (cp_mgmt_host / network / address_range / dns_domain)
    vars/2_object_groups.yml -> playbooks/2_object-groups.yml  (cp_mgmt_group)
    vars/3_services.yml      -> playbooks/3_services.yml        (cp_mgmt_service_tcp / udp / service_group)
    vars/4_policy.yml        -> playbooks/4_policy.yml          (cp_mgmt_access_rule)
    vars/5_nat.yml           -> playbooks/5_nat.yml             (cp_mgmt_nat_rule)

Design notes
------------
* Read-only: this script NEVER touches Check Point. It only reads the Cisco config
  and writes YAML. All Check Point changes happen through the Ansible playbooks.
* Inline literals inside groups / ACLs (e.g. `network-object host 10.0.0.1`, or a bare
  `eq https` in an ACL) have no Cisco object name. Check Point groups/rules can only
  reference named objects, so we synthesise deterministic auto-objects (h_10.0.0.1,
  n_10.10.0.0_16, range_..., svc_tcp_443 ...) and add them to the relevant vars file so
  the dependency exists before the group/rule that needs it.
* Anything we cannot translate is not silently dropped: it is recorded under an
  `unsupported:` list in the relevant vars file and printed to stderr so a human reviews it.

Usage:
    python3 ftd_to_cp.py --config ../samples/ftd_running-config.txt --out ../vars
"""

import argparse
import json
import os
import re
import sys
from collections import OrderedDict
from datetime import datetime

import yaml
from ciscoconfparse2 import CiscoConfParse

# ---------------------------------------------------------------------------
# Cisco "well known" port name -> number (the names ASA prints in eq/range).
# Extend as needed; unknown names are passed through verbatim and flagged.
# ---------------------------------------------------------------------------
PORT_NAMES = {
    "ftp-data": 20, "ftp": 21, "ssh": 22, "telnet": 23, "smtp": 25,
    "domain": 53, "tftp": 69, "http": 80, "www": 80, "https": 443,
    "pop3": 110, "nntp": 119, "ntp": 123, "snmp": 161, "snmptrap": 162,
    "bgp": 179, "ldap": 389, "ldaps": 636, "imap4": 143, "isakmp": 500,
    "syslog": 514, "sip": 5060, "rip": 520, "radius": 1812,
    "radius-acct": 1813, "sqlnet": 1521, "h323": 1720, "pptp": 1723,
    "kerberos": 750, "lpd": 515, "nfs": 2049, "sunrpc": 111,
    "netbios-ssn": 139, "netbios-ns": 137, "netbios-dgm": 138,
    "cifs": 3020, "ms-sql": 1433, "rtsp": 554, "discard": 9,
    "echo": 7, "finger": 79, "gopher": 70, "ident": 113,
    "irc": 194, "pim-auto-rp": 496, "uucp": 540, "whois": 43,
    "aol": 5190, "citrix-ica": 1494, "ctiqbe": 2748, "daytime": 13,
    "exec": 512, "klogin": 543, "kshell": 544, "login": 513,
    "secureid-udp": 5510, "talk": 517, "time": 37, "xdmcp": 177,
    "biff": 512, "bootpc": 68, "bootps": 67, "dnsix": 195,
    "mobile-ip": 434, "nameserver": 42, "who": 513,
}

# ---------------------------------------------------------------------------
# Cisco IP-protocol keyword -> protocol number (for `object-group protocol`).
# 'ip' is special-cased to Check Point "Any". Numeric protocol-objects pass
# through as-is. Unknown keywords are flagged for review.
# ---------------------------------------------------------------------------
PROTOCOL_NAMES = {
    "icmp": 1, "igmp": 2, "ggp": 3, "ipinip": 4, "ip-in-ip": 4, "tcp": 6,
    "igrp": 9, "udp": 17, "gre": 47, "esp": 50, "ipsec": 50, "ah": 51,
    "ahp": 51, "icmp6": 58, "ipv6-icmp": 58, "eigrp": 88, "ospf": 89,
    "nos": 94, "pim": 103, "pcp": 108, "snp": 109, "vrrp": 112, "sctp": 132,
}


# Flags whose message contains one of these are "auto-handled (FYI)" -- a safe
# transformation the parser made; everything else is "needs your attention".
HANDLED_MARKERS = ("treated as Any", "rewritten to Any", "mapped to generic ICMP",
                   "reusing Check Point predefined", "not selected for conversion",
                   "no network group created", "renamed to")

_USE_COLOR = sys.stdout.isatty() and not os.environ.get("NO_COLOR")


def c(code, text):
    """Wrap text in an ANSI color/style code when output is a TTY."""
    return f"\033[{code}m{text}\033[0m" if _USE_COLOR else text


class _IndentedDumper(yaml.SafeDumper):
    """YAML dumper that indents block sequences under their key, so the output
    passes yamllint's default `indentation: {indent-sequences: true}` rule."""

    def increase_indent(self, flow=False, indentless=False):
        return super().increase_indent(flow, False)


def warn(msg):
    print("  [warn] " + msg, file=sys.stderr)


# Check Point predefined/reserved object names (case-insensitive) that a migrated
# object/group must not reuse, or the API errors "more than one object named X".
RESERVED_NAMES = {"any", "all", "none", "internet", "all_internet"}

# Check Point predefined service names (lowercased). Migrated services/groups with
# these names are NOT created -- references resolve to the built-in (user chose
# "reuse the built-in"). Extend as collisions are found.
PREDEFINED_SERVICES = {
    "ftp", "ftp_bidir", "ftp-port", "ftp-pasv", "http", "https", "ssh", "telnet",
    "smtp", "pop-3", "pop3", "imap", "nntp", "ntp", "ntp-udp", "snmp", "snmp-trap",
    "ldap", "ldap-udp", "ldap-ssl", "rdp", "kerberos", "kerberos_v5_tcp", "radius",
    "radius-acct", "tacacs", "sip", "sip_any", "h323", "rtsp", "dns", "domain-tcp",
    "domain-udp", "dns_tcp", "dns_udp", "tftp", "syslog", "echo-request", "icmp-proto",
    "netbios-ns", "netbios-dgm", "netbios-ssn", "nbname", "nbdatagram", "nbsession",
    "microsoft-ds", "ms-sql-s", "ms-sql-m", "gre", "esp", "ah", "ospf", "bgp", "rip",
    "pim", "igmp", "vrrp", "sqlnet1", "sqlnet2", "ica", "finger", "gopher", "whois",
    "lpd", "ident", "daytime", "discard", "irc", "uucp", "ica-browsing",
}


def is_predef_service(name):
    """True if name collides with a Check Point predefined service (reuse built-in)."""
    return name.lower() in PREDEFINED_SERVICES


def cp_name(raw):
    """Sanitise a Cisco identifier into a legal Check Point object name.
    Check Point names may not contain spaces and a limited punctuation set;
    we keep [A-Za-z0-9_.-] and replace everything else with '_'. Names that
    collide with a Check Point reserved name (e.g. 'any') get an '_obj' suffix."""
    name = re.sub(r"[^A-Za-z0-9_.\-]", "_", raw.strip())
    if name and name[0].isdigit():
        name = "obj_" + name
    name = name or "obj_unnamed"
    if name.lower() in RESERVED_NAMES:
        name = name + "_obj"
    return name


def dedup(seq):
    """Return list with duplicates removed, preserving order."""
    seen, out = set(), []
    for x in seq:
        if x not in seen:
            seen.add(x)
            out.append(x)
    return out


def mask_to_prefix(mask):
    """Dotted mask -> prefix length. Returns int or None."""
    try:
        return sum(bin(int(o)).count("1") for o in mask.split("."))
    except ValueError:
        return None


def prefix_to_mask(plen):
    """IPv4 prefix length -> dotted mask, e.g. 24 -> 255.255.255.0."""
    plen = int(plen)
    bits = (0xffffffff >> (32 - plen) << (32 - plen)) if plen else 0
    return ".".join(str((bits >> (24 - 8 * i)) & 0xff) for i in range(4))


def resolve_port(token):
    """Map an ASA port token (name or number) to a numeric string. Returns (port_str, ok)."""
    token = token.strip()
    if token.isdigit():
        return token, True
    if token in PORT_NAMES:
        return str(PORT_NAMES[token]), True
    return token, False  # unknown name; pass through, caller flags it


class Converter:
    def __init__(self, config_path):
        self.parse = CiscoConfParse(config_path, syntax="asa")
        # Emitted data buckets ------------------------------------------------
        self.hosts = OrderedDict()        # name -> {ip_address, comments}
        self.networks = OrderedDict()     # name -> {subnet, mask_length, comments}
        self.ranges = OrderedDict()       # name -> {first, last, comments}
        self.fqdns = OrderedDict()        # name -> {fqdn, comments}
        self.net_groups = OrderedDict()   # name -> {members:[], comments}
        self.svc_tcp = OrderedDict()      # name -> {port, comments}
        self.svc_udp = OrderedDict()      # name -> {port, comments}
        self.svc_other = OrderedDict()    # name -> {ip_protocol, comments}
        self.svc_groups = OrderedDict()   # name -> {members:[], comments}
        self.packages = OrderedDict()     # package name -> {comments}  (one per converted ACL)
        self.iface_groups = set()         # net_group names that came from interfaces
        self.selected_acls = None         # None -> default (global ACL); else list of ACL names
        self.global_acl = None            # ACL bound by 'access-group <name> global'
        self.rules = []                   # list of dicts
        self.nat_rules = []               # list of dicts
        self.unsupported = []             # list of strings
        # bookkeeping: which object names are network-ish vs service-ish
        self._known_net = set()
        self._known_svc = set()
        # named objects that are 0.0.0.0/0 -> resolve references to predefined "Any"
        self.any_aliases = set()
        # FQDN objects: Cisco object name -> Check Point dns-domain name (".<fqdn>")
        self.fqdn_aliases = {}
        # service groups equivalent to Any (e.g. contained 'service-object ip')
        self.svc_any_aliases = set()

    def _ref(self, name):
        """Resolve a network-object reference: 0.0.0.0/0 -> 'Any', FQDN object -> its
        dns-domain name (which must start with '.'), else the name unchanged."""
        if name in self.any_aliases:
            return "Any"
        if name in self.fqdn_aliases:
            return self.fqdn_aliases[name]
        return name

    # ---- auto-object helpers (for inline literals) -------------------------
    def _auto_host(self, ip):
        name = cp_name("h_" + ip)
        if name not in self.hosts:
            self.hosts[name] = {"ip_address": ip, "comments": "auto: inline host literal"}
        self._known_net.add(name)
        return name

    def _auto_network(self, subnet, mask):
        plen = mask_to_prefix(mask)
        if plen == 0:
            return "Any"   # 0.0.0.0/0 == Check Point predefined "Any"
        name = cp_name(f"n_{subnet}_{plen if plen is not None else mask}")
        if name not in self.networks:
            self.networks[name] = {"subnet": subnet, "mask_length": plen,
                                   "comments": "auto: inline network literal"}
        self._known_net.add(name)
        return name

    def _auto_network6(self, addr, plen):
        """Inline IPv6 network literal -> cp_mgmt_network (subnet + mask_length, IPv6)."""
        name = cp_name(f"n6_{addr}_{plen}")
        if name not in self.networks:
            self.networks[name] = {"subnet": addr, "mask_length": int(plen),
                                   "comments": "auto: inline IPv6 network literal"}
        self._known_net.add(name)
        return name

    def _auto_range(self, first, last):
        name = cp_name(f"range_{first}_{last}")
        if name not in self.ranges:
            self.ranges[name] = {"first": first, "last": last,
                                 "comments": "auto: inline range literal"}
        self._known_net.add(name)
        return name

    def _auto_protocol(self, token):
        """Map a Cisco protocol-object token to a Check Point member name.
        Returns a member name, or None if unknown (caller flags it).
        'ip' -> 'Any'; named/numeric IP protocols -> a service-other object."""
        token = token.strip().lower()
        if token == "ip":
            return "Any"
        if token.isdigit():
            num = int(token)
            name = cp_name(f"proto_{num}")
        elif token in PROTOCOL_NAMES:
            num = PROTOCOL_NAMES[token]
            name = cp_name(f"proto_{token}")
        else:
            return None
        if name not in self.svc_other:
            self.svc_other[name] = {"ip_protocol": num,
                                    "comments": f"auto: IP protocol {num} ({token})"}
        self._known_svc.add(name)
        return name

    def _auto_service(self, proto, port):
        port_str, ok = resolve_port(port)
        name = cp_name(f"svc_{proto}_{port_str}")
        bucket = self.svc_tcp if proto == "tcp" else self.svc_udp
        if name not in bucket:
            bucket[name] = {"port": port_str, "comments": "auto: inline service literal"}
            if not ok:
                self.unsupported.append(f"service {proto} port name '{port}' not in port map "
                                        f"(auto object {name}); verify port number")
        self._known_svc.add(name)
        return name

    # ======================================================================
    # 1. NETWORK OBJECTS  -> objects.yml
    # ======================================================================
    def parse_network_objects(self):
        for obj in self.parse.find_objects(r"^object network "):
            name = cp_name(obj.text.split("object network ", 1)[1])
            self._known_net.add(name)
            comments = ""
            for child in obj.children:
                t = child.text.strip()
                if t.startswith("description "):
                    comments = t.split("description ", 1)[1]
            for child in obj.children:
                t = child.text.strip()
                if t.startswith("host "):
                    self.hosts[name] = {"ip_address": t.split()[1], "comments": comments}
                elif t.startswith("subnet "):
                    parts = t.split()
                    if len(parts) == 2 and "/" in parts[1]:        # IPv6: 'subnet 2001:db8::/64'
                        addr, plen = parts[1].split("/", 1)
                        if plen == "0":
                            self.any_aliases.add(name)
                        else:
                            self.networks[name] = {"subnet": addr, "mask_length": int(plen),
                                                   "comments": comments}
                    elif len(parts) >= 3:                          # IPv4: 'subnet a.b.c.d mask'
                        subnet, mask = parts[1], parts[2]
                        if mask_to_prefix(mask) == 0:
                            self.any_aliases.add(name)             # 0.0.0.0/0 == "Any"
                        else:
                            self.networks[name] = {"subnet": subnet,
                                                   "mask_length": mask_to_prefix(mask),
                                                   "comments": comments}
                    else:
                        self.unsupported.append(f"object network: cannot parse '{t}'")
                elif t.startswith("range "):
                    _, first, last = t.split()[:3]
                    self.ranges[name] = {"first": first, "last": last, "comments": comments}
                elif t.startswith("fqdn"):
                    # 'fqdn [v4|v6|dynamic] <domain> [id <n>]'  (FDM appends 'id <n>')
                    parts = t.split()
                    i = 2 if len(parts) > 1 and parts[1] in ("v4", "v6", "dynamic") else 1
                    fqdn = parts[i] if len(parts) > i else ""
                    if "id" in parts:                       # drop trailing 'id <n>'
                        j = parts.index("id")
                        if i >= j:
                            fqdn = ""
                    if fqdn and not re.fullmatch(r"\d+", fqdn):
                        domain = fqdn if fqdn.startswith(".") else "." + fqdn
                        self.fqdns[name] = {"fqdn": fqdn, "comments": comments}
                        self.fqdn_aliases[name] = domain    # references -> dns-domain name
                    else:
                        self.unsupported.append(
                            f"object network: could not extract FQDN from '{t}'")

    # ======================================================================
    # 2. SERVICE OBJECTS  -> services.yml
    # ======================================================================
    def parse_service_objects(self):
        for obj in self.parse.find_objects(r"^object service "):
            name = cp_name(obj.text.split("object service ", 1)[1])
            comments = ""
            for child in obj.children:
                if child.text.strip().startswith("description "):
                    comments = child.text.strip().split("description ", 1)[1]
            for child in obj.children:
                t = child.text.strip()
                # service tcp|udp destination eq PORT   (also 'source', 'range')
                m = re.match(r"service (tcp|udp)\s+(.*)$", t)
                if not m:
                    if t.startswith("service "):
                        self.unsupported.append(
                            f"object service {name}: '{t}' (non tcp/udp protocol)")
                    continue
                proto, rest = m.group(1), m.group(2)
                self._known_svc.add(name)
                pm = re.search(r"destination (eq|range)\s+(\S+)(?:\s+(\S+))?", rest)
                bucket = self.svc_tcp if proto == "tcp" else self.svc_udp
                if pm and pm.group(1) == "eq":
                    port_str, ok = resolve_port(pm.group(2))
                    bucket[name] = {"port": port_str, "comments": comments}
                    if not ok:
                        self.unsupported.append(f"service {name}: port name "
                                                f"'{pm.group(2)}' not mapped")
                elif pm and pm.group(1) == "range":
                    p1, _ = resolve_port(pm.group(2))
                    p2, _ = resolve_port(pm.group(3))
                    bucket[name] = {"port": f"{p1}-{p2}", "comments": comments}
                else:
                    self.unsupported.append(
                        f"object service {name}: '{t}' (only destination eq/range supported)")

    # ======================================================================
    # 3. NETWORK OBJECT-GROUPS  -> object_groups.yml
    # ======================================================================
    def parse_network_groups(self):
        for obj in self.parse.find_objects(r"^object-group network "):
            name = cp_name(obj.text.split("object-group network ", 1)[1])
            members, comments = [], ""
            for child in obj.children:
                t = child.text.strip()
                if t.startswith("description "):
                    comments = t.split("description ", 1)[1]
                    continue
                if t.startswith("network-object object "):
                    members.append(self._ref(cp_name(t.split("network-object object ", 1)[1])))
                elif t.startswith("group-object "):
                    members.append(cp_name(t.split("group-object ", 1)[1]))
                elif t.startswith("network-object host "):
                    members.append(self._auto_host(t.split()[2]))
                elif t.startswith("network-object range "):
                    parts = t.split()
                    members.append(self._auto_range(parts[2], parts[3]))
                elif t.startswith("network-object "):
                    parts = t.split()
                    tok = parts[1]
                    if "/" in tok and tok.split("/", 1)[1] == "0":
                        members.append("Any")                 # ::/0 or 0.0.0.0/0 == Any
                    elif ":" in tok and "/" in tok:           # IPv6 CIDR
                        addr, plen = tok.split("/", 1)
                        members.append(self._auto_network6(addr, plen))
                    elif ":" in tok:                          # bare IPv6 host
                        members.append(self._auto_host(tok))
                    elif "/" in tok:                          # IPv4 CIDR (a.b.c.d/n)
                        addr, plen = tok.split("/", 1)
                        members.append(self._auto_network(addr, prefix_to_mask(plen)))
                    elif len(parts) >= 3 and re.match(r"\d+\.\d+\.\d+\.\d+", tok):
                        members.append(self._auto_network(tok, parts[2]))  # 'a.b.c.d mask'
                    else:
                        self.unsupported.append(f"group {name}: cannot parse '{t}'")
                else:
                    self.unsupported.append(f"group {name}: cannot parse '{t}'")
            self.net_groups[name] = {"members": members, "comments": comments}

    # ======================================================================
    # 4. SERVICE OBJECT-GROUPS / PROTOCOL GROUPS -> services.yml
    # ======================================================================
    def parse_service_groups(self):
        for obj in self.parse.find_objects(r"^object-group service "):
            header = obj.text.split("object-group service ", 1)[1].split()
            name = cp_name(header[0])
            proto_hint = header[1] if len(header) > 1 else None  # tcp|udp|tcp-udp
            members, comments = [], ""
            for child in obj.children:
                t = child.text.strip()
                if t.startswith("description "):
                    comments = t.split("description ", 1)[1]
                    continue
                # port-object eq PORT  /  port-object range A B   (proto from header)
                m = re.match(r"port-object (eq|range)\s+(\S+)(?:\s+(\S+))?", t)
                if m:
                    protos = ["tcp", "udp"] if proto_hint == "tcp-udp" else [proto_hint or "tcp"]
                    for proto in protos:
                        if m.group(1) == "eq":
                            members.append(self._auto_service(proto, m.group(2)))
                        else:
                            p1, _ = resolve_port(m.group(2))
                            p2, _ = resolve_port(m.group(3))
                            sname = cp_name(f"svc_{proto}_{p1}_{p2}")
                            bucket = self.svc_tcp if proto == "tcp" else self.svc_udp
                            bucket.setdefault(sname, {"port": f"{p1}-{p2}",
                                                      "comments": "auto: port range"})
                            members.append(sname)
                    continue
                # service-object tcp|udp destination eq PORT
                m = re.match(r"service-object (tcp|udp)\s+destination (eq|range)\s+(\S+)(?:\s+(\S+))?", t)
                if m:
                    proto = m.group(1)
                    if m.group(2) == "eq":
                        members.append(self._auto_service(proto, m.group(3)))
                    else:
                        p1, _ = resolve_port(m.group(3))
                        p2, _ = resolve_port(m.group(4))
                        sname = cp_name(f"svc_{proto}_{p1}_{p2}")
                        bucket = self.svc_tcp if proto == "tcp" else self.svc_udp
                        bucket.setdefault(sname, {"port": f"{p1}-{p2}", "comments": "auto"})
                        members.append(sname)
                    continue
                # service-object object NAME
                if t.startswith("service-object object "):
                    members.append(cp_name(t.split("service-object object ", 1)[1]))
                    continue
                if t.startswith("group-object "):
                    members.append(cp_name(t.split("group-object ", 1)[1]))
                    continue
                # service-object <protocol>  (no port): ip -> Any, icmp/esp/gre/.. -> service-other
                m = re.match(r"service-object (\S+)$", t)
                if m:
                    member = self._auto_protocol(m.group(1))
                    if member:
                        members.append(member)
                    else:
                        self.unsupported.append(
                            f"service-group {name}: unsupported 'service-object {m.group(1)}'")
                    continue
                self.unsupported.append(f"service-group {name}: cannot parse '{t}'")
            self.svc_groups[name] = {"members": members, "comments": comments}

        # protocol groups -> Check Point service group of service-other objects.
        for obj in self.parse.find_objects(r"^object-group protocol "):
            name = cp_name(obj.text.split("object-group protocol ", 1)[1])
            members, comments = [], ""
            for child in obj.children:
                t = child.text.strip()
                if t.startswith("description "):
                    comments = t.split("description ", 1)[1]
                    continue
                if t.startswith("protocol-object "):
                    proto = t.split("protocol-object ", 1)[1].strip()
                    member = self._auto_protocol(proto)
                    if member:
                        members.append(member)
                    else:
                        self.unsupported.append(f"object-group protocol {name}: unknown "
                                                f"protocol '{proto}' (not in protocol map)")
                else:
                    self.unsupported.append(f"object-group protocol {name}: cannot parse '{t}'")
            self.svc_groups[name] = {"members": members, "comments": comments}

        # icmp-type groups -> service group with the ICMP service-other (ip_protocol 1).
        # Per-type granularity (echo, unreachable, ...) is NOT preserved; flagged below.
        for obj in self.parse.find_objects(r"^object-group icmp-type "):
            name = cp_name(obj.text.split("object-group icmp-type ", 1)[1])
            comments = ""
            types = []
            for child in obj.children:
                t = child.text.strip()
                if t.startswith("description "):
                    comments = t.split("description ", 1)[1]
                elif t.startswith("icmp-object "):
                    types.append(t.split("icmp-object ", 1)[1].strip())
            self.svc_groups[name] = {"members": [self._auto_protocol("icmp")],
                                     "comments": comments}
            self.unsupported.append(
                f"object-group icmp-type {name}: mapped to generic ICMP (types "
                f"{', '.join(types) or 'none'} not preserved); review if type granularity needed")

    # ======================================================================
    # 5. ACCESS-LISTS  -> policy.yml
    # ======================================================================
    def _resolve_addr_tokens(self, tokens):
        """Consume leading address tokens from an ACL, return (list_of_cp_objs, remaining)."""
        if not tokens:
            return ["Any"], tokens
        head = tokens[0]
        if head in ("any", "any4", "any6"):
            return ["Any"], tokens[1:]
        if head == "object":
            return [self._ref(cp_name(tokens[1]))], tokens[2:]
        if head == "object-group":
            return [cp_name(tokens[1])], tokens[2:]
        if head == "host":
            return [self._auto_host(tokens[1])], tokens[2:]
        if head == "interface":
            self.unsupported.append(
                f"acl: 'interface {tokens[1]}' used as an address -> mapped to Any; "
                f"set to that gateway interface's IP object if needed")
            return ["Any"], tokens[2:]
        # a.b.c.d  m.m.m.m  (IPv4 subnet + mask)
        if re.match(r"^\d+\.\d+\.\d+\.\d+$", head) and len(tokens) > 1 and \
           re.match(r"^\d+\.\d+\.\d+\.\d+$", tokens[1]):
            if mask_to_prefix(tokens[1]) == 0:
                return ["Any"], tokens[2:]
            return [self._auto_network(head, tokens[1])], tokens[2:]
        # CIDR (IPv4 or IPv6)  a.b.c.d/n  or  2001:db8::/n  or ::/0
        if "/" in head:
            addr, plen = head.split("/", 1)
            if plen == "0":
                return ["Any"], tokens[1:]
            if ":" in addr:
                return [self._auto_network6(addr, plen)], tokens[1:]
            return [self._auto_network(addr, prefix_to_mask(plen))], tokens[1:]
        if ":" in head:                       # bare IPv6 host
            return [self._auto_host(head)], tokens[1:]
        return ["Any"], tokens[1:]             # fallback

    def _consume_ports(self, proto, tokens):
        """If tokens begin a tcp/udp port spec, consume it and return
        (service_names, remaining). Returns (None, tokens) when no port spec."""
        if proto not in ("tcp", "udp") or not tokens:
            return None, tokens
        h = tokens[0]
        bucket = self.svc_tcp if proto == "tcp" else self.svc_udp
        if h == "eq" and len(tokens) > 1:
            return [self._auto_service(proto, tokens[1])], tokens[2:]
        if h == "range" and len(tokens) > 2:
            p1, _ = resolve_port(tokens[1])
            p2, _ = resolve_port(tokens[2])
            sname = cp_name(f"svc_{proto}_{p1}_{p2}")
            bucket.setdefault(sname, {"port": f"{p1}-{p2}", "comments": "auto: port range"})
            return [sname], tokens[3:]
        if h in ("lt", "gt") and len(tokens) > 1:
            p, _ = resolve_port(tokens[1])
            if p.isdigit():
                rng = f"1-{int(p) - 1}" if h == "lt" else f"{int(p) + 1}-65535"
                sname = cp_name(f"svc_{proto}_{h}_{p}")
                bucket.setdefault(sname, {"port": rng, "comments": f"auto: {h} {p}"})
                return [sname], tokens[2:]
            self.unsupported.append(f"acl: port '{h} {tokens[1]}' not numeric; review")
            return [], tokens[2:]
        if h == "neq" and len(tokens) > 1:
            self.unsupported.append(
                f"acl: 'neq {tokens[1]}' port not representable as one CP service; review")
            return [], tokens[2:]
        if h == "object-group" and len(tokens) > 1 and cp_name(tokens[1]) in self.svc_groups:
            return [cp_name(tokens[1])], tokens[2:]
        if h == "object" and len(tokens) > 1 and cp_name(tokens[1]) in self._known_svc:
            return [cp_name(tokens[1])], tokens[2:]
        return None, tokens

    def _consume_ifc(self, tokens):
        """Consume a leading 'ifc <zone>' interface qualifier -> (zone_name|None, rest)."""
        if len(tokens) >= 2 and tokens[0] == "ifc":
            return cp_name(tokens[1]), tokens[2:]
        return None, tokens

    def parse_access_lists(self):
        # bindings + which ACL is bound globally
        binding = {}
        self.global_acl = None
        for ag in self.parse.find_objects(r"^access-group "):
            parts = ag.text.split()
            if len(parts) >= 3 and parts[2] == "global":
                self.global_acl = parts[1]
                binding[parts[1]] = "global"
            elif len(parts) >= 2:
                binding[parts[1]] = " ".join(parts[2:])

        ace_re = r"^access-list \S+ (?:extended|advanced) "
        all_acls = []
        for a in self.parse.find_objects(ace_re):
            nm = a.text.split()[1]
            if nm not in all_acls:
                all_acls.append(nm)

        # selection: explicit list -> else the global ACL -> else everything
        if self.selected_acls:
            targets = [a for a in self.selected_acls if a in all_acls]
            for m in (set(self.selected_acls) - set(all_acls)):
                self.unsupported.append(f"selected ACL '{m}' not found in config; skipped")
        elif self.global_acl:
            targets = [self.global_acl]
        else:
            targets = list(all_acls)
        for a in all_acls:
            if a not in targets:
                self.unsupported.append(
                    f"ACL '{a}' not selected for conversion (skipped); pass --acls to include it")

        # remark text per rule-id (FTD: 'remark rule-id N: <ACCESS/L7 RULE>: name')
        remarks = {}
        for r in self.parse.find_objects(r"^access-list \S+ remark "):
            m = re.search(r"rule-id (\d+):\s*(.*)$", r.text)
            if m:
                remarks[m.group(1)] = m.group(2).strip()

        counters = {}
        for acl in self.parse.find_objects(ace_re):
            toks = acl.text.split()
            if len(toks) < 5:
                continue
            aclname = toks[1]
            if aclname not in targets:
                continue
            # A single malformed/unsupported ACE must never abort the whole parse
            # (real FMC rulebases have hundreds of lines and constructs this parser
            # may not know -- user/identity, security-group, fqdn-in-ACL, etc.).
            # Flag it as needs-attention and keep going so the rest still convert.
            try:
                self._parse_ace(acl, toks, aclname, binding, remarks, counters)
            except Exception as exc:  # noqa: BLE001 - any parse failure is non-fatal
                self.unsupported.append(
                    f"acl {aclname}: could not parse rule "
                    f"'{acl.text.strip()[:90]}' ({type(exc).__name__}: {exc}); skipped, review")

    def _parse_ace(self, acl, toks, aclname, binding, remarks, counters):
        """Convert one matched 'access-list ... extended|advanced ...' line into a
        rule dict appended to self.rules. Raises on unexpected token shapes; the
        caller treats any exception as a non-fatal 'needs attention' flag."""
        action_word = toks[3]
        proto = toks[4]
        rest = toks[5:]
        inactive = "inactive" in toks
        rule_id = toks[toks.index("rule-id") + 1] if "rule-id" in toks else None

        # protocol given as a service object/group:  'permit object-group SVC ...'
        svc_from_proto = None
        if proto in ("object", "object-group") and rest:
            svc_from_proto = [cp_name(rest[0])]
            rest = rest[1:]

        szone, rest = self._consume_ifc(rest)        # source 'ifc <zone>'
        src, rest = self._resolve_addr_tokens(rest)
        sp, rest = self._consume_ports(proto, rest)  # optional source port
        if sp:
            self.unsupported.append(
                f"acl {aclname}: source-port match not represented in CP service; review")
        dzone, rest = self._consume_ifc(rest)        # destination 'ifc <zone>'
        dst, rest = self._resolve_addr_tokens(rest)
        svc, rest = self._consume_ports(proto, rest)  # optional destination port

        if svc_from_proto is not None:
            svc = svc_from_proto
        elif svc is None:
            if proto in ("icmp", "icmp6"):
                svc = ["icmp-proto"]
            elif proto in ("ip", "tcp", "udp"):
                svc = ["Any"]
            else:
                # named/numeric IP protocol (gre, ipinip, esp, 41, ...) -> service-other
                member = self._auto_protocol(proto)
                if member:
                    svc = [member]
                else:
                    svc = ["Any"]
                    self.unsupported.append(
                        f"acl {aclname}: unknown protocol '{proto}' -> Any; review")

        # interface (ifc) qualifiers are NOT wired into the rule (no zones in
        # the rulebase); they're recorded in the comment for reference.
        source = dedup(src)
        destination = dedup(dst)
        ifc_note = ""
        if szone or dzone:
            ifc_note = f" [ifc {szone or 'any'} -> {dzone or 'any'}]"

        if any(t in ("object", "object-group", "ifc") for t in rest):
            self.unsupported.append(
                f"acl {aclname} rule-id {rule_id}: unparsed tokens '{' '.join(rest)}'; review")
        if "time-range" in toks:
            self.unsupported.append(f"acl {aclname}: time-range not migrated; review")

        package = cp_name(aclname)
        self.packages[package] = {"comments": f"from Cisco ACL {aclname} "
                                              f"({binding.get(aclname, 'unbound')})"}
        counters[aclname] = counters.get(aclname, 0) + 1
        note = f"from {aclname}"
        if rule_id:
            note += f" rule-id {rule_id}"
            if rule_id in remarks:
                note += f" [{remarks[rule_id]}]"
        note += ifc_note
        if inactive:
            note += " [inactive]"
        self.rules.append({
            "acl": aclname,
            "package": package,
            "layer": f"{package} Network",
            "name": f"{package}-{counters[aclname]}",
            "action": "Accept" if action_word == "permit" else "Drop",
            "source": source,
            "destination": destination,
            "service": svc,
            "enabled": not inactive,
            "comments": note,
        })

    # ======================================================================
    # 6. NAT  -> nat.yml
    # ======================================================================
    def parse_nat(self):
        # --- Object (auto) NAT: 'nat (real,mapped) static|dynamic ...' under object network
        for obj in self.parse.find_objects(r"^object network "):
            oname = cp_name(obj.text.split("object network ", 1)[1])
            for child in obj.children:
                t = child.text.strip()
                m = re.match(r"nat \((\S+?),(\S+?)\) (static|dynamic) (\S+)", t)
                if not m:
                    continue
                real_if, mapped_if, kind, mapped = m.group(1), m.group(2), m.group(3), m.group(4)
                rule = {
                    "name": f"objnat-{oname}",
                    "type": "object",
                    "original_source": oname,
                    "comments": f"object NAT ({real_if},{mapped_if}) {kind} {mapped}",
                    "enabled": True,
                }
                if kind == "static":
                    rule["method"] = "static"
                    rule["translated_source"] = cp_name(mapped)
                else:  # dynamic
                    rule["method"] = "hide"
                    if mapped == "interface":
                        rule["translated_source"] = "interface"   # hide behind gateway IP
                        rule["hide_behind"] = "gateway"
                    else:
                        rule["translated_source"] = cp_name(mapped)
                self.nat_rules.append(rule)

        # --- Manual / twice NAT: top-level 'nat (real,mapped) source ...'
        for nat in self.parse.find_objects(r"^nat \("):
            t = nat.text.strip()
            # Tolerate position/section keywords (after-auto, after-object, line N) between
            # the interface pair and 'source', and ignore trailing flags (no-proxy-arp,
            # route-lookup, dns, inactive, unidirectional, description ...).
            m = re.match(r"nat \((\S+?),(\S+?)\)(?:\s+(?:after-auto|after-object|inactive))?"
                         r"(?:\s+line\s+\d+)? source (static|dynamic) (\S+) (\S+)"
                         r"(?: destination static (\S+) (\S+))?(?: service (\S+) (\S+))?", t)
            if not m:
                self.unsupported.append(f"manual NAT not parsed: '{t}'")
                continue
            real_if, mapped_if, kind = m.group(1), m.group(2), m.group(3)
            real_src, mapped_src = m.group(4), m.group(5)
            rule = {
                "name": f"manualnat-{cp_name(real_src)}-{cp_name(mapped_src)}",
                "type": "manual",
                "method": "static" if kind == "static" else "hide",
                "original_source": "Any" if real_src == "any" else cp_name(real_src),
                "comments": f"manual NAT ({real_if},{mapped_if}) source {kind}",
                "enabled": True,
            }
            if kind == "dynamic" and mapped_src == "interface":
                rule["translated_source"] = "interface"
                rule["hide_behind"] = "gateway"
            elif mapped_src != real_src:                 # real translation
                rule["translated_source"] = cp_name(mapped_src)
            # else identity (no translation) -> omit translated_source entirely
            if m.group(6):  # destination static REAL MAPPED
                rule["original_destination"] = cp_name(m.group(6))
                if m.group(7) != m.group(6):
                    rule["translated_destination"] = cp_name(m.group(7))
            if m.group(8):  # service REAL MAPPED
                rule["original_service"] = cp_name(m.group(8))
                if m.group(9) != m.group(8):
                    rule["translated_service"] = cp_name(m.group(9))
            self.nat_rules.append(rule)

    # ======================================================================
    # ======================================================================
    # 7. INTERFACES -> network groups (named after nameif)
    # ======================================================================
    def parse_interfaces(self):
        """Each Cisco interface 'nameif' becomes a Check Point network GROUP named
        after the nameif, containing the interface's directly-connected network
        (from 'ip address'). Created for grouping/reference; NOT wired into rules
        (most deployments don't use the interface dimension in the rulebase)."""
        for obj in self.parse.find_objects(r"^interface "):
            nameif = seclevel = ip = mask = None
            for c in obj.children:
                ct = c.text.strip()
                if ct.startswith("nameif "):
                    nameif = ct.split("nameif ", 1)[1].strip()
                elif ct.startswith("security-level "):
                    seclevel = ct.split("security-level ", 1)[1].strip()
                elif ct.startswith("ip address "):
                    p = ct.split()
                    if len(p) >= 4 and re.match(r"\d+\.\d+\.\d+\.\d+", p[2]):
                        ip, mask = p[2], p[3]
            if not nameif:
                continue
            hw = obj.text.split("interface ", 1)[1].strip()
            note = f"from Cisco interface {hw} (nameif {nameif})"
            if seclevel is not None:
                note += f", security-level {seclevel}"
            if not (ip and mask):
                # No IPv4 (e.g. diagnostic / port-channel parent) -> skip; nothing to group.
                self.unsupported.append(
                    f"interface '{nameif}': no IPv4 address -> no network group created (skipped)")
                continue
            # Group is named after the nameif (e.g. 'inside', 'outside').
            gname = cp_name(nameif)
            self.net_groups[gname] = {"members": [self._auto_network(ip, mask)], "comments": note}
            self.iface_groups.add(gname)

    def _resolve_any_groups(self):
        """Check Point's predefined 'Any' cannot be a group member. A group that
        ended up containing 'Any' (from 0.0.0.0/0 or service-object ip) is therefore
        equivalent to Any: drop the group and rewrite every reference to it to 'Any'.
        Iterates to a fixpoint so groups-of-any-groups collapse too."""
        # --- network groups ---
        changed = True
        while changed:
            changed = False
            for n, v in list(self.net_groups.items()):
                if n in self.any_aliases:
                    continue
                v["members"] = [("Any" if m in self.any_aliases else m) for m in v["members"]]
                if "Any" in v["members"]:
                    self.any_aliases.add(n)
                    self.unsupported.append(
                        f"network group {n}: contains 0.0.0.0/0 -> treated as Any "
                        f"('Any' can't be a group member); references rewritten to Any")
                    changed = True
        for n in self.any_aliases:
            self.net_groups.pop(n, None)
        for v in self.net_groups.values():
            v["members"] = dedup(["Any" if m in self.any_aliases else m for m in v["members"]])
        for r in self.rules:
            r["source"] = dedup(["Any" if x in self.any_aliases else x for x in r["source"]])
            r["destination"] = dedup(["Any" if x in self.any_aliases else x for x in r["destination"]])
        for r in self.nat_rules:
            for k in ("original_source", "original_destination",
                      "translated_source", "translated_destination"):
                if r.get(k) in self.any_aliases:
                    r[k] = "Any"

        # --- service groups ---
        changed = True
        while changed:
            changed = False
            for n, v in list(self.svc_groups.items()):
                if n in self.svc_any_aliases:
                    continue
                v["members"] = [("Any" if m in self.svc_any_aliases else m) for m in v["members"]]
                if "Any" in v["members"]:
                    self.svc_any_aliases.add(n)
                    self.unsupported.append(
                        f"service group {n}: contains 'ip'/Any -> treated as Any service; "
                        f"references rewritten to Any")
                    changed = True
        for n in self.svc_any_aliases:
            self.svc_groups.pop(n, None)
        for v in self.svc_groups.values():
            v["members"] = dedup(["Any" if m in self.svc_any_aliases else m for m in v["members"]])
        for r in self.rules:
            r["service"] = dedup(["Any" if x in self.svc_any_aliases else x for x in r["service"]])

    def _check_references(self):
        """Flag references to objects that were never created (parser gap or a
        reference undefined in the config). Dangling group MEMBERS are dropped so
        the group still imports; dangling rule/NAT references are flagged only."""
        known = (set(self.hosts) | set(self.networks) | set(self.ranges)
                 | set(self.svc_tcp) | set(self.svc_udp)
                 | set(self.svc_other) | set(self.net_groups) | set(self.svc_groups))
        known |= {(v["fqdn"] if v["fqdn"].startswith(".") else "." + v["fqdn"])
                  for v in self.fqdns.values()}
        predefined = {"Any", "Original", "interface", "icmp-proto"}
        valid = known | predefined

        for n, v in self.net_groups.items():
            kept = []
            for m in v["members"]:
                if m in valid or is_predef_service(m):
                    kept.append(m)
                else:
                    self.unsupported.append(
                        f"network group {n}: member '{m}' is not defined in the config "
                        f"(dropped from group); define the object or fix the source name")
            v["members"] = kept
        for n, v in self.svc_groups.items():
            kept = []
            for m in v["members"]:
                if m in valid or is_predef_service(m):
                    kept.append(m)
                else:
                    self.unsupported.append(
                        f"service group {n}: member '{m}' is not defined (dropped from group)")
            v["members"] = kept
        for r in self.rules:
            for fld in ("source", "destination", "service"):
                for x in r[fld]:
                    if x not in valid and not is_predef_service(x):
                        self.unsupported.append(
                            f"access rule {r['name']}: undefined object '{x}' in {fld} "
                            f"(rule will fail to import until it exists)")
        for r in self.nat_rules:
            for k in ("original_source", "original_destination", "original_service",
                      "translated_source", "translated_destination", "translated_service"):
                x = r.get(k)
                if x and x not in valid and not is_predef_service(x):
                    self.unsupported.append(
                        f"nat rule {r['name']}: undefined object '{x}' in {k}")

    def run(self):
        self.parse_interfaces()
        self.parse_network_objects()
        self.parse_service_objects()
        self.parse_network_groups()
        self.parse_service_groups()
        self.parse_access_lists()
        self.parse_nat()
        self._resolve_any_groups()
        self._check_references()

    # ---- YAML emit ---------------------------------------------------------
    def _dump(self, out_dir, fname, data):
        path = os.path.join(out_dir, fname)
        with open(path, "w") as fh:
            fh.write("---\n")
            fh.write("# AUTO-GENERATED by ftd_to_cp.py -- do not edit by hand.\n")
            fh.write("# Re-run the parser to regenerate. Review before applying.\n")
            yaml.dump(data, fh, Dumper=_IndentedDumper, default_flow_style=False,
                      sort_keys=False, width=4096, allow_unicode=True)
        return path

    def emit(self, out_dir):
        os.makedirs(out_dir, exist_ok=True)

        objects = {
            "cp_hosts": [dict(name=n, **v) for n, v in self.hosts.items()],
            "cp_networks": [dict(name=n, **v) for n, v in self.networks.items()],
            "cp_address_ranges": [dict(name=n, ip_address_first=v["first"],
                                       ip_address_last=v["last"], comments=v["comments"])
                                  for n, v in self.ranges.items()],
            "cp_dns_domains": self._dns_domain_list(),
        }
        groups = {"cp_network_groups": [dict(name=n, members=dedup(v["members"]),
                                             comments=v["comments"])
                                        for n, v in self.net_groups.items()]}
        # Services/groups named like a Check Point predefined are NOT created
        # (references resolve to the built-in). Flag each as auto-handled.
        for n in set(list(self.svc_tcp) + list(self.svc_udp)
                     + list(self.svc_other) + list(self.svc_groups)):
            if is_predef_service(n):
                self.unsupported.append(
                    f"service '{n}': reusing Check Point predefined (not created)")
        services = {
            "cp_services_tcp": [dict(name=n, **v) for n, v in self.svc_tcp.items()
                                if not is_predef_service(n)],
            "cp_services_udp": [dict(name=n, **v) for n, v in self.svc_udp.items()
                                if not is_predef_service(n)],
            "cp_services_other": [dict(name=n, **v) for n, v in self.svc_other.items()
                                  if not is_predef_service(n)],
            "cp_service_groups": [dict(name=n, members=dedup(v["members"]), comments=v["comments"])
                                  for n, v in self.svc_groups.items() if not is_predef_service(n)],
        }
        policy = {
            "cp_packages": [dict(name=n, comments=v["comments"]) for n, v in self.packages.items()],
            "cp_access_rules": self.rules,
        }
        nat = {"cp_nat_rules": self.nat_rules}

        written = [
            self._dump(out_dir, "1_objects.yml", objects),
            self._dump(out_dir, "2_object_groups.yml", groups),
            self._dump(out_dir, "3_services.yml", services),
            self._dump(out_dir, "4_policy.yml", policy),
            self._dump(out_dir, "5_nat.yml", nat),
        ]
        return written, objects, groups, services, policy, nat

    def _dns_domain_list(self):
        """Build cp_dns_domains, de-duplicated by domain name (many FTD FQDN
        objects can resolve to the same domain)."""
        seen, out = set(), []
        for v in self.fqdns.values():
            dn = v["fqdn"] if v["fqdn"].startswith(".") else "." + v["fqdn"]
            if dn in seen:
                continue
            seen.add(dn)
            out.append(dict(name=dn, fqdn=v["fqdn"], comments=v["comments"]))
        return out

    # ---- reporting ---------------------------------------------------------
    def source_counts(self):
        """Count source constructs in the Cisco config (what we found to convert)."""
        p = self.parse
        obj_nat = 0
        for obj in p.find_objects(r"^object network "):
            obj_nat += sum(1 for c in obj.children if c.text.strip().startswith("nat ("))
        return OrderedDict([
            ("interface (nameif)", len(p.find_objects(r"^interface "))),
            ("object network", len(p.find_objects(r"^object network "))),
            ("object service", len(p.find_objects(r"^object service "))),
            ("object-group network", len(p.find_objects(r"^object-group network "))),
            ("object-group service", len(p.find_objects(r"^object-group service "))),
            ("object-group protocol", len(p.find_objects(r"^object-group protocol "))),
            ("access-list (ACEs)", len(p.find_objects(r"^access-list \S+ (?:extended|advanced) "))),
            ("object NAT", obj_nat),
            ("manual NAT", len(p.find_objects(r"^nat \("))),
        ])

    def build_stats(self, objects, groups, services, policy, nat):
        """Assemble the parse statistics dict (source vs converted vs review)."""
        auto = (sum(1 for v in self.hosts.values() if v["comments"].startswith("auto:"))
                + sum(1 for v in self.networks.values() if v["comments"].startswith("auto:"))
                + sum(1 for v in self.ranges.values() if v["comments"].startswith("auto:"))
                + sum(1 for v in self.svc_tcp.values() if v["comments"].startswith("auto:"))
                + sum(1 for v in self.svc_udp.values() if v["comments"].startswith("auto:"))
                + sum(1 for v in self.svc_other.values() if v["comments"].startswith("auto:")))
        return OrderedDict([
            ("source", self.source_counts()),
            ("converted", OrderedDict([
                ("hosts", len(objects["cp_hosts"])),
                ("networks", len(objects["cp_networks"])),
                ("address_ranges", len(objects["cp_address_ranges"])),
                ("dns_domains", len(objects["cp_dns_domains"])),
                ("any_aliases (0.0.0.0/0 -> Any)", len(self.any_aliases)),
                ("network_groups", len(groups["cp_network_groups"])),
                ("tcp_services", len(services["cp_services_tcp"])),
                ("udp_services", len(services["cp_services_udp"])),
                ("other_services", len(services["cp_services_other"])),
                ("service_groups", len(services["cp_service_groups"])),
                ("policy_packages", len(policy["cp_packages"])),
                ("access_rules", len(policy["cp_access_rules"])),
                ("nat_rules", len(nat["cp_nat_rules"])),
                ("auto_generated_objects (inline literals)", auto),
            ])),
            ("handled", sorted(m for m in set(self.unsupported)
                               if any(k in m for k in HANDLED_MARKERS))),
            ("attention", sorted(m for m in set(self.unsupported)
                                 if not any(k in m for k in HANDLED_MARKERS))),
        ])

    def write_reports(self, reports_dir, stats):
        """Write reports/parse_summary.md (human) and parse_report.json (machine)."""
        os.makedirs(reports_dir, exist_ok=True)
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        md = os.path.join(reports_dir, "parse_summary.md")
        js = os.path.join(reports_dir, "parse_report.json")

        lines = [f"# Parse summary ({ts})", "",
                 "## Found in config vs converted", "",
                 "| Source construct | In config |",
                 "|---|---:|"]
        for k, v in stats["source"].items():
            lines.append(f"| {k} | {v} |")
        lines += ["", "## Converted to Check Point objects", "",
                  "| Object type | Count |", "|---|---:|"]
        for k, v in stats["converted"].items():
            lines.append(f"| {k} | {v} |")
        lines += ["", f"## ✅ Auto-handled — no action needed ({len(stats['handled'])})",
                  "", "_Safe transformations the parser made; listed so you're aware._", ""]
        if stats["handled"]:
            for item in stats["handled"]:
                lines.append(f"- {item}")
        else:
            lines.append("_Nothing._")
        lines += ["", f"## ⚠️ Needs your attention ({len(stats['attention'])})", ""]
        if stats["attention"]:
            lines.append("_Review these — they may not import or may need manual work._")
            lines.append("")
            for item in stats["attention"]:
                lines.append(f"- {item}")
        else:
            lines.append("_None — nothing needs manual work._ 🎉")
        lines.append("")
        with open(md, "w") as fh:
            fh.write("\n".join(lines))
        with open(js, "w") as fh:
            json.dump(stats, fh, indent=2)
        return md, js


def main():
    ap = argparse.ArgumentParser(description="Convert Cisco FTD running-config to Check Point Ansible vars.")
    ap.add_argument("--config", required=True, help="Path to FTD show running-config file")
    ap.add_argument("--out", default="../vars", help="Output directory for *.yml vars files")
    ap.add_argument("--reports", default="reports",
                    help="Directory for parse_summary.md / parse_report.json")
    ap.add_argument("--acls", default="",
                    help="Comma-separated Cisco ACL names to convert (each -> its own "
                         "policy package). Default: the ACL bound 'access-group <name> global'.")
    args = ap.parse_args()

    if not os.path.isfile(args.config):
        sys.exit(f"Config file not found: {args.config}")

    # Remove any vars/*.yml from a previous parse BEFORE we start. If this run
    # fails partway, the apply stage then finds no vars and fails loudly, instead
    # of silently re-applying stale data from an earlier (e.g. sample) parse.
    if os.path.isdir(args.out):
        for fn in ("1_objects.yml", "2_object_groups.yml", "3_services.yml",
                   "4_policy.yml", "5_nat.yml"):
            stale = os.path.join(args.out, fn)
            if os.path.isfile(stale):
                os.remove(stale)

    conv = Converter(args.config)
    if args.acls.strip():
        conv.selected_acls = [a.strip() for a in args.acls.split(",") if a.strip()]
    conv.run()
    written, objects, groups, services, policy, nat = conv.emit(args.out)
    stats = conv.build_stats(objects, groups, services, policy, nat)
    md, js = conv.write_reports(args.reports, stats)

    col = 26
    print("\n" + c("1;36", "PARSE OVERVIEW  (found in config -> converted)"))
    print(c("36", "=" * 52))
    print(c("1", "Found in config:"))
    for k, v in stats["source"].items():
        print(f"  {k:<{col}} {v:>6}")
    print("\n" + c("1", "Converted to Check Point:"))
    for k, v in stats["converted"].items():
        print(f"  {k:<{col}} {v:>6}")

    handled, attention = stats["handled"], stats["attention"]
    print("\n" + c("32", f"  ✔ auto-handled (FYI) ......... {len(handled):>4}"))
    att_color = "33" if attention else "32"
    print(c(att_color, f"  ⚠ needs your attention ...... {len(attention):>4}"))

    print("\n" + c("1", "Wrote:"))
    for p in written + [md, js]:
        print("  " + p)

    if handled:
        print("\n" + c("32", f"✔ Auto-handled (no action needed) — {len(handled)}:"))
        for line in handled:
            print(c("32", "    • " + line))
    if attention:
        print("\n" + c("1;33", f"⚠ Needs your attention — {len(attention)} "
                               f"(see {md}):"))
        for line in attention:
            print(c("33", "    • " + line))
        print("\n" + c("1;33", "NEXT: review the items above and reports/parse_summary.md, "
                               "then run  ./3_apply.sh"))
    else:
        print("\n" + c("1;32", "✔ Parse is clean — nothing needs manual work."))
        print(c("1;32", "NEXT: run  ./3_apply.sh  to push the changes to Check Point."))


if __name__ == "__main__":
    main()

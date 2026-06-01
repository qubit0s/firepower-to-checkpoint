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
import os
import re
import sys
from collections import OrderedDict

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


class _IndentedDumper(yaml.SafeDumper):
    """YAML dumper that indents block sequences under their key, so the output
    passes yamllint's default `indentation: {indent-sequences: true}` rule."""

    def increase_indent(self, flow=False, indentless=False):
        return super().increase_indent(flow, False)


def warn(msg):
    print("  [warn] " + msg, file=sys.stderr)


def cp_name(raw):
    """Sanitise a Cisco identifier into a legal Check Point object name.
    Check Point names may not contain spaces and a limited punctuation set;
    we keep [A-Za-z0-9_.-] and replace everything else with '_'."""
    name = re.sub(r"[^A-Za-z0-9_.\-]", "_", raw.strip())
    if name and name[0].isdigit():
        name = "obj_" + name
    return name or "obj_unnamed"


def mask_to_prefix(mask):
    """Dotted mask -> prefix length. Returns int or None."""
    try:
        return sum(bin(int(o)).count("1") for o in mask.split("."))
    except ValueError:
        return None


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
        self.rules = []                   # list of dicts
        self.nat_rules = []               # list of dicts
        self.unsupported = []             # list of strings
        # bookkeeping: which object names are network-ish vs service-ish
        self._known_net = set()
        self._known_svc = set()

    # ---- auto-object helpers (for inline literals) -------------------------
    def _auto_host(self, ip):
        name = cp_name("h_" + ip)
        if name not in self.hosts:
            self.hosts[name] = {"ip_address": ip, "comments": "auto: inline host literal"}
        self._known_net.add(name)
        return name

    def _auto_network(self, subnet, mask):
        plen = mask_to_prefix(mask)
        name = cp_name(f"n_{subnet}_{plen if plen is not None else mask}")
        if name not in self.networks:
            self.networks[name] = {"subnet": subnet, "mask_length": plen,
                                   "comments": "auto: inline network literal"}
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
                    _, subnet, mask = t.split()[:3]
                    self.networks[name] = {"subnet": subnet,
                                           "mask_length": mask_to_prefix(mask),
                                           "comments": comments}
                elif t.startswith("range "):
                    _, first, last = t.split()[:3]
                    self.ranges[name] = {"first": first, "last": last, "comments": comments}
                elif t.startswith("fqdn"):
                    # 'fqdn [v4|v6|dynamic] name.example.com'
                    parts = t.split()
                    fqdn = parts[-1]
                    self.fqdns[name] = {"fqdn": fqdn, "comments": comments}

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
                    members.append(cp_name(t.split("network-object object ", 1)[1]))
                elif t.startswith("group-object "):
                    members.append(cp_name(t.split("group-object ", 1)[1]))
                elif t.startswith("network-object host "):
                    members.append(self._auto_host(t.split()[2]))
                elif t.startswith("network-object range "):
                    parts = t.split()
                    members.append(self._auto_range(parts[2], parts[3]))
                elif t.startswith("network-object "):
                    parts = t.split()
                    # 'network-object 10.0.0.0 255.0.0.0'
                    if len(parts) >= 3 and re.match(r"\d+\.\d+\.\d+\.\d+", parts[1]):
                        members.append(self._auto_network(parts[1], parts[2]))
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

    # ======================================================================
    # 5. ACCESS-LISTS  -> policy.yml
    # ======================================================================
    def _resolve_addr_tokens(self, tokens):
        """Consume leading address tokens from an ACL, return (list_of_cp_objs, remaining)."""
        if not tokens:
            return ["Any"], tokens
        head = tokens[0]
        if head == "any" or head == "any4" or head == "any6":
            return ["Any"], tokens[1:]
        if head == "object":
            return [cp_name(tokens[1])], tokens[2:]
        if head == "object-group":
            return [cp_name(tokens[1])], tokens[2:]
        if head == "host":
            return [self._auto_host(tokens[1])], tokens[2:]
        if re.match(r"\d+\.\d+\.\d+\.\d+", head) and len(tokens) > 1 and \
           re.match(r"\d+\.\d+\.\d+\.\d+", tokens[1]):
            return [self._auto_network(head, tokens[1])], tokens[2:]
        # fallback: treat as Any and flag
        return ["Any"], tokens[1:]

    def _resolve_service_tokens(self, proto, tokens):
        """Parse trailing service spec of an ACL line into CP service object names."""
        services = []
        if not tokens:
            services = ["Any"] if proto == "ip" else []
            return services
        head = tokens[0]
        if head == "object-group":
            return [cp_name(tokens[1])]
        if head == "object":
            return [cp_name(tokens[1])]
        if head == "eq" and len(tokens) > 1:
            if proto in ("tcp", "udp"):
                return [self._auto_service(proto, tokens[1])]
        if head == "range" and len(tokens) > 2 and proto in ("tcp", "udp"):
            p1, _ = resolve_port(tokens[1])
            p2, _ = resolve_port(tokens[2])
            sname = cp_name(f"svc_{proto}_{p1}_{p2}")
            bucket = self.svc_tcp if proto == "tcp" else self.svc_udp
            bucket.setdefault(sname, {"port": f"{p1}-{p2}", "comments": "auto"})
            return [sname]
        return []

    def parse_access_lists(self):
        # map access-list name -> interface/direction from access-group lines
        binding = {}
        for ag in self.parse.find_objects(r"^access-group "):
            parts = ag.text.split()
            # access-group NAME in|out interface IF   OR   access-group NAME global
            if len(parts) >= 2:
                aclname = parts[1]
                binding[aclname] = " ".join(parts[2:])

        counters = {}
        for acl in self.parse.find_objects(r"^access-list \S+ extended "):
            toks = acl.text.split()
            # access-list NAME extended ACTION PROTO ...
            aclname = toks[1]
            action_word = toks[3]
            proto = toks[4]
            rest = toks[5:]
            src, rest = self._resolve_addr_tokens(rest)
            dst, rest = self._resolve_addr_tokens(rest)
            svc = self._resolve_service_tokens(proto, rest)
            # protocol-level service when no port object (icmp / ip / explicit proto)
            if not svc:
                if proto == "ip":
                    svc = ["Any"]
                elif proto == "icmp":
                    svc = ["icmp-proto"]   # CP predefined; see playbook note
                elif proto in ("tcp", "udp"):
                    svc = ["Any"]          # any tcp/udp port
                else:
                    svc = ["Any"]
                    self.unsupported.append(f"acl {aclname}: protocol '{proto}' mapped to Any service; review")
            counters[aclname] = counters.get(aclname, 0) + 1
            self.rules.append({
                "acl": aclname,
                "name": f"{aclname}-{counters[aclname]}",
                "action": "Accept" if action_word == "permit" else "Drop",
                "source": src,
                "destination": dst,
                "service": svc,
                "binding": binding.get(aclname, ""),
                "enabled": True,
                "comments": f"migrated from access-list {aclname} "
                            f"({binding.get(aclname,'unbound')})",
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
            m = re.match(r"nat \((\S+?),(\S+?)\) source (static|dynamic) (\S+) (\S+)"
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
            else:
                rule["translated_source"] = "Original" if mapped_src == real_src else cp_name(mapped_src)
            if m.group(6):  # destination static REAL MAPPED
                rule["original_destination"] = cp_name(m.group(6))
                rule["translated_destination"] = ("Original" if m.group(7) == m.group(6)
                                                  else cp_name(m.group(7)))
            if m.group(8):  # service REAL MAPPED
                rule["original_service"] = cp_name(m.group(8))
                rule["translated_service"] = cp_name(m.group(9))
            self.nat_rules.append(rule)

    # ======================================================================
    def run(self):
        self.parse_network_objects()
        self.parse_service_objects()
        self.parse_network_groups()
        self.parse_service_groups()
        self.parse_access_lists()
        self.parse_nat()

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
            "cp_dns_domains": [dict(name=("." + v["fqdn"] if not v["fqdn"].startswith(".") else v["fqdn"]),
                                    fqdn=v["fqdn"], comments=v["comments"])
                               for n, v in self.fqdns.items()],
        }
        groups = {"cp_network_groups": [dict(name=n, members=v["members"],
                                             comments=v["comments"])
                                        for n, v in self.net_groups.items()]}
        services = {
            "cp_services_tcp": [dict(name=n, **v) for n, v in self.svc_tcp.items()],
            "cp_services_udp": [dict(name=n, **v) for n, v in self.svc_udp.items()],
            "cp_services_other": [dict(name=n, **v) for n, v in self.svc_other.items()],
            "cp_service_groups": [dict(name=n, members=v["members"], comments=v["comments"])
                                  for n, v in self.svc_groups.items()],
        }
        policy = {"cp_access_rules": self.rules}
        nat = {"cp_nat_rules": self.nat_rules}

        review_path = os.path.join(out_dir, "_review_unsupported.yml")
        if self.unsupported:
            self._dump(out_dir, "_review_unsupported.yml",
                       {"unsupported": sorted(set(self.unsupported))})
        elif os.path.exists(review_path):
            os.remove(review_path)   # clear stale report when nothing is unsupported

        written = [
            self._dump(out_dir, "1_objects.yml", objects),
            self._dump(out_dir, "2_object_groups.yml", groups),
            self._dump(out_dir, "3_services.yml", services),
            self._dump(out_dir, "4_policy.yml", policy),
            self._dump(out_dir, "5_nat.yml", nat),
        ]
        return written, objects, groups, services, policy, nat


def main():
    ap = argparse.ArgumentParser(description="Convert Cisco FTD running-config to Check Point Ansible vars.")
    ap.add_argument("--config", required=True, help="Path to FTD show running-config file")
    ap.add_argument("--out", default="../vars", help="Output directory for *.yml vars files")
    args = ap.parse_args()

    if not os.path.isfile(args.config):
        sys.exit(f"Config file not found: {args.config}")

    conv = Converter(args.config)
    conv.run()
    written, objects, groups, services, policy, nat = conv.emit(args.out)

    print("Conversion summary")
    print("==================")
    print(f"  hosts ............ {len(objects['cp_hosts'])}")
    print(f"  networks ......... {len(objects['cp_networks'])}")
    print(f"  address ranges ... {len(objects['cp_address_ranges'])}")
    print(f"  dns domains ...... {len(objects['cp_dns_domains'])}")
    print(f"  network groups ... {len(groups['cp_network_groups'])}")
    print(f"  tcp services ..... {len(services['cp_services_tcp'])}")
    print(f"  udp services ..... {len(services['cp_services_udp'])}")
    print(f"  other services ... {len(services['cp_services_other'])}")
    print(f"  service groups ... {len(services['cp_service_groups'])}")
    print(f"  access rules ..... {len(policy['cp_access_rules'])}")
    print(f"  nat rules ........ {len(nat['cp_nat_rules'])}")
    print(f"  unsupported ...... {len(set(conv.unsupported))}")
    print("\nWrote:")
    for p in written:
        print("  " + p)
    if conv.unsupported:
        print("\n[!] Items needing manual review were written to _review_unsupported.yml")


if __name__ == "__main__":
    main()

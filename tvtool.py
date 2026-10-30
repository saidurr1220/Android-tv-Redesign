#!/usr/bin/env python3
"""Find Android TV devices on the local network and make them feel faster.

Run this on a computer connected to the same network as the TV.
Only the Python standard library is needed for discovery; the
`optimize`, `restore` and `info` commands also need `adb` on PATH.

    python3 tvtool.py discover            # mDNS + fast port scan
    python3 tvtool.py info 192.168.1.50
    python3 tvtool.py optimize 192.168.1.50
    python3 tvtool.py restore 192.168.1.50
"""

import argparse
import ipaddress
import json
import os
import shutil
import socket
import struct
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor

MDNS_ADDR = ("224.0.0.251", 5353)

# Services that Android TV / Google TV devices commonly advertise.
MDNS_SERVICES = [
    "_androidtvremote2._tcp.local",
    "_androidtvremote._tcp.local",
    "_googlecast._tcp.local",
    "_adb-tls-connect._tcp.local",
    "_adb._tcp.local",
]

# Ports used for the fallback scan, with what an open port suggests.
TV_PORTS = {
    5555: "adb",
    6466: "androidtv-remote",
    6467: "androidtv-pairing",
    8008: "cast-http",
    8009: "cast",
}

ANIMATION_KEYS = [
    "window_animation_scale",
    "transition_animation_scale",
    "animator_duration_scale",
]

# Packages that must stay enabled; turning these off has left TVs stuck at boot.
# Based on the "never turn off" list in https://github.com/Ansub/tv-detox.
PROTECTED_PACKAGES = {
    "android",
    "com.android.systemui",
    "com.android.settings",
    "com.android.vending",
    "com.android.providers.settings",
    "com.android.bluetooth",
    "com.android.inputmethod.latin",
    "com.android.tv.settings",
    "com.google.android.gms",
    "com.google.android.gsf",
    "com.google.android.tvlauncher",
    "com.google.android.apps.tv.launcherx",
    "com.google.android.leanbacklauncher",
    "com.google.android.tvsetup",
    "com.google.android.leanbackime",
    "com.google.android.inputmethod.latin",
    "com.droidlogic.tvinput",
    "com.mediatek.tvinput",
}
PROTECTED_KEYWORDS = ("setupwizard", "tvinput", "tuner", "hdmi", "inputmethod", "keyboard", "systemui")

STATE_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".tvtool_state.json")


# ---------------------------------------------------------------- mDNS

def _encode_name(name):
    out = b""
    for label in name.rstrip(".").split("."):
        out += bytes([len(label)]) + label.encode()
    return out + b"\x00"


def _build_query(services):
    header = struct.pack("!HHHHHH", 0, 0, len(services), 0, 0, 0)
    # QTYPE=PTR(12), QCLASS=IN with the unicast-response bit set.
    questions = b"".join(_encode_name(s) + struct.pack("!HH", 12, 0x8001) for s in services)
    return header + questions


def _read_name(data, offset):
    labels, jumped, end = [], False, offset
    for _ in range(128):  # guard against pointer loops
        length = data[offset]
        if length == 0:
            offset += 1
            break
        if length & 0xC0 == 0xC0:
            pointer = struct.unpack("!H", data[offset:offset + 2])[0] & 0x3FFF
            if not jumped:
                end = offset + 2
            jumped = True
            offset = pointer
            continue
        offset += 1
        labels.append(data[offset:offset + length].decode("utf-8", "replace"))
        offset += length
    return ".".join(labels), (end if jumped else offset)


def _parse_records(data):
    _, _, qd, an, ns, ar = struct.unpack("!HHHHHH", data[:12])
    offset = 12
    for _ in range(qd):
        _, offset = _read_name(data, offset)
        offset += 4
    records = []
    for _ in range(an + ns + ar):
        name, offset = _read_name(data, offset)
        rtype, _, _, rdlen = struct.unpack("!HHIH", data[offset:offset + 10])
        offset += 10
        rdata = data[offset:offset + rdlen]
        if rtype == 12:  # PTR
            value, _ = _read_name(data, offset)
        elif rtype == 33:  # SRV
            port = struct.unpack("!H", rdata[4:6])[0]
            target, _ = _read_name(data, offset + 6)
            value = (target, port)
        elif rtype == 1 and rdlen == 4:  # A
            value = socket.inet_ntoa(rdata)
        elif rtype == 16:  # TXT
            value, i = {}, 0
            while i < len(rdata):
                ln = rdata[i]
                entry = rdata[i + 1:i + 1 + ln].decode("utf-8", "replace")
                key, _, val = entry.partition("=")
                value[key] = val
                i += 1 + ln
        else:
            value = None
        records.append((name.lower(), rtype, value))
        offset += rdlen
    return records


def mdns_discover(timeout):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)
    sock.settimeout(0.2)
    query = _build_query(MDNS_SERVICES)
    records = []
    deadline = time.time() + timeout
    next_send = 0.0
    while time.time() < deadline:
        if time.time() >= next_send:
            sock.sendto(query, MDNS_ADDR)
            next_send = time.time() + 1.0
        try:
            data, (src, _) = sock.recvfrom(9000)
        except socket.timeout:
            continue
        except OSError:
            break
        try:
            records.extend((src,) + r for r in _parse_records(data))
        except (IndexError, struct.error):
            continue
    sock.close()

    ptrs = {}   # instance name -> service
    srvs = {}   # instance name -> (host, port)
    addrs = {}  # host -> ip
    txts = {}   # instance name -> dict
    sources = {}
    for src, name, rtype, value in records:
        if rtype == 12 and value:
            ptrs[value.lower()] = name
            sources.setdefault(value.lower(), src)
        elif rtype == 33 and value:
            srvs[name] = (value[0].lower(), value[1])
            sources.setdefault(name, src)
        elif rtype == 1 and value:
            addrs[name] = value
        elif rtype == 16 and value:
            txts[name] = value

    devices = {}
    for instance, service in ptrs.items():
        host, port = srvs.get(instance, (None, None))
        ip = addrs.get(host) or sources.get(instance)
        if not ip:
            continue
        txt = txts.get(instance, {})
        label = txt.get("fn") or instance.split("._")[0]
        dev = devices.setdefault(ip, {"ip": ip, "name": label, "services": {}, "model": txt.get("md", "")})
        dev["services"][service.split(".")[0].lstrip("_")] = port
        if txt.get("fn"):
            dev["name"] = txt["fn"]
    return devices


# ---------------------------------------------------------- port scan

def local_ipv4():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("10.255.255.255", 1))  # no packet is sent for UDP connect
        return s.getsockname()[0]
    except OSError:
        return None
    finally:
        s.close()


def _probe(ip, port, timeout):
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except OSError:
        return False


def port_scan(subnet, timeout):
    hosts = [str(h) for h in ipaddress.ip_network(subnet, strict=False).hosts()]
    jobs = [(ip, port) for ip in hosts for port in TV_PORTS]
    devices = {}
    with ThreadPoolExecutor(max_workers=256) as pool:
        for (ip, port), is_open in zip(jobs, pool.map(lambda j: _probe(j[0], j[1], timeout), jobs)):
            if is_open:
                dev = devices.setdefault(ip, {"ip": ip, "name": "", "services": {}, "model": ""})
                dev["services"][TV_PORTS[port]] = port
    # Port 8008/8009 alone also matches Chromecasts and speakers; require a TV-ish port.
    tvish = {"adb", "androidtv-remote", "androidtv-pairing"}
    return {ip: d for ip, d in devices.items() if tvish & set(d["services"])}


def cmd_discover(args):
    my_ip = local_ipv4()
    subnet = args.subnet or (f"{my_ip}/24" if my_ip else None)
    print(f"This computer: {my_ip or 'unknown'}   scanning: {subnet or 'mDNS only'}")

    found = mdns_discover(args.mdns_timeout)
    if subnet and not args.mdns_only:
        for ip, dev in port_scan(subnet, args.port_timeout).items():
            merged = found.setdefault(ip, dev)
            merged["services"].update(dev["services"])

    if not found:
        print("No Android TV devices found. Check that the TV is on and on the same network,")
        print("and that the network does not isolate clients (guest Wi-Fi often does).")
        return 1
    for dev in sorted(found.values(), key=lambda d: ipaddress.ip_address(d["ip"])):
        services = ", ".join(f"{k}:{v}" if v else k for k, v in dev["services"].items())
        name = dev["name"] or "(unnamed)"
        model = f" [{dev['model']}]" if dev["model"] else ""
        print(f"  {dev['ip']:<15}  {name}{model}  ->  {services}")
    if args.json:
        print(json.dumps(list(found.values()), indent=2))
    return 0


# ---------------------------------------------------------------- adb

def _adb(*args, check=True):
    result = subprocess.run(["adb", *args], capture_output=True, text=True)
    if check and result.returncode != 0:
        raise SystemExit(f"adb {' '.join(args)} failed: {result.stderr.strip() or result.stdout.strip()}")
    return result.stdout.strip()


def _connect(host):
    if not shutil.which("adb"):
        raise SystemExit("adb not found. Install Android platform-tools and add it to PATH.")
    serial = host if ":" in host else f"{host}:5555"
    out = _adb("connect", serial)
    if "connected" not in out:
        raise SystemExit(
            f"Could not connect to {serial}: {out}\n"
            "On the TV: Settings > Device Preferences > About > press 'Build' 7 times,\n"
            "then Developer options > enable 'USB debugging' / 'Network debugging'.\n"
            "Accept the 'Allow debugging' prompt on the TV the first time."
        )
    return serial


def _shell(serial, command):
    return _adb("-s", serial, "shell", command, check=False)


def _load_state():
    try:
        with open(STATE_FILE) as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def _save_state(state):
    with open(STATE_FILE, "w") as f:
        json.dump(state, f, indent=2)


def cmd_info(args):
    serial = _connect(args.host)
    props = {
        "model": "ro.product.model",
        "brand": "ro.product.brand",
        "android": "ro.build.version.release",
        "sdk": "ro.build.version.sdk",
    }
    for label, prop in props.items():
        print(f"{label:>10}: {_shell(serial, f'getprop {prop}')}")
    for key in ANIMATION_KEYS:
        print(f"{key:>10}: {_shell(serial, f'settings get global {key}')}")
    mem = _shell(serial, "cat /proc/meminfo | head -3")
    print(mem)
    print("\nHome launcher:")
    print(_shell(serial, "cmd package resolve-activity --brief -a android.intent.action.MAIN -c android.intent.category.HOME | tail -1"))
    return 0


def cmd_optimize(args):
    serial = _connect(args.host)
    state = _load_state()
    previous = state.setdefault(serial, {"settings": {}, "disabled": []})

    # Record original values once so `restore` can put them back.
    for key in ANIMATION_KEYS:
        if key not in previous["settings"]:
            previous["settings"][key] = _shell(serial, f"settings get global {key}")
        _shell(serial, f"settings put global {key} {args.animation_scale}")
        print(f"set {key} = {args.animation_scale}")

    for package in args.disable or []:
        if package in PROTECTED_PACKAGES or any(k in package.lower() for k in PROTECTED_KEYWORDS):
            print(f"skip {package}: protected, the TV may need it to start")
            continue
        out = _shell(serial, f"pm disable-user --user 0 {package}")
        print(f"disable {package}: {out or 'done'}")
        if "disabled" in out and package not in previous["disabled"]:
            previous["disabled"].append(package)

    # Ask Android to compile apps ahead of time; can take several minutes.
    if args.compile:
        print("Compiling apps (speed profile), this can take a few minutes...")
        print(_shell(serial, "cmd package compile -m speed-profile -a") or "done")

    _shell(serial, "am kill-all")
    _save_state(state)
    print(f"\nDone. Original values saved in {STATE_FILE}; run `restore {args.host}` to undo.")
    return 0


def cmd_restore(args):
    serial = _connect(args.host)
    state = _load_state()
    previous = state.get(serial)
    if not previous:
        raise SystemExit(f"No saved state for {serial}.")
    for key, value in previous["settings"].items():
        if value in ("", "null"):
            _shell(serial, f"settings delete global {key}")
        else:
            _shell(serial, f"settings put global {key} {value}")
        print(f"restored {key} = {value or 'default'}")
    for package in previous["disabled"]:
        print(f"enable {package}: {_shell(serial, f'pm enable {package}') or 'done'}")
    del state[serial]
    _save_state(state)
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("discover", help="find Android TVs on this network")
    p.add_argument("--subnet", help="CIDR to scan, default: this computer's /24")
    p.add_argument("--mdns-timeout", type=float, default=2.5, help="seconds to listen for mDNS replies")
    p.add_argument("--port-timeout", type=float, default=0.3, help="per-connection timeout for the port scan")
    p.add_argument("--mdns-only", action="store_true", help="skip the port scan")
    p.add_argument("--json", action="store_true", help="also print results as JSON")
    p.set_defaults(func=cmd_discover)

    p = sub.add_parser("info", help="show device details over adb")
    p.add_argument("host")
    p.set_defaults(func=cmd_info)

    p = sub.add_parser("optimize", help="speed up UI over adb (reversible)")
    p.add_argument("host")
    p.add_argument("--animation-scale", default="0.5", help="0 = off, 0.5 = snappy, 1 = stock (default 0.5)")
    p.add_argument("--disable", nargs="*", metavar="PACKAGE", help="packages to disable (reversible with restore)")
    p.add_argument("--compile", action="store_true", help="AOT-compile installed apps (slow, one-time)")
    p.set_defaults(func=cmd_optimize)

    p = sub.add_parser("restore", help="undo changes made by optimize")
    p.add_argument("host")
    p.set_defaults(func=cmd_restore)

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())

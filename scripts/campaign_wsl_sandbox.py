"""Run one campaign command in an allowlisted Linux network namespace (WSL/Linux)."""

import argparse
import ipaddress
import json
import os
import re
import socket
import subprocess
import sys
import tempfile
import uuid
from pathlib import Path
from urllib.parse import urlsplit

try:
    import fcntl
except ImportError:  # Windows only invokes the helper inside WSL.
    fcntl = None


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "assessment_campaign.py"


def _run(command, *, input_text=None, capture=True, check=True):
    result = subprocess.run(command, input=input_text, text=True,
                            stdout=subprocess.PIPE if capture else subprocess.DEVNULL,
                            stderr=subprocess.PIPE if capture else subprocess.DEVNULL,
                            check=False)
    if check and result.returncode:
        detail = (result.stderr or "").strip()[-1200:]
        raise RuntimeError("sandbox setup command failed: {}{}".format(
            command[0], ": " + detail if detail else ""))
    return result


def _wsl_path(value):
    value = str(value)
    if not re.match(r"^[A-Za-z]:[\\/]", value):
        return value
    result = _run(["wslpath", "-u", value])
    return result.stdout.strip()


def _translate_argument(value):
    if not isinstance(value, str):
        raise ValueError("campaign arguments must be strings")
    if re.match(r"^[A-Za-z]:[\\/]", value):
        return _wsl_path(value)
    if "=" in value:
        prefix, suffix = value.split("=", 1)
        if re.match(r"^[A-Za-z]:[\\/]", suffix):
            return prefix + "=" + _wsl_path(suffix)
    return value


def _resolve_ipv4(host):
    try:
        address = ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        address = None
    if address is not None:
        if address.version != 4:
            raise ValueError("WSL network namespace currently supports IPv4 targets only")
        values = {address.compressed}
    else:
        values = {row[4][0] for row in socket.getaddrinfo(
            host, None, family=socket.AF_INET, type=socket.SOCK_STREAM)}
    if not values:
        raise ValueError("target host did not resolve to IPv4")
    for value in values:
        parsed = ipaddress.ip_address(value)
        if parsed.is_loopback or parsed.is_unspecified or parsed.is_multicast:
            raise ValueError("loopback, unspecified, and multicast targets are not reachable in WSL isolation")
    return sorted(values)


def _allowed_network(plan, step_id):
    step = next((value for value in plan["steps"] if value["id"] == step_id), None)
    if step is None:
        raise ValueError("selected campaign step does not exist")
    selected = urlsplit(step["origin"])
    origin_host = selected.hostname
    origin_port = selected.port or (443 if selected.scheme == "https" else 80)
    address_map = {origin_host: _resolve_ipv4(origin_host)}
    endpoints = {}
    for address in address_map[origin_host]:
        endpoints[(address, "tcp", origin_port)] = None
    for endpoint in plan["scope"]["network_endpoints"]:
        host = endpoint["host"]
        if host not in address_map:
            address_map[host] = _resolve_ipv4(host)
        addresses = address_map[host]
        for address in addresses:
            for port in endpoint["ports"]:
                endpoints[(address, endpoint["protocol"], port)] = None
    return step, address_map, endpoints


def _local_ipv4_addresses():
    output = _run(["ip", "-o", "-4", "addr", "show"]).stdout
    return {line.split()[3].split("/", 1)[0] for line in output.splitlines() if len(line.split()) >= 4}


def build_firewall_rules(table, host_veth, uplink, subnet, allowed, local_addresses):
    forward_rules = []
    input_rules = []
    for address, protocol, port in sorted(allowed):
        l4 = "tcp" if protocol == "tcp" else "udp"
        if address in local_addresses:
            input_rules.append('iifname "{0}" ip daddr {1} {2} dport {3} accept'.format(
                host_veth, address, l4, port))
        forward_rules.append('iifname "{0}" ip daddr {1} {2} dport {3} accept'.format(
            host_veth, address, l4, port))
    forward_rules.extend([
        'iifname "{}" meta nfproto ipv6 drop'.format(host_veth),
        'iifname "{}" drop'.format(host_veth),
        'oifname "{}" ct state established,related accept'.format(host_veth),
        'oifname "{}" meta nfproto ipv6 drop'.format(host_veth),
        'oifname "{}" drop'.format(host_veth),
    ])
    input_rules.append('iifname "{}" drop'.format(host_veth))
    lines = [
        "table inet {} {{".format(table),
        " chain forward { type filter hook forward priority -50; policy accept;",
        *forward_rules,
        " }",
        " chain input { type filter hook input priority -50; policy accept;",
        *input_rules,
        " }",
        " chain postrouting { type nat hook postrouting priority 100; policy accept;",
        'oifname "{}" ip saddr {} masquerade'.format(uplink, subnet),
        " }",
        "}",
    ]
    return "\n".join(lines) + "\n"


class NetworkNamespace:
    def __init__(self, allowed):
        suffix = uuid.uuid4().hex[:8]
        self.name = "cmns" + suffix
        self.host_veth = "cmh" + suffix
        self.peer_veth = "cmn" + suffix
        self.table = "cm" + suffix
        self.allowed = allowed
        self.created_netns = False
        self.created_veth = False
        self.created_table = False
        self.forwarding_before = None
        self.subnet = None
        self.gateway = None
        self.peer = None
        self.uplink = None

    def __enter__(self):
        try:
            return self._setup()
        except BaseException:
            self.__exit__(None, None, None)
            raise

    def _setup(self):
        _run(["ip", "netns", "add", self.name])
        self.created_netns = True
        _run(["ip", "link", "add", self.host_veth, "type", "veth", "peer", "name", self.peer_veth])
        self.created_veth = True
        _run(["ip", "link", "set", self.peer_veth, "netns", self.name])
        route = _run(["ip", "-4", "route", "show", "default"]).stdout.splitlines()
        match = re.search(r"\bdev\s+(\S+)", route[0]) if route else None
        if not match:
            raise RuntimeError("WSL host has no IPv4 default route")
        self.uplink = match.group(1)
        second_octet = int(uuid.uuid4().hex[2:4], 16)
        self.subnet = "10.254.{}.0/30".format(second_octet)
        self.gateway = "10.254.{}.1".format(second_octet)
        self.peer = "10.254.{}.2".format(second_octet)
        _run(["ip", "addr", "add", self.gateway + "/30", "dev", self.host_veth])
        _run(["ip", "link", "set", self.host_veth, "up"])
        _run(["ip", "-n", self.name, "addr", "add", self.peer + "/30", "dev", self.peer_veth])
        _run(["ip", "-n", self.name, "link", "set", "lo", "up"])
        _run(["ip", "-n", self.name, "link", "set", self.peer_veth, "up"])
        _run(["ip", "-n", self.name, "route", "add", "default", "via", self.gateway,
              "dev", self.peer_veth])
        self.forwarding_before = _run(["sysctl", "-n", "net.ipv4.ip_forward"]).stdout.strip()
        _run(["sysctl", "-w", "net.ipv4.ip_forward=1"])
        firewall = build_firewall_rules(
            self.table, self.host_veth, self.uplink, self.subnet,
            self.allowed, _local_ipv4_addresses())
        _run(["nft", "-f", "-"], input_text=firewall)
        self.created_table = True
        return self

    def __exit__(self, *_exc):
        if self.created_table:
            _run(["nft", "delete", "table", "inet", self.table], check=False)
        if self.created_netns:
            _run(["ip", "netns", "del", self.name], check=False)
        if self.created_veth:
            _run(["ip", "link", "del", self.host_veth], check=False)
        if self.forwarding_before in ("0", "1"):
            _run(["sysctl", "-w", "net.ipv4.ip_forward=" + self.forwarding_before], check=False)


def _inner_argv(request, output_path):
    argv = [_translate_argument(value) for value in request["argv"]]
    if argv[0] in ("run-workflow", "run-step"):
        output_index = argv.index("--output")
        argv[output_index + 1] = str(output_path)
    else:
        separator = argv.index("--") if "--" in argv else len(argv)
        argv[separator:separator] = ["--output", str(output_path)]
    return argv


def execute_request(request):
    if os.geteuid() != 0:
        raise RuntimeError("WSL namespace isolation requires root inside the WSL distro")
    if fcntl is None:
        raise RuntimeError("WSL network namespace isolation requires Linux file locking support")
    argv = request.get("argv")
    allowed_commands = ("run-cli", "run-external", "run-workflow", "run-step")
    if not isinstance(argv, list) or not argv or argv[0] not in allowed_commands:
        raise ValueError("isolated execution received an unsupported campaign command")
    translated = [_translate_argument(value) for value in argv]
    manifest_value = translated[translated.index("--manifest") + 1]
    step_id = translated[translated.index("--step") + 1]
    confirm_target = translated[translated.index("--confirm-target") + 1]
    import assessment_campaign as campaign
    manifest = campaign._read_json(manifest_value)
    plan = campaign.validate_manifest(manifest)
    if campaign.canonical_origin(confirm_target) != next(
            step["origin"] for step in plan["steps"] if step["id"] == step_id):
        raise ValueError("--confirm-target does not match selected step")
    _selected, address_map, allowed = _allowed_network(plan, step_id)
    role_environment = request.get("environment", {})
    if not isinstance(role_environment, dict):
        raise ValueError("isolated credential environment must be an object")
    protected_names = {"PATH", "PYTHONPATH", "PYTHONHOME", "HOME", "SHELL", "COMSPEC",
                       "WSLENV", "LD_PRELOAD", "LD_LIBRARY_PATH"}
    for name, value in role_environment.items():
        if (not isinstance(name, str) or not campaign.MAX_ENV.fullmatch(name)
                or name in protected_names or name.startswith("CATUS_CAMPAIGN_GATE_")
                or name.startswith("LD_") or not isinstance(value, str) or "\x00" in value):
            raise ValueError("isolated role credential uses a reserved environment variable")
    lock_path = Path("/run/lock/catus-campaign-netns.lock")
    with lock_path.open("a+") as lock_file:
        fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
        with NetworkNamespace(set(allowed)) as namespace:
            with tempfile.TemporaryDirectory(prefix="catus-campaign-result-") as directory:
                os.chown(directory, 65534, 65534)
                result_path = Path(directory) / "result.json"
                inner_args = _inner_argv(request, result_path)
                env = os.environ.copy()
                for key in tuple(env):
                    if key.startswith("CATUS_CAMPAIGN_GATE_"):
                        env.pop(key, None)
                env["CATUS_CAMPAIGN_GATE_ORIGIN_ADDRESSES"] = json.dumps(
                    address_map[urlsplit(_selected["origin"]).hostname])
                env["CATUS_CAMPAIGN_GATE_ENDPOINT_ADDRESSES"] = json.dumps(address_map)
                env["PYTHONPATH"] = str(ROOT / "scripts")
                env["PYTHONDONTWRITEBYTECODE"] = "1"
                env.update(role_environment)
                for proxy_variable in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy",
                                       "https_proxy", "all_proxy"):
                    env.pop(proxy_variable, None)
                command = ["ip", "netns", "exec", namespace.name]
                command += ["setpriv", "--reuid=65534", "--regid=65534", "--clear-groups",
                            "--bounding-set=-all", "--inh-caps=-all", "--ambient-caps=-all",
                            "--no-new-privs", "--", sys.executable, str(SCRIPT), *inner_args]
                completed = subprocess.run(command, env=env, cwd=str(ROOT), check=False,
                                           stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                                           text=True, timeout=campaign.CLI_TIMEOUT_SECONDS + 60)
                if completed.returncode:
                    diagnostic = next((line for line in reversed((completed.stderr or "").splitlines())
                                       if "assessment_campaign.py: error:" in line), "")
                    raise RuntimeError("isolated campaign command failed with exit code {}{}".format(
                        completed.returncode, ": " + diagnostic[-300:] if diagnostic else ""))
                return json.loads(result_path.read_text(encoding="utf-8"))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--request-stdin", action="store_true", required=True)
    parser.parse_args(argv)
    request = json.load(sys.stdin)
    try:
        result = execute_request(request)
    except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired) as exc:
        print("campaign WSL isolation failed: {}".format(exc), file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2, allow_nan=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())

"""Install opt-in campaign guards on Python process-launch APIs.

Python imports this file automatically only when this repository's scripts
directory is on PYTHONPATH. Normal skill execution has no campaign gate and is
unchanged. In campaign-launched tools, every child process must use an explicit
bounded adapter. Shell and direct os process-launch APIs fail closed.
"""

import os
import ipaddress
import json
import socket
import subprocess
import urllib.request
from urllib.parse import urlsplit


if (os.environ.get("CATUS_CAMPAIGN_GATE_DB")
        and not os.environ.get("CATUS_CAMPAIGN_GATE_SUPERVISOR")):
    try:
        from campaign_request_gate import (
            CampaignGateError,
            _mark_status,
            _normalize_network_host,
            network_endpoint_is_scoped,
            reserve_external_command_from_environment,
        )
    except ImportError as error:  # fail closed if campaign mode cannot load its gate
        _campaign_gate_import_error = error

        class CampaignGateError(RuntimeError):
            pass

        def _mark_status(_flag):
            pass

        def _normalize_network_host(host):
            value = str(host).strip().strip("[]").rstrip(".")
            try:
                return ipaddress.ip_address(value).compressed.lower()
            except ValueError:
                return value.encode("idna").decode("ascii").lower()

        def network_endpoint_is_scoped(_host, _port, _protocol="tcp"):
            return False

        def reserve_external_command_from_environment(_command, *, shell=False):
            raise RuntimeError("campaign subprocess gate is unavailable") from _campaign_gate_import_error

        class CampaignGuardedPopen(subprocess.Popen):
            def __init__(self, *args, **kwargs):
                raise RuntimeError("campaign subprocess gate is unavailable") from _campaign_gate_import_error

    else:
        _OriginalPopen = subprocess.Popen

        class CampaignGuardedPopen(_OriginalPopen):
            def __init__(self, args, *positional, **kwargs):
                safe_args = reserve_external_command_from_environment(
                    args, shell=kwargs.get("shell", False))
                super().__init__(safe_args, *positional, **kwargs)

    subprocess.Popen = CampaignGuardedPopen

    def _blocked_process_launch(*_args, **_kwargs):
        if "_campaign_gate_import_error" in globals():
            raise RuntimeError("campaign subprocess gate is unavailable") from _campaign_gate_import_error
        _mark_status("gate_errors")
        raise CampaignGateError("campaign gate blocks direct os process-launch APIs")

    for _process_api in (
        "system", "popen", "spawnl", "spawnle", "spawnlp", "spawnlpe", "spawnv",
        "spawnve", "spawnvp", "spawnvpe", "execl", "execle", "execlp", "execlpe",
        "execv", "execve", "execvp", "execvpe", "startfile",
    ):
        if hasattr(os, _process_api):
            setattr(os, _process_api, _blocked_process_launch)

    _gate_origin = os.environ.get("CATUS_CAMPAIGN_GATE_ORIGIN", "")
    try:
        _parsed_origin = urlsplit(_gate_origin)
        _origin_host = _normalize_network_host(_parsed_origin.hostname or "")
        _origin_port = _parsed_origin.port or (443 if _parsed_origin.scheme == "https" else 80)
        try:
            ipaddress.ip_address(_origin_host)
            _origin_addresses = {_origin_host}
        except ValueError:
            _origin_addresses = set()
    except (ValueError, TypeError):
        _origin_host, _origin_port, _origin_addresses = "", 0, set()

    _original_getaddrinfo = socket.getaddrinfo
    _original_connect = socket.socket.connect
    _original_connect_ex = socket.socket.connect_ex
    _original_sendto = socket.socket.sendto
    _original_sendmsg = getattr(socket.socket, "sendmsg", None)

    try:
        _origin_addresses.update(
            _normalize_network_host(item)
            for item in json.loads(os.environ.get("CATUS_CAMPAIGN_GATE_ORIGIN_ADDRESSES", "[]"))
            if isinstance(item, str)
        )
    except (TypeError, ValueError, json.JSONDecodeError):
        pass

    try:
        _endpoint_addresses = json.loads(
            os.environ.get("CATUS_CAMPAIGN_GATE_ENDPOINT_ADDRESSES", "{}"))
    except (TypeError, ValueError, json.JSONDecodeError):
        _endpoint_addresses = {}

    if (_origin_host and not _origin_addresses
            and "_campaign_gate_import_error" not in globals()):
        try:
            _origin_addresses.update(
                _normalize_network_host(row[4][0])
                for row in _original_getaddrinfo(
                    _origin_host, _origin_port, type=socket.SOCK_STREAM)
            )
        except (OSError, ValueError):
            pass
    os.environ["CATUS_CAMPAIGN_GATE_ORIGIN_ADDRESSES"] = json.dumps(sorted(_origin_addresses))

    def _deny_network_escape():
        _mark_status("off_origin_requests_blocked")
        raise CampaignGateError("campaign socket guard blocked an unscoped network endpoint")

    def _port_number(port):
        if port is None:
            return None
        try:
            return int(port)
        except (TypeError, ValueError):
            try:
                return socket.getservbyname(str(port), "tcp")
            except OSError:
                return None

    def _check_socket_address(address, protocol):
        if not isinstance(address, tuple) or len(address) < 2:
            return
        host, port = address[0], _port_number(address[1])
        if port is None or not network_endpoint_is_scoped(host, port, protocol):
            _deny_network_escape()

    def _guard_getaddrinfo(host, port, family=0, type=0, proto=0, flags=0):
        try:
            normalized = _normalize_network_host(host)
        except (TypeError, ValueError, UnicodeError):
            normalized = ""
        try:
            ipaddress.ip_address(normalized)
            is_ip = True
        except ValueError:
            is_ip = False
        if not is_ip:
            requested_port = _port_number(port)
            protocol = "udp" if type == socket.SOCK_DGRAM else "tcp"
            if normalized == _origin_host and (requested_port is None or requested_port == _origin_port):
                addresses = _origin_addresses
            elif (requested_port is not None
                  and network_endpoint_is_scoped(normalized, requested_port, protocol)):
                addresses = {_normalize_network_host(item) for item in
                             _endpoint_addresses.get(normalized, []) if isinstance(item, str)}
                if not addresses:
                    return _original_getaddrinfo(host, port, family, type, proto, flags)
            else:
                _deny_network_escape()
            numeric_results = []
            for address in addresses:
                try:
                    numeric_results.extend(_original_getaddrinfo(
                        address, port, family, type, proto, flags | socket.AI_NUMERICHOST))
                except OSError:
                    continue
            if not numeric_results:
                _deny_network_escape()
            return numeric_results
        return _original_getaddrinfo(host, port, family, type, proto, flags)

    def _guard_gethostbyname(host):
        results = _guard_getaddrinfo(host, _origin_port, family=socket.AF_INET,
                                     type=socket.SOCK_STREAM)
        if not results:
            raise OSError("campaign origin has no IPv4 address")
        return results[0][4][0]

    def _guard_gethostbyname_ex(host):
        results = _guard_getaddrinfo(host, _origin_port, family=socket.AF_INET,
                                     type=socket.SOCK_STREAM)
        addresses = sorted({row[4][0] for row in results})
        if not addresses:
            raise OSError("campaign origin has no IPv4 address")
        return str(host), [], addresses

    def _guard_gethostbyaddr(address):
        _deny_network_escape()

    def _guard_connect(sock, address):
        if sock.family != getattr(socket, "AF_UNIX", object()):
            _check_socket_address(address, "tcp" if sock.type & socket.SOCK_STREAM else "udp")
        return _original_connect(sock, address)

    def _guard_connect_ex(sock, address):
        if sock.family != getattr(socket, "AF_UNIX", object()):
            _check_socket_address(address, "tcp" if sock.type & socket.SOCK_STREAM else "udp")
        return _original_connect_ex(sock, address)

    def _guard_sendto(sock, data, *args, **kwargs):
        address = kwargs.get("address") or (args[-1] if args else None)
        if sock.family != getattr(socket, "AF_UNIX", object()):
            _check_socket_address(address, "udp")
        return _original_sendto(sock, data, *args, **kwargs)

    def _guard_sendmsg(sock, buffers, ancdata=(), flags=0, address=None):
        if sock.family != getattr(socket, "AF_UNIX", object()) and address is not None:
            _check_socket_address(address, "udp")
        if _original_sendmsg is None:
            raise CampaignGateError("campaign socket guard does not support sendmsg")
        return _original_sendmsg(sock, buffers, ancdata, flags, address)

    socket.getaddrinfo = _guard_getaddrinfo
    socket.gethostbyname = _guard_gethostbyname
    socket.gethostbyname_ex = _guard_gethostbyname_ex
    socket.gethostbyaddr = _guard_gethostbyaddr
    socket.socket.connect = _guard_connect
    socket.socket.connect_ex = _guard_connect_ex
    socket.socket.sendto = _guard_sendto
    if _original_sendmsg is not None:
        socket.socket.sendmsg = _guard_sendmsg
    def _no_campaign_proxies():
        return {}

    urllib.request.getproxies = _no_campaign_proxies
    for _proxy_variable in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy",
                            "https_proxy", "all_proxy"):
        os.environ.pop(_proxy_variable, None)

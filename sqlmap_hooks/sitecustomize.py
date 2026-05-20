import os
import random
import socket
import sys


PORT_ENV = "SQLMAP_DNS_PORT"
START_ENV = "SQLMAP_DNS_PORT_RANGE_START"
END_ENV = "SQLMAP_DNS_PORT_RANGE_END"
DEFAULT_START = 30000
DEFAULT_END = 40000

_CACHED_DNS_PORT = None


def _warn(message):
    try:
        sys.stderr.write(f"{message}\n")
    except Exception:
        pass


def _to_int(value, default):
    try:
        return int(str(value).strip())
    except Exception:
        return default


def _resolve_port_range():
    start = _to_int(os.getenv(START_ENV), DEFAULT_START)
    end = _to_int(os.getenv(END_ENV), DEFAULT_END)
    if start > end:
        start, end = end, start
    start = max(1024, start)
    end = min(65535, end)
    if start > end:
        start, end = DEFAULT_START, DEFAULT_END
    return start, end


def _can_bind_udp_port(port):
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(("", port))
        return True
    except OSError:
        return False
    finally:
        if sock:
            sock.close()


def _choose_random_port(start, end):
    candidates = list(range(start, end + 1))
    random.SystemRandom().shuffle(candidates)
    for port in candidates:
        if _can_bind_udp_port(port):
            return port
    raise RuntimeError(f"no available UDP port found in range {start}-{end}")


def get_dns_port():
    global _CACHED_DNS_PORT

    if _CACHED_DNS_PORT is not None:
        return _CACHED_DNS_PORT

    start, end = _resolve_port_range()
    configured = os.getenv(PORT_ENV)

    if configured:
        port = _to_int(configured, -1)
        if not (start <= port <= end):
            raise RuntimeError(
                f"{PORT_ENV} must be within {start}-{end}, got {configured!r}"
            )
        _CACHED_DNS_PORT = port
    else:
        _CACHED_DNS_PORT = _choose_random_port(start, end)
        os.environ[PORT_ENV] = str(_CACHED_DNS_PORT)

    return _CACHED_DNS_PORT


def _install_dns_server_patch():
    import binascii
    import threading

    from lib.request import dns as dns_module

    def _check_localhost(self):
        response = b""
        sock = None
        port = get_dns_port()

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(1.0)
            sock.connect(("", port))
            sock.send(
                binascii.unhexlify(
                    "6509012000010000000000010377777706676f6f676c6503636f6d00000100010000291000000000000000"
                )
            )
            response = sock.recv(512)
        except Exception:
            pass
        finally:
            if sock:
                sock.close()

        if response and b"google" in response:
            raise socket.error(
                f"another DNS service already running on '0.0.0.0:{port}'"
            )

    def _patched_init(self):
        self._dns_port = get_dns_port()
        self._check_localhost()
        self._requests = []
        self._lock = threading.Lock()

        try:
            self._socket = socket._orig_socket(socket.AF_INET, socket.SOCK_DGRAM)
        except AttributeError:
            self._socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._socket.bind(("", self._dns_port))
        self._running = False
        self._initialized = False

    dns_module.DNSServer._check_localhost = _check_localhost
    dns_module.DNSServer.__init__ = _patched_init


def _install_option_patch():
    from lib.core import option as option_module
    from lib.core.common import getSafeExString
    from lib.core.exception import SqlmapGenericException
    from lib.core.exception import SqlmapMissingPrivileges

    def _patched_set_dns_server():
        if not option_module.conf.dnsDomain:
            return

        option_module.logger.info("setting up DNS server instance")

        dns_port = get_dns_port()
        needs_admin = dns_port < 1024

        if needs_admin and not option_module.runningAsAdmin():
            err_msg = "you need to run sqlmap as an administrator "
            err_msg += "if you want to perform a DNS data exfiltration attack "
            err_msg += f"as it will need to listen on privileged UDP port {dns_port} "
            err_msg += "for incoming address resolution attempts"
            raise SqlmapMissingPrivileges(err_msg)

        try:
            option_module.conf.dnsServer = option_module.DNSServer()
            option_module.conf.dnsServer.run()
        except socket.error as ex:
            err_msg = "there was an error while setting up "
            err_msg += "DNS server instance ('%s')" % getSafeExString(ex)
            raise SqlmapGenericException(err_msg)

    option_module._setDNSServer = _patched_set_dns_server


def _install_api_patch():
    import os as _os
    import sys as _sys

    from lib.core.settings import IS_WIN
    from lib.core.subprocessng import Popen
    from lib.utils import api as api_module

    def _patched_engine_start(self):
        handle, config_file = api_module.tempfile.mkstemp(
            prefix=api_module.MKSTEMP_PREFIX.CONFIG,
            text=True,
        )
        _os.close(handle)
        api_module.saveConfig(self.options, config_file)

        wrapper_bin = _os.getenv("SQLMAP_API_WRAPPER")
        if wrapper_bin:
            self.process = Popen(
                [wrapper_bin, "--api", "-c", config_file],
                shell=False,
                close_fds=not IS_WIN,
            )
            return

        if _os.path.exists("sqlmap.py"):
            self.process = Popen(
                [_sys.executable or "python", "sqlmap.py", "--api", "-c", config_file],
                shell=False,
                close_fds=not IS_WIN,
            )
        elif _os.path.exists(_os.path.join(_os.getcwd(), "sqlmap.py")):
            self.process = Popen(
                [_sys.executable or "python", "sqlmap.py", "--api", "-c", config_file],
                shell=False,
                cwd=_os.getcwd(),
                close_fds=not IS_WIN,
            )
        elif _os.path.exists(_os.path.join(_os.path.abspath(_os.path.dirname(_sys.argv[0])), "sqlmap.py")):
            self.process = Popen(
                [_sys.executable or "python", "sqlmap.py", "--api", "-c", config_file],
                shell=False,
                cwd=_os.path.join(_os.path.abspath(_os.path.dirname(_sys.argv[0]))),
                close_fds=not IS_WIN,
            )
        else:
            self.process = Popen(
                ["sqlmap", "--api", "-c", config_file],
                shell=False,
                close_fds=not IS_WIN,
            )

    api_module.Task.engine_start = _patched_engine_start


def _try_install(label, installer, success_message):
    try:
        installer()
        _warn(success_message)
        return True
    except Exception as ex:
        _warn(f"[sqlmap-hook] {label} not activated: {ex}")
        return False


def _bootstrap():
    port = None
    try:
        port = get_dns_port()
        _warn(f"[sqlmap-hook] Selected UDP port {port} for sqlmap DNS handling")
    except Exception as ex:
        _warn(f"[sqlmap-hook] DNS port selection failed: {ex}")

    dns_patch_ok = _try_install(
        "DNS server patch",
        _install_dns_server_patch,
        "[sqlmap-hook] DNS server patch installed",
    )
    option_patch_ok = _try_install(
        "DNS option patch",
        _install_option_patch,
        "[sqlmap-hook] DNS option patch installed",
    )
    _try_install(
        "API wrapper patch",
        _install_api_patch,
        "[sqlmap-hook] API wrapper patch installed",
    )

    if port is not None and dns_patch_ok and option_patch_ok:
        _warn(f"[sqlmap-hook] DNS server will use UDP port {port}")


_bootstrap()

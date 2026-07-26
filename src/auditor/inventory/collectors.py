"""Production SSH / WinRM / composite discovery collectors (INPUT-005)."""

from __future__ import annotations

import asyncio
import logging
import re
import socket
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Protocol

from auditor.domain.inventory import ClientInventory, InventoryHost
from auditor.inventory.discovery_evidence import (
    COLLECTOR_VERSION,
    CommandEvidence,
    HostDiscoveryEvidence,
    persist_host_evidence,
    sanitize_text,
    utc_now,
)
from auditor.secrets_file import (
    InventorySshTarget,
    bind_ssh_target,
    bind_winrm_target,
    list_client_ssh_targets,
)

logger = logging.getLogger(__name__)

# Typed discovery error codes (INPUT-005 §4).
ERROR_CONNECTION_TIMEOUT = "connection_timeout"
ERROR_AUTHENTICATION_FAILED = "authentication_failed"
ERROR_HOST_UNREACHABLE = "host_unreachable"
ERROR_COMMAND_TIMEOUT = "command_timeout"
ERROR_UNSUPPORTED_TRANSPORT = "unsupported_transport"
ERROR_DISCOVERY_FAILED = "discovery_failed"
ERROR_PARTIAL_DISCOVERY = "partial_discovery"

ConfidenceLevel = str  # high | medium | low


@dataclass(slots=True)
class DiscoveryHostSettings:
    """Per-host discovery timeouts and retries."""

    connection_timeout: float = 15.0
    command_timeout: float = 30.0
    retry_count: int = 1  # one retry after the initial attempt (2 tries)


@dataclass(slots=True)
class CommandResult:
    """Raw remote command outcome before sanitization."""

    command: str
    exit_code: int | None = None
    stdout: str = ""
    stderr: str = ""
    error: str = ""
    error_code: str = ""


class ShellTransport(Protocol):
    """Injectable transport for unit tests and production collectors."""

    def run(self, command: str, *, timeout: float) -> CommandResult: ...


@dataclass(slots=True)
class DiscoveredHostFacts:
    """Facts collected by read-only SSH/WinRM discovery."""

    host_id: str
    os_name: str = ""
    os_family: str = ""
    os_version: str = ""
    hostname: str = ""
    services: list[str] = field(default_factory=list)
    running_services: list[str] = field(default_factory=list)
    listening_ports: list[int] = field(default_factory=list)
    postgres_packages: list[str] = field(default_factory=list)
    postgres_processes: list[str] = field(default_factory=list)
    postgres_services: list[str] = field(default_factory=list)
    postgres_binaries: list[str] = field(default_factory=list)
    transport: str = ""
    collector: str = ""
    confidence: ConfidenceLevel = "high"
    evidence_ref: str = ""
    collected_at: str = ""
    error: str = ""
    error_code: str = ""
    limitations: list[str] = field(default_factory=list)
    command_results: list[CommandResult] = field(default_factory=list)


# Re-export name used by discovery.py / tests historically.
# (discovery.py will import DiscoveredHostFacts from here or redefine thin wrapper)


SSH_COMMANDS: tuple[str, ...] = (
    "hostname",
    "cat /etc/os-release",
    "uname -a",
    "ss -lntup || netstat -lntup",
    "systemctl list-units --type=service --state=running --no-pager",
    "command -v psql",
    "command -v postgres",
    "ps -ef",
    "ps -ef | grep '[p]ostgres'",
    "systemctl list-units --type=service --all | grep -i postgres",
    "dpkg-query -W 2>/dev/null | grep -i postgres || rpm -qa 2>/dev/null | grep -i postgres",
)

WINRM_COMMANDS: tuple[str, ...] = (
    (
        "Get-CimInstance Win32_OperatingSystem | "
        "Select-Object Caption,Version,OSArchitecture | Format-List"
    ),
    "$env:COMPUTERNAME",
    "Get-Service | Select-Object Name,Status,DisplayName | Format-Table -AutoSize",
    (
        "Get-NetTCPConnection -State Listen | "
        "Select-Object LocalAddress,LocalPort,OwningProcess | Format-Table -AutoSize"
    ),
    "Get-Process | Select-Object Name,Id,Path | Format-Table -AutoSize",
    "Get-CimInstance Win32_Product | Select-Object Name,Version | Format-Table -AutoSize",
)


def _classify_transport_error(exc: BaseException) -> str:
    text = f"{type(exc).__name__}: {exc}".lower()
    if "auth" in text or "permission denied" in text or "credentials" in text:
        return ERROR_AUTHENTICATION_FAILED
    if "timed out" in text or "timeout" in text:
        return ERROR_CONNECTION_TIMEOUT
    if (
        "connection refused" in text
        or "no route" in text
        or "network is unreachable" in text
        or "name or service not known" in text
        or "nodename nor servname" in text
    ):
        return ERROR_HOST_UNREACHABLE
    return ERROR_DISCOVERY_FAILED


def _os_family_from_name(os_name: str) -> str:
    low = (os_name or "").strip().lower()
    if not low:
        return ""
    if "win" in low:
        return "windows"
    if any(
        tok in low
        for tok in ("ubuntu", "debian", "linux", "centos", "rhel", "rocky", "fedora", "suse")
    ):
        return "linux"
    return "unknown"


def _parse_os_release(text: str) -> tuple[str, str, str]:
    """Return (os_name, os_family, os_version) from /etc/os-release."""
    data: dict[str, str] = {}
    for line in (text or "").splitlines():
        if "=" not in line:
            continue
        key, _, raw = line.partition("=")
        data[key.strip()] = raw.strip().strip('"')
    name = data.get("PRETTY_NAME") or data.get("NAME") or ""
    version = data.get("VERSION_ID") or data.get("VERSION") or ""
    family = _os_family_from_name(name) or "linux"
    return name, family, version


def _parse_listening_ports_linux(text: str) -> list[int]:
    ports: set[int] = set()
    for match in re.finditer(r":(\d{1,5})\s", text or ""):
        try:
            port = int(match.group(1))
        except ValueError:
            continue
        if 1 <= port <= 65535:
            ports.add(port)
    return sorted(ports)


def _parse_listening_ports_windows(text: str) -> list[int]:
    ports: set[int] = set()
    for match in re.finditer(r"\b(\d{1,5})\b", text or ""):
        try:
            port = int(match.group(1))
        except ValueError:
            continue
        if 1 <= port <= 65535 and port not in {0}:
            # Heuristic: WinRM Format-Table includes LocalPort column values.
            if port >= 1:
                ports.add(port)
    # Keep common server ports; drop very high ephemeral-looking noise later if needed.
    return sorted(p for p in ports if p < 60000)


def _parse_running_services_linux(text: str) -> list[str]:
    names: list[str] = []
    for line in (text or "").splitlines():
        line = line.strip()
        if not line or line.startswith("UNIT") or line.startswith("●"):
            # systemctl may prefix with ●
            line = line.lstrip("●").strip()
        if not line or line.startswith("UNIT") or line.startswith("LOAD"):
            continue
        parts = line.split()
        if not parts:
            continue
        unit = parts[0]
        if unit.endswith(".service"):
            names.append(unit[: -len(".service")])
        elif "." not in unit and unit not in {"loaded", "active"}:
            names.append(unit)
    return sorted(set(names))


def _parse_running_services_windows(text: str) -> list[str]:
    names: list[str] = []
    for line in (text or "").splitlines():
        low = line.lower()
        if "running" not in low:
            continue
        parts = line.split()
        if parts:
            names.append(parts[0])
    return sorted(set(names))


def postgres_confirmed(
    *,
    processes: list[str],
    services: list[str],
    packages: list[str],
    binaries: list[str],
    listening_ports: list[int],
) -> bool:
    """Return True only when strong PostgreSQL evidence exists."""
    if processes or services:
        return True
    has_pkg_or_bin = bool(packages or binaries)
    if has_pkg_or_bin and (processes or services or 5432 in listening_ports):
        return True
    if packages and binaries:
        return True
    return False


def _extract_postgres_linux(
    results: dict[str, CommandResult],
) -> tuple[list[str], list[str], list[str], list[str]]:
    processes: list[str] = []
    services: list[str] = []
    packages: list[str] = []
    binaries: list[str] = []

    proc = results.get("ps -ef | grep '[p]ostgres'")
    if proc and proc.stdout.strip():
        processes = [ln.strip() for ln in proc.stdout.splitlines() if ln.strip()]

    # Also scan full ps -ef for postgres postmaster.
    ps_all = results.get("ps -ef")
    if ps_all and not processes:
        for ln in ps_all.stdout.splitlines():
            if re.search(r"\b(postgres|postmaster)\b", ln, re.I) and "grep" not in ln:
                processes.append(ln.strip())

    svc = results.get("systemctl list-units --type=service --all | grep -i postgres")
    if svc and svc.stdout.strip():
        for ln in svc.stdout.splitlines():
            parts = ln.lstrip("●").split()
            if parts:
                name = parts[0].removesuffix(".service")
                if "postgres" in name.lower():
                    services.append(name)

    pkg_cmd = (
        "dpkg-query -W 2>/dev/null | grep -i postgres || rpm -qa 2>/dev/null | grep -i postgres"
    )
    pkg = results.get(pkg_cmd)
    if pkg and pkg.stdout.strip():
        packages = [ln.strip() for ln in pkg.stdout.splitlines() if ln.strip()]

    for cmd in ("command -v psql", "command -v postgres"):
        res = results.get(cmd)
        if res and res.exit_code == 0 and res.stdout.strip():
            binaries.append(res.stdout.strip().splitlines()[0].strip())

    return processes, services, packages, binaries


def _extract_postgres_windows(
    results: dict[str, CommandResult],
) -> tuple[list[str], list[str], list[str]]:
    processes: list[str] = []
    services: list[str] = []
    products: list[str] = []

    svc = results.get(
        "Get-Service | Select-Object Name,Status,DisplayName | Format-Table -AutoSize"
    )
    if svc:
        for ln in svc.stdout.splitlines():
            if "postgres" in ln.lower():
                services.append(ln.strip())

    proc = results.get("Get-Process | Select-Object Name,Id,Path | Format-Table -AutoSize")
    if proc:
        for ln in proc.stdout.splitlines():
            if re.search(r"\bpostgres", ln, re.I):
                processes.append(ln.strip())

    prod = results.get(
        "Get-CimInstance Win32_Product | Select-Object Name,Version | Format-Table -AutoSize"
    )
    if prod:
        for ln in prod.stdout.splitlines():
            if "postgres" in ln.lower():
                products.append(ln.strip())

    return processes, services, products


@dataclass(slots=True)
class FakeShellTransport:
    """Deterministic transport for unit tests."""

    responses: dict[str, CommandResult] = field(default_factory=dict)
    default: CommandResult | None = None
    connect_error: Exception | None = None

    def run(self, command: str, *, timeout: float) -> CommandResult:
        if self.connect_error is not None:
            raise self.connect_error
        if command in self.responses:
            return self.responses[command]
        for key, value in self.responses.items():
            if key in command or command in key:
                return value
        if self.default is not None:
            return self.default
        return CommandResult(command=command, exit_code=0, stdout="")


@dataclass(slots=True)
class AsyncsshTransport:
    """Production SSH transport using asyncssh (sync wrapper)."""

    host: str
    port: int
    username: str
    password: str = ""
    private_key_path: str = ""
    connect_timeout: float = 15.0
    strict_host_key: bool = False

    def run(self, command: str, *, timeout: float) -> CommandResult:
        def _call() -> CommandResult:
            return asyncio.run(self._arun(command, timeout=timeout))

        try:
            asyncio.get_running_loop()
        except RuntimeError:
            return _call()
        # FastAPI / other running loops: offload to a worker thread.
        with ThreadPoolExecutor(max_workers=1) as pool:
            return pool.submit(_call).result()

    async def _arun(self, command: str, *, timeout: float) -> CommandResult:
        import asyncssh

        kwargs: dict[str, Any] = {
            "host": self.host,
            "port": self.port,
            "username": self.username,
            "connect_timeout": self.connect_timeout,
        }
        if not self.strict_host_key:
            kwargs["known_hosts"] = None
        if self.private_key_path:
            kwargs["client_keys"] = [self.private_key_path]
        elif self.password:
            kwargs["password"] = self.password
        try:
            async with asyncssh.connect(**kwargs) as conn:
                try:
                    result = await asyncio.wait_for(
                        conn.run(command, check=False),
                        timeout=timeout,
                    )
                except TimeoutError:
                    return CommandResult(
                        command=command,
                        error=f"command timeout after {timeout}s",
                        error_code=ERROR_COMMAND_TIMEOUT,
                    )
                stdout_raw = result.stdout or ""
                stderr_raw = result.stderr or ""
                stdout = (
                    stdout_raw.decode("utf-8", errors="replace")
                    if isinstance(stdout_raw, bytes)
                    else str(stdout_raw)
                )
                stderr = (
                    stderr_raw.decode("utf-8", errors="replace")
                    if isinstance(stderr_raw, bytes)
                    else str(stderr_raw)
                )
                exit_code = result.exit_status
                if exit_code is None and not stderr.strip():
                    # Some servers omit exit status on clean channel close.
                    exit_code = 0
                return CommandResult(
                    command=command,
                    exit_code=int(exit_code) if exit_code is not None else None,
                    stdout=stdout,
                    stderr=stderr,
                )
        except Exception as exc:  # noqa: BLE001
            code = _classify_transport_error(exc)
            if "timeout" in str(exc).lower() and code == ERROR_DISCOVERY_FAILED:
                code = ERROR_CONNECTION_TIMEOUT
            raise DiscoveryTransportError(str(exc), code=code) from exc


@dataclass(slots=True)
class WinrmTransport:
    """Production WinRM transport using pywinrm."""

    host: str
    port: int
    username: str
    password: str = ""
    transport: str = "ntlm"
    use_ssl: bool = False
    verify_ssl: bool = False
    command_timeout: float = 30.0

    def run(self, command: str, *, timeout: float) -> CommandResult:
        try:
            import winrm
        except ImportError as exc:  # pragma: no cover
            raise DiscoveryTransportError(
                "pywinrm is not installed",
                code=ERROR_DISCOVERY_FAILED,
            ) from exc
        scheme = "https" if self.use_ssl else "http"
        endpoint = f"{scheme}://{self.host}:{self.port}/wsman"
        try:
            session = winrm.Session(
                endpoint,
                auth=(self.username, self.password),
                transport=self.transport or "ntlm",
                server_cert_validation="validate" if self.verify_ssl else "ignore",
                operation_timeout_sec=int(timeout or self.command_timeout),
                read_timeout_sec=int(timeout or self.command_timeout) + 10,
            )
            result = session.run_ps(command)
            stdout = (result.std_out or b"").decode("utf-8", errors="replace")
            stderr = (result.std_err or b"").decode("utf-8", errors="replace")
            return CommandResult(
                command=command,
                exit_code=int(result.status_code) if result.status_code is not None else None,
                stdout=stdout,
                stderr=stderr,
            )
        except Exception as exc:  # noqa: BLE001
            code = _classify_transport_error(exc)
            raise DiscoveryTransportError(str(exc), code=code) from exc


class DiscoveryTransportError(Exception):
    """Transport-level discovery failure with a typed code."""

    def __init__(self, message: str, *, code: str = ERROR_DISCOVERY_FAILED) -> None:
        super().__init__(message)
        self.code = code


def _host_settings(
    host: InventoryHost,
    defaults: DiscoveryHostSettings,
    overrides: dict[str, DiscoveryHostSettings] | None,
) -> DiscoveryHostSettings:
    if overrides and host.host_id in overrides:
        return overrides[host.host_id]
    # Optional host-note overrides: connection_timeout=… command_timeout=… retry_count=…
    note = host.notes or ""
    conn = defaults.connection_timeout
    cmd = defaults.command_timeout
    retry = defaults.retry_count
    for key, caster in (
        ("connection_timeout", float),
        ("command_timeout", float),
        ("retry_count", int),
    ):
        match = re.search(rf"{key}\s*=\s*([0-9.]+)", note, re.I)
        if match:
            try:
                value = caster(match.group(1))
            except ValueError:
                continue
            if key == "connection_timeout":
                conn = float(value)
            elif key == "command_timeout":
                cmd = float(value)
            else:
                retry = int(value)
    return DiscoveryHostSettings(
        connection_timeout=conn,
        command_timeout=cmd,
        retry_count=retry,
    )


def _match_credential(
    host: InventoryHost,
    targets: list[InventorySshTarget],
    *,
    transport: str,
) -> InventorySshTarget | None:
    """Resolve runtime credentials for a host.

    Prefers an address/IP match from the credentials table over a host-id match
    from an in-scope hosts table (which often has Access+Host columns but no
    secret). Targets with a password or private key are preferred.
    """
    address = (host.address or host.hostname or "").strip().lower()
    host_id = host.host_id.strip().lower()
    matching = [t for t in targets if (t.transport or "ssh").strip().lower() == transport]

    def _score(target: InventorySshTarget) -> tuple[int, int, int]:
        th = (target.host or "").strip().lower()
        label = (target.label or "").strip().lower()
        address_hit = int(bool(th and address and th == address))
        host_id_hit = int(bool(th and th == host_id) or bool(label and label == host_id))
        has_secret = int(bool(target.password or target.private_key_path))
        return (address_hit, has_secret, host_id_hit)

    ranked = sorted(matching, key=_score, reverse=True)
    for target in ranked:
        address_hit, has_secret, host_id_hit = _score(target)
        if address_hit:
            return target
        if host_id_hit and has_secret:
            return target
    # Last resort: host-id match without secret (injected transports / lab).
    for target in ranked:
        _address_hit, _has_secret, host_id_hit = _score(target)
        if host_id_hit:
            return target
    return None


def _tcp_reachable(host: str, port: int, timeout: float) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def _sanitize_command_results(
    results: list[CommandResult],
    *,
    known_secrets: list[str],
) -> list[CommandResult]:
    """Return command results with secrets redacted (safe for in-memory facts)."""
    sanitized: list[CommandResult] = []
    for item in results:
        sanitized.append(
            CommandResult(
                command=item.command,
                exit_code=item.exit_code,
                stdout=sanitize_text(item.stdout, known_secrets=known_secrets),
                stderr=sanitize_text(item.stderr, known_secrets=known_secrets),
                error=sanitize_text(item.error, known_secrets=known_secrets),
                error_code=item.error_code,
            )
        )
    return sanitized


def _run_with_retries(
    transport: ShellTransport,
    command: str,
    *,
    settings: DiscoveryHostSettings,
) -> CommandResult:
    attempts = max(1, int(settings.retry_count) + 1)
    last: CommandResult | None = None
    for attempt in range(attempts):
        try:
            result = transport.run(command, timeout=settings.command_timeout)
        except DiscoveryTransportError as exc:
            last = CommandResult(command=command, error=str(exc), error_code=exc.code)
            if attempt + 1 >= attempts:
                return last
            continue
        except Exception as exc:  # noqa: BLE001
            code = _classify_transport_error(exc)
            last = CommandResult(command=command, error=str(exc), error_code=code)
            if attempt + 1 >= attempts:
                return last
            continue
        if result.error_code == ERROR_COMMAND_TIMEOUT and attempt + 1 < attempts:
            last = result
            continue
        return result
    return last or CommandResult(
        command=command,
        error="discovery failed",
        error_code=ERROR_DISCOVERY_FAILED,
    )


@dataclass(slots=True)
class SshDiscoveryCollector:
    """Read-only SSH discovery for Linux/Unix hosts."""

    inventory_dir: Path | str
    client_name: str
    artifacts_root: Path | str | None = None
    defaults: DiscoveryHostSettings = field(default_factory=DiscoveryHostSettings)
    host_overrides: dict[str, DiscoveryHostSettings] = field(default_factory=dict)
    transport_factory: (
        Callable[[InventorySshTarget, DiscoveryHostSettings], ShellTransport] | None
    ) = None
    collector_version: str = COLLECTOR_VERSION

    def discover(self, inventory: ClientInventory) -> list[DiscoveredHostFacts]:
        targets = list_client_ssh_targets(self.inventory_dir, self.client_name)
        results: list[DiscoveredHostFacts] = []
        for host in inventory.hosts:
            if "ssh" not in host.connection_types and host.os_family == "windows":
                continue
            if "ssh" not in host.connection_types and "winrm" in host.connection_types:
                continue
            os_ok = host.os_family in {"", "linux", "unknown"}
            if "ssh" not in host.connection_types and not os_ok:
                # Still try SSH when access is undeclared / linux-ish.
                if "winrm" in host.connection_types:
                    continue
            results.append(self._discover_host(host, inventory, targets))
        return results

    def _discover_host(
        self,
        host: InventoryHost,
        inventory: ClientInventory,
        targets: list[InventorySshTarget],
    ) -> DiscoveredHostFacts:
        settings = _host_settings(host, self.defaults, self.host_overrides)
        cred = _match_credential(host, targets, transport="ssh")
        collected_at = utc_now()
        if cred is None:
            return DiscoveredHostFacts(
                host_id=host.host_id,
                transport="ssh",
                collector="ssh",
                collected_at=collected_at,
                error="no SSH credentials resolved at runtime",
                error_code=ERROR_AUTHENTICATION_FAILED,
                limitations=["missing_ssh_credentials"],
                confidence="low",
            )
        known_secrets = [cred.password] if cred.password else []

        factory = self.transport_factory or _default_ssh_transport
        try:
            transport = factory(cred, settings)
        except Exception as exc:  # noqa: BLE001
            return DiscoveredHostFacts(
                host_id=host.host_id,
                transport="ssh",
                collector="ssh",
                collected_at=collected_at,
                error=str(exc),
                error_code=_classify_transport_error(exc),
                confidence="low",
            )

        # Optional reachability probe.
        try:
            port = int(cred.port or "22")
        except ValueError:
            port = 22
        if not _tcp_reachable(cred.host, port, settings.connection_timeout):
            facts = DiscoveredHostFacts(
                host_id=host.host_id,
                transport="ssh",
                collector="ssh",
                collected_at=collected_at,
                error=f"host unreachable: {cred.host}:{port}",
                error_code=ERROR_HOST_UNREACHABLE,
                limitations=["host_unreachable"],
                confidence="low",
            )
            self._persist(facts, inventory, known_secrets)
            return facts

        command_results: list[CommandResult] = []
        by_cmd: dict[str, CommandResult] = {}
        connect_error: DiscoveredHostFacts | None = None
        with bind_ssh_target(cred):
            for command in SSH_COMMANDS:
                result = _run_with_retries(transport, command, settings=settings)
                command_results.append(result)
                by_cmd[command] = result
                if (
                    result.error_code
                    in {
                        ERROR_AUTHENTICATION_FAILED,
                        ERROR_CONNECTION_TIMEOUT,
                        ERROR_HOST_UNREACHABLE,
                    }
                    and command == SSH_COMMANDS[0]
                ):
                    connect_error = DiscoveredHostFacts(
                        host_id=host.host_id,
                        transport="ssh",
                        collector="ssh",
                        collected_at=collected_at,
                        error=result.error or result.error_code,
                        error_code=result.error_code,
                        limitations=[result.error_code],
                        confidence="low",
                        command_results=command_results,
                    )
                    break

        if connect_error is not None:
            connect_error.command_results = _sanitize_command_results(
                connect_error.command_results, known_secrets=known_secrets
            )
            self._persist(connect_error, inventory, known_secrets)
            return connect_error

        os_name = ""
        os_family = ""
        os_version = ""
        hostname = ""
        limitations: list[str] = []
        partial = False

        hn = by_cmd.get("hostname")
        if hn and hn.stdout.strip() and not hn.error_code:
            hostname = hn.stdout.strip().splitlines()[0].strip()
        elif hn and (hn.error_code or (hn.exit_code not in {0, None} and not hn.stdout.strip())):
            partial = True
            limitations.append("hostname_command_failed")

        osr = by_cmd.get("cat /etc/os-release")
        if osr and osr.stdout.strip() and not osr.error_code:
            os_name, os_family, os_version = _parse_os_release(osr.stdout)
        else:
            uname = by_cmd.get("uname -a")
            if uname and uname.stdout.strip():
                os_name = uname.stdout.strip()
                os_family = "linux" if "linux" in os_name.lower() else _os_family_from_name(os_name)
            else:
                partial = True
                limitations.append("os_release_unavailable")

        ports_res = by_cmd.get("ss -lntup || netstat -lntup")
        listening_ports: list[int] = []
        if ports_res and ports_res.stdout.strip() and not ports_res.error_code:
            listening_ports = _parse_listening_ports_linux(ports_res.stdout)
        elif ports_res and ports_res.error_code:
            partial = True
            limitations.append("listening_ports_unavailable")

        svc_res = by_cmd.get("systemctl list-units --type=service --state=running --no-pager")
        running_services: list[str] = []
        if svc_res and svc_res.stdout.strip() and not svc_res.error_code:
            running_services = _parse_running_services_linux(svc_res.stdout)
        elif svc_res and svc_res.error_code:
            partial = True
            limitations.append("running_services_unavailable")

        processes, pg_services, packages, binaries = _extract_postgres_linux(by_cmd)
        confirmed = postgres_confirmed(
            processes=processes,
            services=pg_services,
            packages=packages,
            binaries=binaries,
            listening_ports=listening_ports,
        )
        services = ["ssh"]
        if confirmed:
            services.append("postgresql")

        confidence: ConfidenceLevel = "high"
        error_code = ""
        error = ""
        if partial and (os_family or services):
            error_code = ERROR_PARTIAL_DISCOVERY
            error = "partial discovery: some commands failed"
            confidence = "medium"
        elif not os_family and not services:
            error_code = ERROR_DISCOVERY_FAILED
            error = "discovery produced no usable facts"
            confidence = "low"

        evidence_ref = (
            f"artifacts/{inventory.client_id}/preflight/"
            f"{inventory.version.version_id}/{host.host_id}/discovery.json"
        )
        safe_results = _sanitize_command_results(command_results, known_secrets=known_secrets)
        facts = DiscoveredHostFacts(
            host_id=host.host_id,
            os_name=os_name,
            os_family=os_family or _os_family_from_name(os_name),
            os_version=os_version,
            hostname=hostname,
            services=services,
            running_services=running_services,
            listening_ports=listening_ports,
            postgres_packages=packages,
            postgres_processes=[sanitize_text(p, known_secrets=known_secrets) for p in processes],
            postgres_services=pg_services,
            postgres_binaries=binaries,
            transport="ssh",
            collector="ssh",
            confidence=confidence,
            evidence_ref=evidence_ref,
            collected_at=collected_at,
            error=error,
            error_code=error_code,
            limitations=limitations,
            command_results=safe_results,
        )
        self._persist(facts, inventory, known_secrets)
        return facts

    def _persist(
        self,
        facts: DiscoveredHostFacts,
        inventory: ClientInventory,
        known_secrets: list[str],
    ) -> None:
        if self.artifacts_root is None:
            return
        commands = [
            CommandEvidence(
                command=c.command,
                exit_code=c.exit_code,
                stdout=sanitize_text(c.stdout, known_secrets=known_secrets),
                stderr=sanitize_text(c.stderr, known_secrets=known_secrets),
                collected_at=facts.collected_at,
                transport="ssh",
                error=sanitize_text(c.error, known_secrets=known_secrets),
            )
            for c in facts.command_results
        ]
        evidence = HostDiscoveryEvidence(
            host_id=facts.host_id,
            transport="ssh",
            collector="ssh",
            collector_version=self.collector_version,
            collected_at=facts.collected_at,
            facts={
                "hostname": facts.hostname,
                "os_name": facts.os_name,
                "os_family": facts.os_family,
                "os_version": facts.os_version,
                "running_services": list(facts.running_services),
                "listening_ports": list(facts.listening_ports),
                "postgres_packages": list(facts.postgres_packages),
                "postgres_processes": [
                    sanitize_text(p, known_secrets=known_secrets) for p in facts.postgres_processes
                ],
                "postgres_services": list(facts.postgres_services),
                "postgres_binaries": list(facts.postgres_binaries),
                "services": list(facts.services),
                "confidence": facts.confidence,
                "source": "discovered",
                "collector": "ssh",
            },
            commands=commands,
            error_code=facts.error_code,
            error=facts.error,
            limitations=list(facts.limitations),
        )
        try:
            persist_host_evidence(
                evidence,
                artifacts_root=self.artifacts_root,
                client_slug=inventory.client_id,
                inventory_version_id=inventory.version.version_id,
                known_secrets=known_secrets,
            )
        except Exception:  # noqa: BLE001
            logger.exception("failed to persist SSH discovery evidence for %s", facts.host_id)


def _default_ssh_transport(
    cred: InventorySshTarget,
    settings: DiscoveryHostSettings,
) -> ShellTransport:
    try:
        port = int(cred.port or "22")
    except ValueError:
        port = 22
    return AsyncsshTransport(
        host=cred.host,
        port=port,
        username=cred.user,
        password=cred.password,
        private_key_path=cred.private_key_path,
        connect_timeout=settings.connection_timeout,
        strict_host_key=(cred.strict_host_key or "").lower() in {"1", "true", "yes"},
    )


@dataclass(slots=True)
class WinrmDiscoveryCollector:
    """Read-only WinRM discovery for Windows hosts."""

    inventory_dir: Path | str
    client_name: str
    artifacts_root: Path | str | None = None
    defaults: DiscoveryHostSettings = field(default_factory=DiscoveryHostSettings)
    host_overrides: dict[str, DiscoveryHostSettings] = field(default_factory=dict)
    transport_factory: (
        Callable[[InventorySshTarget, DiscoveryHostSettings], ShellTransport] | None
    ) = None
    collector_version: str = COLLECTOR_VERSION

    def discover(self, inventory: ClientInventory) -> list[DiscoveredHostFacts]:
        targets = list_client_ssh_targets(self.inventory_dir, self.client_name)
        results: list[DiscoveredHostFacts] = []
        for host in inventory.hosts:
            if "winrm" not in host.connection_types and host.os_family != "windows":
                continue
            if "winrm" not in host.connection_types and "ssh" in host.connection_types:
                continue
            results.append(self._discover_host(host, inventory, targets))
        return results

    def _discover_host(
        self,
        host: InventoryHost,
        inventory: ClientInventory,
        targets: list[InventorySshTarget],
    ) -> DiscoveredHostFacts:
        settings = _host_settings(host, self.defaults, self.host_overrides)
        cred = _match_credential(host, targets, transport="winrm")
        collected_at = utc_now()
        if cred is None:
            return DiscoveredHostFacts(
                host_id=host.host_id,
                transport="winrm",
                collector="winrm",
                collected_at=collected_at,
                error="no WinRM credentials resolved at runtime",
                error_code=ERROR_AUTHENTICATION_FAILED,
                limitations=["missing_winrm_credentials"],
                confidence="low",
            )
        known_secrets = [cred.password] if cred.password else []
        factory = self.transport_factory or _default_winrm_transport
        try:
            transport = factory(cred, settings)
        except Exception as exc:  # noqa: BLE001
            return DiscoveredHostFacts(
                host_id=host.host_id,
                transport="winrm",
                collector="winrm",
                collected_at=collected_at,
                error=str(exc),
                error_code=_classify_transport_error(exc),
                confidence="low",
            )

        command_results: list[CommandResult] = []
        by_cmd: dict[str, CommandResult] = {}
        with bind_winrm_target(cred):
            for command in WINRM_COMMANDS:
                result = _run_with_retries(transport, command, settings=settings)
                command_results.append(result)
                by_cmd[command] = result
                if (
                    result.error_code
                    in {
                        ERROR_AUTHENTICATION_FAILED,
                        ERROR_CONNECTION_TIMEOUT,
                        ERROR_HOST_UNREACHABLE,
                    }
                    and command == WINRM_COMMANDS[0]
                ):
                    facts = DiscoveredHostFacts(
                        host_id=host.host_id,
                        transport="winrm",
                        collector="winrm",
                        collected_at=collected_at,
                        error=result.error or result.error_code,
                        error_code=result.error_code,
                        limitations=[result.error_code],
                        confidence="low",
                        command_results=command_results,
                    )
                    facts.command_results = _sanitize_command_results(
                        facts.command_results, known_secrets=known_secrets
                    )
                    self._persist(facts, inventory, known_secrets)
                    return facts

        os_cmd = WINRM_COMMANDS[0]
        os_res = by_cmd.get(os_cmd)
        os_name = ""
        os_version = ""
        if os_res and os_res.stdout.strip():
            for ln in os_res.stdout.splitlines():
                if "Caption" in ln and ":" in ln:
                    os_name = ln.split(":", 1)[1].strip()
                if "Version" in ln and ":" in ln and "OSArchitecture" not in ln:
                    os_version = ln.split(":", 1)[1].strip()
            if not os_name:
                os_name = os_res.stdout.strip().splitlines()[0].strip()
        if not os_name:
            os_name = "Windows Server"
        os_family = "windows"

        hn_res = by_cmd.get("$env:COMPUTERNAME")
        hostname = ""
        if hn_res and hn_res.stdout.strip():
            hostname = hn_res.stdout.strip().splitlines()[0].strip()

        svc_out = by_cmd.get(WINRM_COMMANDS[2])
        ports_out = by_cmd.get(WINRM_COMMANDS[3])
        running_services = _parse_running_services_windows(
            svc_out.stdout if svc_out is not None else ""
        )
        listening_ports = _parse_listening_ports_windows(
            ports_out.stdout if ports_out is not None else ""
        )
        processes, pg_services, products = _extract_postgres_windows(by_cmd)
        confirmed = postgres_confirmed(
            processes=processes,
            services=pg_services,
            packages=products,
            binaries=[],
            listening_ports=listening_ports,
        )
        services = ["winrm"]
        if confirmed:
            services.append("postgresql")

        partial = any(c.error_code for c in command_results[1:])
        confidence: ConfidenceLevel = "medium" if partial else "high"
        error_code = ERROR_PARTIAL_DISCOVERY if partial else ""
        error = "partial discovery: some commands failed" if partial else ""
        evidence_ref = (
            f"artifacts/{inventory.client_id}/preflight/"
            f"{inventory.version.version_id}/{host.host_id}/discovery.json"
        )
        safe_results = _sanitize_command_results(command_results, known_secrets=known_secrets)
        facts = DiscoveredHostFacts(
            host_id=host.host_id,
            os_name=os_name,
            os_family=os_family,
            os_version=os_version,
            hostname=hostname,
            services=services,
            running_services=running_services,
            listening_ports=listening_ports,
            postgres_packages=products,
            postgres_processes=[sanitize_text(p, known_secrets=known_secrets) for p in processes],
            postgres_services=pg_services,
            transport="winrm",
            collector="winrm",
            confidence=confidence,
            evidence_ref=evidence_ref,
            collected_at=collected_at,
            error=error,
            error_code=error_code,
            limitations=["partial_commands"] if partial else [],
            command_results=safe_results,
        )
        self._persist(facts, inventory, known_secrets)
        return facts

    def _persist(
        self,
        facts: DiscoveredHostFacts,
        inventory: ClientInventory,
        known_secrets: list[str],
    ) -> None:
        if self.artifacts_root is None:
            return
        commands = [
            CommandEvidence(
                command=c.command,
                exit_code=c.exit_code,
                stdout=sanitize_text(c.stdout, known_secrets=known_secrets),
                stderr=sanitize_text(c.stderr, known_secrets=known_secrets),
                collected_at=facts.collected_at,
                transport="winrm",
                error=sanitize_text(c.error, known_secrets=known_secrets),
            )
            for c in facts.command_results
        ]
        evidence = HostDiscoveryEvidence(
            host_id=facts.host_id,
            transport="winrm",
            collector="winrm",
            collector_version=self.collector_version,
            collected_at=facts.collected_at,
            facts={
                "hostname": facts.hostname,
                "os_name": facts.os_name,
                "os_family": facts.os_family,
                "os_version": facts.os_version,
                "running_services": list(facts.running_services),
                "listening_ports": list(facts.listening_ports),
                "postgres_packages": list(facts.postgres_packages),
                "postgres_processes": [
                    sanitize_text(p, known_secrets=known_secrets) for p in facts.postgres_processes
                ],
                "postgres_services": list(facts.postgres_services),
                "services": list(facts.services),
                "confidence": facts.confidence,
                "source": "discovered",
                "collector": "winrm",
            },
            commands=commands,
            error_code=facts.error_code,
            error=facts.error,
            limitations=list(facts.limitations),
        )
        try:
            persist_host_evidence(
                evidence,
                artifacts_root=self.artifacts_root,
                client_slug=inventory.client_id,
                inventory_version_id=inventory.version.version_id,
                known_secrets=known_secrets,
            )
        except Exception:  # noqa: BLE001
            logger.exception("failed to persist WinRM discovery evidence for %s", facts.host_id)


def _default_winrm_transport(
    cred: InventorySshTarget,
    settings: DiscoveryHostSettings,
) -> ShellTransport:
    try:
        port = int(cred.port or "5985")
    except ValueError:
        port = 5985
    use_ssl = (cred.winrm_use_ssl or "").lower() in {"1", "true", "yes"} or port == 5986
    verify_ssl = (cred.winrm_verify_ssl or "").lower() in {"1", "true", "yes"}
    return WinrmTransport(
        host=cred.host,
        port=port,
        username=cred.user,
        password=cred.password,
        transport=cred.winrm_transport or "ntlm",
        use_ssl=use_ssl,
        verify_ssl=verify_ssl,
        command_timeout=settings.command_timeout,
    )


@dataclass(slots=True)
class CompositeDiscoveryCollector:
    """Fan-out SSH + WinRM discovery; one host failure does not stop others."""

    inventory_dir: Path | str
    client_name: str
    artifacts_root: Path | str | None = None
    defaults: DiscoveryHostSettings = field(default_factory=DiscoveryHostSettings)
    host_overrides: dict[str, DiscoveryHostSettings] = field(default_factory=dict)
    ssh_transport_factory: (
        Callable[[InventorySshTarget, DiscoveryHostSettings], ShellTransport] | None
    ) = None
    winrm_transport_factory: (
        Callable[[InventorySshTarget, DiscoveryHostSettings], ShellTransport] | None
    ) = None
    collector_version: str = COLLECTOR_VERSION

    def discover(self, inventory: ClientInventory) -> list[DiscoveredHostFacts]:
        ssh = SshDiscoveryCollector(
            inventory_dir=self.inventory_dir,
            client_name=self.client_name,
            artifacts_root=self.artifacts_root,
            defaults=self.defaults,
            host_overrides=self.host_overrides,
            transport_factory=self.ssh_transport_factory,
            collector_version=self.collector_version,
        )
        winrm = WinrmDiscoveryCollector(
            inventory_dir=self.inventory_dir,
            client_name=self.client_name,
            artifacts_root=self.artifacts_root,
            defaults=self.defaults,
            host_overrides=self.host_overrides,
            transport_factory=self.winrm_transport_factory,
            collector_version=self.collector_version,
        )
        # Collect per-host independently so one failure never aborts siblings.
        by_id: dict[str, DiscoveredHostFacts] = {}
        for host in inventory.hosts:
            try:
                use_winrm = "winrm" in host.connection_types or host.os_family == "windows"
                use_ssh = "ssh" in host.connection_types or (
                    not use_winrm and host.os_family in {"", "linux", "unknown"}
                )
                if use_winrm and not use_ssh:
                    subset = inventory.model_copy(update={"hosts": (host,)})
                    for fact in winrm.discover(subset):
                        by_id[fact.host_id] = fact
                elif use_ssh:
                    subset = inventory.model_copy(update={"hosts": (host,)})
                    for fact in ssh.discover(subset):
                        by_id[fact.host_id] = fact
                else:
                    by_id[host.host_id] = DiscoveredHostFacts(
                        host_id=host.host_id,
                        error="unsupported transport for discovery",
                        error_code=ERROR_UNSUPPORTED_TRANSPORT,
                        limitations=["unsupported_transport"],
                        confidence="low",
                        collected_at=utc_now(),
                    )
            except Exception as exc:  # noqa: BLE001
                logger.exception("discovery failed for host %s", host.host_id)
                by_id[host.host_id] = DiscoveredHostFacts(
                    host_id=host.host_id,
                    error=str(exc),
                    error_code=_classify_transport_error(exc),
                    limitations=["discovery_failed"],
                    confidence="low",
                    collected_at=utc_now(),
                )
        return [by_id[h.host_id] for h in inventory.hosts if h.host_id in by_id]


def production_discovery_collector(
    inventory_dir: Path | str,
    client_name: str,
    *,
    artifacts_root: Path | str | None = None,
    defaults: DiscoveryHostSettings | None = None,
) -> CompositeDiscoveryCollector:
    """Factory for the default production composite collector."""
    return CompositeDiscoveryCollector(
        inventory_dir=inventory_dir,
        client_name=client_name,
        artifacts_root=artifacts_root,
        defaults=defaults or DiscoveryHostSettings(),
    )

"""Reversible anonymization helpers for report/evidence exports.

The anonymizer replaces sensitive values with stable placeholder tokens and
persists a plain mapping file so text can be de-anonymized later.
"""

from __future__ import annotations

import ipaddress
import json
import re
import shutil
from collections import defaultdict
from pathlib import Path
from typing import Any, Iterable

_EMAIL_RE = re.compile(
    r"(?<![A-Za-z0-9._%+-])"
    r"([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})"
    # Allow sentence '.' / ',' after the address; still block token continuation.
    r"(?![A-Za-z0-9_%+-])"
)
_IPV4_CANDIDATE_RE = re.compile(r"(?<![\w.])(\d{1,3}(?:\.\d{1,3}){3})(?![\w.])")
_IPV6_CANDIDATE_RE = re.compile(r"(?<![0-9A-Fa-f:])([0-9A-Fa-f:]{2,})(?![0-9A-Fa-f:])")

# aa:bb:cc:dd:ee:ff or aa-bb-cc-dd-ee-ff (separator must be consistent)
_MAC_SEP_RE = re.compile(
    r"(?<![0-9A-Fa-f])"
    r"((?:[0-9A-Fa-f]{2}([-:]))(?:[0-9A-Fa-f]{2}\2){4}[0-9A-Fa-f]{2})"
    r"(?![0-9A-Fa-f])"
)
# Cisco-style aaaa.bbbb.cccc
_MAC_DOT_RE = re.compile(
    r"(?<![0-9A-Fa-f.])"
    r"([0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4})"
    r"(?![0-9A-Fa-f.])"
)

# http(s)/jdbc/postgres/…://authority — path/query left for later passes
_URL_AUTHORITY_RE = re.compile(
    r"(?i)\b("
    r"(?:https?|ftp|ldaps?|postgres(?:ql)?|mysql|mongodb|redis|amqp"
    r"|jdbc:[a-z0-9+.-]+)"
    r"://)"
    r"([^\s/?#]+)"
)

# DOMAIN\user (not UNC \\server\share, not C:\ path which uses ':')
_WIN_ACCOUNT_RE = re.compile(
    r"(?<![\\/\w])"
    r"([A-Za-z0-9][A-Za-z0-9_-]{0,63})"
    r"\\"
    r"([A-Za-z0-9._$-]{1,128})"
    r"\b"
)

# LDAP / X.509 DN: CN=…,OU=…,DC=…
_LDAP_DN_RE = re.compile(
    r"(?i)\b("
    r"(?:CN|OU|DC|O|L|ST|UID|SN|GIVENNAME)=[^,=;/\n]+"
    r"(?:,\s*(?:CN|OU|DC|O|L|ST|UID|SN|GIVENNAME)=[^,=;/\n]+)+"
    r")"
)

_GENERIC_DB_NAMES = frozenset(
    {
        "postgres",
        "template0",
        "template1",
        "mysql",
        "sys",
        "information_schema",
        "performance_schema",
        "public",
        "master",
        "msdb",
        "tempdb",
        "model",
    }
)

_BINARY_SUFFIXES = {
    ".docx",
    ".xlsx",
    ".zip",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".webp",
    ".pdf",
    ".ico",
}


def is_generic_db_name(name: str) -> bool:
    """Return True for built-in DB/schema names that should not be masked."""
    return (name or "").strip().lower() in _GENERIC_DB_NAMES


class ReversibleAnonymizer:
    """Replace sensitive values with deterministic placeholders."""

    def __init__(self) -> None:
        self._forward: dict[str, str] = {}
        self._reverse: dict[str, str] = {}
        self._counters: dict[str, int] = defaultdict(int)

    def _token_for(self, value: str, kind: str) -> str:
        key = value
        if key in self._forward:
            return self._forward[key]
        safe_kind = re.sub(r"[^A-Z0-9_]+", "_", kind.upper()).strip("_") or "VALUE"
        self._counters[safe_kind] += 1
        token = f"{safe_kind}_{self._counters[safe_kind]:03d}"
        self._forward[key] = token
        self._reverse[token] = key
        return token

    def _replace_regex(self, text: str, pattern: re.Pattern[str], kind: str) -> str:
        def _repl(match: re.Match[str]) -> str:
            value = match.group(1)
            if not value:
                return match.group(0)
            return self._token_for(value, kind)

        return pattern.sub(_repl, text)

    def _mask_host_token(self, host: str) -> str:
        """Mask a hostname or IP for URL authorities."""
        cleaned = (host or "").strip()
        if not cleaned:
            return cleaned
        if cleaned.startswith("[") and cleaned.endswith("]"):
            inner = cleaned[1:-1]
            try:
                addr = ipaddress.ip_address(inner)
            except ValueError:
                return self._token_for(cleaned, "HOST")
            if addr.is_loopback or addr.is_unspecified:
                return cleaned
            return f"[{self._token_for(inner, 'IP')}]"
        try:
            addr = ipaddress.ip_address(cleaned)
        except ValueError:
            return self._token_for(cleaned, "HOST")
        if addr.is_loopback or addr.is_unspecified:
            return cleaned
        return self._token_for(cleaned, "IP")

    def _replace_ip_candidates(self, text: str) -> str:
        def _v4_repl(match: re.Match[str]) -> str:
            value = match.group(1)
            try:
                addr = ipaddress.ip_address(value)
            except ValueError:
                return match.group(0)
            if addr.version != 4:
                return match.group(0)
            if addr.is_loopback or addr.is_unspecified:
                return match.group(0)
            return self._token_for(value, "IP")

        def _v6_repl(match: re.Match[str]) -> str:
            value = match.group(1)
            if ":" not in value:
                return match.group(0)
            try:
                addr = ipaddress.ip_address(value)
            except ValueError:
                return match.group(0)
            if addr.version != 6:
                return match.group(0)
            if addr.is_loopback or addr.is_unspecified:
                return match.group(0)
            return self._token_for(value, "IP")

        masked = _IPV4_CANDIDATE_RE.sub(_v4_repl, text)
        masked = _IPV6_CANDIDATE_RE.sub(_v6_repl, masked)
        return masked

    def _replace_mac_addresses(self, text: str) -> str:
        masked = self._replace_regex(text, _MAC_SEP_RE, "MAC")
        return self._replace_regex(masked, _MAC_DOT_RE, "MAC")

    def _replace_urls(self, text: str) -> str:
        def _repl(match: re.Match[str]) -> str:
            scheme = match.group(1)
            authority = match.group(2)
            userinfo: str | None = None
            hostport = authority
            if "@" in authority:
                raw_userinfo, hostport = authority.rsplit("@", 1)
                # Never persist passwords in the reversible mapping.
                user = raw_userinfo.split(":", 1)[0]
                userinfo = self._token_for(user, "USER") if user else None

            host = hostport
            port: str | None = None
            if hostport.startswith("["):
                end = hostport.find("]")
                if end != -1:
                    host = hostport[: end + 1]
                    rest = hostport[end + 1 :]
                    if rest.startswith(":") and rest[1:].isdigit():
                        port = rest[1:]
            elif hostport.count(":") == 1:
                maybe_host, maybe_port = hostport.rsplit(":", 1)
                if maybe_port.isdigit():
                    host, port = maybe_host, maybe_port

            masked_host = self._mask_host_token(host)
            auth = masked_host if port is None else f"{masked_host}:{port}"
            if userinfo:
                auth = f"{userinfo}@{auth}"
            return f"{scheme}{auth}"

        return _URL_AUTHORITY_RE.sub(_repl, text)

    def _replace_windows_accounts(self, text: str) -> str:
        def _repl(match: re.Match[str]) -> str:
            account = f"{match.group(1)}\\{match.group(2)}"
            return self._token_for(account, "WINUSER")

        return _WIN_ACCOUNT_RE.sub(_repl, text)

    def _replace_ldap_dns(self, text: str) -> str:
        return self._replace_regex(text, _LDAP_DN_RE, "DN")

    def _replace_domain_hostnames(
        self,
        text: str,
        domains: Iterable[str],
    ) -> str:
        masked = text
        for domain in domains:
            cleaned = (domain or "").strip().lower().lstrip(".")
            if "." not in cleaned:
                continue
            pattern = re.compile(
                rf"(?i)\b([a-z0-9][a-z0-9-]*(?:\.[a-z0-9-]+)*\.{re.escape(cleaned)})\b"
            )
            masked = self._replace_regex(masked, pattern, "HOST")
            # Hide bare domain token too when present.
            masked = re.sub(
                rf"(?i)\b{re.escape(cleaned)}\b",
                self._token_for(cleaned, "DOMAIN"),
                masked,
            )
        return masked

    def _replace_user_home_paths(self, text: str, users: Iterable[str]) -> str:
        masked = text
        cleaned_users = sorted(
            {
                u.strip()
                for u in users
                if u
                and str(u).strip()
                and "/" not in str(u)
                and "\\" not in str(u)
                and str(u).strip() not in {".", ".."}
            },
            key=len,
            reverse=True,
        )
        for user in cleaned_users:
            esc = re.escape(user)

            def _path_repl(match: re.Match[str]) -> str:
                return self._token_for(match.group(1), "PATH")

            for pattern in (
                re.compile(rf"(?i)(/home/{esc})(?=/|\b)"),
                re.compile(rf"(?i)(/Users/{esc})(?=/|\b)"),
                re.compile(rf"(?i)([A-Za-z]:\\Users\\{esc})(?=\\|\b)"),
            ):
                masked = pattern.sub(_path_repl, masked)
        return masked

    def _replace_literal(self, text: str, value: str, kind: str) -> str:
        cleaned = (value or "").strip()
        if not cleaned:
            return text
        if kind.upper() == "DB" and is_generic_db_name(cleaned):
            return text
        token = self._token_for(cleaned, kind)
        return re.sub(re.escape(cleaned), token, text)

    def anonymize_text(
        self,
        text: str,
        *,
        literal_groups: dict[str, Iterable[str]] | None = None,
    ) -> str:
        """Anonymize text with regex-first passes, then explicit literals."""
        masked = text
        domains: list[str] = []
        users: list[str] = []
        if literal_groups:
            domains = [str(v) for v in literal_groups.get("DOMAIN", []) if str(v).strip()]
            users = [str(v) for v in literal_groups.get("USER", []) if str(v).strip()]
        # Emails / UPNs before bare-domain replacement so `user@domain`
        # is not split by DOMAIN literals.
        masked = self._replace_ldap_dns(masked)
        masked = self._replace_mac_addresses(masked)
        masked = self._replace_urls(masked)
        masked = self._replace_windows_accounts(masked)
        masked = self._replace_regex(masked, _EMAIL_RE, "EMAIL")
        if domains:
            masked = self._replace_domain_hostnames(masked, domains)
        masked = self._replace_ip_candidates(masked)
        if users:
            masked = self._replace_user_home_paths(masked, users)
        if literal_groups:
            # Replace longer literals first to avoid splitting nested values.
            pairs: list[tuple[str, str]] = []
            for kind, values in literal_groups.items():
                for value in values:
                    cleaned = (value or "").strip()
                    if cleaned:
                        pairs.append((cleaned, kind))
            pairs.sort(key=lambda item: len(item[0]), reverse=True)
            for value, kind in pairs:
                masked = self._replace_literal(masked, value, kind)
        return masked

    def deanonymize_text(self, text: str) -> str:
        """Restore anonymized text using reverse mapping."""
        restored = text
        for token in sorted(self._reverse.keys(), key=len, reverse=True):
            restored = restored.replace(token, self._reverse[token])
        return restored

    def mapping(self) -> dict[str, Any]:
        """Return serializable mapping payload."""
        return {
            "forward": dict(sorted(self._forward.items(), key=lambda item: item[1])),
            "reverse": dict(sorted(self._reverse.items())),
        }


def _is_text_file(path: Path) -> bool:
    if path.suffix.lower() in _BINARY_SUFFIXES:
        return False
    try:
        sample = path.read_bytes()
    except OSError:
        return False
    if b"\x00" in sample:
        return False
    try:
        sample.decode("utf-8")
    except UnicodeDecodeError:
        return False
    return True


def _anonymize_relpath(
    rel: Path,
    *,
    src_is_dir: bool,
    anonymizer: ReversibleAnonymizer,
    literal_groups: dict[str, Iterable[str]] | None = None,
) -> Path:
    """Anonymize each relative path segment while preserving file suffixes."""
    if not rel.parts:
        return rel
    out: list[str] = []
    for idx, part in enumerate(rel.parts):
        is_last = idx == len(rel.parts) - 1
        is_file = is_last and not src_is_dir
        if is_file:
            suffix = "".join(Path(part).suffixes)
            stem = part[: -len(suffix)] if suffix else part
            masked_stem = anonymizer.anonymize_text(
                stem,
                literal_groups=literal_groups,
            )
            out.append(f"{masked_stem}{suffix}")
            continue
        out.append(
            anonymizer.anonymize_text(
                part,
                literal_groups=literal_groups,
            )
        )
    return Path(*out)


def anonymize_directory_tree(
    source_root: Path,
    destination_root: Path,
    *,
    anonymizer: ReversibleAnonymizer,
    literal_groups: dict[str, Iterable[str]] | None = None,
) -> None:
    """Copy source tree and anonymize text files in destination."""
    if destination_root.exists():
        shutil.rmtree(destination_root)
    destination_root.mkdir(parents=True, exist_ok=True)
    for src in source_root.rglob("*"):
        rel = src.relative_to(source_root)
        masked_rel = _anonymize_relpath(
            rel,
            src_is_dir=src.is_dir(),
            anonymizer=anonymizer,
            literal_groups=literal_groups,
        )
        dst = destination_root / masked_rel
        if src.is_dir():
            dst.mkdir(parents=True, exist_ok=True)
            continue
        dst.parent.mkdir(parents=True, exist_ok=True)
        if not _is_text_file(src):
            shutil.copy2(src, dst)
            continue
        try:
            text = src.read_text(encoding="utf-8")
        except OSError:
            shutil.copy2(src, dst)
            continue
        masked = anonymizer.anonymize_text(text, literal_groups=literal_groups)
        dst.write_text(masked, encoding="utf-8")


def write_mapping_file(destination_root: Path, anonymizer: ReversibleAnonymizer) -> Path:
    """Write mapping file into anonymized run root."""
    path = destination_root / "anonymization_mapping.json"
    path.write_text(
        json.dumps(anonymizer.mapping(), indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    return path

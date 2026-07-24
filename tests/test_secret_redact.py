"""Tests for irreversible secret redaction during anonymization."""

from pathlib import Path
from unittest.mock import patch

from auditor.anonymization import ReversibleAnonymizer, anonymize_directory_tree
from auditor.secret_redact import (
    REDACTED,
    collect_secrets_for_redaction,
    inventory_secrets,
    parse_trufflehog_jsonl,
    redact_secrets_in_text,
)


def test_inventory_secrets_skips_key_paths():
    creds = {
        "SSH_PASSWORD": "s3cret-pass",
        "PG_PASSWORD": "pg-secret-99",
        "SSH_PRIVATE_KEY_PATH": "/keys/id_ed25519",
        "SSH_USER": "ubuntu",
    }
    found = inventory_secrets(creds)
    assert found == {"s3cret-pass", "pg-secret-99"}


def test_parse_trufflehog_jsonl_raw_fields():
    stdout = "\n".join(
        [
            '{"DetectorName":"URI","Raw":"super-secret-token-abc","Verified":false}',
            "not-json",
            '{"RawV2":"another-token-xyz123"}',
            '{"Raw":"tiny"}',
        ]
    )
    found = parse_trufflehog_jsonl(stdout)
    assert found == {"super-secret-token-abc", "another-token-xyz123"}


def test_redact_secrets_longest_first():
    text = "token=abcdef123456 and nest=abcdef123456789"
    masked = redact_secrets_in_text(
        text, {"abcdef123456", "abcdef123456789"}
    )
    assert "abcdef" not in masked
    assert masked.count(REDACTED) == 2


def test_anonymize_redacts_before_mapping(tmp_path: Path):
    src = tmp_path / "src"
    dst = tmp_path / "dst"
    src.mkdir()
    secret = "Hunter2-not-in-map"
    (src / "report.md").write_text(
        f"password={secret} host=10.1.2.3\n",
        encoding="utf-8",
    )
    anonymizer = ReversibleAnonymizer()
    anonymize_directory_tree(
        src,
        dst,
        anonymizer=anonymizer,
        secrets_to_redact={secret},
    )
    text = (dst / "report.md").read_text(encoding="utf-8")
    assert secret not in text
    assert REDACTED in text
    assert "10.1.2.3" not in text
    mapping = anonymizer.mapping()
    assert secret not in mapping["forward"]
    assert secret not in mapping["reverse"].values()


def test_collect_secrets_merges_inventory_and_trufflehog(tmp_path: Path):
    root = tmp_path / "run"
    root.mkdir()
    fake_jsonl = '{"Raw":"truffle-found-secret99"}\n'

    class _Proc:
        returncode = 0
        stdout = fake_jsonl
        stderr = ""

    with patch("auditor.secret_redact.shutil.which", return_value="/bin/trufflehog"):
        with patch("auditor.secret_redact.subprocess.run", return_value=_Proc()):
            secrets = collect_secrets_for_redaction(
                evidence_root=root,
                inventory_creds={"WINRM_PASSWORD": "inv-password-42"},
                trufflehog_enabled=True,
            )
    assert "inv-password-42" in secrets
    assert "truffle-found-secret99" in secrets


def test_trufflehog_disabled_uses_inventory_only(tmp_path: Path):
    root = tmp_path / "run"
    root.mkdir()
    with patch("auditor.secret_redact.discover_secrets_with_trufflehog") as scan:
        secrets = collect_secrets_for_redaction(
            evidence_root=root,
            inventory_creds={"PG_PASSWORD": "only-inventory-secret"},
            trufflehog_enabled=False,
        )
        scan.assert_not_called()
    assert secrets == {"only-inventory-secret"}

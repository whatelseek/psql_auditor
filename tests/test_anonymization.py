from pathlib import Path

from auditor.anonymization import (
    ReversibleAnonymizer,
    anonymize_directory_tree,
    write_mapping_file,
)


def test_regex_anonymization_ipv4_ipv6_email_reversible():
    anonymizer = ReversibleAnonymizer()
    text = (
        "Contact Admin@Example.COM, backup admin@example.com. IPs: 10.200.29.78 and 2001:db8::7334."
    )
    masked = anonymizer.anonymize_text(text)
    assert "10.200.29.78" not in masked
    assert "2001:db8::7334" not in masked
    assert "admin@example.com" not in masked.lower()
    assert "EMAIL_001" in masked
    assert "IP_001" in masked
    assert "IP_002" in masked
    restored = anonymizer.deanonymize_text(masked)
    assert restored == text


def test_regex_edge_cases_embedded_punctuation_and_repeats():
    anonymizer = ReversibleAnonymizer()
    text = "email(admin@example.com), ip=10.0.0.1; again 10.0.0.1!"
    masked = anonymizer.anonymize_text(text)
    assert "admin@example.com" not in masked
    assert "10.0.0.1" not in masked
    assert masked.count("IP_001") == 2
    assert "IP_002" not in masked


def test_ip_false_positives_not_masked():
    anonymizer = ReversibleAnonymizer()
    text = "version 0.24.04.3 build time 11:26:02"
    masked = anonymizer.anonymize_text(text)
    assert masked == text


def test_local_and_unspecified_ips_not_masked():
    anonymizer = ReversibleAnonymizer()
    text = "bind 0.0.0.0 loopback 127.0.0.1 and ::1 plus external 10.1.2.3"
    masked = anonymizer.anonymize_text(text)
    assert "0.0.0.0" in masked
    assert "127.0.0.1" in masked
    assert "::1" in masked
    assert "10.1.2.3" not in masked
    assert "IP_001" in masked


def test_directory_anonymization_writes_mapping(tmp_path: Path):
    src = tmp_path / "src"
    dst = tmp_path / "dst"
    src.mkdir()
    (src / "report.md").write_text(
        "Client TestCompany host 10.1.2.3 email sec@testcompany.local\n",
        encoding="utf-8",
    )
    (src / "report.docx").write_bytes(b"PK\x03\x04fake")

    anonymizer = ReversibleAnonymizer()
    anonymize_directory_tree(
        src,
        dst,
        anonymizer=anonymizer,
        literal_groups={"CLIENT": {"TestCompany"}, "DOMAIN": {"testcompany.local"}},
    )
    mapping = write_mapping_file(dst, anonymizer)

    text = (dst / "report.md").read_text(encoding="utf-8")
    assert "TestCompany" not in text
    assert "10.1.2.3" not in text
    assert "sec@testcompany.local" not in text
    assert (dst / "report.docx").read_bytes() == b"PK\x03\x04fake"
    assert mapping.is_file()


def test_directory_path_segments_are_anonymized(tmp_path: Path):
    src = tmp_path / "src"
    dst = tmp_path / "dst"
    path = src / "testcompany" / "10.1.2.3"
    path.mkdir(parents=True)
    (path / "host_testcompany.txt").write_text(
        "host=10.1.2.3 client=testcompany\n",
        encoding="utf-8",
    )

    anonymizer = ReversibleAnonymizer()
    anonymize_directory_tree(
        src,
        dst,
        anonymizer=anonymizer,
        literal_groups={"CLIENT": {"testcompany"}},
    )

    # Original path tree should be hidden in destination.
    assert not (dst / "testcompany").exists()
    assert not (dst / "testcompany" / "10.1.2.3").exists()

    # New anonymized tree exists and contains anonymized payload.
    text_files = list(dst.rglob("*.txt"))
    assert len(text_files) == 1
    text = text_files[0].read_text(encoding="utf-8")
    assert "testcompany" not in text
    assert "10.1.2.3" not in text

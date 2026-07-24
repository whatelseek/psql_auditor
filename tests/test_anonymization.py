from pathlib import Path

from auditor.anonymization import (
    ReversibleAnonymizer,
    anonymize_directory_tree,
    write_mapping_file,
)


def test_regex_anonymization_ipv4_ipv6_email_reversible():
    anonymizer = ReversibleAnonymizer()
    text = (
        "Contact Admin@Example.COM, backup admin@example.com. "
        "IPs: 10.200.29.78 and 2001:db8::7334."
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


def test_mac_address_anonymization():
    anonymizer = ReversibleAnonymizer()
    text = "nic 00:1A:2B:3C:4D:5E and cisco 001a.2b3c.4d5e again 00:1A:2B:3C:4D:5E"
    masked = anonymizer.anonymize_text(text)
    assert "00:1A:2B:3C:4D:5E" not in masked
    assert "001a.2b3c.4d5e" not in masked
    assert masked.count("MAC_001") == 2
    assert "MAC_002" in masked
    assert anonymizer.deanonymize_text(masked) == text


def test_url_authority_anonymization_keeps_path():
    anonymizer = ReversibleAnonymizer()
    text = (
        "see https://db.acme.local:5432/app/health "
        "and jdbc:postgresql://10.1.2.3:5432/appdb "
        "and https://user:secret@db.acme.local/x"
    )
    masked = anonymizer.anonymize_text(text)
    assert "db.acme.local" not in masked
    assert "10.1.2.3" not in masked
    assert "secret" not in masked
    assert "/app/health" in masked
    assert "/appdb" in masked
    assert "USER_001@" in masked
    # Password must not appear in reversible mapping.
    assert "secret" not in anonymizer.mapping()["forward"]
    assert "secret" not in anonymizer.mapping()["reverse"].values()


def test_windows_account_and_upn():
    anonymizer = ReversibleAnonymizer()
    text = r"login CORP\jsmith and upn jsmith@corp.local; path C:\Windows\System32"
    masked = anonymizer.anonymize_text(text)
    assert r"CORP\jsmith" not in masked
    assert "jsmith@corp.local" not in masked
    assert "WINUSER_001" in masked
    assert "EMAIL_001" in masked
    assert r"C:\Windows\System32" in masked


def test_ldap_dn_anonymization():
    anonymizer = ReversibleAnonymizer()
    text = "bind CN=John Doe,OU=Users,DC=corp,DC=local for ldap"
    masked = anonymizer.anonymize_text(text)
    assert "John Doe" not in masked
    assert "DC=corp" not in masked
    assert "DN_001" in masked
    assert anonymizer.deanonymize_text(masked) == text


def test_user_home_paths_and_db_literals():
    anonymizer = ReversibleAnonymizer()
    text = (
        "files in /home/jsmith/.ssh and C:\\Users\\jsmith\\Documents; "
        "db=acme_prod also postgres template1"
    )
    masked = anonymizer.anonymize_text(
        text,
        literal_groups={"USER": {"jsmith"}, "DB": {"acme_prod", "postgres", "template1"}},
    )
    assert "/home/jsmith" not in masked
    assert r"C:\Users\jsmith" not in masked
    assert "PATH_001" in masked
    assert "acme_prod" not in masked
    assert "DB_001" in masked
    # Generic DB names are not masked.
    assert "postgres" in masked
    assert "template1" in masked


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

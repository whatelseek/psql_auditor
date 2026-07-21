from auditor.language import detect_report_language, language_instruction, normalize_language_code
from auditor.state import Finding, render_report


def test_detect_explicit_english():
    lang = detect_report_language("Run Ubuntu CIS audit in English")
    assert lang.code == "en"
    assert lang.name == "English"


def test_detect_explicit_russian():
    lang = detect_report_language("Проведи аудит Ubuntu CIS на русском")
    assert lang.code == "ru"
    assert lang.name == "Russian"


def test_detect_cyrillic_request_defaults_russian():
    lang = detect_report_language("Запусти полный аудит postgres")
    assert lang.code == "ru"


def test_unsupported_language_falls_back_to_english():
    lang = detect_report_language("Start CIS audit in German please")
    assert lang.code == "en"
    assert lang.name == "English"
    assert normalize_language_code("uk") == "en"
    assert normalize_language_code("fr") == "en"
    assert normalize_language_code("de") == "en"


def test_report_language_code_token():
    lang = detect_report_language("report language: ru")
    assert lang.code == "ru"
    lang = detect_report_language("report language: de")
    assert lang.code == "en"


def test_language_instruction_mentions_target():
    text = language_instruction(detect_report_language("report in Russian"))
    assert "Russian" in text


def test_render_report_russian_chrome():
    findings = {
        "REQ-001": Finding(
            requirement_id="REQ-001",
            title="SSH root",
            status="fail",
            severity="Critical",
            evidence="PermitRootLogin yes",
            remediation="Set no",
        )
    }
    md = render_report("Ubuntu CIS", findings, language="ru")
    assert "Сводная таблица" in md
    assert "Наблюдение" in md
    assert "PermitRootLogin yes" in md

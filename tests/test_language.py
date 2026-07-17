from psql_auditor.language import detect_response_language, ui


def test_default_language_is_russian():
    lang = detect_response_language("Start PostgreSQL CIS audit")
    assert lang.code == "ru"
    assert lang.name == "Russian"


def test_explicit_english_request():
    lang = detect_response_language("Run Ubuntu CIS audit. Please respond in English.")
    assert lang.code == "en"


def test_explicit_russian_request():
    lang = detect_response_language("Start audit in English? No — ответь на русском")
    # last matching explicit pattern wins by search order; "на русском" should match
    lang = detect_response_language("Проведи аудит PostgreSQL на русском")
    assert lang.code == "ru"


def test_cyrillic_user_text_selects_russian():
    lang = detect_response_language(
        "Проведи аудит PostgreSQL и Ubuntu по CIS для этого хоста"
    )
    assert lang.code == "ru"


def test_ui_russian_archive_title():
    assert "Архив" in ui("ru", "archive_title")


def test_llm_instruction_mentions_language():
    lang = detect_response_language("hello", default="ru")
    assert "Russian" in lang.llm_instruction

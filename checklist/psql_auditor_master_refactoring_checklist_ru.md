# `psql_auditor` — Мастер-чеклист разработки и приёмки

Версия чеклиста: **1.15-draft**  
Дата: **2026-07-27**  
Репозиторий: `whatelseek/psql_auditor`  
Базовый commit: [`b064e26`](https://github.com/whatelseek/psql_auditor/commit/b064e26e9150d0bf4ebc2036ecc7c839b4b219e4)  
Последняя независимо рассмотренная ревизия: [`770fe4e`](https://github.com/whatelseek/psql_auditor/commit/770fe4ebea81de4fc33ee37460c0e3e951d03a7e)  
Всего верхнеуровневых задач: **77**

Чеклист сохраняет прежние разделы `M0`–`M8`, верхнеуровневые идентификаторы и
статусы. Под каждым requirement добавлены implementation work items, чтобы
формировать отдельное ТЗ на конкретный функционал, заранее указывать ожидаемые
файлы и проводить точечную приёмку.

Дочерние work items:

- не увеличивают общее количество `77`;
- не входят в defect-map как самостоятельные requirements;
- не могут автоматически изменить статус родительской задачи;
- могут уточняться при постановке ТЗ после проверки фактической структуры кода.

## Сводка статусов

| Статус                 |           Количество |
| ---------------------- | -------------------: |
| Принято `[x]`          |  **10 / 77 (13,0%)** |
| Частично `[~]`         | **11 / 77 (14,3%)** |
| Открыто `[ ]`          |  **56 / 77 (72,7%)** |
| Не полностью завершено |  **67 / 77 (87,0%)** |

Принято: `AUD-001`, `AUD-002`, `AUD-003`, `CORE-001`, `CORE-002`, `CORE-003`,
`CORE-004`, `CORE-005`, `INPUT-001`, `INPUT-003`.

Частично: `CORE-006`, `INPUT-002`, `INPUT-004`, `INPUT-005`, `TOOL-001`,
`FLOW-007`, `EVID-001`, `EVID-002`, `EVID-003`, `OPS-004`, `DOC-001`.

## Статусы дочерних work items

| Статус | Значение |
|---|---|
| `Done` | Реализация подтверждена текущим кодом/тестами родительской задачи |
| `Partial` | Реализована только часть указанного scope |
| `Open` | Work item ещё не реализован или не принят |
| `Blocked` | Нельзя начать до завершения dependency |
| `Backlog` | Осознанно отложено, но сохранено для production hardening |

## Формат постановки ТЗ

Для разработки используется один конкретный child ID:

```text
Implement INPUT005-09 only.
Do not start INPUT005-10 or INPUT005-11.
Modify the declared primary files unless the repository structure requires
a documented alternative.
Update tests and provide acceptance evidence for INPUT005-09.
Do not change parent INPUT-005 to [x].
```

## Архитектурное решение продукта

Целевой продукт — управляемый AI-аудитор, а не набор жёстко запрограммированных
веток для отдельных платформ. Администратор добавляет версионированный inventory,
ссылки на credentials, человекочитаемые Markdown-фреймворки, MCP-серверы,
инструменты и политики capabilities. LLM использует эти ресурсы, чтобы планировать
discovery, собирать и интерпретировать evidence, выбирать все применимые
фреймворки и выполнять проверки.

Детерминированный control plane отвечает за валидацию входов, защиту credentials,
авторизацию инструментов, read-only ограничения, сохранение evidence, provenance,
фиксацию версий и хешей, отклонение stale plan, подтверждение запуска и audit log.
Рассуждение агента может быть недетерминированным, но принятый `AuditPlan` должен
воспроизводиться из зафиксированных inventory, каталога фреймворков, каталога
инструментов, policy snapshot и набора evidence.

## Последняя проверка

PR #40, head `770fe4e`, независимо рассмотрен как POC-срез `INPUT-005`.
Подтверждены effective inventory, registry-driven SSH discovery,
`HostCapabilitySnapshot`, deterministic technology detection, plan revision,
stale gates, explicit per-host targets и API/CLI E2E.

`INPUT-005` остаётся `[~]`: динамическая применимость Markdown-фреймворков,
registry-driven TCP/HTTP/SNMP discovery, plan revision pin в confirm contract,
YAML/JSON execution E2E и полноценный agent-driven preflight ещё не приняты.

| Проверка          | Результат |
| ----------------- | --------- |
| Format / Lint     | Passed |
| Type check        | Passed |
| Unit tests        | 486 passed |
| Integration tests | 8 passed |
| Full suite        | 494 passed |
| Defect map        | `validate-defect-map: OK` (77/77) |

## Реестр задач

### M0 — Базовая линия, тесты и CI

- [x] `AUD-001` — Зафиксировать воспроизводимую базовую линию.

  **Декомпозиция:**

  - **`AUD001-01` · `Done`** — Зафиксировать поддерживаемую версию Python, locked dependencies и команды установки.
    - **Основные файлы:** `pyproject.toml`, lock-файл, `README.md`
    - **Приёмка:** Чистое окружение устанавливается без ручных исправлений.
  - **`AUD001-02` · `Done`** — Зафиксировать baseline-команды format, lint, typecheck, unit, integration и full suite.
    - **Основные файлы:** `Makefile`, `pyproject.toml`, `.github/workflows/ci.yml`
    - **Приёмка:** Локальные и CI-команды используют одинаковые параметры.
  - **`AUD001-03` · `Done`** — Зафиксировать базовые количества тестов и defect-map.
    - **Основные файлы:** `checklist/`, `scripts/validate_defect_map.py`
    - **Приёмка:** Все 77 верхнеуровневых ID покрыты и baseline документирован.

  **Правило родительского статуса:** requirement принят независимо; дочерние `Done` фиксируют принятую реализацию.

- [x] `AUD-002` — Единые локальные и CI quality gates.

  **Декомпозиция:**

  - **`AUD002-01` · `Done`** — Свести format/lint/typecheck/test gates в единый `make check`.
    - **Основные файлы:** `Makefile`, `pyproject.toml`
    - **Приёмка:** `make check` завершается ненулевым кодом при любом упавшем gate.
  - **`AUD002-02` · `Done`** — Повторить те же gates в GitHub Actions.
    - **Основные файлы:** `.github/workflows/ci.yml`
    - **Приёмка:** CI не пропускает merge при упавшем обязательном job.
  - **`AUD002-03` · `Done`** — Добавить изолированный integration job с PostgreSQL.
    - **Основные файлы:** `.github/workflows/ci.yml`, `tests/integration/`
    - **Приёмка:** Integration tests не зависят от локальной БД разработчика.

  **Правило родительского статуса:** requirement принят независимо; дочерние `Done` фиксируют принятую реализацию.

- [x] `AUD-003` — Общие детерминированные тестовые фикстуры.

  **Декомпозиция:**

  - **`AUD003-01` · `Done`** — Создать канонические inventory/framework/evidence fixtures.
    - **Основные файлы:** `tests/fixtures/`
    - **Приёмка:** Фикстуры не содержат реальных секретов и дают стабильные hashes.
  - **`AUD003-02` · `Done`** — Использовать общие fixtures в unit и integration tests.
    - **Основные файлы:** `tests/`
    - **Приёмка:** Дублирующиеся локальные фикстуры удалены или обоснованы.
  - **`AUD003-03` · `Done`** — Добавить canary-секреты для проверки redaction.
    - **Основные файлы:** `tests/fixtures/`, security-focused tests
    - **Приёмка:** Canary не появляется в payload, logs, evidence и exceptions.

  **Правило родительского статуса:** requirement принят независимо; дочерние `Done` фиксируют принятую реализацию.

### M1 — Идентификаторы и доменная модель

- [x] `CORE-001` — Разделить `client_id` и `audit_run_id`.

  **Декомпозиция:**

  - **`CORE001-01` · `Done`** — Ввести отдельные типы/генераторы client и run identity.
    - **Основные файлы:** `src/auditor/domain/`, `src/auditor/client_registry.py`, `src/auditor/audit_registry.py`
    - **Приёмка:** Client identity не переиспользуется как run identity.
  - **`CORE001-02` · `Done`** — Протянуть обе identity через API, CLI, graph и persistence.
    - **Основные файлы:** `src/auditor/api/`, `src/auditor/cli.py`, `src/auditor/graph.py`
    - **Приёмка:** Каждый runtime record содержит правильные client/run references.
  - **`CORE001-03` · `Done`** — Добавить regression tests на смешение идентификаторов.
    - **Основные файлы:** `tests/test_identity*.py`
    - **Приёмка:** Ошибочная подстановка client_id вместо audit_run_id отклоняется.

  **Правило родительского статуса:** requirement принят независимо; дочерние `Done` фиксируют принятую реализацию.

- [x] `CORE-002` — Разделить `AuditRun` и `AuditJob`.

  **Декомпозиция:**

  - **`CORE002-01` · `Done`** — Определить отдельные доменные модели run и job.
    - **Основные файлы:** `src/auditor/domain/audit_models.py`
    - **Приёмка:** Run хранит lifecycle запуска, job — конкретную единицу исполнения.
  - **`CORE002-02` · `Done`** — Разделить persistence и transitions.
    - **Основные файлы:** `src/auditor/audit_registry.py`
    - **Приёмка:** Job transitions не изменяют другие jobs и не подменяют run status.
  - **`CORE002-03` · `Done`** — Покрыть multi-host/multi-framework jobs.
    - **Основные файлы:** `tests/test_audit_registry*.py`
    - **Приёмка:** Один run содержит независимые jobs с устойчивыми IDs.

  **Правило родительского статуса:** requirement принят независимо; дочерние `Done` фиксируют принятую реализацию.

- [x] `CORE-003` — Каноническая идентичность результата.

  **Декомпозиция:**

  - **`CORE003-01` · `Done`** — Определить result identity из run/job/host/framework/requirement.
    - **Основные файлы:** `src/auditor/domain/`, result persistence modules
    - **Приёмка:** Одинаковая проверка не создаёт неоднозначные result keys.
  - **`CORE003-02` · `Done`** — Использовать identity во всех write/read paths.
    - **Основные файлы:** `src/auditor/evidence_store.py`, reporting inputs, repositories
    - **Приёмка:** Результат можно однозначно получить по canonical key.
  - **`CORE003-03` · `Done`** — Добавить duplicate/replay regression.
    - **Основные файлы:** `tests/test_result_identity*.py`
    - **Приёмка:** Replay не создаёт конфликтующие или дублирующие результаты.

  **Правило родительского статуса:** requirement принят независимо; дочерние `Done` фиксируют принятую реализацию.

- [x] `CORE-004` — Структурированный `AssessmentResult`.

  **Декомпозиция:**

  - **`CORE004-01` · `Done`** — Определить typed status/observation/recommendation/evidence fields.
    - **Основные файлы:** `src/auditor/domain/assessment_result.py` или текущий domain module
    - **Приёмка:** Невалидный status или отсутствующая identity отклоняются.
  - **`CORE004-02` · `Done`** — Убрать свободный dict из канонического persistence path.
    - **Основные файлы:** assessment workflow и persistence modules
    - **Приёмка:** Сохраняется только валидированный доменный объект.
  - **`CORE004-03` · `Done`** — Добавить JSON round-trip и schema tests.
    - **Основные файлы:** `tests/test_assessment_result*.py`
    - **Приёмка:** Сериализация стабильна и обратно совместима в рамках версии.

  **Правило родительского статуса:** requirement принят независимо; дочерние `Done` фиксируют принятую реализацию.

- [x] `CORE-005` — Изоляция checkpoint и артефактов по audit run.

  **Декомпозиция:**

  - **`CORE005-01` · `Done`** — Использовать audit_run_id в checkpoint namespace.
    - **Основные файлы:** `src/auditor/graph.py`, checkpoint/runtime modules
    - **Приёмка:** Два запуска одного клиента не разделяют state.
  - **`CORE005-02` · `Done`** — Разделить evidence/report/archive directories по run.
    - **Основные файлы:** `src/auditor/evidence_store.py`, archive/report modules
    - **Приёмка:** Артефакты разных запусков не перезаписываются.
  - **`CORE005-03` · `Done`** — Добавить parallel-run regression.
    - **Основные файлы:** `tests/test_run_isolation*.py`
    - **Приёмка:** Параллельные runs не читают и не изменяют чужие данные.

  **Правило родительского статуса:** requirement принят независимо; дочерние `Done` фиксируют принятую реализацию.

- [~] `CORE-006` — Убрать скрытое глобальное изменяемое состояние.

  **Декомпозиция:**

  - **`CORE006-01` · `Done`** — Ввести `ApplicationRuntime` и dependency injection для graph/settings/registries.
    - **Основные файлы:** `src/auditor/application_runtime.py`, `src/auditor/api/app.py`
    - **Приёмка:** Основной API lifecycle создаёт и закрывает runtime явно.
  - **`CORE006-02` · `Partial`** — Убрать process-wide cached registries там, где нужен immutable snapshot на run.
    - **Основные файлы:** `src/auditor/tool_registry.py`, framework/client registries
    - **Приёмка:** Run использует pinned snapshot, а не изменяемый singleton.
  - **`CORE006-03` · `Open`** — Удалить deprecated global graph getters и скрытые module-level mutable objects.
    - **Основные файлы:** `src/auditor/graph.py`, `src/auditor/api/`, compatibility modules
    - **Приёмка:** Production path не зависит от process-wide singleton.
  - **`CORE006-04` · `Open`** — Добавить concurrency/lifecycle acceptance tests.
    - **Основные файлы:** `tests/test_application_runtime*.py`
    - **Приёмка:** Несколько runtime instances корректно работают и закрываются независимо.

  **Правило родительского статуса:** сохранять `[~]`, пока все обязательные work items не завершены и не проведена независимая приёмка.

### M2 — Входы и планирование аудита

- [x] `INPUT-001` — Строгий `AuditRequest`.

  **Декомпозиция:**

  - **`INPUT001-01` · `Done`** — Определить immutable versioned request schema.
    - **Основные файлы:** `src/auditor/domain/audit_request.py`
    - **Приёмка:** Unknown/secret-shaped fields и невалидные значения отклоняются.
  - **`INPUT001-02` · `Done`** — Закрепить inventory version/content hash и target/framework identities.
    - **Основные файлы:** `src/auditor/domain/audit_request.py`, request validation
    - **Приёмка:** Stale inventory fail-closed на API, CLI, direct execution и replay.
  - **`INPUT001-03` · `Done`** — Резолвить credentials только runtime.
    - **Основные файлы:** `src/auditor/effective_settings.py`, inventory/runtime modules
    - **Приёмка:** Секреты отсутствуют в request payload и persistence.
  - **`INPUT001-04` · `Done`** — Покрыть Markdown/YAML/JSON request ingress regressions.
    - **Основные файлы:** `tests/test_inventory_driven_audit.py`
    - **Приёмка:** Все поддерживаемые входы создают одинаково валидируемый request.

  **Правило родительского статуса:** requirement принят независимо; дочерние `Done` фиксируют принятую реализацию.

- [~] `INPUT-002` — Строгая валидация и регистрация текстовых фреймворков.

  **Декомпозиция:**

  - **`INPUT002-01` · `Done`** — Загружать Markdown frameworks из `agents/`, извлекать ID/title/version/hash.
    - **Основные файлы:** `src/auditor/frameworks.py`, `agents/`
    - **Приёмка:** Новый базовый Markdown framework виден без изменения core Python.
  - **`INPUT002-02` · `Done`** — Хранить invalid frameworks в каталоге как non-executable с validation issues.
    - **Основные файлы:** `src/auditor/frameworks.py`, registry tests
    - **Приёмка:** Один invalid файл не ломает валидный каталог.
  - **`INPUT002-03` · `Open`** — Добавить typed front matter для applicability, required facts/capabilities и discovery hints.
    - **Основные файлы:** `src/auditor/domain/framework_applicability.py` (new), `src/auditor/frameworks.py`
    - **Приёмка:** Metadata проходит schema validation без executable expressions.
  - **`INPUT002-04` · `Open`** — Закрыть deferred parser hardening: ambiguous headings, duplicate IDs/requirements, unsafe metadata.
    - **Основные файлы:** `src/auditor/frameworks.py`, `tests/test_framework_registry.py`
    - **Приёмка:** Parser fail-closed и выдаёт точные issues.
  - **`INPUT002-05` · `Open`** — Добавить compatibility/versioning contract для framework schema.
    - **Основные файлы:** `src/auditor/domain/`, docs, tests
    - **Приёмка:** Несовместимая schema version отклоняется с понятной ошибкой.

  **Правило родительского статуса:** сохранять `[~]`, пока все обязательные work items не завершены и не проведена независимая приёмка.

- [x] `INPUT-003` — Валидируемая модель inventory.

  **Декомпозиция:**

  - **`INPUT003-01` · `Done`** — Определить typed client/host/service/fact/credential-reference models.
    - **Основные файлы:** `src/auditor/domain/inventory.py`
    - **Приёмка:** Domain model не хранит raw secrets.
  - **`INPUT003-02` · `Done`** — Поддержать Markdown, YAML и JSON loaders.
    - **Основные файлы:** `src/auditor/inventory/loaders.py`, `normalize.py`
    - **Приёмка:** Форматы нормализуются в одну модель.
  - **`INPUT003-03` · `Done`** — Ввести stable version_id/content_hash и typed validation issues.
    - **Основные файлы:** inventory domain/service modules
    - **Приёмка:** Одинаковый effective input имеет одинаковую identity.
  - **`INPUT003-04` · `Done`** — Добавить fixtures и cross-format tests.
    - **Основные файлы:** `tests/fixtures/inventory/`, `tests/test_inventory_driven_audit.py`
    - **Приёмка:** Cross-format значения и ошибки эквивалентны.

  **Правило родительского статуса:** requirement принят независимо; дочерние `Done` фиксируют принятую реализацию.

- [~] `INPUT-004` — Управляемый администратором реестр MCP/инструментов и политика capabilities.

  **Декомпозиция:**

  - **`INPUT004-01` · `Done`** — Ввести versioned tool manifests и fail-closed registry validation.
    - **Основные файлы:** `src/auditor/tool_registry.py`, `tools/catalog/`, `tests/test_tool_registry.py`
    - **Приёмка:** Invalid tool видим, но не executable/bindable.
  - **`INPUT004-02` · `Done`** — Ввести capability-policy snapshot и hashes.
    - **Основные файлы:** `tools/policies/`, tool registry/domain modules
    - **Приёмка:** Plan/run фиксируют tool_catalog_hash и capability_policy_hash.
  - **`INPUT004-03` · `Partial`** — Унифицировать built-in adapters и MCP registrations в одном каталоге.
    - **Основные файлы:** `src/auditor/tool_registry.py`, `mcps/registry.json`, adapter modules
    - **Приёмка:** Оба типа tools проходят одну validation/authorization модель.
  - **`INPUT004-04` · `Open`** — Добавить administrator-facing install/update/disable lifecycle для manifests.
    - **Основные файлы:** registry service/API/CLI, docs
    - **Приёмка:** Изменение каталога создаёт новую immutable snapshot identity.
  - **`INPUT004-05` · `Open`** — Применять manifest timeout/retry/output limits в runtime для всех adapters.
    - **Основные файлы:** tool invocation/runtime modules
    - **Приёмка:** Runtime не игнорирует manifest limits.
  - **`INPUT004-06` · `Backlog`** — Закрыть hardening: empty allow-list deny-all, hash propagation/freeze, adapter import visibility.
    - **Основные файлы:** `src/auditor/tool_registry.py`, invocation tests
    - **Приёмка:** Все известные production backlog findings закрыты.

  **Правило родительского статуса:** сохранять `[~]`, пока все обязательные work items не завершены и не проведена независимая приёмка.

- [~] `TOOL-001` — Зарегистрированный SSH execution adapter.

  **Декомпозиция:**

  - **`TOOL001-01` · `Done`** — Манифесты `ssh_run` и `ssh_read_file`, schemas/capabilities.
    - **Основные файлы:** `tools/catalog/ssh_run.json`, `ssh_read_file.json`
    - **Приёмка:** Registry валидирует и публикует обе операции.
  - **`TOOL001-02` · `Done`** — Runtime target/credential resolution только из active inventory/run context.
    - **Основные файлы:** SSH adapter modules, `effective_settings`
    - **Приёмка:** LLM не задаёт произвольный host или credential.
  - **`TOOL001-03` · `Done`** — Strict command allow-list, path gate, redaction и normalized `ToolResult`.
    - **Основные файлы:** `src/auditor/tools/ssh_policy.py`, SSH adapters
    - **Приёмка:** Shell composition/interpreters и запрещённые paths блокируются.
  - **`TOOL001-04` · `Backlog`** — Защитить `ssh_read_file` от symlink bypass.
    - **Основные файлы:** SSH adapter/policy tests
    - **Приёмка:** Разрешённый symlink на запрещённый файл не читается.
  - **`TOOL001-05` · `Backlog`** — Полностью применять manifest timeout/max-output/retry и immutable hash snapshot.
    - **Основные файлы:** tool invocation/runtime modules
    - **Приёмка:** Реальный execution path использует pinned limits/hashes.
  - **`TOOL001-06` · `Open`** — Независимая acceptance на реальном SSH target.
    - **Основные файлы:** integration/E2E tests
    - **Приёмка:** Adapter подтверждён вне fake transport.

  **Правило родительского статуса:** сохранять `[~]`, пока все обязательные work items не завершены и не проведена независимая приёмка.

- [ ] `TOOL-002` — Зарегистрированный WinRM PowerShell adapter.

  **Декомпозиция:**

  - **`TOOL002-01` · `Open`** — Определить manifests, capabilities и PowerShell operation IDs.
    - **Основные файлы:** `tools/catalog/winrm_*.json` (new), policy
    - **Приёмка:** Только read-only операции доступны.
  - **`TOOL002-02` · `Open`** — Реализовать WinRM adapter с TLS validation и runtime credentials.
    - **Основные файлы:** `src/auditor/tools/adapters/winrm.py` (new)
    - **Приёмка:** Insecure mode только явным policy-controlled override.
  - **`TOOL002-03` · `Open`** — Нормализовать structured PowerShell JSON output и typed errors.
    - **Основные файлы:** WinRM adapter/domain result modules
    - **Приёмка:** Не использовать `Win32_Product`; LocalPort не смешивается с PID.
  - **`TOOL002-04` · `Open`** — Добавить fake и real Windows integration tests.
    - **Основные файлы:** `tests/test_winrm_tool.py`, integration fixtures
    - **Приёмка:** Windows Server и PostgreSQL-on-Windows E2E проходят.

  **Правило родительского статуса:** сохранять `[ ]` до появления значимой реализации; перевод в `[~]` или `[x]` только после независимого review.

- [ ] `TOOL-003` — Зарегистрированный HTTP/HTTPS request adapter.

  **Декомпозиция:**

  - **`TOOL003-01` · `Open`** — Определить manifests для GET/HEAD и bounded response.
    - **Основные файлы:** `tools/catalog/http_get.json` (new), policy
    - **Приёмка:** POST/PUT/PATCH/DELETE отсутствуют.
  - **`TOOL003-02` · `Open`** — Реализовать adapter с target scope, TLS и redirect restrictions.
    - **Основные файлы:** `src/auditor/tools/adapters/http.py` (new)
    - **Приёмка:** Redirect не выходит за разрешённый host/scope.
  - **`TOOL003-03` · `Open`** — Redact headers/cookies/tokens и нормализовать status/headers/body metadata.
    - **Основные файлы:** HTTP adapter, `ToolResult` normalizer
    - **Приёмка:** Секретные headers не сохраняются.
  - **`TOOL003-04` · `Open`** — Добавить local HTTP fixture и integration tests.
    - **Основные файлы:** `tests/test_http_tool.py`, test server fixture
    - **Приёмка:** Timeout, size limit, TLS errors и redirects покрыты.

  **Правило родительского статуса:** сохранять `[ ]` до появления значимой реализации; перевод в `[~]` или `[x]` только после независимого review.

- [ ] `TOOL-004` — Зарегистрированный TCP connectivity adapter.

  **Декомпозиция:**

  - **`TOOL004-01` · `Open`** — Определить manifest `tcp.connect` с bounded list of ports.
    - **Основные файлы:** `tools/catalog/tcp_connect.json` (new), policy
    - **Приёмка:** Не более policy-approved портов на host.
  - **`TOOL004-02` · `Open`** — Реализовать adapter; прямые socket calls оставить только внутри него.
    - **Основные файлы:** `src/auditor/tools/adapters/tcp.py` (new)
    - **Приёмка:** Workflow не импортирует `socket` напрямую.
  - **`TOOL004-03` · `Open`** — Нормализовать open/closed/timeout/unreachable facts.
    - **Основные файлы:** TCP adapter, fact normalizer
    - **Приёмка:** Ошибки различимы и secret-free.
  - **`TOOL004-04` · `Open`** — Добавить integration tests с локальными open/closed ports.
    - **Основные файлы:** `tests/test_tcp_tool.py`
    - **Приёмка:** Нет subnet scanning и target override.

  **Правило родительского статуса:** сохранять `[ ]` до появления значимой реализации; перевод в `[~]` или `[x]` только после независимого review.

- [ ] `TOOL-005` — Зарегистрированный SNMP GET/WALK adapter.

  **Декомпозиция:**

  - **`TOOL005-01` · `Open`** — Определить SNMP GET/WALK manifests и OID allow-list.
    - **Основные файлы:** `tools/catalog/snmp_get.json`, `snmp_walk.json` (new), policy
    - **Приёмка:** SNMP SET отсутствует.
  - **`TOOL005-02` · `Open`** — Реализовать SNMPv3-first adapter и runtime secret resolution.
    - **Основные файлы:** `src/auditor/tools/adapters/snmp.py` (new)
    - **Приёмка:** Community/auth keys не попадают в LLM/evidence.
  - **`TOOL005-03` · `Open`** — Ограничить walk prefix/output/time и нормализовать vendor/model/platform facts.
    - **Основные файлы:** SNMP adapter/fact normalizer
    - **Приёмка:** Walk не выходит за policy OID prefixes.
  - **`TOOL005-04` · `Open`** — Добавить fake-agent и optional real integration tests.
    - **Основные файлы:** `tests/test_snmp_tool.py`
    - **Приёмка:** Cisco discovery работает без Python framework mapping.

  **Правило родительского статуса:** сохранять `[ ]` до появления значимой реализации; перевод в `[~]` или `[x]` только после независимого review.

- [~] `INPUT-005` — Воспроизводимый агентный preflight и `AuditPlan`.

  **Декомпозиция:**

  - **`INPUT005-01` · `Done`** — Inventory validation, normalization и запрет discovery при errors.
    - **Основные файлы:** inventory domain/loaders/service tests
    - **Приёмка:** Invalid inventory не запускает probes.
  - **`INPUT005-02` · `Done`** — Persistence/reload effective inventory для confirm/start.
    - **Основные файлы:** `src/auditor/inventory/service.py`, API routes
    - **Приёмка:** Discovery facts сохраняются через lifecycle.
  - **`INPUT005-03` · `Done`** — Registry-authorized SSH discovery без `_tcp_reachable`.
    - **Основные файлы:** `src/auditor/inventory/collectors.py`, `tool_discovery.py`
    - **Приёмка:** SSH adapter классифицирует failures.
  - **`INPUT005-04` · `Done`** — HostCapabilitySnapshot для supported и unsupported assets.
    - **Основные файлы:** host capability domain/tool discovery
    - **Приёмка:** Каждый asset остаётся видимым.
  - **`INPUT005-05` · `Done`** — Единый deterministic technology detection.
    - **Основные файлы:** `src/auditor/inventory/detect.py`, snapshot sync
    - **Приёмка:** Port-only PostgreSQL = suspected.
  - **`INPUT005-06` · `Done`** — Deterministic AuditPlan, stale gates, confirmation и plan↔job identity.
    - **Основные файлы:** audit plan/service/API modules
    - **Приёмка:** Jobs создаются только после confirmation и совпадают с targets.
  - **`INPUT005-07` · `Backlog`** — Pin `plan_revision_id` в API/CLI confirm/start contract.
    - **Основные файлы:** `src/auditor/api/inventory_routes.py`, service/domain tests
    - **Приёмка:** Старая отображённая revision не подтверждает новый latest plan.
  - **`INPUT005-08` · `Backlog`** — Immutable storage plan/effective-inventory по revision.
    - **Основные файлы:** inventory plan/service persistence
    - **Приёмка:** Предыдущие revisions retrievable и не перезаписываются.
  - **`INPUT005-09` · `Open`** — Typed applicability metadata schema в Markdown framework.
    - **Основные файлы:** `src/auditor/domain/framework_applicability.py` (new), `frameworks.py`
    - **Приёмка:** Invalid metadata non-executable.
  - **`INPUT005-10` · `Open`** — Safe predicate evaluator `all/any/none`, no executable expressions.
    - **Основные файлы:** `src/auditor/framework_applicability.py` (new)
    - **Приёмка:** Unknown fact = missing_evidence.
  - **`INPUT005-11` · `Open`** — Stable normalized fact namespace с source/confidence/evidence.
    - **Основные файлы:** `src/auditor/inventory/facts.py` (new)
    - **Приёмка:** Predicates не читают raw tool output.
  - **`INPUT005-12` · `Open`** — Framework candidate evaluation для всех host/framework pairs.
    - **Основные файлы:** `src/auditor/inventory/framework_candidates.py` (new)
    - **Приёмка:** not_matched candidates не инициируют discovery.
  - **`INPUT005-13` · `Open`** — Удалить production dependency от hardcoded platform mapping.
    - **Основные файлы:** `src/auditor/inventory/select_frameworks.py`, `agents/*.md`
    - **Приёмка:** Новый Markdown framework выбирается без Python changes.
  - **`INPUT005-14` · `Open`** — Typed capability-based discovery plan из missing facts.
    - **Основные файлы:** `src/auditor/domain/discovery_plan.py`, `inventory/discovery_plan.py` (new)
    - **Приёмка:** Planner запрашивает capability, а не protocol client.
  - **`INPUT005-15` · `Open`** — Интегрировать TCP discovery capability.
    - **Основные файлы:** TOOL-004 files + discovery plan
    - **Приёмка:** Port facts собираются через registry.
  - **`INPUT005-16` · `Open`** — Интегрировать HTTP discovery capability.
    - **Основные файлы:** TOOL-003 files + discovery plan
    - **Приёмка:** HTTP facts собираются через registry.
  - **`INPUT005-17` · `Open`** — Интегрировать SNMP discovery capability.
    - **Основные файлы:** TOOL-005 files + discovery plan
    - **Приёмка:** Cisco facts и selection не hardcoded.
  - **`INPUT005-18` · `Open`** — Evidence-backed framework selection provenance.
    - **Основные файлы:** selection/domain/plan modules
    - **Приёмка:** Каждый selected framework содержит facts, tools, evidence refs и confidence.
  - **`INPUT005-19` · `Open`** — Operator clarification loop для missing/conflicting evidence.
    - **Основные файлы:** audit plan/service/API modules
    - **Приёмка:** Ответ оператора создаёт новую plan revision с provenance.
  - **`INPUT005-20` · `Open`** — Markdown plug-in E2E: Redis framework без Python изменений.
    - **Основные файлы:** `agents/redis_health.md` fixture, dynamic framework tests
    - **Приёмка:** Framework selected только для Redis hosts.
  - **`INPUT005-21` · `Open`** — Multi-protocol discovery E2E: TCP/HTTP/SNMP.
    - **Основные файлы:** dynamic discovery E2E tests
    - **Приёмка:** Blocked capability остаётся видимой.
  - **`INPUT005-22` · `Open`** — Markdown/YAML/JSON execution E2E.
    - **Основные файлы:** inventory fixtures/E2E tests
    - **Приёмка:** Форматы дают эквивалентный effective plan и jobs.
  - **`INPUT005-23` · `Open`** — Независимая acceptance и перевод parent в `[x]`.
    - **Основные файлы:** checklists, defect map, CI evidence
    - **Приёмка:** Все mandatory items Done, CI green, 77/77.

  **Правило родительского статуса:** сохранять `[~]`, пока все обязательные work items не завершены и не проведена независимая приёмка.

### M3 — Управляемый агент, LangGraph и сбор доказательств

- [ ] `AGENT-001` — Реализовать управляемый LLM agent runtime.

  **Декомпозиция:**

  - **`AGENT001-01` · `Open`** — Определить typed agent input/output contracts и allowed context.
    - **Основные файлы:** `src/auditor/domain/agent.py` (new), prompts/runtime
    - **Приёмка:** Raw credentials не входят в model context.
  - **`AGENT001-02` · `Open`** — Передавать inventory, framework catalog, tool schemas и policy snapshot.
    - **Основные файлы:** agent runtime/context builder
    - **Приёмка:** Контекст pinned и versioned.
  - **`AGENT001-03` · `Open`** — Реализовать discovery planning/tool-selection loop с structured outputs.
    - **Основные файлы:** agent nodes/subgraph
    - **Приёмка:** LLM предлагает только зарегистрированные capabilities.
  - **`AGENT001-04` · `Open`** — Детерминированно валидировать facts, decisions и AuditPlan.
    - **Основные файлы:** agent validators + INPUT-005 modules
    - **Приёмка:** LLM не расширяет scope и не подтверждает plan.
  - **`AGENT001-05` · `Open`** — HITL questions и continuation after operator response.
    - **Основные файлы:** API/OpenWebUI integration, graph state
    - **Приёмка:** Ответы создают auditable state transition.
  - **`AGENT001-06` · `Open`** — E2E: Windows+AD DS, Linux+PostgreSQL, unsupported, tool failure, custom framework.
    - **Основные файлы:** `tests/test_agent_e2e.py` (new)
    - **Приёмка:** Все сценарии дают evidence-backed decisions.

  **Правило родительского статуса:** сохранять `[ ]` до появления значимой реализации; перевод в `[~]` или `[x]` только после независимого review.

- [ ] `FLOW-001` — Типизированное минимальное состояние графа.

  **Декомпозиция:**

  - **`FLOW001-01` · `Open`** — Определить immutable/typed graph state fields.
    - **Основные файлы:** `src/auditor/domain/graph_state.py` (new)
    - **Приёмка:** Нет untyped catch-all state dict.
  - **`FLOW001-02` · `Open`** — Разделить run-level и worker-level state.
    - **Основные файлы:** graph/subgraph modules
    - **Приёмка:** Workers не перезаписывают общий state.
  - **`FLOW001-03` · `Open`** — Добавить serialization/checkpoint round-trip tests.
    - **Основные файлы:** `tests/test_graph_state.py`
    - **Приёмка:** State восстанавливается без потери identity.

  **Правило родительского статуса:** сохранять `[ ]` до появления значимой реализации; перевод в `[~]` или `[x]` только после независимого review.

- [ ] `FLOW-002` — Заменить `asyncio.gather` на LangGraph `Send`.

  **Декомпозиция:**

  - **`FLOW002-01` · `Open`** — Сформировать fan-out payloads по host/framework/requirement.
    - **Основные файлы:** graph orchestration modules
    - **Приёмка:** Каждый Send несёт canonical job identity.
  - **`FLOW002-02` · `Open`** — Реализовать fan-in через reducer.
    - **Основные файлы:** graph builder/reducer modules
    - **Приёмка:** Результаты не зависят от completion order.
  - **`FLOW002-03` · `Open`** — Добавить concurrency/backpressure tests.
    - **Основные файлы:** `tests/test_graph_send.py`
    - **Приёмка:** Пределы параллелизма соблюдаются.

  **Правило родительского статуса:** сохранять `[ ]` до появления значимой реализации; перевод в `[~]` или `[x]` только после независимого review.

- [ ] `FLOW-003` — Бесшовный reducer результатов.

  **Декомпозиция:**

  - **`FLOW003-01` · `Open`** — Определить reducer key и merge semantics.
    - **Основные файлы:** `src/auditor/graph_reducers.py` (new)
    - **Приёмка:** Duplicate result identity обрабатывается детерминированно.
  - **`FLOW003-02` · `Open`** — Сохранить partial/errors без скрытой потери.
    - **Основные файлы:** reducer + domain models
    - **Приёмка:** Один failed worker не удаляет успешные результаты.
  - **`FLOW003-03` · `Open`** — Order-independent property tests.
    - **Основные файлы:** `tests/test_graph_reducers.py`
    - **Приёмка:** Перестановка результатов не меняет final state.

  **Правило родительского статуса:** сохранять `[ ]` до появления значимой реализации; перевод в `[~]` или `[x]` только после независимого review.

- [ ] `FLOW-004` — Отдельный worker/subgraph требований.

  **Декомпозиция:**

  - **`FLOW004-01` · `Open`** — Выделить lifecycle requirement worker.
    - **Основные файлы:** `src/auditor/workflows/requirement_worker.py` (new)
    - **Приёмка:** Load→tools→evidence→assess→persist изолированы.
  - **`FLOW004-02` · `Open`** — Передавать только scoped tools/evidence.
    - **Основные файлы:** worker/context modules
    - **Приёмка:** Worker не видит чужие hosts/frameworks.
  - **`FLOW004-03` · `Open`** — Unit tests на success/blocked/error/partial.
    - **Основные файлы:** `tests/test_requirement_worker.py`
    - **Приёмка:** Transitions и outputs типизированы.

  **Правило родительского статуса:** сохранять `[ ]` до появления значимой реализации; перевод в `[~]` или `[x]` только после независимого review.

- [ ] `FLOW-005` — Таймауты, retries и backpressure.

  **Декомпозиция:**

  - **`FLOW005-01` · `Open`** — Typed retry policy по error taxonomy.
    - **Основные файлы:** workflow retry module
    - **Приёмка:** Policy denied/auth/invalid args не retry.
  - **`FLOW005-02` · `Open`** — Per-tool/per-worker timeout и max attempts.
    - **Основные файлы:** graph/tool runtime
    - **Приёмка:** Зависшие операции завершаются bounded.
  - **`FLOW005-03` · `Open`** — Global/per-host concurrency limits.
    - **Основные файлы:** graph scheduler/settings
    - **Приёмка:** Лимиты конфигурируемы и проверяются.
  - **`FLOW005-04` · `Open`** — Load/failure regression tests.
    - **Основные файлы:** `tests/test_flow_resilience.py`
    - **Приёмка:** Нет retry storm и unbounded queue.

  **Правило родительского статуса:** сохранять `[ ]` до появления значимой реализации; перевод в `[~]` или `[x]` только после независимого review.

- [ ] `FLOW-006` — Корректный resume и cancellation.

  **Декомпозиция:**

  - **`FLOW006-01` · `Open`** — Checkpoint completed/interrupted/pending jobs.
    - **Основные файлы:** graph checkpoint modules
    - **Приёмка:** Completed jobs не выполняются повторно.
  - **`FLOW006-02` · `Open`** — Resume with new attempt identity for interrupted worker.
    - **Основные файлы:** workflow/job registry
    - **Приёмка:** История попыток сохраняется.
  - **`FLOW006-03` · `Open`** — Cancellation state и stop-new-work semantics.
    - **Основные файлы:** API/CLI/graph lifecycle
    - **Приёмка:** Новые Send не создаются после cancel.
  - **`FLOW006-04` · `Open`** — E2E cancel/resume tests.
    - **Основные файлы:** `tests/test_resume_cancel.py`
    - **Приёмка:** Run корректно доходит до terminal state.

  **Правило родительского статуса:** сохранять `[ ]` до появления значимой реализации; перевод в `[~]` или `[x]` только после независимого review.

- [~] `FLOW-007` — Убрать process-wide singleton графа.

  **Декомпозиция:**

  - **`FLOW007-01` · `Done`** — API runtime создаёт graph через `ApplicationRuntime`.
    - **Основные файлы:** `src/auditor/application_runtime.py`, API app
    - **Приёмка:** FastAPI path не требует global graph.
  - **`FLOW007-02` · `Partial`** — Перевести CLI/tests на явную graph factory/dependency.
    - **Основные файлы:** CLI/compatibility/test modules
    - **Приёмка:** Новые call sites не используют singleton getters.
  - **`FLOW007-03` · `Open`** — Удалить deprecated process-wide getters/cache.
    - **Основные файлы:** `src/auditor/graph.py` и exports
    - **Приёмка:** В production code отсутствует singleton graph.
  - **`FLOW007-04` · `Open`** — Lifecycle acceptance для нескольких graph instances.
    - **Основные файлы:** runtime tests
    - **Приёмка:** Instances не разделяют mutable state.

  **Правило родительского статуса:** сохранять `[~]`, пока все обязательные work items не завершены и не проведена независимая приёмка.

- [~] `EVID-001` — Нормализация вывода инструментов.

  **Декомпозиция:**

  - **`EVID001-01` · `Done`** — Определить `ToolResult` v1 для SSH slice.
    - **Основные файлы:** `src/auditor/domain/tool_result.py`
    - **Приёмка:** Status/output/error/identity/timestamps присутствуют.
  - **`EVID001-02` · `Open`** — Применить ToolResult ко всем registered adapters и MCP.
    - **Основные файлы:** tool adapters/MCP wrappers
    - **Приёмка:** Нет transport-specific raw dict в workflow.
  - **`EVID001-03` · `Open`** — Версионировать normalizers и output schemas.
    - **Основные файлы:** domain/normalizer registry
    - **Приёмка:** Невалидный adapter output fail-closed.
  - **`EVID001-04` · `Open`** — Cross-protocol contract tests.
    - **Основные файлы:** `tests/test_tool_result_contract.py`
    - **Приёмка:** SSH/WinRM/HTTP/TCP/SNMP/MCP дают совместимую форму.

  **Правило родительского статуса:** сохранять `[~]`, пока все обязательные work items не завершены и не проведена независимая приёмка.

- [~] `EVID-002` — Read-only поведение и безопасный вызов.

  **Декомпозиция:**

  - **`EVID002-01` · `Done`** — SSH strict allow-list и path restrictions.
    - **Основные файлы:** SSH policy/adapter tests
    - **Приёмка:** Опасные команды блокируются.
  - **`EVID002-02` · `Open`** — Единая risk/read-only policy для всех capabilities.
    - **Основные файлы:** capability policy/domain modules
    - **Приёмка:** Dangerous operation требует отдельного explicit policy.
  - **`EVID002-03` · `Open`** — Pre/post invocation guards для target, args и output.
    - **Основные файлы:** tool execution workflow
    - **Приёмка:** LLM не обходит policy через arguments.
  - **`EVID002-04` · `Backlog`** — Закрыть SSH symlink и другие protocol hardening findings.
    - **Основные файлы:** adapter-specific tests
    - **Приёмка:** Known bypasses устранены.

  **Правило родительского статуса:** сохранять `[~]`, пока все обязательные work items не завершены и не проведена независимая приёмка.

- [~] `EVID-003` — Provenance для каждого evidence.

  **Декомпозиция:**

  - **`EVID003-01` · `Done`** — SSH sidecars содержат client/run/framework/requirement и hashes.
    - **Основные файлы:** evidence store/tool execution
    - **Приёмка:** Базовая provenance доступна.
  - **`EVID003-02` · `Open`** — Добавить tool/version/capability/target/attempt/timestamps для всех sources.
    - **Основные файлы:** evidence domain/store
    - **Приёмка:** Каждый факт трассируется до invocation.
  - **`EVID003-03` · `Open`** — Связать normalized facts и framework decisions с evidence refs.
    - **Основные файлы:** INPUT-005 fact/selection modules
    - **Приёмка:** Selected framework имеет проверяемую цепочку evidence.
  - **`EVID003-04` · `Open`** — Tamper/missing-provenance validation tests.
    - **Основные файлы:** `tests/test_evidence_provenance.py`
    - **Приёмка:** Evidence без обязательной provenance не принимается.

  **Правило родительского статуса:** сохранять `[~]`, пока все обязательные work items не завершены и не проведена независимая приёмка.

- [ ] `EVID-004` — Structured output вместо хрупкого JSON-парсинга.

  **Декомпозиция:**

  - **`EVID004-01` · `Open`** — Определить Pydantic/JSON Schema outputs для LLM nodes.
    - **Основные файлы:** domain agent/assessment schemas
    - **Приёмка:** Свободный JSON extraction удалён.
  - **`EVID004-02` · `Open`** — Использовать provider structured output или constrained parser.
    - **Основные файлы:** LLM adapter/runtime
    - **Приёмка:** Schema violation даёт typed error/retry.
  - **`EVID004-03` · `Open`** — Regression на malformed/partial model output.
    - **Основные файлы:** tests
    - **Приёмка:** Невалидный output не попадает в results.

  **Правило родительского статуса:** сохранять `[ ]` до появления значимой реализации; перевод в `[~]` или `[x]` только после независимого review.

- [ ] `EVID-005` — Достаточность evidence и confidence.

  **Декомпозиция:**

  - **`EVID005-01` · `Open`** — Определить evidence requirements по requirement/framework.
    - **Основные файлы:** framework metadata/domain
    - **Приёмка:** Минимальные источники и freshness заданы явно.
  - **`EVID005-02` · `Open`** — Рассчитать deterministic sufficiency/confidence.
    - **Основные файлы:** evidence evaluator module
    - **Приёмка:** LLM explanation не меняет score.
  - **`EVID005-03` · `Open`** — Блокировать final conclusion при insufficient evidence.
    - **Основные файлы:** assessment workflow
    - **Приёмка:** Status становится unknown/needs_evidence.
  - **`EVID005-04` · `Open`** — Tests на strong/weak/conflicting evidence.
    - **Основные файлы:** tests
    - **Приёмка:** Границы confidence воспроизводимы.

  **Правило родительского статуса:** сохранять `[ ]` до появления значимой реализации; перевод в `[~]` или `[x]` только после независимого review.

- [ ] `EVID-006` — Защита неизменяемых полей фреймворка.

  **Декомпозиция:**

  - **`EVID006-01` · `Open`** — Отделить immutable framework cells от model-filled cells.
    - **Основные файлы:** framework/assessment domain
    - **Приёмка:** ID/title/category/severity/pass criteria не изменяются.
  - **`EVID006-02` · `Open`** — Validate result against pinned framework hash.
    - **Основные файлы:** assessment persistence
    - **Приёмка:** Result от другого framework revision отклоняется.
  - **`EVID006-03` · `Open`** — Mutation/adversarial tests.
    - **Основные файлы:** tests
    - **Приёмка:** LLM не переписывает immutable metadata.

  **Правило родительского статуса:** сохранять `[ ]` до появления значимой реализации; перевод в `[~]` или `[x]` только после независимого review.

- [ ] `EVID-007` — Без скрытой потери данных при truncation.

  **Декомпозиция:**

  - **`EVID007-01` · `Open`** — Определить explicit truncation metadata и original size/hash.
    - **Основные файлы:** ToolResult/evidence domain
    - **Приёмка:** Truncated output явно помечен.
  - **`EVID007-02` · `Open`** — Сохранять полный raw artifact отдельно при policy permit.
    - **Основные файлы:** evidence store
    - **Приёмка:** Assessment использует bounded view, raw доступен по ref.
  - **`EVID007-03` · `Open`** — Chunk/continuation strategy для важных данных.
    - **Основные файлы:** tool/evidence workflow
    - **Приёмка:** Нет silent tail loss.
  - **`EVID007-04` · `Open`** — Tests на boundary sizes и secret redaction.
    - **Основные файлы:** tests
    - **Приёмка:** Truncation не раскрывает и не скрывает критично без marker.

  **Правило родительского статуса:** сохранять `[ ]` до появления значимой реализации; перевод в `[~]` или `[x]` только после независимого review.

### M4 — PostgreSQL, история и исключения

- [ ] `DB-001` — Версионированные миграции БД.

  **Декомпозиция:**

  - **`DB001-01` · `Open`** — Выбрать migration framework и baseline schema.
    - **Основные файлы:** `alembic.ini`, `migrations/` (new), DB settings
    - **Приёмка:** Новая БД поднимается одной командой.
  - **`DB001-02` · `Open`** — Миграции для clients/runs/jobs/results/evidence/exceptions.
    - **Основные файлы:** migration files
    - **Приёмка:** Schema отражает canonical identities.
  - **`DB001-03` · `Open`** — Upgrade/downgrade и CI migration tests.
    - **Основные файлы:** integration tests/CI
    - **Приёмка:** Миграции воспроизводимы на PostgreSQL.

  **Правило родительского статуса:** сохранять `[ ]` до появления значимой реализации; перевод в `[~]` или `[x]` только после независимого review.

- [ ] `DB-002` — Repository и границы транзакций.

  **Декомпозиция:**

  - **`DB002-01` · `Open`** — Определить repository interfaces и unit-of-work.
    - **Основные файлы:** `src/auditor/repositories/` (new)
    - **Приёмка:** Domain не зависит от SQLAlchemy session напрямую.
  - **`DB002-02` · `Open`** — Реализовать PostgreSQL repositories.
    - **Основные файлы:** repository implementations
    - **Приёмка:** Writes атомарны в заявленных границах.
  - **`DB002-03` · `Open`** — Integration tests на rollback/idempotency.
    - **Основные файлы:** tests/integration
    - **Приёмка:** Partial write не оставляет inconsistent state.

  **Правило родительского статуса:** сохранять `[ ]` до появления значимой реализации; перевод в `[~]` или `[x]` только после независимого review.

- [ ] `DB-003` — Разделить initial/external/analyst/effective оценки.

  **Декомпозиция:**

  - **`DB003-01` · `Open`** — Определить source-specific result models/columns.
    - **Основные файлы:** domain + migrations
    - **Приёмка:** Каждая оценка сохраняется отдельно.
  - **`DB003-02` · `Open`** — Deterministic effective-result resolver.
    - **Основные файлы:** result service
    - **Приёмка:** Приоритеты и provenance явны.
  - **`DB003-03` · `Open`** — Regression на пересчёт после review/override.
    - **Основные файлы:** tests
    - **Приёмка:** Initial evidence не перезаписывается.

  **Правило родительского статуса:** сохранять `[ ]` до появления значимой реализации; перевод в `[~]` или `[x]` только после независимого review.

- [ ] `DB-004` — Optimistic concurrency и audit log.

  **Декомпозиция:**

  - **`DB004-01` · `Open`** — Version/revision columns и compare-and-swap writes.
    - **Основные файлы:** migrations/repositories
    - **Приёмка:** Stale update отклоняется.
  - **`DB004-02` · `Open`** — Append-only audit events.
    - **Основные файлы:** audit log domain/repository
    - **Приёмка:** Actor/action/before-after/reason фиксируются.
  - **`DB004-03` · `Open`** — Concurrent analyst/review tests.
    - **Основные файлы:** integration tests
    - **Приёмка:** Lost update невозможен.

  **Правило родительского статуса:** сохранять `[ ]` до появления значимой реализации; перевод в `[~]` или `[x]` только после независимого review.

- [ ] `HIST-001` — Получение предыдущего сравнимого результата.

  **Декомпозиция:**

  - **`HIST001-01` · `Open`** — Определить comparison key client/asset/framework/requirement.
    - **Основные файлы:** history domain
    - **Приёмка:** Сравниваются только совместимые revisions.
  - **`HIST001-02` · `Open`** — Repository query latest comparable result.
    - **Основные файлы:** history repository/service
    - **Приёмка:** Cancelled/incomplete runs фильтруются.
  - **`HIST001-03` · `Open`** — Tests на отсутствующий/несовместимый history.
    - **Основные файлы:** tests
    - **Приёмка:** Нет ложного сравнения.

  **Правило родительского статуса:** сохранять `[ ]` до появления значимой реализации; перевод в `[~]` или `[x]` только после независимого review.

- [ ] `HIST-002` — Детерминированный классификатор изменений.

  **Декомпозиция:**

  - **`HIST002-01` · `Open`** — Определить states new/resolved/regressed/unchanged/changed.
    - **Основные файлы:** history classifier
    - **Приёмка:** Правила не зависят от LLM.
  - **`HIST002-02` · `Open`** — Сравнивать status и normalized observations.
    - **Основные файлы:** classifier service
    - **Приёмка:** Порядок observed items не влияет.
  - **`HIST002-03` · `Open`** — Property/regression tests.
    - **Основные файлы:** tests
    - **Приёмка:** Классификация воспроизводима.

  **Правило родительского статуса:** сохранять `[ ]` до появления значимой реализации; перевод в `[~]` или `[x]` только после независимого review.

- [ ] `EXC-001` — Реестр утверждённых исключений.

  **Декомпозиция:**

  - **`EXC001-01` · `Open`** — Определить exception model: scope, owner, reason, expiry, approval.
    - **Основные файлы:** domain + migrations
    - **Приёмка:** Exception не является свободным комментарием.
  - **`EXC001-02` · `Open`** — CRUD/service/API с authorization и audit log.
    - **Основные файлы:** exception service/API
    - **Приёмка:** Изменение требует actor/reason.
  - **`EXC001-03` · `Open`** — Expiry/revocation tests.
    - **Основные файлы:** tests
    - **Приёмка:** Expired exception не применяется.

  **Правило родительского статуса:** сохранять `[ ]` до появления значимой реализации; перевод в `[~]` или `[x]` только после независимого review.

- [ ] `EXC-002` — Применение исключений к observed items.

  **Декомпозиция:**

  - **`EXC002-01` · `Open`** — Детерминированный matcher exception↔finding.
    - **Основные файлы:** exception matcher
    - **Приёмка:** Scope exact и fail-closed.
  - **`EXC002-02` · `Open`** — Сохранять original observation и applied exception provenance.
    - **Основные файлы:** result service
    - **Приёмка:** Finding не удаляется.
  - **`EXC002-03` · `Open`** — Tests на partial/non-match/expiry.
    - **Основные файлы:** tests
    - **Приёмка:** Лишние findings не подавляются.

  **Правило родительского статуса:** сохранять `[ ]` до появления значимой реализации; перевод в `[~]` или `[x]` только после независимого review.

- [ ] `HIST-003` — История и исключения в текущей оценке.

  **Декомпозиция:**

  - **`HIST003-01` · `Open`** — Добавить comparable history/exceptions в assessment context.
    - **Основные файлы:** assessment context builder
    - **Приёмка:** Только scoped/pinned records передаются.
  - **`HIST003-02` · `Open`** — Deterministic pre/post processing вокруг LLM.
    - **Основные файлы:** assessment workflow
    - **Приёмка:** LLM не изменяет exception semantics.
  - **`HIST003-03` · `Open`** — Persist change classification и exception application.
    - **Основные файлы:** result repository
    - **Приёмка:** Report может объяснить текущий статус.

  **Правило родительского статуса:** сохранять `[ ]` до появления значимой реализации; перевод в `[~]` или `[x]` только после независимого review.

- [ ] `HIST-004` — E2E регрессия повторного аудита.

  **Декомпозиция:**

  - **`HIST004-01` · `Open`** — Создать synthetic first/second audit dataset.
    - **Основные файлы:** tests/fixtures/history
    - **Приёмка:** Содержит resolved/regressed/accepted exception cases.
  - **`HIST004-02` · `Open`** — Run two audits and verify classifications.
    - **Основные файлы:** E2E tests
    - **Приёмка:** Previous result корректно найден.
  - **`HIST004-03` · `Open`** — Verify report/history persistence.
    - **Основные файлы:** reporting E2E
    - **Приёмка:** Результаты воспроизводимы после restart.

  **Правило родительского статуса:** сохранять `[ ]` до появления значимой реализации; перевод в `[~]` или `[x]` только после независимого review.

### M5 — Единая генерация отчётов

- [ ] `REPORT-001` — Отдельный reporting-пакет.

  **Декомпозиция:**

  - **`REPORT001-01` · `Open`** — Создать package boundary и public service API.
    - **Основные файлы:** `src/auditor/reporting/` (new)
    - **Приёмка:** Workflow не форматирует отчёты inline.
  - **`REPORT001-02` · `Open`** — Определить renderer interfaces.
    - **Основные файлы:** reporting interfaces
    - **Приёмка:** Markdown/Excel/Word используют один dataset.
  - **`REPORT001-03` · `Open`** — Удалить/адаптировать legacy report call sites.
    - **Основные файлы:** graph/API/CLI
    - **Приёмка:** Один reporting entry point.

  **Правило родительского статуса:** сохранять `[ ]` до появления значимой реализации; перевод в `[~]` или `[x]` только после независимого review.

- [ ] `REPORT-002` — Версионированный `ReportDataset`.

  **Декомпозиция:**

  - **`REPORT002-01` · `Open`** — Определить strict versioned dataset schema.
    - **Основные файлы:** `src/auditor/reporting/domain.py`
    - **Приёмка:** Unknown fields/version validation.
  - **`REPORT002-02` · `Open`** — Включить identities, results, history, exceptions, metrics.
    - **Основные файлы:** reporting domain
    - **Приёмка:** Все renderers получают достаточные structured data.
  - **`REPORT002-03` · `Open`** — JSON round-trip/schema tests.
    - **Основные файлы:** tests/reporting
    - **Приёмка:** Dataset deterministic.

  **Правило родительского статуса:** сохранять `[ ]` до появления значимой реализации; перевод в `[~]` или `[x]` только после независимого review.

- [ ] `REPORT-003` — Сборка dataset из структурированных источников.

  **Декомпозиция:**

  - **`REPORT003-01` · `Open`** — Dataset builder из repositories/evidence/registry.
    - **Основные файлы:** reporting builder
    - **Приёмка:** Нет Markdown re-parsing.
  - **`REPORT003-02` · `Open`** — Resolve effective result/history/exceptions.
    - **Основные файлы:** builder services
    - **Приёмка:** Source provenance сохранена.
  - **`REPORT003-03` · `Open`** — Missing/partial data semantics.
    - **Основные файлы:** builder tests
    - **Приёмка:** Incomplete run не выдаётся как полный.

  **Правило родительского статуса:** сохранять `[ ]` до появления значимой реализации; перевод в `[~]` или `[x]` только после независимого review.

- [ ] `REPORT-004` — Межзаписевая валидация.

  **Декомпозиция:**

  - **`REPORT004-01` · `Open`** — Проверить foreign identities и uniqueness.
    - **Основные файлы:** reporting validator
    - **Приёмка:** Нет orphan results/jobs.
  - **`REPORT004-02` · `Open`** — Проверить totals/status consistency.
    - **Основные файлы:** validator
    - **Приёмка:** Summary совпадает с details.
  - **`REPORT004-03` · `Open`** — Fail/warn policy и tests.
    - **Основные файлы:** tests
    - **Приёмка:** Критичная inconsistency блокирует публикацию.

  **Правило родительского статуса:** сохранять `[ ]` до появления значимой реализации; перевод в `[~]` или `[x]` только после независимого review.

- [ ] `REPORT-005` — Единый metrics engine.

  **Декомпозиция:**

  - **`REPORT005-01` · `Open`** — Определить canonical metric formulas.
    - **Основные файлы:** reporting metrics
    - **Приёмка:** Формулы versioned.
  - **`REPORT005-02` · `Open`** — Считать management/host/framework metrics из dataset.
    - **Основные файлы:** metrics engine
    - **Приёмка:** Renderers не пересчитывают независимо.
  - **`REPORT005-03` · `Open`** — Golden tests на counts/percentages.
    - **Основные файлы:** tests
    - **Приёмка:** Нет расхождения Markdown/Excel/Word.

  **Правило родительского статуса:** сохранять `[ ]` до появления значимой реализации; перевод в `[~]` или `[x]` только после независимого review.

- [ ] `REPORT-006` — Канонический `report.json` и checksum.

  **Декомпозиция:**

  - **`REPORT006-01` · `Open`** — Serialize canonical sorted JSON.
    - **Основные файлы:** reporting serializer
    - **Приёмка:** Одинаковый dataset = одинаковый JSON.
  - **`REPORT006-02` · `Open`** — Вычислять checksum и manifest.
    - **Основные файлы:** reporting publication
    - **Приёмка:** Checksum фиксируется до render.
  - **`REPORT006-03` · `Open`** — Integrity tests.
    - **Основные файлы:** tests
    - **Приёмка:** Изменение artifact обнаруживается.

  **Правило родительского статуса:** сохранять `[ ]` до появления значимой реализации; перевод в `[~]` или `[x]` только после независимого review.

- [ ] `REPORT-007` — Markdown из `ReportDataset`.

  **Декомпозиция:**

  - **`REPORT007-01` · `Open`** — Deterministic Markdown renderer.
    - **Основные файлы:** reporting markdown module
    - **Приёмка:** Нет LLM rewriting immutable results.
  - **`REPORT007-02` · `Open`** — Management summary + per-host tables.
    - **Основные файлы:** templates
    - **Приёмка:** Все findings и limitations представлены.
  - **`REPORT007-03` · `Open`** — Golden-file tests.
    - **Основные файлы:** tests/golden
    - **Приёмка:** Output стабилен.

  **Правило родительского статуса:** сохранять `[ ]` до появления значимой реализации; перевод в `[~]` или `[x]` только после независимого review.

- [ ] `REPORT-008` — Excel для менеджмента.

  **Декомпозиция:**

  - **`REPORT008-01` · `Open`** — Workbook layout: Management Summary, dashboard, per-host results.
    - **Основные файлы:** reporting excel module/template
    - **Приёмка:** Один workbook покрывает все hosts.
  - **`REPORT008-02` · `Open`** — Charts/KPI из metrics engine.
    - **Основные файлы:** excel renderer
    - **Приёмка:** Charts связаны с dataset, не ручными values.
  - **`REPORT008-03` · `Open`** — Validation/formats/freeze/filter usability.
    - **Основные файлы:** template/tests
    - **Приёмка:** Файл открывается без repair warnings.
  - **`REPORT008-04` · `Open`** — Golden/structural tests.
    - **Основные файлы:** tests
    - **Приёмка:** Sheets, tables, formulas и counts проверяются.

  **Правило родительского статуса:** сохранять `[ ]` до появления значимой реализации; перевод в `[~]` или `[x]` только после независимого review.

- [ ] `REPORT-009` — Word для менеджмента.

  **Декомпозиция:**

  - **`REPORT009-01` · `Open`** — DOCX template и renderer.
    - **Основные файлы:** reporting docx module/template
    - **Приёмка:** Стили и sections единообразны.
  - **`REPORT009-02` · `Open`** — Management narrative только из structured fields.
    - **Основные файлы:** renderer
    - **Приёмка:** Нет выдуманных данных.
  - **`REPORT009-03` · `Open`** — Document structure regression.
    - **Основные файлы:** tests
    - **Приёмка:** Tables/headings/links корректны.

  **Правило родительского статуса:** сохранять `[ ]` до появления значимой реализации; перевод в `[~]` или `[x]` только после независимого review.

- [ ] `REPORT-010` — Атомарная публикация и версионирование.

  **Декомпозиция:**

  - **`REPORT010-01` · `Open`** — Stage→validate→atomic rename publication.
    - **Основные файлы:** reporting publisher
    - **Приёмка:** Частичный набор файлов не публикуется.
  - **`REPORT010-02` · `Open`** — Version directory/manifest/latest pointer.
    - **Основные файлы:** publisher
    - **Приёмка:** Старые отчёты сохраняются.
  - **`REPORT010-03` · `Open`** — Crash/retry tests.
    - **Основные файлы:** tests
    - **Приёмка:** Повторная публикация idempotent.

  **Правило родительского статуса:** сохранять `[ ]` до появления значимой реализации; перевод в `[~]` или `[x]` только после независимого review.

- [ ] `REPORT-011` — Интеграция reporting во все call sites.

  **Декомпозиция:**

  - **`REPORT011-01` · `Open`** — CLI/API/graph используют reporting service.
    - **Основные файлы:** call sites
    - **Приёмка:** Нет альтернативных renderer paths.
  - **`REPORT011-02` · `Open`** — Async/status/error semantics.
    - **Основные файлы:** API/runtime
    - **Приёмка:** Публикация отражается в run status.
  - **`REPORT011-03` · `Open`** — Compatibility cleanup.
    - **Основные файлы:** legacy report modules
    - **Приёмка:** Старые paths удалены или deprecated.

  **Правило родительского статуса:** сохранять `[ ]` до появления значимой реализации; перевод в `[~]` или `[x]` только после независимого review.

- [ ] `REPORT-012` — Полный reporting regression suite.

  **Декомпозиция:**

  - **`REPORT012-01` · `Open`** — Synthetic dataset with edge cases.
    - **Основные файлы:** tests/fixtures/reporting
    - **Приёмка:** History/exceptions/partial/unsupported включены.
  - **`REPORT012-02` · `Open`** — Cross-format consistency tests.
    - **Основные файлы:** tests/reporting
    - **Приёмка:** Markdown/Excel/Word имеют одинаковые counts.
  - **`REPORT012-03` · `Open`** — Artifact integrity and reproducibility tests.
    - **Основные файлы:** tests
    - **Приёмка:** Checksums стабильны.

  **Правило родительского статуса:** сохранять `[ ]` до появления значимой реализации; перевод в `[~]` или `[x]` только после независимого review.

### M6 — Анонимизация и внешний model review

- [ ] `REVIEW-001` — Версионированный `ReviewPackage`.

  **Декомпозиция:**

  - **`REVIEW001-01` · `Open`** — Strict package schema и identity.
    - **Основные файлы:** review domain
    - **Приёмка:** Package привязан к report/result revisions.
  - **`REVIEW001-02` · `Open`** — Manifest/checksum/source references.
    - **Основные файлы:** review package builder
    - **Приёмка:** Пакет воспроизводим.
  - **`REVIEW001-03` · `Open`** — Schema/round-trip tests.
    - **Основные файлы:** tests/review
    - **Приёмка:** Unsupported version rejected.

  **Правило родительского статуса:** сохранять `[ ]` до появления значимой реализации; перевод в `[~]` или `[x]` только после независимого review.

- [ ] `REVIEW-002` — Обратимая карта анонимизации.

  **Декомпозиция:**

  - **`REVIEW002-01` · `Open`** — Tokenization rules для hosts/users/IPs/secrets/identifiers.
    - **Основные файлы:** anonymization module
    - **Приёмка:** Mapping deterministic внутри package.
  - **`REVIEW002-02` · `Open`** — Encrypted/access-controlled mapping storage.
    - **Основные файлы:** review persistence
    - **Приёмка:** Карта не отправляется внешней модели.
  - **`REVIEW002-03` · `Open`** — Collision/round-trip tests.
    - **Основные файлы:** tests
    - **Приёмка:** Деанонимизация точна.

  **Правило родительского статуса:** сохранять `[ ]` до появления значимой реализации; перевод в `[~]` или `[x]` только после независимого review.

- [ ] `REVIEW-003` — Детекция утечек перед отправкой.

  **Декомпозиция:**

  - **`REVIEW003-01` · `Open`** — Secret/PII/IP/domain scanners.
    - **Основные файлы:** leak detector
    - **Приёмка:** Known canaries обнаруживаются.
  - **`REVIEW003-02` · `Open`** — Fail-closed release gate.
    - **Основные файлы:** review service
    - **Приёмка:** Package с leak не отправляется.
  - **`REVIEW003-03` · `Open`** — False-positive allow mechanism with audit.
    - **Основные файлы:** policy/tests
    - **Приёмка:** Исключение явное и логируется.

  **Правило родительского статуса:** сохранять `[ ]` до появления значимой реализации; перевод в `[~]` или `[x]` только после независимого review.

- [ ] `REVIEW-004` — Адаптер внешней модели.

  **Декомпозиция:**

  - **`REVIEW004-01` · `Open`** — Provider-neutral interface и settings.
    - **Основные файлы:** external model adapter
    - **Приёмка:** Provider secrets runtime-only.
  - **`REVIEW004-02` · `Open`** — Timeout/retry/rate-limit/cost metadata.
    - **Основные файлы:** adapter runtime
    - **Приёмка:** Ошибки typed.
  - **`REVIEW004-03` · `Open`** — Mock provider tests.
    - **Основные файлы:** tests
    - **Приёмка:** No network in unit tests.

  **Правило родительского статуса:** сохранять `[ ]` до появления значимой реализации; перевод в `[~]` или `[x]` только после независимого review.

- [ ] `REVIEW-005` — Валидация ответа внешней модели.

  **Декомпозиция:**

  - **`REVIEW005-01` · `Open`** — Structured response schema.
    - **Основные файлы:** review domain
    - **Приёмка:** Свободный prose не изменяет results.
  - **`REVIEW005-02` · `Open`** — Validate referenced IDs and allowed changes.
    - **Основные файлы:** review validator
    - **Приёмка:** Unknown/missing IDs rejected.
  - **`REVIEW005-03` · `Open`** — Adversarial/malformed tests.
    - **Основные файлы:** tests
    - **Приёмка:** Prompt injection не расширяет scope.

  **Правило родительского статуса:** сохранять `[ ]` до появления значимой реализации; перевод в `[~]` или `[x]` только после независимого review.

- [ ] `REVIEW-006` — Атомарная деанонимизация.

  **Декомпозиция:**

  - **`REVIEW006-01` · `Open`** — Validate full mapping before replacement.
    - **Основные файлы:** deanonymizer
    - **Приёмка:** Partial mapping blocks operation.
  - **`REVIEW006-02` · `Open`** — Atomic output creation.
    - **Основные файлы:** review service
    - **Приёмка:** Нет partially deanonymized artifact.
  - **`REVIEW006-03` · `Open`** — Round-trip tests.
    - **Основные файлы:** tests
    - **Приёмка:** Original identifiers restored exactly.

  **Правило родительского статуса:** сохранять `[ ]` до появления значимой реализации; перевод в `[~]` или `[x]` только после независимого review.

- [ ] `REVIEW-007` — Сохранение review и пересчёт effective results.

  **Декомпозиция:**

  - **`REVIEW007-01` · `Open`** — Persist immutable external review.
    - **Основные файлы:** DB/repository
    - **Приёмка:** Initial result unchanged.
  - **`REVIEW007-02` · `Open`** — Recompute effective result with source priorities.
    - **Основные файлы:** result service
    - **Приёмка:** External changes traceable.
  - **`REVIEW007-03` · `Open`** — Audit log/tests.
    - **Основные файлы:** tests
    - **Приёмка:** Повторный import idempotent.

  **Правило родительского статуса:** сохранять `[ ]` до появления значимой реализации; перевод в `[~]` или `[x]` только после независимого review.

- [ ] `REVIEW-008` — Семантика ошибок и публикации.

  **Декомпозиция:**

  - **`REVIEW008-01` · `Open`** — Typed lifecycle statuses queued/sent/received/validated/rejected/published.
    - **Основные файлы:** review domain/service
    - **Приёмка:** Status transitions valid.
  - **`REVIEW008-02` · `Open`** — Retry and terminal error policy.
    - **Основные файлы:** review runtime
    - **Приёмка:** No duplicate publication.
  - **`REVIEW008-03` · `Open`** — Operator-visible API errors.
    - **Основные файлы:** API/docs/tests
    - **Приёмка:** Secrets absent.

  **Правило родительского статуса:** сохранять `[ ]` до появления значимой реализации; перевод в `[~]` или `[x]` только после независимого review.

- [ ] `REVIEW-009` — Тест полного external-review пути.

  **Декомпозиция:**

  - **`REVIEW009-01` · `Open`** — Build→anonymize→scan→send→validate→deanonymize→persist fixture.
    - **Основные файлы:** E2E tests
    - **Приёмка:** Все stages covered.
  - **`REVIEW009-02` · `Open`** — Failure injection at each stage.
    - **Основные файлы:** E2E tests
    - **Приёмка:** Atomicity preserved.
  - **`REVIEW009-03` · `Open`** — Verify report regeneration.
    - **Основные файлы:** report/review E2E
    - **Приёмка:** Effective results reflected once.

  **Правило родительского статуса:** сохранять `[ ]` до появления значимой реализации; перевод в `[~]` или `[x]` только после независимого review.

### M7 — Правки аналитика и регенерация

- [ ] `ANALYST-001` — Детерминированный импорт reviewed Excel.

  **Декомпозиция:**

  - **`ANALYST001-01` · `Open`** — Define editable cells/row identity/template version.
    - **Основные файлы:** analyst import domain
    - **Приёмка:** Immutable columns protected.
  - **`ANALYST001-02` · `Open`** — Parse workbook without formula ambiguity.
    - **Основные файлы:** import service
    - **Приёмка:** Rows map to canonical result IDs.
  - **`ANALYST001-03` · `Open`** — Validation/error report.
    - **Основные файлы:** tests
    - **Приёмка:** Invalid workbook does not partially apply.

  **Правило родительского статуса:** сохранять `[ ]` до появления значимой реализации; перевод в `[~]` или `[x]` только после независимого review.

- [ ] `ANALYST-002` — Транзакционные overrides и версии отчётов.

  **Декомпозиция:**

  - **`ANALYST002-01` · `Open`** — Persist analyst override separately.
    - **Основные файлы:** DB/domain
    - **Приёмка:** Original/external results unchanged.
  - **`ANALYST002-02` · `Open`** — Apply all workbook changes in one transaction.
    - **Основные файлы:** repository/service
    - **Приёмка:** Failure rolls back all.
  - **`ANALYST002-03` · `Open`** — Create new effective/report revision.
    - **Основные файлы:** report service
    - **Приёмка:** Old version retained.

  **Правило родительского статуса:** сохранять `[ ]` до появления значимой реализации; перевод в `[~]` или `[x]` только после независимого review.

- [ ] `ANALYST-003` — Явные service/CLI/API операции.

  **Декомпозиция:**

  - **`ANALYST003-01` · `Open`** — Service commands validate/import/preview/apply/regenerate.
    - **Основные файлы:** analyst service
    - **Приёмка:** No direct repository access from API.
  - **`ANALYST003-02` · `Open`** — CLI/API endpoints with actor/reason.
    - **Основные файлы:** CLI/API
    - **Приёмка:** Mutations audited.
  - **`ANALYST003-03` · `Open`** — Authorization/idempotency tests.
    - **Основные файлы:** tests
    - **Приёмка:** Repeated apply safe.

  **Правило родительского статуса:** сохранять `[ ]` до появления значимой реализации; перевод в `[~]` или `[x]` только после независимого review.

- [ ] `ANALYST-004` — Round-trip тесты import/regeneration.

  **Декомпозиция:**

  - **`ANALYST004-01` · `Open`** — Generate workbook from synthetic dataset.
    - **Основные файлы:** E2E fixture
    - **Приёмка:** Known editable cells.
  - **`ANALYST004-02` · `Open`** — Modify/import/regenerate all formats.
    - **Основные файлы:** E2E tests
    - **Приёмка:** Overrides reflected consistently.
  - **`ANALYST004-03` · `Open`** — Verify history/audit log/version preservation.
    - **Основные файлы:** tests
    - **Приёмка:** No source data loss.

  **Правило родительского статуса:** сохранять `[ ]` до появления значимой реализации; перевод в `[~]` или `[x]` только после независимого review.

### M8 — Наблюдаемость, cleanup и release gate

- [ ] `OPS-001` — Типизированная таксономия ошибок.

  **Декомпозиция:**

  - **`OPS001-01` · `Open`** — Определить domain error codes/categories/retryability.
    - **Основные файлы:** `src/auditor/domain/errors.py` (new)
    - **Приёмка:** No string matching for control flow.
  - **`OPS001-02` · `Open`** — Map adapters/workflows/API to taxonomy.
    - **Основные файлы:** runtime/API modules
    - **Приёмка:** HTTP/CLI semantics consistent.
  - **`OPS001-03` · `Open`** — Contract tests and secret-safe messages.
    - **Основные файлы:** tests
    - **Приёмка:** Errors contain IDs, not secrets.

  **Правило родительского статуса:** сохранять `[ ]` до появления значимой реализации; перевод в `[~]` или `[x]` только после независимого review.

- [ ] `OPS-002` — Structured logs, metrics и run manifest.

  **Декомпозиция:**

  - **`OPS002-01` · `Open`** — Structured log schema with correlation IDs.
    - **Основные файлы:** logging config/runtime
    - **Приёмка:** client/run/job/tool IDs present.
  - **`OPS002-02` · `Open`** — Metrics for lifecycle, tools, errors, latency, retries.
    - **Основные файлы:** metrics module
    - **Приёмка:** Bounded labels/no secrets.
  - **`OPS002-03` · `Open`** — Persist run manifest with pinned identities/config.
    - **Основные файлы:** run manifest module
    - **Приёмка:** Execution reproducible/auditable.
  - **`OPS002-04` · `Open`** — Observability tests.
    - **Основные файлы:** tests
    - **Приёмка:** Required fields emitted.

  **Правило родительского статуса:** сохранять `[ ]` до появления значимой реализации; перевод в `[~]` или `[x]` только после независимого review.

- [ ] `OPS-003` — Убрать legacy Markdown-парсинг из production flow.

  **Декомпозиция:**

  - **`OPS003-01` · `Open`** — Identify production reads of generated Markdown.
    - **Основные файлы:** code search/architecture doc
    - **Приёмка:** List fixed.
  - **`OPS003-02` · `Open`** — Replace with structured repositories/datasets.
    - **Основные файлы:** workflow/report modules
    - **Приёмка:** Markdown only presentation/source framework where intended.
  - **`OPS003-03` · `Open`** — Delete compatibility parsers after migration.
    - **Основные файлы:** legacy modules/tests
    - **Приёмка:** No hidden production dependency.

  **Правило родительского статуса:** сохранять `[ ]` до появления значимой реализации; перевод в `[~]` или `[x]` только после независимого review.

- [~] `OPS-004` — Модульный cleanup и dependency review.

  **Декомпозиция:**

  - **`OPS004-01` · `Partial`** — Разделить крупные inventory/tool/workflow modules.
    - **Основные файлы:** `src/auditor/inventory/`, tools/workflows
    - **Приёмка:** Public boundaries documented.
  - **`OPS004-02` · `Open`** — Удалить dead/deprecated paths и duplicate helpers.
    - **Основные файлы:** repo-wide
    - **Приёмка:** No unused fallback implementation.
  - **`OPS004-03` · `Open`** — Review dependency pins/licenses/security.
    - **Основные файлы:** `pyproject.toml`, lock file, docs
    - **Приёмка:** Unused deps removed, risky versions addressed.
  - **`OPS004-04` · `Open`** — Import-cycle/module-size/static checks.
    - **Основные файлы:** CI/scripts
    - **Приёмка:** Architecture regressions detected.

  **Правило родительского статуса:** сохранять `[~]`, пока все обязательные work items не завершены и не проведена независимая приёмка.

- [~] `DOC-001` — Обновить пользовательскую и developer-документацию.

  **Декомпозиция:**

  - **`DOC001-01` · `Partial`** — Документировать inventory/framework/tool-registry/preflight lifecycle.
    - **Основные файлы:** `README.md`, `docs/architecture.md`, `docs/tools.md`
    - **Приёмка:** Docs отражают current POC.
  - **`DOC001-02` · `Open`** — Документировать work-item checklist и процесс постановки ТЗ.
    - **Основные файлы:** `checklist/README.md` (new), contribution docs
    - **Приёмка:** Любой child ID можно отдать отдельным PR.
  - **`DOC001-03` · `Open`** — Синхронизировать EN/RU docs и CI counters.
    - **Основные файлы:** `checklist/*.md`, docs
    - **Приёмка:** Нет расходящихся статусов/чисел.
  - **`DOC001-04` · `Open`** — Operator runbooks: analyze/confirm/start/stale/errors.
    - **Основные файлы:** `docs/runbooks/` (new)
    - **Приёмка:** Примеры API/CLI актуальны.

  **Правило родительского статуса:** сохранять `[~]`, пока все обязательные work items не завершены и не проведена независимая приёмка.

- [ ] `DOC-002` — Полностью синтетический sample package.

  **Декомпозиция:**

  - **`DOC002-01` · `Open`** — Synthetic inventory/credentials refs/frameworks/evidence.
    - **Основные файлы:** `examples/sample_client/` (new)
    - **Приёмка:** Нет real client data.
  - **`DOC002-02` · `Open`** — Expected plans/results/reports.
    - **Основные файлы:** examples/golden
    - **Приёмка:** Demo воспроизводима offline/fake adapters.
  - **`DOC002-03` · `Open`** — Quickstart validation in CI.
    - **Основные файлы:** CI/example tests
    - **Приёмка:** Sample не устаревает.

  **Правило родительского статуса:** сохранять `[ ]` до появления значимой реализации; перевод в `[~]` или `[x]` только после независимого review.

- [ ] `CI-001` — Полный release pipeline.

  **Декомпозиция:**

  - **`CI001-01` · `Open`** — Migration + unit + integration + E2E matrix.
    - **Основные файлы:** `.github/workflows/release.yml` (new)
    - **Приёмка:** Release blocked by any mandatory suite.
  - **`CI001-02` · `Open`** — Build/package/SBOM/vulnerability scan.
    - **Основные файлы:** CI scripts
    - **Приёмка:** Artifacts reproducible and scanned.
  - **`CI001-03` · `Open`** — Publish signed/checksummed artifacts.
    - **Основные файлы:** release workflow
    - **Приёмка:** Provenance available.
  - **`CI001-04` · `Open`** — Release checklist/version/tag rules.
    - **Основные файлы:** docs/scripts
    - **Приёмка:** No manual undocumented release path.

  **Правило родительского статуса:** сохранять `[ ]` до появления значимой реализации; перевод в `[~]` или `[x]` только после независимого review.

- [ ] `E2E-001` — Финальный acceptance-сценарий.

  **Декомпозиция:**

  - **`E2E001-01` · `Open`** — Synthetic multi-client/multi-host inventory and tools.
    - **Основные файлы:** E2E fixtures
    - **Приёмка:** Linux/Windows/PostgreSQL/Cisco/unsupported included.
  - **`E2E001-02` · `Open`** — Analyze→discovery→confirm→execute→history/exceptions→reports.
    - **Основные файлы:** E2E suite
    - **Приёмка:** Lifecycle completes with canonical identities.
  - **`E2E001-03` · `Open`** — External review + analyst override + regeneration.
    - **Основные файлы:** E2E suite
    - **Приёмка:** Effective result/report revisions correct.
  - **`E2E001-04` · `Open`** — Failure/resume/cancel/stale/security scenarios.
    - **Основные файлы:** E2E suite
    - **Приёмка:** Fail-closed behavior verified.
  - **`E2E001-05` · `Open`** — Independent release acceptance evidence.
    - **Основные файлы:** checklist/release artifacts
    - **Приёмка:** All mandatory parents accepted.

  **Правило родительского статуса:** сохранять `[ ]` до появления значимой реализации; перевод в `[~]` или `[x]` только после независимого review.

## Текущие блокеры и ближайшая последовательность

1. `INPUT005-07` — pin конкретной `plan_revision_id` при confirm/start.
2. `INPUT005-09` + `INPUT005-10` + `INPUT005-11` — metadata, predicates и
   normalized fact namespace.
3. `INPUT005-12` + `INPUT005-13` — dynamic framework selection без hardcoded mapping.
4. `INPUT005-14` + `INPUT005-18` + `INPUT005-19` — discovery plan, provenance и
   operator clarification.
5. `TOOL-003` + `TOOL-004` + `TOOL-005` — HTTP, TCP и SNMP adapters.
6. `FLOW-001` + `FLOW-003` + `FLOW-004` — typed graph foundation и requirement worker.
7. `FLOW-002` + `FLOW-005` + `FLOW-006` — Send, resilience, resume/cancellation.
8. `AGENT-001` — governed LLM runtime.
9. `E2E-001` — финальная product acceptance.

Рекомендуемое разбиение ближайших PR:

```text
PR A: INPUT005-07
PR B: INPUT005-09 + INPUT005-10 + INPUT005-11
PR C: INPUT005-12 + INPUT005-13
PR D: INPUT005-14 + INPUT005-18 + INPUT005-19
PR E: TOOL-004 + INPUT005-15
PR F: TOOL-003 + INPUT005-16
PR G: TOOL-005 + INPUT005-17
PR H: INPUT005-20 + INPUT005-21 + INPUT005-22
```

## Правила статусов

- `[ ]` Открыто: независимая приёмка не подтверждена.
- `[~]` Частично: есть значимая реализация, но не все критерии приёмки.
- `[x]` Принято: все критерии подтверждены кодом, тестами и независимой проверкой.
- `Done/Partial/Open/Blocked/Backlog` применяются только к дочерним work items.
- Зелёный CI сам по себе не переводит родительский requirement в `[x]`.
- При появлении новой проблемы создаётся child work item у соответствующего
  родителя; верхнеуровневый список из 77 задач не расширяется без отдельного
  архитектурного решения.

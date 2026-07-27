# `psql_auditor` — Мастер-чеклист разработки и приёмки

Версия чеклиста: **1.14**
Дата: **2026-07-27**
Репозиторий: `whatelseek/psql_auditor`
Базовый commit: [`b064e26`](https://github.com/whatelseek/psql_auditor/commit/b064e26e9150d0bf4ebc2036ecc7c839b4b219e4)
Последняя независимо рассмотренная ревизия: [`eb2ef61`](https://github.com/whatelseek/psql_auditor/commit/eb2ef6130ac17e3f2d7142095045c316ed9a6cbd)
Всего задач: **77**

Синхронизирован с английской версией
[`psql_auditor_master_refactoring_checklist (5).md`](psql_auditor_master_refactoring_checklist%20%285%29.md).
Оба файла обновляются одновременно. Открытые пункты нельзя помечать принятыми
без независимой приёмки.

## Сводка статусов

| Статус                 |          Количество |
| ---------------------- | ------------------: |
| Принято `[x]`          | **10 / 77 (13,0%)** |
| Частично `[~]`         |   **6 / 77 (7,8%)** |
| Открыто `[ ]`          | **61 / 77 (79,2%)** |
| Не полностью завершено | **67 / 77 (87,0%)** |

Принято: `AUD-001`, `AUD-002`, `AUD-003`, `CORE-001`, `CORE-002`, `CORE-003`, `CORE-004`, `CORE-005`, `INPUT-001`, `INPUT-003`.

Частично: `CORE-006`, `INPUT-002`, `INPUT-005`, `FLOW-007`, `OPS-004`, `DOC-001`.

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

PR #36 влит в `main` commit
[`7be1eae`](https://github.com/whatelseek/psql_auditor/commit/7be1eae717f002612efe5d434d517f5c47a219f1).
`INPUT-001` и `INPUT-003` остаются независимо принятыми. `INPUT-005` остаётся
`[~]`: детерминированная основа preflight реализована, но остаются интеграция
YAML/JSON execution и переход от hardcoded discovery collectors к реестру tools.

В v1.14 добавлены `TOOL-001`…`TOOL-005`. Локальная defect map в этом пакете
покрывает все **77** ID; после commit требуется повторно запустить
`make validate-defect-map` в repository CI.

| Проверка          | Результат                                           |
| ----------------- | --------------------------------------------------- |
| Format / Lint     | Passed на PR #36                                    |
| Type check        | Passed, 88 files на PR #36                          |
| Unit tests        | 442 passed на PR #36                                |
| Integration tests | 8 passed на PR #36                                  |
| Full suite        | 450 passed на PR #36                                |
| Defect map        | Локальный пакет v1.14: 77/77 ID; требуется CI rerun |

## Реестр задач

### M0 — Базовая линия, тесты и CI

* [x] `AUD-001` — Зафиксировать воспроизводимую базовую линию.
* [x] `AUD-002` — Единые локальные и CI quality gates.
* [x] `AUD-003` — Общие детерминированные тестовые фикстуры.

`AUD-001` принят. Checklist v1.14 и локальная defect map покрывают все 77 ID.
После commit требуется повторно запустить `make validate-defect-map` в CI.

### M1 — Идентификаторы и доменная модель

* [x] `CORE-001` — Разделить `client_id` и `audit_run_id`.
* [x] `CORE-002` — Разделить `AuditRun` и `AuditJob`.
* [x] `CORE-003` — Каноническая идентичность результата.
* [x] `CORE-004` — Структурированный `AssessmentResult`.
* [x] `CORE-005` — Изоляция checkpoint и артефактов по audit run.
* [~] `CORE-006` — Убрать скрытое глобальное изменяемое состояние.

`CORE-006` остаётся частичным до независимой приёмки.

### M2 — Входы и планирование аудита

* [x] `INPUT-001` — Строгий `AuditRequest`.

Доказательства приёмки:

* strict immutable versioned request model;

* pinned normalized inventory `version_id` и `content_hash`;

* stale request fail-closed на CLI, HTTP, direct execution и replay;

* secret-shaped поля отклоняются, credentials резолвятся только runtime;

* независимо принято на review-base PR #35 и перенесено в merged PR #36.

* [~] `INPUT-002` — Строгая валидация и регистрация текстовых фреймворков.

* [x] `INPUT-003` — Валидируемая модель inventory.

Для приёмки `INPUT-002` администратор должен добавлять человекочитаемый
Markdown-фреймворк в `agents/` без изменения core Python. Фреймворк должен
структурно валидироваться, версионироваться либо получать детерминированный
content hash, регистрироваться и предоставляться агенту. Markdown остаётся
source of truth; невалидные фреймворки fail-closed и не ломают валидные.

Доказательства приёмки `INPUT-003`:

* канонические модели inventory/host/service/fact/credential reference;

* загрузка Markdown, YAML и JSON с typed validation issues;

* stable normalized identity и secret-free persisted payloads;

* независимо принято на review-base PR #35 и перенесено в merged PR #36.

* [ ] `INPUT-004` — Управляемый администратором реестр MCP/инструментов и политика capabilities.

Текущие временные способы расширения:

* MCP tool: запись в `mcps/registry.json`, runtime-resolve credentials из
  inventory, curated read-only wrappers, binding в runtime и policy/evidence tests;
* встроенный tool: Python `@tool` adapter в `src/auditor/tools/`, экспорт через
  `get_*_tools()`, binding в audit/discovery runtime и тесты;
* SSH и WinRM дополнительно существуют как hardcoded discovery collectors,
  поэтому новый protocol сейчас приходится подключать в нескольких местах.

Целевая модель после `INPUT-004`:

* известный MCP server → registry entry + capability policy;
* известный adapter → versioned manifest в каталоге tools без изменений graph;
* новый protocol → один Python adapter + manifest;
* manifest описывает tool id/version, adapter entrypoint, capabilities, risk,
  input/output schemas, inventory access types, credential source, blocked
  operations, timeout/retry и output limits;
* registry validation работает fail-closed: invalid tools видимы администратору,
  но не bind-ятся модели;
* каждый `AuditRun` фиксирует immutable snapshot tool catalog и capability policy;
* LLM получает только tools, разрешённые для подтверждённых target и scope.

### Зарегистрированные transport и protocol tools

Следующие задачи реализуют только границу transport/execution. Они не должны
содержать technology detection, framework selection или audit conclusions.
Агент выбирает tools через `INPUT-004`; детерминированный код контролирует scope,
authorization, read-only policy, timeout, credentials, sanitization и provenance.

* [ ] `TOOL-001` — Зарегистрированный SSH execution adapter.
* [ ] `TOOL-002` — Зарегистрированный WinRM PowerShell adapter.
* [ ] `TOOL-003` — Зарегистрированный HTTP/HTTPS request adapter.
* [ ] `TOOL-004` — Зарегистрированный TCP connectivity adapter.
* [ ] `TOOL-005` — Зарегистрированный SNMP GET/WALK adapter.

Общие критерии приёмки:

* versioned tool id, input/output schemas и capability declaration;
* authorization target и runtime-only credential resolution;
* normalized `ToolResult`, совместимый с `EVID-001` и `EVID-003`;
* safe defaults, bounded output, timeout/retry и redaction секретов;
* вызов агентом только через registry и активный capability-policy snapshot;
* protocol-specific integration tests и typed failure taxonomy.

Дополнительные критерии `TOOL-002`:

* structured PowerShell output, предпочтительно `ConvertTo-Json`;

* не использовать `Win32_Product` для inventory;

* TLS certificate validation включена по умолчанию, insecure override явный;

* `LocalPort` парсится без смешивания с PID;

* integration test на реальном Windows Server/WinRM;

* E2E selection для Windows Server и PostgreSQL на Windows.

* [~] `INPUT-005` — Воспроизводимый агентный preflight и `AuditPlan`.

Для приёмки `INPUT-004` нужны добавляемые администратором MCP и инструменты,
версионированные schemas/capabilities, политика read-only и опасных действий,
secret-safe invocation, неизменяемый snapshot каталога на запуск и fail-closed
авторизация. LLM может выбирать зарегистрированные capabilities, но не может
создать незарегистрированный transport, обойти policy или выполнить скрытый код.

Частичные доказательства `INPUT-005`: типизированный `AuditPlan` с обязательным
подтверждением; stale-plan при расхождении inventory **или** discovery/effective
facts; runtime-резолв `CREDENTIALS.md` / `credentials.md` / `connection.md` без
персистенции секретов; переходные
`SshDiscoveryCollector` / `WinrmDiscoveryCollector` / `CompositeDiscoveryCollector`
из PR #36; это не целевая extensibility boundary, их нужно перенести в
`TOOL-001` / `TOOL-002` и общий discovery workflow. Сейчас они используются
по умолчанию (`--no-discovery` / `{ "discovery": false }` → no-op); read-only
SSH/WinRM; PostgreSQL только по сильным признакам (порт 5432 сам по себе не
выбирает `postgres_cis`); типизированные ошибки discovery, timeout/retry,
изоляция сбоя одного хоста; санитизированные evidence + детерминированные
preflight-ревизии; `audit start --confirm` не перезапускает discovery молча
(`--refresh-discovery` опционально); docs `docs/inventory-driven-audit.md` +
RU manual; тесты `tests/test_input005_discovery.py`,
`tests/integration/test_ssh_discovery_container.py`.
Независимая приёмка обязательна — не помечать `[x]` автоматически.

Дополнительные критерии `INPUT-005`:

* preflight передаёт управляемой LLM нормализованный inventory, валидные
  Markdown-фреймворки, зарегистрированные MCP/tools и активный policy snapshot;
* LLM может составлять и уточнять discovery-план, собирать дополнительные
  evidence, определять ПО/роли/сервисы и выбирать несколько фреймворков;
* выбор не ограничен hardcoded mapping «платформа → фреймворк»;
* каждый выбранный фреймворк имеет evidence-backed причину применимости;
* финальный план фиксирует identities inventory, frameworks, tools, policy и evidence;
* одинаковые pinned inputs и принятые evidence дают стабильный plan payload;
* неопределённость и конфликты превращаются в вопросы/ограничения, а не в
  молча выдуманные факты;
* discovery расширяется через registry: HTTP, TCP, SNMP и другие capabilities
  добавляются без нового hardcoded collector для платформы;
* завершены YAML/JSON execution integration и независимая приёмка.

### M3 — Управляемый агент, LangGraph и сбор доказательств

* [ ] `AGENT-001` — Реализовать управляемый LLM agent runtime.

Критерии приёмки `AGENT-001`:

* LLM получает нормализованный inventory и ссылки на credentials, но raw
  credentials не сохраняются и не включаются в контекст без необходимости;

* LLM получает все валидные текстовые фреймворки и schemas зарегистрированных
  MCP/tools;

* LLM может планировать discovery, выбирать разрешённые инструменты,
  интерпретировать вывод, запрашивать дополнительные evidence, определять
  технологии и выбирать несколько фреймворков;

* каждый существенный факт и решение о фреймворке содержит evidence reference,
  tool identity, время сбора, provenance и confidence;

* детерминированный код авторизует вызовы, обеспечивает read-only policy,
  санитизирует и сохраняет evidence, фиксирует версии/хеши, отклоняет stale plan
  и ведёт audit trail;

* LLM не может обойти capability policy, изменить целевую систему, незаметно
  расширить подтверждённый scope или выполнить незарегистрированный код;

* pinned snapshot evidence/catalog даёт стабильный финальный `AuditPlan`, даже
  если внутреннее рассуждение агента отличается;

* E2E покрывает Windows + AD DS, Linux + PostgreSQL, неподдерживаемые активы,
  недостаточные evidence, сбой MCP/tool и добавляемый администратором framework.

* [ ] `FLOW-001` — Типизированное минимальное состояние графа.

* [ ] `FLOW-002` — Заменить `asyncio.gather` на LangGraph `Send`.

* [ ] `FLOW-003` — Бесшовный reducer результатов.

* [ ] `FLOW-004` — Отдельный worker/subgraph требований.

* [ ] `FLOW-005` — Таймауты, retries и backpressure.

* [ ] `FLOW-006` — Корректный resume и cancellation.

* [~] `FLOW-007` — Убрать process-wide singleton графа.

* [ ] `EVID-001` — Нормализация вывода инструментов.

* [ ] `EVID-002` — Read-only поведение и безопасный вызов.

* [ ] `EVID-003` — Provenance для каждого evidence.

* [ ] `EVID-004` — Structured output вместо хрупкого JSON-парсинга.

* [ ] `EVID-005` — Достаточность evidence и confidence.

* [ ] `EVID-006` — Защита неизменяемых полей фреймворка.

* [ ] `EVID-007` — Без скрытой потери данных при truncation.

### M4 — PostgreSQL, история и исключения

* [ ] `DB-001` — Версионированные миграции БД.
* [ ] `DB-002` — Repository и границы транзакций.
* [ ] `DB-003` — Разделить initial/external/analyst/effective оценки.
* [ ] `DB-004` — Optimistic concurrency и audit log.
* [ ] `HIST-001` — Получение предыдущего сравнимого результата.
* [ ] `HIST-002` — Детерминированный классификатор изменений.
* [ ] `EXC-001` — Реестр утверждённых исключений.
* [ ] `EXC-002` — Применение исключений к observed items.
* [ ] `HIST-003` — История и исключения в текущей оценке.
* [ ] `HIST-004` — E2E регрессия повторного аудита.

### M5 — Единая генерация отчётов

* [ ] `REPORT-001` — Отдельный reporting-пакет.
* [ ] `REPORT-002` — Версионированный `ReportDataset`.
* [ ] `REPORT-003` — Сборка dataset из структурированных источников.
* [ ] `REPORT-004` — Межзаписевая валидация.
* [ ] `REPORT-005` — Единый metrics engine.
* [ ] `REPORT-006` — Канонический `report.json` и checksum.
* [ ] `REPORT-007` — Markdown из `ReportDataset`.
* [ ] `REPORT-008` — Excel для менеджмента.
* [ ] `REPORT-009` — Word для менеджмента.
* [ ] `REPORT-010` — Атомарная публикация и версионирование.
* [ ] `REPORT-011` — Интеграция reporting во все call sites.
* [ ] `REPORT-012` — Полный reporting regression suite.

### M6 — Анонимизация и внешний model review

* [ ] `REVIEW-001` — Версионированный `ReviewPackage`.
* [ ] `REVIEW-002` — Обратимая карта анонимизации.
* [ ] `REVIEW-003` — Детекция утечек перед отправкой.
* [ ] `REVIEW-004` — Адаптер внешней модели.
* [ ] `REVIEW-005` — Валидация ответа внешней модели.
* [ ] `REVIEW-006` — Атомарная деанонимизация.
* [ ] `REVIEW-007` — Сохранение review и пересчёт effective results.
* [ ] `REVIEW-008` — Семантика ошибок и публикации.
* [ ] `REVIEW-009` — Тест полного external-review пути.

### M7 — Правки аналитика и регенерация

* [ ] `ANALYST-001` — Детерминированный импорт reviewed Excel.
* [ ] `ANALYST-002` — Транзакционные overrides и версии отчётов.
* [ ] `ANALYST-003` — Явные service/CLI/API операции.
* [ ] `ANALYST-004` — Round-trip тесты import/regeneration.

### M8 — Наблюдаемость, cleanup и release gate

* [ ] `OPS-001` — Типизированная таксономия ошибок.
* [ ] `OPS-002` — Structured logs, metrics и run manifest.
* [ ] `OPS-003` — Убрать legacy Markdown-парсинг из production flow.
* [~] `OPS-004` — Модульный cleanup и dependency review.
* [~] `DOC-001` — Обновить пользовательскую и developer-документацию.
* [ ] `DOC-002` — Полностью синтетический sample package.
* [ ] `CI-001` — Полный release pipeline.
* [ ] `E2E-001` — Финальный acceptance-сценарий.

## Текущие блокеры

* `INPUT-002`: закрыть два deferred parser hardening finding; `AGENT-001`: завершить интеграцию governed runtime.
* `INPUT-004`: единый tool registry, capability policy и immutable per-run catalog snapshot.
* `TOOL-001`…`TOOL-005`: выделить SSH, WinRM, HTTP, TCP и SNMP из hardcoded discovery в protocol adapters.
* `INPUT-005`: перейти на общий tool-driven discovery, завершить YAML/JSON execution и независимую приёмку.
* `FLOW-007`: удалить deprecated process-wide graph getters после независимой приёмки.
* `DOC-001`: синхронизировать architecture, tools и evidence layout.
* `CI-001`: завершить workflow/report/review E2E и migration coverage.

## Правила статусов

* `[ ]` Открыто: независимая приёмка не подтверждена.
* `[~]` Частично: есть значимая реализация, но не все критерии приёмки.
* `[x]` Принято: все критерии подтверждены кодом/тестами и проверкой.

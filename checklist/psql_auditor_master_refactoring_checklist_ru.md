# `psql_auditor` — Мастер-чеклист разработки и приёмки

Версия чеклиста: **1.13**  
Дата: **2026-07-26**  
Репозиторий: `whatelseek/psql_auditor`  
Базовый commit: [`b064e26`](https://github.com/whatelseek/psql_auditor/commit/b064e26e9150d0bf4ebc2036ecc7c839b4b219e4)  
Последняя независимо рассмотренная ревизия: [`83434eb`](https://github.com/whatelseek/psql_auditor/commit/83434eb94643bfeb0df196b0f7f5b35b25415af8)  
Всего задач: **72**

Синхронизирован с английской версией
[`psql_auditor_master_refactoring_checklist (5).md`](psql_auditor_master_refactoring_checklist%20(5).md).
Оба файла обновляются одновременно. Открытые пункты нельзя помечать принятыми
без независимой приёмки.

## Сводка статусов

| Статус | Количество |
| --- | ---: |
| Принято `[x]` | **10 / 72 (13.9%)** |
| Частично `[~]` | **5 / 72 (6.9%)** |
| Открыто `[ ]` | **57 / 72 (79.2%)** |
| Не полностью завершено | **62 / 72 (86.1%)** |

Принято: `AUD-001`, `AUD-002`, `AUD-003`, `CORE-001`, `CORE-002`, `CORE-003`, `CORE-004`, `CORE-005`, `INPUT-001`, `INPUT-003`.

Частично: `CORE-006`, `INPUT-005`, `FLOW-007`, `OPS-004`, `DOC-001`.

## Последняя проверка

PR #36 (inventory-driven audit + production SSH/WinRM discovery) заменяет
закрытый PR #35. Независимая приёмка inventory-driven запуска приняла
`INPUT-001` и `INPUT-003` на commit
[`83434eb`](https://github.com/whatelseek/psql_auditor/commit/83434eb94643bfeb0df196b0f7f5b35b25415af8).
`INPUT-005` остаётся `[~]` до независимой приёмки (интеграция YAML/JSON
execution и review production discovery). Статусы приёмки не меняются
автоматически по зелёному CI.

| Проверка | Результат |
| --- | --- |
| Format / Lint | Passed |
| Type check | Passed, 88 files |
| Unit tests | 442 passed |
| Integration tests | 8 passed |
| Full suite | 450 passed |
| Defect map | `validate-defect-map: OK` (72/72) |
| Prior clean CI (база review PR #35) | [Run 30209929260](https://github.com/whatelseek/psql_auditor/actions/runs/30209929260), все jobs зелёные |
| Prior clean CI (async start + inventory identity) | [Run 30209817551](https://github.com/whatelseek/psql_auditor/actions/runs/30209817551), все jobs зелёные |

### Закрытые findings, перенесённые из PR #35 (superseded by PR #36)

- stale `AuditPlan` confirmation после изменения inventory;
- `CREDENTIALS.md` обнаруживался, но не загружался;
- `audit start` создавал request без запуска execution;
- API start вызывал `asyncio.run()` внутри активного event loop;
- сохранённый `AuditRequest` можно было replay после изменения inventory.

## Реестр задач

### M0 — Базовая линия, тесты и CI

- [x] `AUD-001` — Зафиксировать воспроизводимую базовую линию.
- [x] `AUD-002` — Единые локальные и CI quality gates.
- [x] `AUD-003` — Общие детерминированные тестовые фикстуры.

Доказательства закрытия:

- defect-to-module map покрывает все 72 ID чеклиста и enforced в CI;
- единые local/CI targets: format, lint, typecheck, unit, integration, full suite;
- детерминированные shared fixtures и fake LLM scenarios переиспользуются;
- обязательные тесты блокируют непреднамеренный external HTTP/LLM доступ.

### M1 — Идентификаторы и доменная модель

- [x] `CORE-001` — Разделить `client_id` и `audit_run_id`.
- [x] `CORE-002` — Разделить `AuditRun` и `AuditJob`.
- [x] `CORE-003` — Каноническая идентичность результата.
- [x] `CORE-004` — Структурированный `AssessmentResult`.
- [x] `CORE-005` — Изоляция checkpoint и артефактов по audit run.
- [~] `CORE-006` — Убрать скрытое глобальное изменяемое состояние.

`CORE-006` остаётся частичным. Ownership `ApplicationRuntime` и ряд lifecycle
race-fix реализованы, но полное удаление legacy process-wide mutable state
требует отдельной независимой приёмки.

### M2 — Входы и планирование аудита

- [x] `INPUT-001` — Строгий `AuditRequest`.

Доказательства приёмки:

- строгая типизированная immutable versioned request-модель;
- обязательные client, inventory, targets, framework versions, tool profile и
  run settings;
- secret-shaped поля запрещены;
- inventory reference фиксирует normalized `version_id` и `content_hash`;
- semantic validation перезагружает текущий inventory через loader/normalizer;
- stale requests отклоняются с `inventory_hash_mismatch` /
  `inventory_version_mismatch`;
- та же проверка на границах CLI, HTTP, `AuditorGraph.arun_request()` и
  replay сохранённого request;
- rejection до jobs/sessions/external calls;
- регрессионные тесты secret-safe ошибок и persisted request handling.

- [ ] `INPUT-002` — Строгая валидация фреймворков.
- [ ] `AGENT-001` — Администраторские Markdown audit-агенты в `agents/`.
- [x] `INPUT-003` — Валидируемая модель inventory.

Доказательства приёмки:

- канонические `ClientInventory`, `InventoryHost`, `InventoryService`,
  `InventoryFact` и `CredentialReference`;
- загрузка Markdown/YAML/JSON с уровнями error/warning/information;
- стабильные normalized `version_id` и `content_hash`;
- отдельный разбор `CREDENTIALS.md`, merge, дубликаты и host mapping;
- plaintext-секреты исключены из inventory/plan/request/API/артефактов;
- missing OS → `needs_discovery`, не блокирующая validation error;
- фикстуры Testcompany: пять хостов, несколько форматов, credentials и
  смены версий.

Неполный YAML/JSON execution path не блокирует `INPUT-003`; это относится к
execution integration, а не к validated inventory domain model.

- [ ] `INPUT-004` — Реестр инструментов и политика capabilities.
- [~] `INPUT-005` — Детерминированный preflight и `AuditPlan`.

Частичные доказательства:

- типизированный `AuditPlan` с обязательным явным подтверждением;
- детерминированное technology detection и framework selection с
  select/reject reasons;
- stale-plan rejection на confirm/start при расхождении inventory **или**
  discovery/effective facts;
- secret-safe runtime-резолв `CREDENTIALS.md` / `credentials.md` /
  `connection.md` (секреты не персистятся в models/plans/API/logs/evidence);
- production `SshDiscoveryCollector` / `WinrmDiscoveryCollector` /
  `CompositeDiscoveryCollector` на analyze path по умолчанию
  (`--no-discovery` / `{ "discovery": false }` → no-op);
- read-only SSH/WinRM; PostgreSQL только по сильным признакам (порт 5432 сам
  по себе не выбирает `postgres_cis`);
- типизированные ошибки discovery, timeout/retry, изоляция сбоя одного хоста;
- санитизированные discovery evidence под `artifacts/<slug>/preflight/…` и
  детерминированные preflight-ревизии;
- CLI `start_confirmed_audit` / API `await astart_confirmed_audit` →
  `AuditRequest` → `arun_request` с `audit_run_id` (confirmed start не
  перезапускает discovery молча; `--refresh-discovery` опционально);
- docs: `docs/inventory-driven-audit.md`; тесты:
  `tests/test_input005_discovery.py`,
  `tests/integration/test_ssh_discovery_container.py`.

Осталось:

- интеграция YAML/JSON inventory execution за пределами validated domain model;
- независимая приёмка production discovery (не помечать `[x]` автоматически).

### M3 — Оркестрация LangGraph и сбор доказательств

- [ ] `FLOW-001` — Типизированное минимальное состояние графа.
- [ ] `FLOW-002` — Заменить `asyncio.gather` на LangGraph `Send`.
- [ ] `FLOW-003` — Бесшовный reducer результатов.
- [ ] `FLOW-004` — Отдельный worker/subgraph требований.
- [ ] `FLOW-005` — Таймауты, retries и backpressure.
- [ ] `FLOW-006` — Корректный resume и cancellation.
- [~] `FLOW-007` — Убрать process-wide singleton графа.
- [ ] `EVID-001` — Нормализация вывода инструментов.
- [ ] `EVID-002` — Read-only поведение и безопасный вызов.
- [ ] `EVID-003` — Provenance для каждого evidence.
- [ ] `EVID-004` — Structured output вместо хрупкого JSON-парсинга.
- [ ] `EVID-005` — Достаточность evidence и confidence.
- [ ] `EVID-006` — Защита неизменяемых полей фреймворка.
- [ ] `EVID-007` — Без скрытой потери данных при truncation.

### M4 — PostgreSQL, история и исключения

- [ ] `DB-001` — Версионированные миграции БД.
- [ ] `DB-002` — Repository и границы транзакций.
- [ ] `DB-003` — Разделить initial/external/analyst/effective оценки.
- [ ] `DB-004` — Optimistic concurrency и audit log.
- [ ] `HIST-001` — Получение предыдущего сравнимого результата.
- [ ] `HIST-002` — Детерминированный классификатор изменений.
- [ ] `EXC-001` — Реестр утверждённых исключений.
- [ ] `EXC-002` — Применение исключений к observed items.
- [ ] `HIST-003` — История и исключения в текущей оценке.
- [ ] `HIST-004` — E2E регрессия повторного аудита.

### M5 — Единая генерация отчётов

- [ ] `REPORT-001` — Отдельный reporting-пакет.
- [ ] `REPORT-002` — Версионированный `ReportDataset`.
- [ ] `REPORT-003` — Сборка dataset из структурированных источников.
- [ ] `REPORT-004` — Межзаписевая валидация.
- [ ] `REPORT-005` — Единый metrics engine.
- [ ] `REPORT-006` — Канонический `report.json` и checksum.
- [ ] `REPORT-007` — Markdown из `ReportDataset`.
- [ ] `REPORT-008` — Excel для менеджмента.
- [ ] `REPORT-009` — Word для менеджмента.
- [ ] `REPORT-010` — Атомарная публикация и версионирование.
- [ ] `REPORT-011` — Интеграция reporting во все call sites.
- [ ] `REPORT-012` — Полный reporting regression suite.

### M6 — Анонимизация и внешний model review

- [ ] `REVIEW-001` — Версионированный `ReviewPackage`.
- [ ] `REVIEW-002` — Обратимая карта анонимизации.
- [ ] `REVIEW-003` — Детекция утечек перед отправкой.
- [ ] `REVIEW-004` — Адаптер внешней модели.
- [ ] `REVIEW-005` — Валидация ответа внешней модели.
- [ ] `REVIEW-006` — Атомарная деанонимизация.
- [ ] `REVIEW-007` — Сохранение review и пересчёт effective results.
- [ ] `REVIEW-008` — Семантика ошибок и публикации.
- [ ] `REVIEW-009` — Тест полного external-review пути.

### M7 — Правки аналитика и регенерация

- [ ] `ANALYST-001` — Детерминированный импорт reviewed Excel.
- [ ] `ANALYST-002` — Транзакционные overrides и версии отчётов.
- [ ] `ANALYST-003` — Явные service/CLI/API операции.
- [ ] `ANALYST-004` — Round-trip тесты import/regeneration.

### M8 — Наблюдаемость, cleanup и release gate

- [ ] `OPS-001` — Типизированная таксономия ошибок.
- [ ] `OPS-002` — Structured logs, metrics и run manifest.
- [ ] `OPS-003` — Убрать legacy Markdown-парсинг из production flow.
- [~] `OPS-004` — Модульный cleanup и dependency review.
- [~] `DOC-001` — Обновить пользовательскую и developer-документацию.
- [ ] `DOC-002` — Полностью синтетический sample package.
- [ ] `CI-001` — Полный release pipeline.
- [ ] `E2E-001` — Финальный acceptance-сценарий.

## Текущие блокеры

- `INPUT-005`: завершить YAML/JSON execution integration и независимую приёмку
  production discovery.
- `AGENT-001` / `INPUT-002`: администраторские агенты и строгая валидация
  фреймворков.
- `FLOW-007`: удалить deprecated process-wide graph getters после независимой
  приёмки.
- `DOC-001`: синхронизировать baseline и evidence-layout документацию.
- `CI-001`: завершить workflow/report/review E2E и coverage миграций.

## Правила статусов

- `[ ]` Открыто: независимая приёмка не подтверждена.
- `[~]` Частично: есть значимая реализация, но не все критерии приёмки.
- `[x]` Принято: все критерии подтверждены кодом/тестами и проверкой.

# `psql_auditor` — Мастер-чеклист разработки и приёмки

Версия чеклиста: **1.11**  
Дата: **2026-07-26**  
Репозиторий: `whatelseek/psql_auditor`  
Базовый commit: [`b064e26`](https://github.com/whatelseek/psql_auditor/commit/b064e26e9150d0bf4ebc2036ecc7c839b4b219e4)  
Последняя рассмотренная ревизия: [`5286a4d`](https://github.com/whatelseek/psql_auditor/commit/5286a4d773f62d0bc796b205ddd18994bdfc89af)  
Всего задач: **71**

Синхронизирован с английской версией
[`psql_auditor_master_refactoring_checklist (5).md`](psql_auditor_master_refactoring_checklist%20(5).md).
Оба файла обновляются одновременно. Открытые пункты нельзя помечать принятыми
без независимой приёмки.

## Сводка статусов

| Статус | Количество |
| --- | ---: |
| Принято `[x]` | **8 / 71 (11.3%)** |
| Частично `[~]` | **6 / 71 (8.5%)** |
| Открыто `[ ]` | **57 / 71 (80.3%)** |
| Не полностью завершено | **63 / 71 (88.7%)** |

Принято: `AUD-001`, `AUD-002`, `AUD-003`, `CORE-001`, `CORE-002`, `CORE-003`, `CORE-004`, `CORE-005`.

Частично: `CORE-006`, `INPUT-003`, `INPUT-005`, `FLOW-007`, `OPS-004`, `DOC-001`.

## Последняя проверка

Реализован кандидат на приёмку inventory-driven запуска аудита
(load/validate/analyze/plan/confirm). `INPUT-001` остаётся **открытым** — commit
[`5286a4d`](https://github.com/whatelseek/psql_auditor/commit/5286a4d773f62d0bc796b205ddd18994bdfc89af)
не принимается автоматически. `CORE-006` остаётся `[~]` до независимой приёмки.

| Проверка | Результат |
| --- | --- |
| Format / Lint | Passed |
| Type check | Passed, 84 files |
| Unit tests | 403 passed |
| Defect map | `validate-defect-map: OK` (71/71) |
| Clean CI | [Run 30208213773](https://github.com/whatelseek/psql_auditor/actions/runs/30208213773), все jobs зелёные |

## Реестр задач

### M0 — Базовая линия, тесты и CI

- [x] `AUD-001` — Зафиксировать воспроизводимую базовую линию.
- [x] `AUD-002` — Единые локальные и CI quality gates.
- [x] `AUD-003` — Общие детерминированные тестовые фикстуры.

### M1 — Идентификаторы и доменная модель

- [x] `CORE-001` — Разделить `client_id` и `audit_run_id`.
- [x] `CORE-002` — Разделить `AuditRun` и `AuditJob`.
- [x] `CORE-003` — Каноническая идентичность результата.
- [x] `CORE-004` — Структурированный `AssessmentResult`.
- [x] `CORE-005` — Изоляция checkpoint и артефактов по audit run.
- [~] `CORE-006` — Убрать скрытое глобальное изменяемое состояние.

`CORE-006` остаётся частичным до независимой приёмки.

### M2 — Входы и планирование аудита

- [ ] `INPUT-001` — Строгий `AuditRequest`.

`INPUT-001` остаётся открытым до независимой приёмки. Commit
[`5286a4d`](https://github.com/whatelseek/psql_auditor/commit/5286a4d773f62d0bc796b205ddd18994bdfc89af)
— только кандидат (зелёный CI недостаточен).

- [ ] `INPUT-002` — Строгая валидация фреймворков.
- [~] `INPUT-003` — Валидируемая модель inventory.

Частичные доказательства `INPUT-003`: модель `ClientInventory`, загрузчики
Markdown/YAML/JSON, уровни error/warning/information, версия inventory и
исключение plaintext-секретов; тесты
`tests/test_inventory_driven_audit.py`; документация
`docs/inventory-driven-audit.md`.

- [ ] `INPUT-004` — Реестр инструментов и политика capabilities.
- [~] `INPUT-005` — Детерминированный preflight и `AuditPlan`.

Частичные доказательства `INPUT-005`: типизированный `AuditPlan` с обязательным
подтверждением; stale-plan (`plan_stale`); merge `CREDENTIALS.md`;
`needs_discovery` + injectable read-only discovery/reconcile; confirm →
`AuditRequest` (version/hash) → `arun_request` / `audit_run_id`. Default
discoverer — no-op до wiring live SSH/WinRM; независимая приёмка обязательна.

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

## Правила статусов

- `[ ]` Открыто: независимая приёмка не подтверждена.
- `[~]` Частично: есть значимая реализация, но не все критерии приёмки.
- `[x]` Принято: все критерии подтверждены кодом/тестами и проверкой.

# Руководство пользователя — auditor

Практическое руководство: **развёртывание**, **настройка**, **проведение аудита**, **добавление своих чек-листов (Markdown)** и **playbook-ов**.

Модель в Open WebUI: **`auditor`**.

---

## Содержание

1. [Что это такое](#1-что-это-такое)
2. [Требования](#2-требования)
3. [Развёртывание (Docker)](#3-развёртывание-docker)
4. [Настройка `.env`](#4-настройка-env)
5. [Подключение Open WebUI](#5-подключение-open-webui)
6. [Как провести аудит](#6-как-провести-аудит)
7. [Человек в контуре (HITL)](#7-человек-в-контуре-hitl)
8. [Отчёт, ZIP и артефакты](#8-отчёт-zip-и-артефакты)
9. [Диаграммы соответствия CIS](#9-диаграммы-соответствия-cis)
10. [Как добавить свой Markdown-фреймворк](#10-как-добавить-свой-markdown-фреймворк)
11. [Playbook-и (долговременная память команд)](#11-playbook-и-долговременная-память-команд)
12. [Встроенные фреймворки](#12-встроенные-фреймворки)
13. [Типовые проблемы](#13-типовые-проблемы)
14. [Краткая шпаргалка](#14-краткая-шпаргалка)

---

## 1. Что это такое

**auditor** — агент аудита ИТ-инфраструктуры на LangGraph. Вы описываете проверки в файлах `agents/*.md`, оператор в чате Open WebUI запускает аудит, агент:

- выбирает фреймворк(и) по тексту запроса;
- собирает доказательства по SSH и/или через MCP PostgreSQL;
- заполняет в отчёте только ячейки **Status / Observation / Recommendation**;
- при сбоях сессии пробует переподключиться;
- при ошибках проверки спрашивает **пропустить / повторить** (HITL);
- сохраняет отчёт и выводы команд в `artifacts/` и отдаёт **ZIP** в чат.

Это **не** замена ручному пентесту: агент следует вашему чек-листу и инструментам, которые вы ему дали.

---

## 2. Требования

- Docker и Docker Compose
- Ключ к модели для LiteLLM (например `OPENAI_API_KEY`)
- Доступ по **SSH** к целевому хосту (для Ubuntu/Windows-проверок)
- Учётные данные **PostgreSQL** (для проверок БД через MCP)
- Браузер → Open WebUI на порту **3000** (по умолчанию)

---

## 3. Развёртывание (Docker)

### 3.1. Быстрый старт

```bash
git clone https://github.com/whatelseek/psql_auditor.git
cd psql_auditor

cp .env.example .env
# Отредактируйте .env — см. раздел 4

docker compose up --build
```

Сервисы:

| Сервис | URL | Назначение |
|--------|-----|------------|
| Open WebUI | http://localhost:3000 | Чат с оператором |
| Агент `auditor` | http://localhost:8000 | API `/v1` (OpenAI-совместимый) |
| LiteLLM | http://localhost:4000 | Шлюз к модели |

Проверка живости агента:

```bash
curl -s http://localhost:8000/healthz
```

Ожидается JSON со `"status":"ok"`.

### 3.2. Остановка и обновление

```bash
docker compose down
git pull
docker compose up --build -d
```

### 3.3. Тома и данные на диске

| Путь на хосте | В контейнере | Содержимое |
|---------------|--------------|------------|
| `./agents` | `/app/agents` | Чек-листы `*.md` и `playbooks/` |
| `./memory` | `/app/memory` | Выученные playbook-и |
| `./artifacts` | `/app/artifacts` | Отчёты и выводы команд по запускам |
| `./.keys` | `/keys` | SSH-ключи (по желанию) |

---

## 4. Настройка `.env`

Минимум для работы:

```env
OPENAI_API_KEY=sk-...          # ключ провайдера для LiteLLM
API_KEY=sk-auditor-local       # ключ, с которым Open WebUI ходит в агент

# Цель по умолчанию (если нет другого способа передать креды)
SSH_HOST=10.0.0.15
SSH_USER=auditor
SSH_PASSWORD=...               # или SSH_PRIVATE_KEY_PATH=/keys/id_ed25519

PG_HOST=10.0.0.15
PG_PORT=5432
PG_USER=postgres
PG_PASSWORD=...
PG_DATABASE=postgres

PUBLIC_BASE_URL=http://localhost:8000
OPEN_WEBUI_URL=http://open-webui:8080
OPEN_WEBUI_PUBLIC_URL=http://localhost:3000
MODEL_ID=auditor
```

Полезные переключатели:

| Переменная | По умолчанию | Смысл |
|------------|--------------|--------|
| `HITL_ENABLED` | `true` | Пауза skip/retry при ошибках REQ |
| `ARCHIVE_ENABLED` | `true` | ZIP отчёта в чат |
| `MEMORY_ENABLED` / `MEMORY_LEARN` | `true` | Подсказки playbook / обучение |
| `COMPLIANCE_CHARTS_IN_REPORT` | `true` | SVG-графики % соответствия в отчёте |
| `MAX_PARALLEL_ASSESSMENTS` | `5` | Параллельные REQ-воркеры |
| `MAX_SESSION_RETRIES` | `2` | Повторы при обрыве SSH/MCP |
| `LITELLM_MODEL` | `gpt-4o-mini` | Имя модели в LiteLLM |

Полный список — в [`.env.example`](../.env.example).

**Безопасность:** не коммитьте `.env` с паролями. Файл `.env` уже в `.gitignore`.

---

## 5. Подключение Open WebUI

В `docker compose` Open WebUI уже указывает на агент:

- `OPENAI_API_BASE_URL=http://agent:8000/v1`
- ключ = `API_KEY` из `.env`

В интерфейсе:

1. Откройте http://localhost:3000
2. Выберите модель **`auditor`**
3. (Рекомендуется) для файлов-целей отключите «сжатие» вложения до RAG-фрагментов — нужен **полный текст** файла в контексте чата (см. [docs/starting-an-audit.md](starting-an-audit.md))

Если модели нет в списке: Admin → Connections / OpenAI → проверьте base URL и API key, обновите список моделей (`GET /v1/models` на агенте).

---

## 6. Как провести аудит

### 6.1. Базовый сценарий

1. Убедитесь, что в `.env` заданы `SSH_*` и/или `PG_*` для цели.
2. В чате с моделью `auditor` напишите, **какой фреймворк** запускать, например:

```text
Проведи аудит PostgreSQL CIS
Проведи аудит Ubuntu CIS на этом хосте
Проведи аудит PostgreSQL и Ubuntu
```

3. Дождитесь отчёта. При HITL ответьте `skip` / `retry` (или по-русски: `пропустить` / `повторить`).
4. Скачайте ZIP по ссылке в конце ответа.

### 6.2. Файл цели (рекомендуется)

Прикрепите YAML/JSON с описанием хоста (шаблон: [`examples/target.example.yaml`](examples/target.example.yaml)):

```yaml
host:
  hostname: db-01.example.com
  description: "Prod Postgres 16 on Ubuntu 22.04"
  os: ubuntu

ssh:
  user: auditor
  port: 22
  password: "changeme"

postgres:
  host: db-01.example.com
  port: 5432
  user: postgres
  password: "changeme"
  database: postgres

frameworks:
  - postgres_cis
  - ubuntu_cis
```

Сообщение в чате:

```text
Запусти аудит PostgreSQL и Ubuntu CIS по приложенному target
```

Подробности полей: [starting-an-audit.md](starting-an-audit.md).

> **Важно:** основная рабочая схема креденшелов сейчас — переменные окружения `SSH_*` / `PG_*`. Файл цели полезен как описание и подсказка маршрутизации; полный парсинг «креды только на этот run» может требовать актуальной версии агента. Держите секреты в `.env` или секретах оркестратора.

### 6.3. Несколько фреймворков

Запрос вроде «PostgreSQL и Ubuntu» запускает **отдельный граф на каждый** фреймворк. При включённом HITL они идут **последовательно**; в конце — объединённый отчёт и один ZIP.

### 6.4. Примеры фраз

| Цель | Пример фразы |
|------|----------------|
| PostgreSQL | `Запусти аудит PostgreSQL CIS` |
| Ubuntu | `Проведи Ubuntu CIS аудит` |
| Windows | `Проверка Windows Server CIS` |
| Два фреймворка | `Проведи аудит PostgreSQL и Ubuntu` |

Агент выбирает файл из `agents/` по `id`, `aliases` и заголовку.

---

## 7. Человек в контуре (HITL)

Если проверка `REQ-*` завершилась ошибкой (SSH/MCP) после авто-переподключений, агент пишет в чат:

- какой `REQ-*` не прошёл;
- почему;
- рекомендации;
- вопрос: **skip** / **retry** (также: skip all / retry all).

Ответьте в **том же** чате. В ответе агента есть маркер `[AUDIT_HITL:<thread>]` — следующее сообщение оператора возобновляет паузу.

Отключить паузы (ошибки останутся в отчёте как `error`):

```env
HITL_ENABLED=false
```

Русские формулировки решений тоже поддерживаются (`пропустить`, `повторить` и т.п.).

---

## 8. Отчёт, ZIP и артефакты

### 8.1. Фиксированный формат отчёта

| Из вашего `agents/*.md` (не меняется моделью) | Заполняет модель |
|-----------------------------------------------|------------------|
| ID, Title, Category, Severity, Pass criteria, How to verify | Status, Observation, Recommendation |

Статусы: `pass` | `fail` | `partial` | `error` | `skipped`.

### 8.2. Структура на диске

```text
artifacts/<run_id>/
  meta.json
  report.md
  <framework_id>/
    report.md
    REQ-001/
      requirement.json
      001_ssh_run.txt
      001_ssh_run.json
      finding.json
    REQ-002/
      ...
```

ZIP: `artifacts/<run_id>_audit.zip` + ссылка в чате (`PUBLIC_BASE_URL`).

### 8.3. Дополнительные проверки после аудита

После завершения аудита можно **дозапросить REQ** — новые логи пишутся в ту же папку `REQ-*` (файлы `003_…`, `004_…`), затем **обновить отчёт**:

```text
Перепроверь REQ-002 на Ubuntu
Run another check for REQ-002: `sshd -T | grep permitrootlogin`
Обнови отчёт
Update the report from new evidence
```

Подробнее: [post-audit-followup.md](post-audit-followup.md).

---

## 9. Диаграммы соответствия CIS

В конец отчёта может добавляться блок с **% соответствия по severity** (Overall / Critical / High / …).

Формула: `(pass + 0.5 × partial) / assessed × 100` (skipped не входят в знаменатель).

- В отчёте агента: `COMPLIANCE_CHARTS_IN_REPORT=true`
- В Open WebUI отдельно: функции из `openwebui/functions/` — см. [cis-compliance-charts.md](cis-compliance-charts.md)

---

## 10. Как добавить свой Markdown-фреймворк

Код менять **не нужно**. Достаточно положить файл в `agents/`.

### 10.1. Создайте файл

Имя файла = удобный идентификатор, например `agents/my_app_cis.md`.

```markdown
---
id: my_app_cis
aliases: [myapp, приложение, app]
description: Чек-лист безопасности My App
---
# My App Security Checklist

## REQ-001: HTTPS only
**Category:** Network
**Severity:** High
**How to verify:** SSH: проверить reverse proxy / TLS на порту 443
**Pass criteria:** HTTP редиректит на HTTPS, слабые шифры отключены

## REQ-002: Секреты не в репозитории
**Category:** Secrets
**Severity:** Critical
**How to verify:** SSH: поиск типовых утечек в каталоге деплоя
**Pass criteria:** Нет plaintext паролей в конфигах приложения
```

### 10.2. Обязательные элементы

1. **YAML frontmatter** (рекомендуется): `id`, `aliases`, `description` — для маршрутизации из чата.
2. Заголовок `# …`
3. Требования строго вида:

```markdown
## REQ-NNN: Краткий заголовок
**Category:** …
**Severity:** Critical|High|Medium|Low|Info
**How to verify:** …
**Pass criteria:** …
```

Нумерация `REQ-001`, `REQ-002`, … должна быть уникальна внутри файла.

### 10.3. Применение без пересборки образа

Каталог `./agents` смонтирован в контейнер. После сохранения `.md`:

- новый чат / новый запрос подхватит файл;
- при сомнении перезапустите только агент: `docker compose restart agent`.

### 10.4. Инструменты проверки

Агент использует:

- **SSH:** `ssh_run`, `ssh_read_file` — хост Linux/Ubuntu; для Windows — команды через OpenSSH/PowerShell на цели;
- **PostgreSQL:** `mcp_query` (только чтение: `SELECT` / `SHOW`) через
  [LangChain MCP adapters](https://github.com/langchain-ai/langchain-mcp-adapters) →
  [antonorlov/mcp-postgres-server](https://github.com/antonorlov/mcp-postgres-server).
  См. также [langchain-mcp.md](langchain-mcp.md).

В **How to verify** пишите, *что* проверять; конкретные команды лучше продублировать в playbook (раздел 11).

### 10.5. Что нельзя сделать только чатом

- Добавить новый постоянный `REQ-*` в отчёт «на лету» без файла в `agents/` — нельзя.
- Прикрепить произвольный `.md` в чат ≠ зарегистрировать новый фреймворк. Фреймворк = файл в `agents/`.

---

## 11. Playbook-и (долговременная память команд)

**Playbook** — рецепт «как проверять REQ»: предпочтительные вызовы инструментов. Это **не** история чата.

| Источник | Путь |
|----------|------|
| Заготовки (seed) | `agents/playbooks/<framework_id>.yaml` |
| Выученное | `memory/learned_playbooks.json` |

Пример seed:

```yaml
framework_id: my_app_cis
framework_tips:
  - Предпочитать ssh_read_file для конфигов.
requirements:
  REQ-001:
    notes: Проверка TLS
    tools:
      - name: ssh_run
        arguments:
          command: "echo | openssl s_client -connect 127.0.0.1:443 2>/dev/null | head -n 20"
```

При `MEMORY_LEARN=true` **успешные** вызовы инструментов запоминаются; ошибки — нет.

Подробнее: [long-term-memory.md](long-term-memory.md).

---

## 12. Встроенные фреймворки

| id | Файл | Типичные aliases |
|----|------|------------------|
| `postgres_cis` | `agents/postgres_cis.md` | postgres, postgresql, psql, database |
| `ubuntu_cis` | `agents/ubuntu_cis.md` | ubuntu, linux, debian, host |
| `windows_cis` | `agents/windows_cis.md` | windows, win, server |

Это **scaffold**-чек-листы: расширяйте под вашу версию CIS / внутренний стандарт.

---

## 13. Типовые проблемы

| Симптом | Что проверить |
|---------|----------------|
| Модели `auditor` нет в UI | Base URL `http://agent:8000/v1`, `API_KEY`, `MODEL_ID` |
| Все REQ в `error`, SSH | `SSH_HOST`/`USER`/ключ или пароль; ключ смонтирован в `/keys` |
| Ошибки MCP / SQL | `PG_*`, сеть до БД из контейнера `agent` |
| HITL не возобновляется | Ответ в том же чате; не удалять маркер `[AUDIT_HITL:…]` из истории |
| Нет ссылки на ZIP | `ARCHIVE_ENABLED=true`, `PUBLIC_BASE_URL` доступен из браузера |
| Новый `.md` не выбирается | `id`/`aliases` в frontmatter; фраза в чате содержит alias; `AGENTS_DIR` |
| LiteLLM 401/ошибка модели | `OPENAI_API_KEY`, `LITELLM_MODEL`, `litellm_config.yaml` |

Логи:

```bash
docker compose logs -f agent
docker compose logs -f litellm
docker compose logs -f open-webui
```

---

## 14. Краткая шпаргалка

```bash
# Развернуть
cp .env.example .env   # заполнить ключи и SSH/PG
docker compose up --build

# Открыть UI
# http://localhost:3000 → модель auditor

# Запуск аудита (пример)
# «Проведи аудит Ubuntu CIS»

# Добавить фреймворк
# создать agents/my_cis.md с ## REQ-001: …
# опционально agents/playbooks/my_cis.yaml

# Перезапуск агента после правок env
docker compose up -d --build agent
```

---

## Связанные документы (EN)

- [starting-an-audit.md](starting-an-audit.md) — старт аудита и формат target-файла  
- [long-term-memory.md](long-term-memory.md) — playbook-память  
- [cis-compliance-charts.md](cis-compliance-charts.md) — графики соответствия  
- [README.md](../README.md) — обзор на английском  

---

*Документ описывает поведение пакета `auditor` (репозиторий `psql_auditor`). При обновлении продукта сверяйте переменные с `.env.example`.*

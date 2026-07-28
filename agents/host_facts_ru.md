---
id: host_facts_ru
aliases: [host facts, host inventory, facts, system inventory, baseline inventory, факты хоста, инвентаризация хоста, системная инвентаризация]
description: Инвентаризация хоста — ОС, оборудование, хранилище, сеть, сервисы, ПО
domain: it
language: ru
family_id: host_facts
detect:
  always: true
version: "1.0"

applicability:
  all:
    - fact: asset.id
      operator: exists

required_facts:
  - asset.id

target:
  scope: client
---
# Чеклист инвентаризации фактов хоста

Глубокая инвентаризация хоста для базовой оценки в рамках аудита.
Используйте SSH-инструменты и фиксируйте только подтвержденные данные.

## REQ-001: Полнота инвентаризации
**Category:** Inventory
**Severity:** High
**How to verify:** Соберите hostname (`hostname -f`), IPv4-адреса (`hostname -I` или `ip -4 addr`), название ОС (`hostnamectl`) и UUID оборудования (`dmidecode -s system-uuid`, если доступно). Зафиксируйте owner/location из INVENTORY.md.
**Pass criteria:** В доказательствах указаны hostname, версия ОС и хотя бы один IPv4-адрес, отличный от loopback.

---

## REQ-002: Версия операционной системы
**Category:** Operating System
**Severity:** High
**How to verify:** Соберите `/etc/os-release`, `hostnamectl` и `uname -r`.
**Pass criteria:** Определены дистрибутив, версия ОС и версия ядра.

---

## REQ-003: SMART-состояние дисков
**Category:** Storage
**Severity:** Medium
**How to verify:** Выполните `smartctl -H` для каждого физического диска, где это доступно.
**Pass criteria:** Общий статус SMART для всех проверенных дисков — PASSED.

---

## REQ-004: Запущенные сервисы
**Category:** Services
**Severity:** High
**How to verify:** Выполните `systemctl list-units --type=service --state=running`.
**Pass criteria:** Собран актуальный перечень запущенных сервисов.

---

## REQ-005: Установленные пакеты
**Category:** Software
**Severity:** Medium
**How to verify:** Выполните `rpm -qa` или `dpkg-query -W`.
**Pass criteria:** Собран актуальный перечень установленных пакетов.

---

## REQ-006: Прослушиваемые порты
**Category:** Network
**Severity:** High
**How to verify:** Выполните `ss -tulpen` (или `netstat -tulpen`, если необходимо) и соберите список TCP/UDP портов в состоянии listening с привязками адресов.
**Pass criteria:** Собрана инвентаризация прослушиваемых портов с владельцем/процессом.

---

# OpenZeppelin Vulnerability Scanner v2

Сканер уязвимостей @openzeppelin/contracts для Hardhat и Foundry проектов.

## Файлы

- `check_oz_vulns.py` — сам скрипт
- `oz_vuln_db.json` — внешняя база уязвимостей (загружается при старте)

## Установка

Зависимостей нет, только Python 3.8+. Положите оба файла рядом.

## Что проверяет

В указанной ветке/каталоге репозитория ищет четыре манифеста и анализирует каждый при наличии:

| Файл               | Источник версии  | Точность          |
|--------------------|------------------|-------------------|
| `package.json`     | объявленные диапазоны | приблизительная (`^4.7.0`) |
| `package-lock.json`| резолвенные версии    | **точная** (приоритет) |
| `foundry.toml`     | `[dependencies]` Soldeer | **точная** |
| `remappings.txt` + `.gitmodules` | путь к git-submodule | SHA коммита, тег — вручную |

Если найдена и точная (`exact`) и диапазонная (`range`) уязвимость по одной и той же CVE — дубль отбрасывается, остаётся точная. Уязвимости из диапазона, недостижимые в установленной версии, остаются как сигнал «обновление может ухудшить ситуацию».

## Использование

```bash
# одна или несколько ссылок на ветку/каталог
python3 check_oz_vulns.py \
  https://github.com/owner/repo \
  https://github.com/owner/repo/tree/dev \
  https://github.com/owner/repo/tree/v1.0/packages/contracts

# из файла
python3 check_oz_vulns.py -f sources.txt

# локальный путь (для CI перед push)
python3 check_oz_vulns.py ./

# JSON-вывод для пайплайна
python3 check_oz_vulns.py -f sources.txt --json > report.json

# кастомная БД
python3 check_oz_vulns.py --db /path/to/custom_db.json https://github.com/foo/bar

# не дёргать GitHub API для определения SHA сабмодулей
python3 check_oz_vulns.py --no-resolve-submodules https://github.com/foo/bar
```

### GitHub-токен

Без токена лимит 60 запросов/час с одного IP. С токеном — 5000/час и доступ к приватным репо:

```bash
export GH_TOKEN=ghp_xxxxxxxxxxxxxxxxxxxx
python3 check_oz_vulns.py https://github.com/private-org/private-repo
```

### Exit codes

- `0` — все источники чисты
- `1` — найдены уязвимости
- `2` — ошибки доступа / парсинга / БД

## Формат БД (`oz_vuln_db.json`)

```json
{
  "schema_version": "1.0",
  "updated_at": "2025-05-11",
  "source": "https://github.com/OpenZeppelin/openzeppelin-contracts/security/advisories",
  "vulnerabilities": [
    {
      "id": "GHSA-...",
      "cve": "CVE-...",
      "severity": "Critical | High | Medium | Low",
      "title": "Краткое описание",
      "packages": ["@openzeppelin/contracts", "@openzeppelin/contracts-upgradeable"],
      "affected": [["3.3.0", "3.4.2"], ["4.0.0", "4.3.1"]],
      "patched":  ["3.4.2", "4.3.1"]
    }
  ]
}
```

- `affected`: список полуоткрытых интервалов `[min_inclusive, max_exclusive)`. Уязвимы все версии `>= min AND < max`.
- `patched`: первые исправленные версии для каждой major-ветки.
- `packages`: только канонические npm-имена. Сабмодульные и soldeer-варианты (`@openzeppelin-contracts`, `openzeppelin-contracts`) маппятся автоматически в коде через `NAME_ALIASES`.

## Обновление БД

База `oz_vuln_db.json` — обычный JSON, редактируется руками. Источники для синхронизации:

- `https://github.com/OpenZeppelin/openzeppelin-contracts/security/advisories`
- `https://github.com/advisories?query=openzeppelin`
- `https://api.github.com/repos/OpenZeppelin/openzeppelin-contracts/security-advisories` (для скриптовой синхронизации)

Рекомендуется ставить cron-job, который раз в неделю проверяет новые advisories и шлёт алерт. Это уже за рамками текущего скрипта.

## Ограничения

1. **Submodule-версия не определяется автоматически.** Скрипт может получить SHA коммита через GitHub API, но сопоставление SHA → тег требует дополнительного запроса либо ручной сверки.
2. **Транзитивные зависимости.** В режиме `package.json` без lockfile видны только верхнеуровневые декларации. Lockfile показывает всё дерево.
3. **Yarn-lock не поддерживается** (только `package-lock.json` v1/v2/v3). Можно добавить — формат текстовый.
4. **Pre-release suffix-ы** (`4.9.4-rc.0`) отбрасываются при сравнении.

## Пример отчёта

```
═══════════════════════════════════════════════════════════════════════════
🔎 https://github.com/foo/old-defi/tree/main
   repo: foo/old-defi  ref: main  path: (root)
═══════════════════════════════════════════════════════════════════════════
Манифесты: package.json, package-lock.json

✗ Найдено уязвимостей: 9

  [HIGH    ] ECDSA signature malleability (EIP-2098 compact sigs)
    ID: GHSA-4h98-2769-gh6h   CVE: CVE-2022-35961   источник: package-lock.json [exact]
    Пакет: @openzeppelin/contracts "4.7.1"
    Уязвимый диапазон: >=4.1.0 <4.7.3  →  fixed in 4.7.3
  ...
```

# crown-indexer — Спека

Канистра ICP: читает `Settled` пиннутого сплиттера и рождения пиннутых фабрик из публичного чейна,
сворачивает `crown-reduce`'ом в книгу, отдаёт на чтение с сертификатом. Денег нет, ключей нет, подписи
нет. **Эмиссия оплачена** (`00-architecture.md §3`): без слепого поллинга, единственный триггер работы —
оплаченный `ingest`.

## Поверхность (`.did`)

**Единственный не-`query`:**
- `ingest(signature) -> IngestResult` — платный (`INGEST_PRICE`). Порядок: `is_applied` → пол
  `msg_cycles_available() >= INGEST_PRICE` → пол `canister_cycle_balance >= CYCLE_FLOOR` → **accept
  циклов** → распознавание + RPC. Ни один outcall/запись **до** accept. Недоплата — reject без работы.

**Query (бесплатны, `00 §6`):**
- `get_reputation(chain, donor, recipient) -> (u128, Witness)`
- `get_birth(escrow) -> (opt Birth, Witness)`
- `get_certificate() -> (opt Certificate, CombinedRoot)`
- `get_reduce_version() -> u32` · `get_applied_count() -> u64` · `get_anomaly_count() -> u64`

## Распознавание и атрибуция (`00 §4, §5`)

- **Сеттлмент** — `Settled` пиннутого `splitter`. Атрибуция донора: `sender==splitter` → `donor` события;
  `sender` выводится из `factory ∈ factories[]` (пересчёт PDA `[b"escrow", salt]` через `crown-derive`,
  `donor` = байты 8..40 аккаунта эскроу) → его донору; иначе — `donor` как есть.
- **Рождение** — инструкция `create_escrow` пиннутой фабрики; **парсинг транзакции** (`getTransaction`),
  `slot` из меты. Хранит `escrow → {donor, slot}` (`gross` не хранится — раскладко-независимо: читаются
  только `donor`=acc0, `escrow`=acc1, `salt`=первый арг@8..40, а PDA-пересчёт `[b"escrow", salt]` — гейт).
  Впись рождения платная, как сеттлмент.
- **Перекрёстная сверка:** `Settled` пиннутого сплиттера сверяется с отдельным исполненным
  `TransferChecked` в той же транзакции (`gross`/минт/authority=донор); нет пары — не засчитано, инкремент
  аномалий (аутентичность события даёт program-id сплиттера, поэтому глубина стека совпадать не обязана).
- **Финальность:** `commitment = finalized`, всегда.

## Состояние, дерево, exactly-once

- Свёртка книги — `crown-reduce`. Книга — **in-memory** (heap): апгрейд теряет её, но повторный
  `ingest` восстанавливает идентично — ровно как «новое поколение пересчитывает из чейна» (`00 §8`).
  Persistence (`StableBTreeMap`) не несёт корректности при этой модели и опциональна; на mainnet
  канистра blackhole (апгрейдов нет).
- **Два keyed-Merkle-корня** — по книге и по рождениям; `combined_root =
  fork_hash(labeled_hash("book", book_root), labeled_hash("births", births_root))` в
  `set_certified_data`; свидетель ключа реконструирует **прямо в `combined_root`** (стандартная
  проверка против NNS root key, без ручной комбинации у клиента). `recertify` O(log n) на вписи;
  свидетель по ключу — `query`. Корень воспроизводим офчейн из тех же `Settled` + `crown-reduce` +
  контракт корня (домен-хеши `ic-hashtree`-листьев/меток). Пересчёт сворачивает **в slot-порядке**:
  рождение эскроу всегда в слоте раньше его расчёта, поэтому атрибуция (`escrow → донор`) в пересчёте
  всегда корректна — это канон. Живая канистра, проингестившая расчёт раньше рождения, атрибутирует
  ошибочно временно; истина — пересчёт нового поколения (`00 §8`). Механизма переатрибуции нет намеренно.
- **Exactly-once** — набор применённых сигнатур. **Пустые сигнатуры applied не помечать** (инвариант #1
  части applied). Прунинг рождений/applied по терминальности (`claim`/`refund`).

## RPC

Только SOL RPC-канистра под NNS (`tghme-zyaaa-aaaar-qarca-cai`), консенсус ≥3 провайдера. Индексер
всегда шлёт `Default(cluster)` — провайдеры выбирает сама канистра, URL'ов здесь нет. `ATTACH_CYCLES` на вызов.
**Кэп `max_response_bytes`** так, что worst-case outcall ≤ `INGEST_PRICE` (инвариант не-отрицательности
#1, `cost.md §6`): раздутая tx не заставляет переплатить.

## Не-отрицательность (владелец: `cost.md §6`)

- #1 кэп `max_response_bytes`; `INGEST_PRICE` ≥ worst-case outcall (тест на раздутой tx).
- applied не растёт от пустых сигнатур; прунинг.
- Индекс само-окупается на марже `INGEST_PRICE − outcall`.

## Конфиг (`01-standards §Конфиг`)

Per-chain: `id`, `source`, `consensus`, `splitter`, `usdc`, `factories`. Профиль-уровень (замораживаемые,
cost-gate): `INGEST_PRICE`, `MIN_GROSS`, `CYCLE_FLOOR`, `ATTACH_CYCLES` (циклы на outcall, ≤ `INGEST_PRICE`),
`RESPONSE_MAX_BYTES` (кэп ответа, инвариант #1). Нет: RPC-URL, ключей, комиссий, `finality_depth`.

Ключ книги хранит **`ChainId`** — непрозрачные 32 байта, `reduce` их не трактует. Индекс выводит их
из метки кластера детерминированно и самодостаточно: `ChainId = sha256("crown-chain:v1:" ‖ id)`
(`id` из конфига). Любой пересчитывающий книгу воспроводит их из одного конфига — без внешних
констант; вбивается `build.rs`'ом, финализируется на заморозке (P8).

## Заморозка

Blackhole (контроллер снят) на mainnet-этапе. Reproducible build, хэш wasm опубликован. Баг неисправим
апгрейдом → новое поколение пересчитывает из чейна. Актив — пара `(адреса периметра, история)`, не канистра.

## DoD / тесты (`01-standards §Тесты 3–8,12`)

`.did` — только `query` кроме `ingest`. E2e: оплаченный `ingest` → `get_reputation` показывает `+gross`.
Exactly-once; пустая сигнатура не applied; признание (чужой `Settled` не засчитан); перекрёстная сверка;
пруф/сертификат против root key NNS; неоплаченный `ingest` не делает outcall; кэп ответа на раздутой tx.

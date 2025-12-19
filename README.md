# WPA2

## Описание

Набор простых утилит для лабораторной работы с моделью восстановления WPA2-PSK.

* `gen_wpa2.py` — генерирует тестовый вектор (искусственный handshake) на основе переданного пароля (passphrase) и SSID. Результат записывается в `test_wpa2.txt` в кодировке UTF-16 в формате:

```
SSID*AP_MAC*STA_MAC*ANONCE*SNONCE*EAPOL_HEX*MIC_HEX
```

* `crack_wpa2.go` — читает `test_wpa2.txt` и перебирает пароли по заданной маске (mask), для каждого кандидата вычисляет PMK/PTK/KCK и проверяет MIC. Если MIC совпадает — найден пароль.


# Как WPA2 генерирует ключи (кратко)

1. **PMK (Pairwise Master Key)** — выводится из фразы-пароля (passphrase) и SSID с помощью PBKDF2-HMAC-SHA1:

```
PMK = PBKDF2-HMAC-SHA1(passphrase, ssid, 4096, 32)
```

2. **PTK (Pairwise Transient Key)** — генерируется PRF-512 (Pairwise key expansion). PRF использует HMAC-SHA1 с ключом PMK и меткой `A = "Pairwise key expansion"` и параметром `B`, где `B = min(MACs)||max(MACs)||min(ANonce)||max(ANonce)`.

PRF вырабатывает 64 байта — первые 16 байт используются как **KCK** (Key Confirmation Key).

3. **MIC (Message Integrity Code)** — в EAPOL-пакете поле MIC вычисляется как HMAC-SHA1(KCK, EAPOL) и в нашей модели используется первые 16 байт от HMAC-SHA1 (HMAC-SHA1-128).

# Логика `gen_wpa2.py`

* Принимает аргументы: `-p/--password`, `-s/--ssid`, опционально MAC-адреса AP/STA.
* Использует фиксированные reproducible nonces (anonce и snonce) по умолчанию — удобно для лаборатории.
* Вычисляет PMK (PBKDF2), затем PTK (PRF-512) и берёт KCK = PTK[0:16].
* Формирует EAPOL-like blob (в котором поле MIC обнулено) и вычисляет MIC как HMAC-SHA1-128.
* Записывает строку с полями разделёнными `*` в файл `test_wpa2.txt` (UTF-16) — такой же формат, который читает `crack_wpa2.go`.

# Логика `crack_wpa2.go` (bruteforce)

1. Читает `test_wpa2.txt`, парсит поля: SSID, AP MAC, STA MAC, ANONCE, SNONCE, EAPOL_HEX, MIC_HEX.
2. Формирует параметр `B` для PRF: упорядоченные MAC и nonces (min, max) как в спецификации.
3. При переборе каждого кандидата пароля (согласно маске):

   * Вычисляет `PMK = PBKDF2(candidate, ssid, 4096, 32)` (реализация PBKDF2 в Go).
   * Генерирует `PTK = PRF-512(PMK, "Pairwise key expansion", B)`.
   * Берёт `KCK = PTK[:16]`.
   * Вычисляет `computed_mic = HMAC-SHA1(KCK, eapol)` и сравнивает первые `len(target_mic)` байт с целевым MIC.
4. Если совпадение — программа выводит найденный пароль и статистику (attempts, elapsed, speed).

Дополнительные детали:

* Маска (`-m`) описывает алфавит по позициям:

  * `a` — объединённый алфавит: `a–z`, `A–Z`, `0–9` (62 символа)
  * `l` — `a–z` (26)
  * `u` — `A–Z` (26)
  * `d` — `0–9` (10)

* Программа выводит прогресс каждые 2 секунды: попытки, процент, скорость (tries/s), текущее значение.

* Поддерживается прерывание по Ctrl+C — программа аккуратно завершает перебор и печатает статистику.

# Как запускать

## Требования

* Python 3 (для `gen_wpa2.py`)
* Go (1.16+)

## Генерация теста

```bash
python3 gen_wpa2.py -p "Ab3d" -s "MySSID"
# -> создаст test_wpa2.txt (UTF-16) и напечатает passphrase
```

## Сборка и запуск перебора

```bash
go build crack_wpa2.go
./crack_wpa2 -m aaaa test_wpa2.txt
```

**Рекомендации для демонстрации (быстро):** используйте маленькое пространство поиска:

* `-m dddd` + пароль `1234` → 10k комбинаций
* `-m llll` + пароль из 4 строчных букв → 26^4 = 456,976
* `-m ddd` → 1000 комбинаций (супер-быстро)

# Формат выходного файла

`test_wpa2.txt` (UTF-16) содержит одну строку с 7 полями, разделённых `*`:

1. SSID (строка)
2. AP MAC (hex, без разделителей)
3. STA MAC (hex)
4. ANONCE (hex)
5. SNONCE (hex)
6. EAPOL blob (hex) — в котором поле MIC занулено для вычисления MIC
7. MIC (hex)

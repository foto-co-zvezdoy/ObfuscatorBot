# Obfuscator Bot

Telegram-бот для обфускации Python-файлов (aiogram, polling).

## Режимы

- `plain` — self-extracting `.py`: XOR(zlib(marshal(code))) после маркера `# === DATA START ===`
- `hikka` — модуль Hikka/FTG с замаскированным классом и зашифрованной логикой

## Запуск

```bash
pip install -r requirements.txt
export BOT_TOKEN=...
python bot.py
```

Health-check: `GET /health` (порт из `PORT`, по умолчанию 8080).

## Render

- Type: Web Service, Runtime: Python
- Build: `pip install -r requirements.txt`
- Start: `python bot.py`
- Health Check Path: `/health`
- Env: `BOT_TOKEN`, `PYTHONUNBUFFERED=1`

> Free-план Render засыпает после ~15 минут без HTTP-трафика — нужен внешний пинг `/health` раз в 5 минут.

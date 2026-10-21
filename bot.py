#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Telegram-бот: обфускация Python-файлов (любое расширение).

Режимы:
  plain  - self-extracting .py: XOR(zlib(marshal(code))) после маркера
           '# === DATA START ===', чтение через __file__, анти-хук/анти-дебаг.
  hikka  - модуль Hikka/FTG: открытый маскировочный класс с пустыми командами,
           реальная логика в HEX после '# === ENCRYPTED LOGIC ===',
           подмена методов в client_ready.
"""
import asyncio
import json
import logging
import os
import secrets
import shutil
import sys
import tempfile
import time
import uuid
from pathlib import Path

from aiogram import Bot, Dispatcher, F
from aiogram.filters import Command
from aiogram.types import (
    CallbackQuery,
    Document,
    FSInputFile,
    InlineKeyboardButton,
    InlineKeyboardMarkup,
    Message,
)

from bat_obfuscator import obfuscate_batch
from health import start_health_server

# ---------------------------------------------------------------------------
# Конфигурация
# ---------------------------------------------------------------------------
TOKEN = os.getenv("BOT_TOKEN")
if not TOKEN:
    raise SystemExit("BOT_TOKEN is not set")
BASE_DIR = Path(__file__).resolve().parent
OBFUSCATOR = BASE_DIR / "obfuscator.py"
WORK_ROOT = Path(os.getenv("WORK_DIR", "/tmp/obfuscator-work"))
STATE_FILE = Path(os.getenv("STATE_FILE", str(BASE_DIR / "state.json")))

MAX_FILE_BYTES = 20 * 1024 * 1024
OBF_TIMEOUT = int(os.getenv("OBF_TIMEOUT_MS", "300000")) / 1000

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)
log = logging.getLogger("obfuscator-bot")

# ---------------------------------------------------------------------------
# Состояние (chat_id -> режим), хранится в JSON
# ---------------------------------------------------------------------------
def _load_state() -> dict:
    try:
        return json.loads(STATE_FILE.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _save_state() -> None:
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    tmp = STATE_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps(_state, ensure_ascii=False), encoding="utf-8")
    tmp.replace(STATE_FILE)


_state = _load_state()


def get_mode(chat_id: int):
    return _state.get(str(chat_id))


def set_mode(chat_id: int, mode: str) -> None:
    _state[str(chat_id)] = mode
    _save_state()


# ---------------------------------------------------------------------------
# Утилиты
# ---------------------------------------------------------------------------
def safe_name(raw: str) -> str:
    name = str(raw or "").strip().replace("\\", "/")
    name = name.rsplit("/", 1)[-1]
    name = "".join(ch for ch in name if ch >= " " and ch != "\x7f")
    name = name.strip()
    if name in ("", ".", ".."):
        name = "file.py"
    return name


def split_ext(name: str):
    base, ext = os.path.splitext(name)
    if not base:
        base, ext = name, ""
    return base, ext


def mode_keyboard() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        inline_keyboard=[
            [InlineKeyboardButton(text="Обычный .py скрипт", callback_data="mode:plain")],
            [InlineKeyboardButton(text="Модуль для Hikka/FTG", callback_data="mode:hikka")],
        ]
    )


MODE_LABEL = {
    "plain": "Обычный .py скрипт (self-extracting)",
    "hikka": "Модуль для Hikka/FTG (маскировочный класс)",
}


async def run_obfuscator(src: Path, dst: Path, mode: str) -> None:
    """Запуск обфускатора отдельным процессом."""
    proc = await asyncio.create_subprocess_exec(
        sys.executable,
        str(OBFUSCATOR),
        str(src),
        str(dst),
        "--mode",
        mode,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        _, err = await asyncio.wait_for(proc.communicate(), timeout=OBF_TIMEOUT)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        raise RuntimeError("превышено время обработки файла")
    if proc.returncode != 0:
        msg = (err or b"").decode("utf-8", "replace").strip()
        raise RuntimeError(msg.splitlines()[-1] if msg else "ошибка обфускатора")


def friendly_error(exc: Exception) -> str:
    text = str(exc)
    low = text.lower()
    if "не модуль hikka" in low or "loader.module" in low:
        return "файл не похож на модуль Hikka/FTG (не найден класс loader.Module)."
    if "syntaxerror" in low or "indentationerror" in low:
        return "файл не является корректным Python-кодом (ошибка синтаксиса)."
    if "timed out" in low or "время обработки" in low:
        return "превышено время обработки. Попробуйте файл меньшего размера."
    if "memoryerror" in low:
        return "не хватило памяти на обработку файла."
    return text.splitlines()[-1] if text else "неизвестная ошибка"


# ---------------------------------------------------------------------------
# Инициализация aiogram
# ---------------------------------------------------------------------------
bot = Bot(token=TOKEN)
dp = Dispatcher()
_lock = asyncio.Lock()

# Файлы, ожидающие выбора режима: token -> {chat_id, user_id, file_id, name, ts}
_pending: dict[str, dict] = {}
_tasks: set[asyncio.Task] = set()
PENDING_TTL = int(os.getenv("PENDING_TTL", "3600"))


def _cleanup_pending() -> None:
    now = time.time()
    stale = [k for k, v in _pending.items() if now - v.get("ts", 0) > PENDING_TTL]
    for key in stale:
        _pending.pop(key, None)


@dp.message(Command("start"))
async def cmd_start(message: Message) -> None:
    await message.answer(
        "👋 Отправьте файл документом (.py, .plugin, .bat, .cmd и т.п.).\n"
        "Для Python-файлов я спрошу режим, .bat/.cmd обработаю сразу.\n\n"
        "Режим по умолчанию для Python:",
        reply_markup=mode_keyboard(),
    )


@dp.message(Command("mode"))
async def cmd_mode(message: Message) -> None:
    await message.answer(
        "🔧 Режим по умолчанию (для каждого файла бот всё равно спросит):",
        reply_markup=mode_keyboard(),
    )


@dp.message(Command("help"))
async def cmd_help(message: Message) -> None:
    await message.answer(
        "1. Отправьте файл документом (.py, .plugin, .bat, .cmd и т.п.).\n"
        "2. Для Python-файлов бот покажет меню: «Обычный .py скрипт» "
        "или «Модуль для Hikka/FTG».\n"
        "3. .bat/.cmd обфусцируются сразу и возвращаются как "
        "<имя>_obf.bat / <имя>_obf.cmd.\n\n"
        "Режим по умолчанию для Python: /mode"
    )


@dp.callback_query(F.data.startswith("mode:"))
async def on_mode(callback: CallbackQuery) -> None:
    mode = (callback.data or "").split(":", 1)[-1]
    if mode not in MODE_LABEL:
        await callback.answer("Неизвестный режим", show_alert=True)
        return

    if callback.message:
        set_mode(callback.message.chat.id, mode)
        try:
            await callback.message.edit_text(
                f"✅ Режим: {MODE_LABEL[mode]}\n\n"
                "Теперь пришлите файл документом (любое расширение)."
            )
        except Exception:
            await callback.message.answer(
                f"✅ Режим: {MODE_LABEL[mode]}\n\nПришлите файл документом."
            )
    await callback.answer()


async def handle_batch_document(
    message: Message, doc: Document, original: str
) -> None:
    """Текстовая обфускация .bat/.cmd (без компиляции и внешних утилит)."""
    log.info("[BAT] Обработка файла: %s", original)

    WORK_ROOT.mkdir(parents=True, exist_ok=True)
    job = Path(tempfile.mkdtemp(prefix="bat-", dir=str(WORK_ROOT)))
    tmp = job / f"{uuid.uuid4().hex}.tmp"

    try:
        await bot.download(doc, destination=tmp)
        raw = tmp.read_bytes()

        # latin-1 — байт-в-байт: не теряем ANSI/UTF-8/BOM в исходном .bat.
        text = raw.decode("latin-1")
        result = obfuscate_batch(text)
        out_bytes = result.encode("latin-1")

        if len(out_bytes) > MAX_FILE_BYTES:
            await message.answer(
                f"⚠️ Результат больше лимита Telegram: {len(out_bytes)} байт "
                f"(максимум {MAX_FILE_BYTES})."
            )
            return

        stem, ext = split_ext(original)
        out_name = f"{stem}_obf{ext}"
        out_path = job / out_name
        out_path.write_bytes(out_bytes)

        await message.reply_document(
            FSInputFile(str(out_path), filename=out_name),
            caption=f"✅ Batch-файл обфусцирован: {out_name}",
        )
        log.info("[BAT] Успешно обфусцирован: %s", original)
    except Exception as exc:
        log.exception("[BAT] Ошибка обработки %s", original)
        await message.answer(f"❌ Не удалось обработать {original}:\n{exc}")
    finally:
        shutil.rmtree(job, ignore_errors=True)


@dp.message(F.document)
async def on_document(message: Message) -> None:
    """Файл получен: .bat/.cmd — сразу, остальные — через меню режима."""
    doc = message.document
    if doc is None:
        return

    if doc.file_size and doc.file_size > MAX_FILE_BYTES:
        await message.answer(
            f"⚠️ Файл слишком большой: {doc.file_size} байт. "
            f"Лимит — {MAX_FILE_BYTES} байт."
        )
        return

    original = safe_name(doc.file_name or f"file_{doc.file_id}.py")
    ext = os.path.splitext(original)[1].lower()

    # .bat/.cmd — текстовая batch-обфускация, без Python-парсера и меню режимов.
    if ext in (".bat", ".cmd"):
        await handle_batch_document(message, doc, original)
        return

    _cleanup_pending()

    token = secrets.token_hex(4)
    _pending[token] = {
        "chat_id": message.chat.id,
        "user_id": message.from_user.id if message.from_user else None,
        "file_id": doc.file_id,
        "name": original,
        "ts": time.time(),
    }

    keyboard = InlineKeyboardMarkup(
        inline_keyboard=[
            [
                InlineKeyboardButton(
                    text="Обычный .py скрипт",
                    callback_data=f"pick:{token}:plain",
                )
            ],
            [
                InlineKeyboardButton(
                    text="Модуль для Hikka/FTG",
                    callback_data=f"pick:{token}:hikka",
                )
            ],
            [
                InlineKeyboardButton(
                    text="Отмена",
                    callback_data=f"pick:{token}:cancel",
                )
            ],
        ]
    )

    await message.answer(
        f"📄 Файл «{original}» получен.\n\n"
        "Что это за файл? Выберите режим защиты:",
        reply_markup=keyboard,
    )


@dp.callback_query(F.data.startswith("pick:"))
async def on_pick(callback: CallbackQuery) -> None:
    """Пользователь выбрал режим для конкретного файла."""
    parts = (callback.data or "").split(":", 2)
    if len(parts) != 3:
        await callback.answer("Некорректный выбор", show_alert=True)
        return

    _, token, mode = parts
    item = _pending.get(token)
    msg = callback.message

    if msg is None:
        await callback.answer("Сообщение недоступно", show_alert=True)
        return

    valid_user = (
        callback.from_user is None
        or item is not None
        and item.get("user_id") in (None, callback.from_user.id)
    )
    if item is None or item.get("chat_id") != msg.chat.id or not valid_user:
        await callback.answer(
            "Файл устарел — отправьте его заново.", show_alert=True
        )
        return

    _pending.pop(token, None)
    await callback.answer()

    if mode == "cancel":
        try:
            await msg.edit_text("❌ Обфускация отменена.")
        except Exception:
            pass
        return

    if mode not in MODE_LABEL:
        await msg.answer("Неизвестный режим.")
        return

    set_mode(msg.chat.id, mode)
    try:
        await msg.edit_text(
            f"✅ Режим: {MODE_LABEL[mode]}\n"
            f"⏳ Обрабатываю «{item['name']}»…"
        )
    except Exception:
        pass

    # Не блокируем polling: обработка идёт фоновой задачей.
    task = asyncio.create_task(process_pending(msg, item, mode))
    _tasks.add(task)
    task.add_done_callback(_tasks.discard)


async def process_pending(message: Message, item: dict, mode: str) -> None:
    """Скачивает файл, обфусцирует и возвращает с исходным расширением."""
    original = item["name"]
    WORK_ROOT.mkdir(parents=True, exist_ok=True)
    job = Path(tempfile.mkdtemp(prefix="job-", dir=str(WORK_ROOT)))
    tmp_txt = job / f"{uuid.uuid4().hex}.txt"

    try:
        await bot.download(item["file_id"], destination=tmp_txt)

        out_txt = job / f"{uuid.uuid4().hex}.out.txt"
        async with _lock:
            await run_obfuscator(tmp_txt, out_txt, mode)

        if not out_txt.exists() or out_txt.stat().st_size == 0:
            raise RuntimeError("обфускатор вернул пустой результат")

        final = job / original  # возвращаем РОДНОЕ имя и расширение
        out_txt.replace(final)

        await message.answer_document(
            FSInputFile(str(final), filename=original),
            caption=f"✅ Готово. Режим: {MODE_LABEL[mode]}",
        )
    except Exception as exc:
        log.exception("job failed")
        await message.answer(f"❌ Не удалось обработать файл:\n{friendly_error(exc)}")
    finally:
        shutil.rmtree(job, ignore_errors=True)


async def main() -> None:
    WORK_ROOT.mkdir(parents=True, exist_ok=True)
    if not OBFUSCATOR.exists():
        raise SystemExit(f"обфускатор не найден: {OBFUSCATOR}")

    me = await bot.get_me()
    log.info("Бот @%s (id %s) запущен", me.username, me.id)
    log.info("Рабочий каталог: %s", WORK_ROOT)
    log.info("Состояние: %s", STATE_FILE)

    runner = await start_health_server()
    try:
        await dp.start_polling(bot)
    finally:
        await runner.cleanup()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except (KeyboardInterrupt, SystemExit):
        pass

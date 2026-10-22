#!/usr/bin/env python3
"""Announce a published sync-server release in the Telegram channel.

The client has the same script (client/scripts/announce-telegram.py). This one
reads a server release from GitHub, turns its notes into Telegram HTML and
adds what self-hosters need: the container image and the setup guides.

Secrets never live in the repository. They come from the environment
(TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID, optional TELEGRAM_PROXY) or, for local
runs, from ~/.config/consolecrypt/telegram.env (KEY=VALUE lines, mode 600).

    announce-telegram.py --tag v0.2.1 --dry-run   # print the message only
    announce-telegram.py --tag v0.2.1             # post it
    announce-telegram.py --check                  # verify bot, proxy, channel
"""

from __future__ import annotations

import argparse
import html
import json
import os
import re
import stat
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

REPO = "evsikovas/consolecrypt-server"
IMAGE = "ghcr.io/evsikovas/consolecrypt-server"
CONFIG = Path.home() / ".config" / "consolecrypt" / "telegram.env"
# Shared with the client script; server keys are prefixed with "server:".
STATE = Path.home() / ".config" / "consolecrypt" / "telegram-announced.json"
LIMIT = 4096  # Telegram message text limit (after entity parsing).

TEXT = {
    "ru": {
        "title": "Сервер синхронизации ConsoleCrypt {version}",
        "image": "Образ",
        "setup": "Свой сервер",
        "docker": "Docker Compose",
        "k8s": "Kubernetes",
        "release": "Релиз и контрольные суммы",
        "notes": "Полный список изменений",
        "guide": "https://consolecrypt.dev/guide",
    },
    "en": {
        "title": "ConsoleCrypt sync server {version}",
        "image": "Image",
        "setup": "Your own server",
        "docker": "Docker Compose",
        "k8s": "Kubernetes",
        "release": "Release and checksums",
        "notes": "Full release notes",
        "guide": "https://consolecrypt.dev/guide",
    },
}


def load_config() -> dict[str, str]:
    values: dict[str, str] = {}
    if CONFIG.exists():
        mode = CONFIG.stat().st_mode
        if mode & (stat.S_IRWXG | stat.S_IRWXO):
            sys.exit(f"{CONFIG} must be readable only by you (chmod 600)")
        for line in CONFIG.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                key, value = line.split("=", 1)
                values[key.strip()] = value.strip()
    for key in ("TELEGRAM_BOT_TOKEN", "TELEGRAM_CHAT_ID", "TELEGRAM_PROXY"):
        if os.environ.get(key):
            values[key] = os.environ[key]
    return values


def github(path: str) -> dict:
    request = urllib.request.Request(f"https://api.github.com/repos/{REPO}/{path}")
    request.add_header("Accept", "application/vnd.github+json")
    token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
    if token:
        request.add_header("Authorization", f"Bearer {token}")
    with urllib.request.urlopen(request, timeout=30) as response:
        return json.load(response)


def release(tag: str | None) -> dict:
    data = github(f"releases/tags/{urllib.parse.quote(tag)}" if tag else "releases/latest")
    if data.get("draft"):
        sys.exit(f"{data.get('tag_name')} is still a draft")
    return data


# --- Markdown → Telegram HTML --------------------------------------------

# Relative links in the notes are relative to server/docs/releases/.
DOCS_BASE = f"https://github.com/{REPO}/blob/main/server/docs/releases/"


def notes_body(body: str) -> str:
    """The release notes without the title and the build footer (source,
    verified build, image digest hints)."""
    lines = []
    for line in body.splitlines():
        if re.match(r"^#\s", line):
            continue
        if line.startswith(("[Source]", "Linux AMD64", "Image:")):
            break
        lines.append(line)
    return "\n".join(lines)


def inline(text: str) -> str:
    """Escape and convert inline Markdown (code, links, bold, italic)."""
    parts: list[str] = []
    pos = 0
    pattern = re.compile(r"`([^`]+)`|\[([^\]]+)\]\(([^)\s]+)\)|\*\*(.+?)\*\*|(?<![\w*])\*(?!\s)(.+?)(?<!\s)\*(?![\w*])")
    for match in pattern.finditer(text):
        parts.append(html.escape(text[pos : match.start()], quote=False))
        code, label, url, bold, italic = match.groups()
        if code is not None:
            parts.append(f"<code>{html.escape(code, quote=False)}</code>")
        elif label is not None:
            target = url if re.match(r"^https?://", url) else urllib.parse.urljoin(DOCS_BASE, url)
            parts.append(f'<a href="{html.escape(target)}">{inline(label)}</a>')
        elif bold is not None:
            parts.append(f"<b>{inline(bold)}</b>")
        else:
            parts.append(f"<i>{inline(italic)}</i>")
        pos = match.end()
    parts.append(html.escape(text[pos:], quote=False))
    return "".join(parts)


def blocks(markdown: str) -> list[str]:
    """Paragraphs, headings and list items with soft-wrapped lines joined."""
    out: list[str] = []
    current: list[str] = []
    kind = ""

    def flush() -> None:
        nonlocal current, kind
        if current:
            text = inline(" ".join(current))
            out.append(f"<b>{text}</b>" if kind == "heading" else f"• {text}" if kind == "item" else text)
        current, kind = [], ""

    for raw in markdown.splitlines():
        line = raw.strip()
        if not line or re.match(r"^(-{3,}|\*{3,})$", line):
            flush()
            continue
        if heading := re.match(r"^#{1,6}\s+(.*)$", line):
            flush()
            current, kind = [heading.group(1)], "heading"
            flush()
            continue
        if item := re.match(r"^(?:[-*+]|\d+[.)])\s+(.*)$", line):
            flush()
            current, kind = [item.group(1)], "item"
            continue
        if not current:
            kind = "text"
        current.append(line)
    flush()
    return out


def join(parts: list[str]) -> str:
    """Blank lines between blocks, single breaks inside a list."""
    text = ""
    for i, part in enumerate(parts):
        if i:
            text += "\n" if part.startswith("• ") and parts[i - 1].startswith("• ") else "\n\n"
        text += part
    return text


def visible_length(markup: str) -> int:
    return len(html.unescape(re.sub(r"<[^>]+>", "", markup)))


# --- Message ------------------------------------------------------------

def message(data: dict, lang: str) -> str:
    t = TEXT[lang]
    version = data["tag_name"].removeprefix("v")
    title = f"<b>{html.escape(t['title'].format(version=version))}</b>"
    release_url = html.escape(data["html_url"])
    tail = "\n".join([
        f"<b>{t['image']}</b>: <code>{IMAGE}:{html.escape(version)}</code> (Linux AMD64, ARM64)",
        f"<b>{t['setup']}</b>: <a href=\"{t['guide']}#server-docker\">{t['docker']}</a>"
        f" · <a href=\"{t['guide']}#server-setup\">{t['k8s']}</a>",
        "",
        f'<a href="{release_url}">{t["release"]}</a>',
    ])
    notes = blocks(notes_body(data.get("body") or ""))
    more = f'<a href="{release_url}">{t["notes"]} →</a>'
    budget = LIMIT - visible_length(title) - visible_length(tail) - visible_length(more) - 8
    kept: list[str] = []
    used = 0
    for block in notes:
        size = visible_length(block) + 2
        if used + size > budget:
            kept.append(more)
            break
        kept.append(block)
        used += size
    return join([title, *kept, tail])


# --- Telegram -----------------------------------------------------------

def telegram(config: dict[str, str], method: str, payload: dict | None = None) -> dict:
    token = config.get("TELEGRAM_BOT_TOKEN")
    if not token:
        sys.exit("TELEGRAM_BOT_TOKEN is not set (environment or ~/.config/consolecrypt/telegram.env)")
    handlers: list[urllib.request.BaseHandler] = []
    if proxy := config.get("TELEGRAM_PROXY"):
        handlers.append(urllib.request.ProxyHandler({"http": proxy, "https": proxy}))
    opener = urllib.request.build_opener(*handlers)
    request = urllib.request.Request(
        f"https://api.telegram.org/bot{token}/{method}",
        data=json.dumps(payload or {}).encode(),
        headers={"Content-Type": "application/json"},
    )
    try:
        with opener.open(request, timeout=30) as response:
            result = json.load(response)
    except urllib.error.HTTPError as error:
        result = json.loads(error.read() or b"{}")
    except urllib.error.URLError as error:
        # Never echo the URL: it contains the bot token.
        sys.exit(f"Telegram is unreachable: {error.reason}")
    if not result.get("ok"):
        sys.exit(f"Telegram {method} failed: {result.get('description', 'unknown error')}")
    return result["result"]


def announced() -> dict:
    try:
        return json.loads(STATE.read_text())
    except (OSError, ValueError):
        return {}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--tag", help="release tag (default: latest release)")
    parser.add_argument("--lang", choices=sorted(TEXT), default="ru")
    parser.add_argument("--dry-run", action="store_true", help="print the message instead of posting")
    parser.add_argument("--force", action="store_true", help="post even if this tag was already announced")
    parser.add_argument("--check", action="store_true", help="verify the bot, proxy and channel access only")
    args = parser.parse_args()

    config = load_config()
    if args.check:
        bot = telegram(config, "getMe")
        chat = telegram(config, "getChat", {"chat_id": config.get("TELEGRAM_CHAT_ID")})
        member = telegram(config, "getChatMember", {"chat_id": chat["id"], "user_id": bot["id"]})
        can_post = member.get("status") == "creator" or member.get("can_post_messages", False)
        print(f"bot @{bot['username']} → {chat.get('title')} ({member.get('status')}, can post: {can_post})")
        sys.exit(0 if can_post else 1)

    data = release(args.tag)
    text = message(data, args.lang)
    if args.dry_run:
        print(text)
        print(f"\n[{visible_length(text)} / {LIMIT} characters]", file=sys.stderr)
        return
    key = f"server:{data['tag_name']}:{args.lang}"
    state = announced()
    if key in state and not args.force:
        sys.exit(f"{key} was already announced (message {state[key]}); use --force to post again")
    chat_id = config.get("TELEGRAM_CHAT_ID")
    if not chat_id:
        sys.exit("TELEGRAM_CHAT_ID is not set")
    sent = telegram(
        config,
        "sendMessage",
        {"chat_id": chat_id, "text": text, "parse_mode": "HTML", "link_preview_options": {"is_disabled": True}},
    )
    state[key] = sent["message_id"]
    try:
        STATE.parent.mkdir(parents=True, exist_ok=True)
        STATE.write_text(json.dumps(state, indent=2))
    except OSError:
        pass  # CI runners have no persistent home; GitHub runs this once per tag.
    print(f"Announced server {data['tag_name']} ({args.lang}) as message {sent['message_id']}")


if __name__ == "__main__":
    main()

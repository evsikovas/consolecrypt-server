"""Exercise the release post without connecting to GitHub or Telegram."""
from pathlib import Path
import runpy
import unittest


announce = runpy.run_path(str(Path(__file__).with_name("announce-telegram.py")))


class ServerAnnouncementTests(unittest.TestCase):
    def test_multilingual_notes_and_cover_caption(self):
        body = ("# Title\n\n![cover](https://example.com/c.png)\n\n## Русский\nRU text\n"
                "## English\nEN text\n## Español\nES text\n## 简体中文\nZH text\n"
                "Image: built image metadata\n")
        notes = announce["notes_body"]
        self.assertEqual(notes(body, "ru").strip(), "RU text")
        self.assertEqual(notes(body, "en").strip(), "EN text")
        self.assertEqual(notes("Older Russian release", "en"), "Older Russian release")
        data = {"body": body.replace("RU text", "RU text\n\n- " + "x" * 1200),
                "tag_name": "v0.2.9", "html_url": "https://example.com/release"}
        caption = announce["message"](data, "ru", announce["CAPTION_LIMIT"])
        self.assertIn("RU text", caption)
        self.assertIn("https://example.com/release", caption)
        self.assertIn("0.2.9", caption)
        self.assertLessEqual(announce["visible_length"](caption), 1024)

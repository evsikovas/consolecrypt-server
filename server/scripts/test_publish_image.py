# SPDX-License-Identifier: AGPL-3.0-only
import tempfile
from pathlib import Path
import unittest
from unittest.mock import patch
from types import SimpleNamespace
import publish_image as publish


class PublicationGuards(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / 'server/src').mkdir(parents=True)
        (self.root / 'server/Cargo.toml').write_text('[package]\nversion = "0.1.9"\n')
        (self.root / 'server/src/lib.rs').write_text('pub fn build_router() {}\n')
        self.git = patch.object(publish, 'run', side_effect=lambda *a, **kw: SimpleNamespace(stdout='a' * 40 if 'rev-parse' in a else ''))
        self.git.start()
        self.addCleanup(self.git.stop)

    def test_commit_images_do_not_move_the_stable_release_tag(self):
        plan = publish.source_plan(self.root, {})
        self.assertEqual(plan['tags'], ['sha-' + 'a' * 40, '0.1.9-' + 'a' * 12])

    def test_server_release_tag_adds_matching_version(self):
        plan = publish.source_plan(self.root, {'CI_COMMIT_TAG': 'server-v0.1.9'})
        self.assertIn('0.1.9', plan['tags'])

    def test_client_or_mismatching_tag_is_rejected(self):
        for tag in ('v0.1.9', 'server-v0.1.8'):
            with self.subTest(tag=tag), self.assertRaises(ValueError):
                publish.source_plan(self.root, {'CI_COMMIT_TAG': tag})

    def test_embedded_website_directory_is_rejected(self):
        (self.root / 'server/web').mkdir()
        with self.assertRaises(ValueError):
            publish.source_plan(self.root, {})

    def test_embedded_router_is_rejected(self):
        (self.root / 'server/src/lib.rs').write_text('pub mod web;\n')
        with self.assertRaises(ValueError):
            publish.source_plan(self.root, {})

    def test_wrong_destination_or_revision_is_rejected(self):
        for env in ({'CC_IMAGE_REPOSITORY': 'other.example/app'}, {'CI_COMMIT_SHA': 'b' * 40}):
            with self.subTest(env=env), self.assertRaises(ValueError):
                publish.source_plan(self.root, env)

    def test_modified_sources_cannot_be_published(self):
        with patch.object(publish, 'run', side_effect=[SimpleNamespace(stdout='a' * 40), SimpleNamespace(stdout=' M server/src/lib.rs')]):
            with self.assertRaises(ValueError):
                publish.source_plan(self.root, {})


if __name__ == '__main__':
    unittest.main()

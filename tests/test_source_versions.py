import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import server


class SourceVersions(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.old_data = server.DATA
        server.DATA = Path(self.tmp.name)
        (server.DATA / "cache").mkdir()

    def tearDown(self):
        server.DATA = self.old_data
        self.tmp.cleanup()

    def test_eol_v1_cached_result_with_releases(self):
        payload = {"product": {"name": "debian"}, "releases": [
            {"name": "13"}, {"name": "12"}, {"name": "11"}
        ]}
        (server.DATA / "cache" / "eol-debian.json").write_text(json.dumps(payload))
        self.assertEqual(
            [v["value"] for v in server.source_versions("eol", "debian")],
            ["13", "12", "11"],
        )

    def test_eol_v1_response_with_result_wrapper(self):
        response = {"result": {"releases": [{"name": "12"}, {"name": "11"}]}}
        with patch.object(server.feeds, "fetch", return_value=json.dumps(response).encode()):
            self.assertEqual(
                [v["value"] for v in server.source_versions("eol", "debian")],
                ["12", "11"],
            )

    def test_github_tags(self):
        server.save_github_sources([{"repo": "owner/project"}])
        response = [{"name": "v2.0"}, {"name": "v1.9"}]
        with patch.object(server.feeds, "fetch", return_value=json.dumps(response).encode()):
            self.assertEqual(
                [v["value"] for v in server.source_versions("github", "owner/project")],
                ["v2.0", "v1.9"],
            )


if __name__ == "__main__":
    unittest.main()

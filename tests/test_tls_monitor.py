import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import server


class TLSMonitorTests(unittest.TestCase):
    def test_normalize_https_url(self):
        self.assertEqual(server.normalize_tls_target('example.com'), 'https://example.com')
        self.assertEqual(server.normalize_tls_target('https://Example.com:8443/'), 'https://example.com:8443')

    def test_rejects_non_https_and_paths(self):
        for value in ('http://example.com', 'https://example.com/path', 'https://user:pass@example.com'):
            with self.subTest(value=value), self.assertRaises(server.HttpError):
                server.normalize_tls_target(value)

    def test_save_and_preserve_last_check(self):
        with tempfile.TemporaryDirectory() as td, patch.object(server, 'DATA', Path(td)):
            server.save_certificates([{'name': 'Site', 'url': 'example.com'}])
            cert = server.load_certificates()[0]
            self.assertEqual(cert['url'], 'https://example.com')
            cert['last_checked'] = '2026-10-21T00:00:00+00:00'
            server.atomic_write(Path(td) / 'certificates.yaml', __import__('yaml').safe_dump({'certificates':[cert]}))
            server.save_certificates([{'id': cert['id'], 'name': 'Site renamed', 'url': 'https://example.com'}])
            updated = server.load_certificates()[0]
            self.assertEqual(updated['last_checked'], '2026-10-21T00:00:00+00:00')
            self.assertEqual(updated['name'], 'Site renamed')


if __name__ == '__main__':
    unittest.main()

from __future__ import annotations

import unittest

from certificate_inspector import inspect_certificate_chain


class CertificateInspectorTests(unittest.TestCase):
    def test_certificate_inspection_requires_https(self) -> None:
        with self.assertRaisesRegex(ValueError, "https"):
            inspect_certificate_chain("http://example.com/")


if __name__ == "__main__":
    unittest.main()

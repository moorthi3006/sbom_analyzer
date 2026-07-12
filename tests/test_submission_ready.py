import os
import tempfile
import unittest

from app import create_app
from config import Config


class SubmissionConfig(Config):
    TESTING = True
    SECRET_KEY = "test-secret"
    DEFAULT_ADMIN_PASSWORD = "test-password"
    _root = os.path.join(os.getcwd(), ".test_runtime")
    SQLALCHEMY_DATABASE_URI = "sqlite:///" + os.path.join(_root, "test.db")
    UPLOAD_FOLDER = os.path.join(_root, "uploads")
    REPORTS_FOLDER = os.path.join(_root, "reports")
    GRAPHS_FOLDER = os.path.join(_root, "graphs")


class SubmissionReadyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = create_app(SubmissionConfig)

    def setUp(self):
        self.client = self.app.test_client()

    def _token(self, response):
        import re
        return re.search(r'name="csrf_token" value="([^"]+)"', response.get_data(as_text=True)).group(1)

    def test_login_requires_csrf_and_accepts_valid_token(self):
        self.assertEqual(self.client.post("/login", data={"username": "admin"}).status_code, 400)
        page = self.client.get("/login")
        response = self.client.post("/login", data={
            "csrf_token": self._token(page), "username": "admin", "password": "test-password"
        })
        self.assertEqual(response.status_code, 302)

    def test_bundled_dataset_is_version_specific(self):
        from backend.services.vulnerability_scanner import VulnerabilityScanner
        scanner = VulnerabilityScanner()
        findings = scanner.scan_dependency("gomock", "3.2.0")
        self.assertTrue(findings)
        self.assertEqual(scanner.scan_dependency("gomock", "999.0.0"), [])
        self.assertEqual(scanner.scan_dependency("unknown-package", "1.0.0"), [])


if __name__ == "__main__":
    unittest.main()

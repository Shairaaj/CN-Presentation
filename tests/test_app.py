import unittest

from app import app, validate_config


class NetworkLabTests(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()

    def test_duplicate_detection(self):
        result = validate_config([
            {"name": "one", "address": "192.168.1.5/24"},
            {"name": "two", "address": "192.168.1.5/24"},
        ])
        self.assertEqual(result["result"], "INVALID")
        self.assertTrue(any("Duplicate" in item["message"] for item in result["findings"]))

    def test_missing_dns_warning(self):
        result = validate_config([{"name": "one", "address": "192.168.1.5/24", "require_dns": True}])
        self.assertEqual(result["result"], "VALID WITH WARNINGS")

    def test_socket_round_trip(self):
        self.assertEqual(self.client.post("/api/socket/tcp/start").status_code, 200)
        response = self.client.post("/api/socket/tcp/send", json={"message": "hello"})
        self.assertEqual(response.json["result"]["message"], "hello")
        self.client.post("/api/socket/tcp/stop")

    def test_health(self):
        self.assertTrue(self.client.get("/api/health").json["ok"])


if __name__ == "__main__":
    unittest.main()

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

    def test_command_catalog_is_allowlisted(self):
        response = self.client.get("/api/commands")
        self.assertEqual(response.status_code, 200)
        self.assertTrue(any(command["id"] == "ipconfig" for command in response.json["commands"]))
        self.assertEqual(self.client.post("/api/commands/run", json={"id": "not-allowed"}).status_code, 404)

    def test_terminal_executes_validated_network_command(self):
        response = self.client.post("/api/commands/execute", json={"command": "ping 127.0.0.1"})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json["result"]["command"], "ping 127.0.0.1")

    def test_terminal_rejects_shell_operators(self):
        response = self.client.post("/api/commands/execute", json={"command": "ipconfig & whoami"})
        self.assertEqual(response.status_code, 400)


if __name__ == "__main__":
    unittest.main()

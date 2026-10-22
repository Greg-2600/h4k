# Tests for ollama.py
import json
from unittest.mock import MagicMock, patch

import pytest

from h4k.api.services.ollama import (
    OLLAMA_DEFAULT_PORT,
    OllamaExploit,
    exploit_tool_call,
    inject_prompt,
    scan_target,
)


@pytest.fixture
def ollama():
    return OllamaExploit("127.0.0.1", port=11434)


class TestOllamaExploitInit:
    def test_default_port(self):
        assert OLLAMA_DEFAULT_PORT == 11434

    def test_sets_target_and_port(self, ollama):
        assert ollama.target == "127.0.0.1"
        assert ollama.port == 11434
        assert ollama.timeout == 30

    def test_custom_timeout(self):
        expl = OllamaExploit("127.0.0.1", timeout=60)
        assert expl.timeout == 60


class TestOllamaDiscover:
    @patch("urllib.request.urlopen")
    def test_discovers_ollama(self, mock_urlopen, ollama):
        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps(
            {
                "models": [
                    {
                        "name": "llama3:latest",
                        "model": "llama3:latest",
                        "size": 4661123456,
                        "capabilities": ["tools", "generate"],
                    },
                    {
                        "name": "mistral:latest",
                        "model": "mistral:latest",
                        "size": 4101234567,
                        "capabilities": ["generate"],
                    },
                ]
            }
        ).encode()
        mock_urlopen.return_value.__enter__.return_value = mock_resp

        result = ollama.discover()

        assert result["ollama_detected"] is True
        assert len(result["models"]) == 2
        assert result["auth_bypass"] is True
        assert result["tool_calling_available"] is True
        assert len(result["dangerous_capabilities"]) == 1
        assert result["dangerous_capabilities"][0]["model"] == "llama3:latest"
        assert result["recommendations"][0]["cve"] == "CVE-2024-37051"

    @patch("urllib.request.urlopen")
    def test_no_model_error(self, mock_urlopen, ollama):
        mock_urlopen.side_effect = Exception("connection refused")
        result = ollama.discover()
        assert result["ollama_detected"] is False
        assert "discovery_error" in result

    @patch("urllib.request.urlopen")
    def test_no_tool_calling_model(self, mock_urlopen, ollama):
        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps(
            {
                "models": [
                    {
                        "name": "llama3:latest",
                        "model": "llama3:latest",
                        "size": 4661123456,
                        "capabilities": ["generate"],
                    },
                ]
            }
        ).encode()
        mock_urlopen.return_value.__enter__.return_value = mock_resp

        result = ollama.discover()

        assert result["tool_calling_available"] is False
        assert result["dangerous_capabilities"] == []


class TestOllamaRound1:
    @patch("urllib.request.urlopen")
    def test_round1_no_model(self, mock_urlopen, ollama):
        ollama._available_models = []
        mock_urlopen.side_effect = Exception("connection refused")
        result = ollama.round1_trigger("hello")
        assert result["error"] == "no model available for tool calling"

    @patch("urllib.request.urlopen")
    def test_round1_success_with_tool_call(self, mock_urlopen, ollama):
        ollama._available_models = [
            {
                "model": "llama3:latest",
                "name": "llama3:latest",
                "capabilities": ["tools"],
            }
        ]
        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps(
            {
                "message": {
                    "content": "",
                    "tool_calls": [
                        {
                            "id": "call_123",
                            "function": {
                                "name": "exec",
                                "arguments": '{"cmd": "ls"}',
                            },
                        }
                    ],
                }
            }
        ).encode()
        mock_urlopen.return_value.__enter__.return_value = mock_resp

        result = ollama.round1_trigger("execute ls")

        assert "tool_calls" in result
        assert len(result["tool_calls"]) == 1
        assert result["tool_calls"][0]["cmd"] == "ls"

    @patch("urllib.request.urlopen")
    def test_round1_no_tool_call(self, mock_urlopen, ollama):
        ollama._available_models = [
            {
                "model": "llama3:latest",
                "name": "llama3:latest",
                "capabilities": ["tools"],
            }
        ]
        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps(
            {"message": {"content": "Hello! How can I help you?"}}
        ).encode()
        mock_urlopen.return_value.__enter__.return_value = mock_resp

        result = ollama.round1_trigger("hello")

        assert "raw_output" in result
        assert result["stdout"] == "Hello! How can I help you?"
        assert result["rc"] == 0

    @patch("urllib.request.urlopen")
    def test_round1_http_error(self, mock_urlopen, ollama):
        ollama._available_models = [
            {
                "model": "llama3:latest",
                "name": "llama3:latest",
                "capabilities": ["tools"],
            }
        ]

        import urllib.error

        mock_urlopen.side_effect = urllib.error.HTTPError(
            "url", 500, "Server Error", {}, None
        )

        result = ollama.round1_trigger("hello")
        assert "error" in result
        assert "500" in result["error"]

    @patch("urllib.request.urlopen")
    def test_round1_url_error(self, mock_urlopen, ollama):
        ollama._available_models = [
            {
                "model": "llama3:latest",
                "name": "llama3:latest",
                "capabilities": ["tools"],
            }
        ]

        import urllib.error

        mock_urlopen.side_effect = urllib.error.URLError("connection refused")

        result = ollama.round1_trigger("hello")
        assert "error" in result
        assert "connection failed" in result["error"]


class TestOllamaExecuteTool:
    @patch("urllib.request.urlopen")
    def test_execute_tool_no_model(self, mock_urlopen, ollama):
        ollama._available_models = []
        mock_urlopen.side_effect = Exception("no connection")
        result = ollama.execute_tool("ls")
        assert result["error"] == "no model available for tool calling"

    @patch("urllib.request.urlopen")
    @patch("subprocess.run")
    def test_execute_tool_success(self, mock_run, mock_urlopen, ollama):
        ollama._available_models = [
            {
                "model": "llama3:latest",
                "name": "llama3:latest",
                "capabilities": ["tools"],
            }
        ]

        mock_urlopen.return_value.__enter__.return_value.read.return_value = json.dumps(
            {
                "message": {
                    "content": "Command executed",
                    "tool_calls": [
                        {
                            "id": "call_abc",
                            "function": {
                                "name": "exec",
                                "arguments": '{"cmd": "echo hello"}',
                            },
                        }
                    ],
                }
            }
        ).encode()

        mock_proc = MagicMock()
        mock_proc.stdout = "hello\n"
        mock_proc.stderr = ""
        mock_proc.returncode = 0
        mock_run.return_value = mock_proc

        result = ollama.execute_tool("echo hello")

        assert result["stdout"] == "hello\n"
        assert result["stderr"] == ""
        assert result["rc"] == 0
        assert "model_response" in result

    @patch("urllib.request.urlopen")
    @patch("subprocess.run")
    def test_execute_tool_no_tool_call_returned(self, mock_run, mock_urlopen, ollama):
        ollama._available_models = [
            {
                "model": "llama3:latest",
                "name": "llama3:latest",
                "capabilities": ["tools"],
            }
        ]

        mock_urlopen.return_value.__enter__.return_value.read.return_value = json.dumps(
            {"message": {"content": "Just a greeting"}}
        ).encode()

        result = ollama.execute_tool("hello")

        assert result["stdout"] == ""
        assert result["model_response"] == "Just a greeting"
        mock_run.assert_not_called()

    @patch("urllib.request.urlopen")
    @patch("subprocess.run")
    def test_execute_tool_subprocess_error(self, mock_run, mock_urlopen, ollama):
        ollama._available_models = [
            {
                "model": "llama3:latest",
                "name": "llama3:latest",
                "capabilities": ["tools"],
            }
        ]

        mock_urlopen.return_value.__enter__.return_value.read.return_value = json.dumps(
            {
                "message": {
                    "content": "",
                    "tool_calls": [
                        {
                            "id": "call_abc",
                            "function": {
                                "name": "exec",
                                "arguments": '{"cmd": "false"}',
                            },
                        }
                    ],
                }
            }
        ).encode()

        mock_run.side_effect = Exception("subprocess error")

        result = ollama.execute_tool("false")
        assert result["stdout"] == ""
        assert "subprocess error" in result["stderr"]
        assert result["rc"] == -1


class TestOllamaInjectSystemPrompt:
    @patch("urllib.request.urlopen")
    def test_inject_system_prompt_success(self, mock_urlopen, ollama):
        ollama._available_models = [
            {"model": "llama3:latest", "name": "llama3:latest", "capabilities": []}
        ]
        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps(
            {"response": "System prompt: you are helpful"}
        ).encode()
        mock_urlopen.return_value.__enter__.return_value = mock_resp

        result = ollama.inject_system_prompt("you are helpful")
        assert result["response"] == "System prompt: you are helpful"
        assert result["model"] == "llama3:latest"

    @patch("urllib.request.urlopen")
    def test_inject_system_prompt_no_model(self, mock_urlopen, ollama):
        ollama._available_models = []
        mock_urlopen.side_effect = Exception("no model")
        result = ollama.inject_system_prompt("system")
        assert result["error"] == "no model specified and none available"

    @patch("urllib.request.urlopen")
    def test_inject_system_prompt_explicit_model(self, mock_urlopen, ollama):
        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps({"response": "injected"}).encode()
        mock_urlopen.return_value.__enter__.return_value = mock_resp

        result = ollama.inject_system_prompt("system", model="llama3:latest")
        assert result["model"] == "llama3:latest"


class TestOllamaShowModelInfo:
    @patch("urllib.request.urlopen")
    def test_show_model_info_success(self, mock_urlopen, ollama):
        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps(
            {
                "name": "llama3:latest",
                "system": "You are a helpful assistant",
                "parameters": {"temperature": 0.7},
            }
        ).encode()
        mock_urlopen.return_value.__enter__.return_value = mock_resp

        result = ollama.show_model_info("llama3:latest")
        assert result["name"] == "llama3:latest"
        assert result["system"] == "You are a helpful assistant"

    @patch("urllib.request.urlopen")
    def test_show_model_info_error(self, mock_urlopen, ollama):
        mock_urlopen.side_effect = Exception("not found")
        result = ollama.show_model_info("nonexistent")
        assert "error" in result


class TestOllamaModuleFunctions:
    @patch.object(OllamaExploit, "discover")
    def test_scan_target(self, mock_discover, ollama):
        mock_discover.return_value = {"ollama_detected": True}
        result = scan_target("192.168.1.1")
        assert result["ollama_detected"] is True

    @patch.object(OllamaExploit, "execute_tool")
    def test_exploit_tool_call(self, mock_exec, ollama):
        mock_exec.return_value = {"stdout": "result", "rc": 0}
        result = exploit_tool_call("192.168.1.1", "whoami")
        assert result["stdout"] == "result"

    @patch.object(OllamaExploit, "inject_system_prompt")
    def test_inject_prompt(self, mock_inject, ollama):
        mock_inject.return_value = {"response": "injected"}
        result = inject_prompt("192.168.1.1", "system")
        assert result["response"] == "injected"

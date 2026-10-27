import unittest
from unittest import mock

import httpx

from aegis import config
from aegis.llm import GroqLLM, LLMUnavailable, OllamaLLM, make_llm


def response(status=200, payload=None):
    return httpx.Response(status, json=payload or {}, request=httpx.Request("POST", "http://test"))


class OllamaTests(unittest.TestCase):
    def test_reply_is_parsed_and_metadata_recorded(self):
        payload = {"model": "qwen2.5:3b", "message": {"content": '{"threat": true}'}, "prompt_eval_count": 120, "eval_count": 15}
        llm = OllamaLLM(model="qwen2.5:3b")
        with mock.patch("httpx.post", return_value=response(payload=payload)) as post:
            self.assertEqual(llm.ask_json("prompt"), {"threat": True})
        sent = post.call_args.kwargs["json"]
        self.assertEqual((sent["format"], sent["options"]["temperature"]), ("json", 0.0))
        self.assertEqual((llm.last_meta["model_version"], llm.last_meta["tokens_in"]), ("qwen2.5:3b", 120))

    def test_not_running_or_model_missing(self):
        llm = OllamaLLM(model="qwen2.5:3b")
        with mock.patch("httpx.get", side_effect=httpx.ConnectError("refused")):
            self.assertFalse(llm.configured)
            self.assertIn("not running", llm.note)
        with mock.patch("httpx.get", return_value=response(payload={"models": [{"name": "llama3:latest"}]})):
            self.assertFalse(llm.configured)
            self.assertIn("ollama pull qwen2.5:3b", llm.note)
        with mock.patch("httpx.get", return_value=response(payload={"models": [{"name": "qwen2.5:3b"}]})):
            self.assertTrue(llm.configured)

    def test_server_error_becomes_unavailable(self):
        with mock.patch("httpx.post", side_effect=httpx.ReadTimeout("slow")):
            with self.assertRaises(LLMUnavailable):
                OllamaLLM().ask_json("prompt")


class GroqTests(unittest.TestCase):
    def test_rate_limit_becomes_unavailable(self):
        with mock.patch("httpx.post", return_value=response(429)):
            with self.assertRaises(LLMUnavailable):
                GroqLLM(api_key="test-key").ask_json("prompt")

    def test_reply_is_parsed(self):
        payload = {"model": "llama-3.1-8b-instant", "choices": [{"message": {"content": '{"ok": 1}'}}], "usage": {"prompt_tokens": 9}}
        with mock.patch("httpx.post", return_value=response(payload=payload)):
            llm = GroqLLM(api_key="test-key")
            self.assertEqual(llm.ask_json("prompt"), {"ok": 1})
            self.assertEqual(llm.last_meta["tokens_in"], 9)


class FactoryTests(unittest.TestCase):
    def test_provider_is_chosen_by_config(self):
        with mock.patch.object(config, "LLM_PROVIDER", "groq"):
            self.assertEqual(make_llm().provider, "groq")
        self.assertEqual(make_llm("ollama").provider, "ollama")
        with self.assertRaises(ValueError):
            make_llm("nope")


if __name__ == "__main__":
    unittest.main()

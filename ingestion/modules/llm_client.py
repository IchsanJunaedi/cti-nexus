from openai import OpenAI

_PROVIDERS = {
    "openai": {
        "base_url": None,
        "default_model": "gpt-4o",
    },
    "deepseek": {
        "base_url": "https://api.deepseek.com",
        "default_model": "deepseek-flash",
    },
    "qwen": {
        "base_url": "https://dashscope-intl.aliyuncs.com/compatible-mode/v1",
        "default_model": "qwen-flash",
    },
    "gemini": {
        "base_url": "https://generativelanguage.googleapis.com/v1beta/openai/",
        "default_model": "gemini-2.0-flash",
    },
}


def get_llm_client(provider: str, api_key: str, model: str = "") -> tuple[OpenAI, str]:
    """Return (OpenAI-compatible client, resolved model name) for the given provider."""
    provider = provider.lower()
    if provider not in _PROVIDERS:
        raise ValueError(f"Unknown LLM provider '{provider}'. Valid: {list(_PROVIDERS)}")
    cfg = _PROVIDERS[provider]
    kwargs: dict = {"api_key": api_key}
    if cfg["base_url"]:
        kwargs["base_url"] = cfg["base_url"]
    return OpenAI(**kwargs), model or cfg["default_model"]


def store_param(provider: str) -> dict:
    """Returns {'store': True} for OpenAI only — other providers don't support it."""
    return {"store": True} if provider.lower() == "openai" else {}

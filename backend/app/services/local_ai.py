import json
import logging

import httpx

from app.config import get_settings

logger = logging.getLogger(__name__)


def ollama_status() -> dict[str, object]:
    settings = get_settings()
    try:
        response = httpx.get(f"{settings.ollama_url.rstrip('/')}/api/tags", timeout=2.5)
        response.raise_for_status()
        models = [item.get("name", "") for item in response.json().get("models", [])]
        qwen_models = [name for name in models if name.split(":", 1)[0].lower().startswith("qwen")]
        model_ready = settings.ollama_model in models
        return {
            "provider": "Ollama",
            "connected": True,
            "model": settings.ollama_model,
            "model_ready": model_ready,
            "available_models": models,
            "available_qwen_models": qwen_models,
        }
    except (httpx.HTTPError, ValueError) as exc:
        return {
            "provider": "Ollama",
            "connected": False,
            "model": settings.ollama_model,
            "model_ready": False,
            "available_models": [],
            "available_qwen_models": [],
            "error": str(exc),
        }


def enhance_local_answer(
    result: dict[str, object],
    model_name: str | None = None,
    model_status: dict[str, object] | None = None,
) -> dict[str, object]:
    if result.get("intent") == "unsupported" or not result.get("facts"):
        return result
    status = model_status or ollama_status()
    settings = get_settings()
    selected_model = model_name or settings.ollama_model
    if not status["connected"] or selected_model not in status["available_models"]:
        return result
    schema = {
        "type": "object",
        "properties": {"answer": {"type": "string"}},
        "required": ["answer"],
    }
    evidence = {
        "question": result["question"],
        "intent": result["intent"],
        "deterministic_summary": result["answer"],
        "database_facts": result["facts"],
    }
    try:
        response = httpx.post(
            f"{settings.ollama_url.rstrip('/')}/api/chat",
            json={
                "model": selected_model,
                "stream": False,
                "format": schema,
                "options": {"temperature": 0.1},
                "messages": [
                    {"role": "system", "content": "You are a local SOC analyst writing assistant. Rewrite the deterministic summary as a concise, clear explanation using only the supplied database facts. Never add indicators, causes, attribution, counts, or recommendations not present in the supplied evidence. State uncertainty plainly. Return only the requested JSON."},
                    {"role": "user", "content": json.dumps(evidence, ensure_ascii=False)},
                ],
            },
            timeout=settings.ollama_timeout_seconds,
        )
        response.raise_for_status()
        generated = response.json().get("message", {}).get("content", "")
        parsed = json.loads(generated)
        answer = parsed.get("answer")
        if isinstance(answer, str) and answer.strip():
            result["answer"] = answer.strip()
            result["data_scope"] = f"{result['data_scope']} Explanation polished by local Ollama model {selected_model}; facts remain database-derived."
    except (httpx.HTTPError, ValueError, TypeError, KeyError) as exc:
        logger.warning("ollama_copilot_fallback", extra={"error_type": type(exc).__name__})
    return result

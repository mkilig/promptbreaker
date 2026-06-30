# runners.py
# ─────────────────────────────────────────────────────────────────────────
# Gemini-only model runner, built on the current `google-genai` SDK
# (the unified SDK that replaced the deprecated `google-generativeai`
# package). This avoids that package's heavy grpc/C++ dependency chain,
# which is what was causing the libstdc++.so.6 ImportError on Replit.
#
# Supports two execution modes:
#   run_single_turn()   — one converted payload, one response
#   run_crescendo()      — a multi-turn conversation, preserving history
#                           turn over turn (the actual mechanism a
#                           Crescendo-style attack depends on)
# ─────────────────────────────────────────────────────────────────────────

import os
from google import genai

MODEL_NAME = "gemini-2.5-flash"


def _get_client():
    api_key = os.environ.get("GOOGLE_API_KEY")
    if not api_key:
        raise RuntimeError("GOOGLE_API_KEY is not set in Secrets.")
    return genai.Client(api_key=api_key)


def run_single_turn(prompt: str) -> dict:
    """Send one prompt to Gemini, return the response and basic metadata."""
    try:
        client = _get_client()
        response = client.models.generate_content(
            model=MODEL_NAME,
            contents=prompt,
        )

        text = response.text if response.text else "[Gemini blocked or returned no text for this response]"

        return {
            "model": "Gemini 2.5 Flash",
            "provider": "Google",
            "response": text,
            "status": "success",
        }
    except Exception as e:
        return {
            "model": "Gemini 2.5 Flash",
            "provider": "Google",
            "response": "",
            "status": "error",
            "error": str(e),
        }


def run_crescendo(turns: list) -> dict:
    """
    Run a multi-turn conversation against Gemini, preserving history so
    each turn sees everything that came before it — this is what makes
    a Crescendo-style escalation possible. Returns every turn's prompt
    and response so the full escalation can be inspected and judged.
    """
    try:
        client = _get_client()
        chat = client.chats.create(model=MODEL_NAME)

        turn_results = []
        for i, turn_prompt in enumerate(turns):
            try:
                response = chat.send_message(turn_prompt)
                text = response.text if response.text else "[Blocked or no text returned for this turn]"
                turn_results.append({
                    "turn_number": i + 1,
                    "prompt": turn_prompt,
                    "response": text,
                    "status": "success",
                })
            except Exception as turn_err:
                turn_results.append({
                    "turn_number": i + 1,
                    "prompt": turn_prompt,
                    "response": "",
                    "status": "error",
                    "error": str(turn_err),
                })
                # Stop the chain if a turn hard-fails (e.g. rate limit)
                break

        return {
            "model": "Gemini 2.5 Flash",
            "provider": "Google",
            "status": "success",
            "turns": turn_results,
        }
    except Exception as e:
        return {
            "model": "Gemini 2.5 Flash",
            "provider": "Google",
            "status": "error",
            "error": str(e),
            "turns": [],
        }


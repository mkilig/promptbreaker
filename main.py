import os
from dotenv import load_dotenv
load_dotenv()
from flask import Flask, render_template, request, jsonify

from attacks import (
    get_attack_categories, get_attacks_by_category,
    get_converters, apply_converter,
    get_crescendo_chains, get_crescendo_turns,
)
from runners import run_single_turn, run_crescendo
from judge import judge_single_turn, judge_crescendo

app = Flask(__name__)


@app.route("/")
def index():
    categories = get_attack_categories()
    converters = get_converters()
    crescendo_chains = get_crescendo_chains()
    return render_template(
        "index.html",
        categories=categories,
        converters=converters,
        crescendo_chains=crescendo_chains,
    )


@app.route("/api/attacks")
def api_attacks():
    category = request.args.get("category", "")
    return jsonify(get_attacks_by_category(category))


@app.route("/api/run_single", methods=["POST"])
def api_run_single():
    """
    Single-turn attack: base payload + selected converter -> Gemini -> judge.
    """
    data = request.json
    atlas_id = data.get("atlas_id", "Unknown")
    atlas_name = data.get("atlas_name", "Unknown")
    intent = data.get("intent", "")
    base_payload = data.get("payload", "").strip()
    converter_key = data.get("converter", "none")
    attack_name = data.get("attack_name", "Custom")

    if not base_payload:
        return jsonify({"error": "No payload provided"}), 400

    final_prompt = apply_converter(converter_key, base_payload)

    model_result = run_single_turn(final_prompt)

    if model_result.get("status") == "error":
        verdict = {
            "manipulated": False,
            "severity": 0,
            "verdict": "API_ERROR",
            "explanation": model_result.get("error", "Unknown error"),
            "red_flags": [],
            "refusal_quality": "N/A",
        }
    else:
        verdict = judge_single_turn(
            atlas_id, atlas_name, intent, final_prompt, model_result.get("response", "")
        )

    return jsonify({
        "mode": "single_turn",
        "attack_name": attack_name,
        "atlas_id": atlas_id,
        "atlas_name": atlas_name,
        "intent": intent,
        "converter": converter_key,
        "base_payload": base_payload,
        "final_prompt": final_prompt,
        "model_result": model_result,
        "judgment": verdict,
    })


@app.route("/api/run_crescendo", methods=["POST"])
def api_run_crescendo():
    """
    Multi-turn crescendo attack: runs the full conversation, then judges
    the entire trajectory at once.
    """
    data = request.json
    chain_key = data.get("chain_key")

    chains = {c["key"]: c for c in get_crescendo_chains()}
    chain_meta = chains.get(chain_key)
    turns_text = get_crescendo_turns(chain_key)

    if not chain_meta or not turns_text:
        return jsonify({"error": "Unknown crescendo chain"}), 400

    chat_result = run_crescendo(turns_text)

    if chat_result.get("status") == "error":
        verdict = {
            "manipulated": False,
            "severity": 0,
            "verdict": "API_ERROR",
            "explanation": chat_result.get("error", "Unknown error"),
            "red_flags": [],
            "refusal_quality": "N/A",
        }
    else:
        verdict = judge_crescendo(
            chain_meta["atlas_id"], chain_meta["atlas_name"],
            chain_meta["intent"], chat_result.get("turns", [])
        )

    return jsonify({
        "mode": "crescendo",
        "chain_name": chain_meta["name"],
        "atlas_id": chain_meta["atlas_id"],
        "atlas_name": chain_meta["atlas_name"],
        "intent": chain_meta["intent"],
        "turns": chat_result.get("turns", []),
        "judgment": verdict,
    })


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    app.run(host="0.0.0.0", port=port, debug=True)

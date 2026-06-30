# PromptBreaker

An AI security red-teaming lab that tests Gemini's resistance to manipulation using real-world frameworks:

- **MITRE ATLAS** technique taxonomy for tagging adversary intent
- **PyRIT-inspired** composable converters (attack delivery disguises) — any converter can wrap any base attack
- **Crescendo** multi-turn escalation chains, where gradual context-building extracts content a single direct request would get refused

Built with Flask + the `google-genai` SDK, deployed on Vercel.

**Live demo:** https://promptbreaker-eight.vercel.app

## How it works

Pick an attack intent (tagged with a real ATLAS technique ID), pick a delivery method (roleplay framing, markdown instruction smuggling, false authority, etc.), and run it against Gemini 2.5 Flash. A second Gemini call acts as judge, scoring whether the model was manipulated and explaining why.

The Crescendo tab runs full multi-turn conversations where the judge evaluates the entire trajectory, not just the final turn — since the danger in a Crescendo attack is cumulative.

## Local development

```bash
python3 -m venv venv
venv/bin/pip install -r requirements.txt
echo "GOOGLE_API_KEY=your_key_here" > .env
venv/bin/python main.py
```

## Architecture

- `attacks.py` — base attacks (ATLAS-tagged), converters, and crescendo chains, kept as separate composable concepts
- `runners.py` — Gemini API calls (single-turn and multi-turn chat)
- `judge.py` — Gemini-as-judge evaluation logic (documented leniency-bias limitation: judge and target share the same model family)
- `main.py` — Flask routes
- `templates/index.html` — vanilla JS/HTML frontend, no build step

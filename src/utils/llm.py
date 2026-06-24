import os
import re
import json
import httpx
from dotenv import load_dotenv

# Look for .env two directories up (project root)
env_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".env"))
load_dotenv(dotenv_path=env_path)

LLM_KEY = os.getenv("LLM_KEY")
if not LLM_KEY:
    if os.path.exists(env_path):
        with open(env_path, "r") as f:
            for line in f:
                if "LLM_KEY" in line:
                    parts = line.split("=", 1)
                    LLM_KEY = parts[1].strip().strip('"').strip("'")
                    break

def query_llm(system_prompt: str, user_prompt: str) -> str:
    """Queries NVIDIA NIM deepseek-ai/deepseek-v4-pro model."""
    if not LLM_KEY:
        raise ValueError("LLM_KEY environment variable is not defined.")

    headers = {
        "Authorization": f"Bearer {LLM_KEY}",
        "Content-Type": "application/json"
    }

    payload = {
        "model": "deepseek-ai/deepseek-v4-pro",
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt}
        ],
        "temperature": 0.1,
    }

    with httpx.Client() as client:
        response = client.post(
            "https://integrate.api.nvidia.com/v1/chat/completions",
            headers=headers,
            json=payload,
            timeout=60.0
        )
        if response.status_code != 200:
            raise Exception(f"LLM API request failed: {response.status_code} - {response.text}")
        return response.json()["choices"][0]["message"]["content"]

def parse_json_safely(text: str) -> dict:
    """Robustly extracts and parses JSON from text, stripping markdown blocks if present."""
    cleaned = text.strip()
    if cleaned.startswith("```"):
        newline_idx = cleaned.find("\n")
        if newline_idx != -1:
            cleaned = cleaned[newline_idx:].strip()
        if cleaned.endswith("```"):
            cleaned = cleaned[:-3].strip()
    
    if cleaned.lower().startswith("json"):
        cleaned = cleaned[4:].strip()

    try:
        return json.loads(cleaned)
    except Exception as e:
        match = re.search(r'\{.*\}', cleaned, re.DOTALL)
        if match:
            try:
                return json.loads(match.group(0))
            except:
                pass
        raise e

from ..utils import llm
from ..database.vdb import VulnerabilityDB

# Initialize vulnerability DB
vuln_db = VulnerabilityDB()

def run_security_agent(filename: str, hunk_text: str) -> list:
    """Analyzes security vulnerabilities, utilizing local RAG context."""
    # Retrieve relevant historical flaws from vdb
    historical_flaws = vuln_db.search(hunk_text, top_k=2)
    rag_context = ""
    if historical_flaws:
        rag_context = "### Historical Vulnerability References (RAG):\n"
        for i, flaw in enumerate(historical_flaws, 1):
            rag_context += (
                f"{i}. Title: {flaw['title']}\n"
                f"   Description: {flaw['description']}\n"
                f"   Severity: {flaw['severity']}\n"
                f"   Example Flaw:\n{flaw['example_flaw']}\n"
                f"   Example Fix:\n{flaw['example_fix']}\n\n"
            )

    system_prompt = (
        "You are a security code analysis agent (SAST).\n"
        "Your task is to analyze the modified lines and hunk context of a file for vulnerabilities.\n"
        "Check strictly for:\n"
        "1. OWASP Top 10 vulnerabilities (SQL injection, CSRF, XSS, SSRF, command injection, path traversal, etc.).\n"
        "2. Leaked API secrets or credentials.\n"
        "3. Input injection surfaces.\n\n"
        "Use the provided Historical Vulnerability References to guide your analysis.\n"
        "Output findings strictly in JSON format matching this schema:\n"
        "{\n"
        "  \"alerts\": [\n"
        "    {\n"
        "      \"line\": <integer line number in the target file where vulnerability exists>,\n"
        "      \"severity\": \"<CRITICAL or WARNING>\",\n"
        "      \"warning\": \"<detailed inline explanation of vulnerability and risk>\",\n"
        "      \"needs_refactor\": <boolean flag: true if it requires code rewrite/refactoring, false if warning only>\n"
        "    }\n"
        "  ]\n"
        "}\n"
        "If there are no alerts, return {\"alerts\": []}.\n"
        "Do not include any conversational explanation outside the JSON."
    )

    user_prompt = f"Filename: {filename}\nCode Hunk:\n{hunk_text}\n\n{rag_context}"
    try:
        response_text = llm.query_llm(system_prompt, user_prompt)
        result = llm.parse_json_safely(response_text)
        alerts = result.get("alerts", [])
        for a in alerts:
            a["file"] = filename
        return alerts
    except Exception as e:
        print(f"[Security Error] Failed on {filename}: {e}")
        return []

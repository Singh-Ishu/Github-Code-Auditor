from ..utils import llm

def run_linter_agent(filename: str, hunk_text: str) -> list:
    """Analyzes style violations on the modified hunk."""
    system_prompt = (
        "You are a strict code quality and linting agent.\n"
        "Your task is to analyze the modified lines and hunk context of a file.\n"
        "Check strictly for:\n"
        "1. Syntax adherence.\n"
        "2. Structural anti-patterns.\n"
        "3. Naming convention discrepancies.\n"
        "4. Performance inefficiencies.\n\n"
        "Maintain zero awareness of security risk vectors. Keep execution prompt focused and efficient.\n"
        "Output findings strictly in JSON format matching this schema:\n"
        "{\n"
        "  \"violations\": [\n"
        "    {\n"
        "      \"line\": <integer line number in the target file where violation is present>,\n"
        "      \"warning\": \"<detailed explanation of style warning>\",\n"
        "      \"needs_refactor\": <boolean flag: true if it requires code rewrite/refactoring, false if warning only>\n"
        "    }\n"
        "  ]\n"
        "}\n"
        "If there are no violations, return {\"violations\": []}.\n"
        "Do not include any conversational explanation outside the JSON."
    )

    user_prompt = f"Filename: {filename}\nCode Hunk:\n{hunk_text}"
    print(f"\n[Linter Agent] Analyzing file: {filename}")
    try:
        response_text = llm.query_llm(system_prompt, user_prompt)
        print(f"[Linter Agent] Raw LLM Response for {filename}:\n{response_text}\n" + "-"*50)
        result = llm.parse_json_safely(response_text)
        violations = result.get("violations", [])
        print(f"[Linter Agent] Parsed {len(violations)} violations for {filename}")
        for v in violations:
            v["file"] = filename
        return violations
    except Exception as e:
        print(f"[Linter Error] Failed on {filename}: {e}")
        return []

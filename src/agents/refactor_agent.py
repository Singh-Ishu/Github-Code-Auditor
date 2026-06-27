import os
import sys
import json
import tempfile
import subprocess
from ..utils import llm
from ..utils.parser import fetch_file_content_from_github

def check_syntax_sandbox(filename: str, proposed_code: str) -> tuple[bool, str]:
    """
    Deploys code to a local static analysis sandbox to check syntax.
    Returns (is_valid, error_msg).
    """
    ext = os.path.splitext(filename)[1].lower()
    
    # Ensure temporary sandbox folder exists inside the workspace (two levels up from src/agents)
    sandbox_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "temp_sandbox"))
    os.makedirs(sandbox_dir, exist_ok=True)
    
    if ext == ".py":
        temp_file = tempfile.NamedTemporaryFile(suffix=".py", dir=sandbox_dir, delete=False)
        temp_path = temp_file.name
        try:
            temp_file.write(proposed_code.encode("utf-8"))
            temp_file.close()
            
            result = subprocess.run(
                [sys.executable, "-m", "py_compile", temp_path],
                capture_output=True,
                text=True
            )
            if result.returncode != 0:
                err_msg = result.stderr.replace(temp_path, filename)
                return False, err_msg
            return True, ""
        finally:
            if os.path.exists(temp_path):
                os.remove(temp_path)
    elif ext == ".json":
        try:
            json.loads(proposed_code)
            return True, ""
        except Exception as e:
            return False, f"JSONDecodeError: {e}"
    else:
        return True, ""

def apply_refactor_patch(original_content: str, start_line: int, end_line: int, suggested_code: str) -> str:
    """Replaces a range of lines (1-indexed, inclusive) with the suggested code."""
    lines = original_content.splitlines()
    start_idx = max(0, start_line - 1)
    end_idx = max(0, end_line)
    
    prefix = lines[:start_idx]
    suffix = lines[end_idx:]
    
    patched_lines = prefix + suggested_code.splitlines() + suffix
    return "\n".join(patched_lines)

def run_refactor_agent(repo_name: str, commit_sha: str, filename: str, hunk: dict, issues: list) -> list:
    """
    Drafts refactoring code suggestions, compiles them in a sandbox,
    and reflects on error logs up to 3 times.
    """
    original_hunk_text = ""
    for type_char, line_no, content in hunk["lines"]:
        prefix = type_char if type_char != " " else " "
        original_hunk_text += f"{prefix}{content}\n"

    original_full_content = fetch_file_content_from_github(repo_name, commit_sha, filename)

    system_prompt = (
        "You are a code refactoring agent.\n"
        "Your task is to propose clean, syntactically correct code fixes for a set of reported style violations and security alerts in a specific code hunk of a file.\n\n"
        "Input:\n"
        "- Original Git hunk text (where lines starting with '+' are additions, '-' are deletions, and ' ' are context).\n"
        "- List of issues/alerts indicating lines containing violations.\n\n"
        "Output findings strictly in JSON format matching this schema:\n"
        "{\n"
        "  \"refactors\": [\n"
        "    {\n"
        "      \"start_line\": <integer line number in the modified file where replacement starts>,\n"
        "      \"end_line\": <integer line number in the modified file where replacement ends>,\n"
        "      \"suggested_code\": \"<complete code block to replace the original lines in this range>\"\n"
        "    }\n"
        "  ]\n"
        "}\n"
        "Make sure to replace precisely the lines containing the bugs or style issues. Keep code clean and efficient.\n"
        "Do not include any conversational explanation outside the JSON."
    )

    issues_summary = json.dumps(issues, indent=2)
    user_prompt = f"Filename: {filename}\nOriginal Hunk:\n{original_hunk_text}\n\nReported Issues:\n{issues_summary}"

    retries = 3
    for attempt in range(retries):
        print(f"\n[Refactor Agent] Running attempt {attempt+1}/{retries} for file: {filename}")
        try:
            response_text = llm.query_llm(system_prompt, user_prompt)
            print(f"[Refactor Agent] Raw LLM Response for {filename} (Attempt {attempt+1}):\n{response_text}\n" + "-"*50)
            result = llm.parse_json_safely(response_text)
            refactors = result.get("refactors", [])
            print(f"[Refactor Agent] Parsed {len(refactors)} refactoring blocks")
            
            if not refactors:
                return []

            all_valid = True
            failed_error = ""
            
            for ref in refactors:
                start_line = ref["start_line"]
                end_line = ref["end_line"]
                suggested_code = ref["suggested_code"]
                print(f"[Refactor Agent] Verifying block range: lines {start_line}-{end_line}")
                
                if not isinstance(start_line, int) or not isinstance(end_line, int):
                    all_valid = False
                    failed_error = "start_line and end_line must be integers."
                    break

                if original_full_content:
                    patched = apply_refactor_patch(original_full_content, start_line, end_line, suggested_code)
                    valid, err = check_syntax_sandbox(filename, patched)
                    if not valid:
                        all_valid = False
                        failed_error = err
                        break
                else:
                    valid, err = check_syntax_sandbox(filename, suggested_code)
                    if not valid:
                        all_valid = False
                        failed_error = err
                        break

            if all_valid:
                print(f"[Refactor Success] Refactor patches compiled successfully for {filename} on attempt {attempt+1}")
                return refactors
            else:
                print(f"[Refactor Sandbox Fail] Attempt {attempt+1} failed with error:\n{failed_error}")
                system_prompt = (
                    "You are a code refactoring agent inside a compilation reflection loop.\n"
                    "You previously suggested a refactoring patch, but when we tried to compile it, the compiler returned an error.\n"
                    "Your task is to fix the suggested patch to resolve the compilation error.\n"
                    "Maintain the exact JSON response schema:\n"
                    "{\n"
                    "  \"refactors\": [\n"
                    "    {\n"
                    "      \"start_line\": <integer line number>,\n"
                    "      \"end_line\": <integer line number>,\n"
                    "      \"suggested_code\": \"<corrected code block>\"\n"
                    "    }\n"
                    "  ]\n"
                    "}"
                )
                user_prompt += f"\n\n--- Reflection Loop: Attempt {attempt+1} Failed ---\nPrevious Suggested Refactors:\n{json.dumps(refactors)}\nCompiler Error output:\n{failed_error}\nPlease resolve this error and return valid code."

        except Exception as e:
            print(f"[Refactor Error] Attempt {attempt+1} failed with exception: {e}")
            
    return []

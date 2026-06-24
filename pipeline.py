import os
import re
import sys
import json
import httpx
import tempfile
import subprocess
from concurrent.futures import ThreadPoolExecutor
from dotenv import load_dotenv
from vdb import VulnerabilityDB

# Load environment
env_path = os.path.join(os.path.dirname(__file__), ".env")
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

GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
if not GITHUB_TOKEN:
    if os.path.exists(env_path):
        with open(env_path, "r") as f:
            for line in f:
                if "GITHUB_TOKEN" in line:
                    parts = line.split("=", 1)
                    GITHUB_TOKEN = parts[1].strip().strip('"').strip("'")
                    break

# Initialize vulnerability DB
vuln_db = VulnerabilityDB()

def parse_git_diff(raw_diff: str) -> dict:
    """
    Parses a raw unified git diff.
    Returns structured data grouped by filename:
    {
      "filename": {
         "added_lines": [{"line": line_no, "content": text}],
         "hunks": [{
             "start_line": int,
             "lines": [ (type, line_no, content) ]
         }]
      }
    }
    """
    files = {}
    current_file = None
    current_new_line = 0
    current_hunk = None

    lines = raw_diff.splitlines()
    for line in lines:
        if line.startswith("diff --git"):
            parts = line.split(" ")
            target_part = parts[-1]
            if target_part.startswith("b/"):
                current_file = target_part[2:]
            else:
                current_file = target_part
            files[current_file] = {"added_lines": [], "hunks": []}
            current_hunk = None
            continue

        if current_file is None:
            continue

        if line.startswith("---") or line.startswith("+++") or line.startswith("index "):
            continue

        if line.startswith("@@"):
            # Parse hunk header: @@ -old_start,old_len +new_start,new_len @@
            match = re.match(r'^@@\s+-\d+(?:,\d+)?\s+\+(\d+)(?:,(\d+))?\s+@@', line)
            if match:
                new_start = int(match.group(1))
                current_new_line = new_start
                current_hunk = {
                    "start_line": new_start,
                    "lines": []
                }
                files[current_file]["hunks"].append(current_hunk)
            continue

        if current_hunk is not None:
            if line.startswith("+"):
                content = line[1:]
                files[current_file]["added_lines"].append({
                    "line": current_new_line,
                    "content": content
                })
                current_hunk["lines"].append(("+", current_new_line, content))
                current_new_line += 1
            elif line.startswith("-"):
                content = line[1:]
                current_hunk["lines"].append(("-", None, content))
            else:
                content = line[1:] if line.startswith(" ") else line
                current_hunk["lines"].append((" ", current_new_line, content))
                current_new_line += 1

    return files

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
    
    # Remove standard json tags if they remain
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

# ----------------- Wave 2: Linter Agent -----------------

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
    try:
        response_text = query_llm(system_prompt, user_prompt)
        result = parse_json_safely(response_text)
        violations = result.get("violations", [])
        # Add filename to each violation
        for v in violations:
            v["file"] = filename
        return violations
    except Exception as e:
        print(f"[Linter Error] Failed on {filename}: {e}")
        return []

# ----------------- Wave 2: Security Agent -----------------

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
        response_text = query_llm(system_prompt, user_prompt)
        result = parse_json_safely(response_text)
        alerts = result.get("alerts", [])
        for a in alerts:
            a["file"] = filename
        return alerts
    except Exception as e:
        print(f"[Security Error] Failed on {filename}: {e}")
        return []

# ----------------- Wave 3: Refactor Agent & Sandbox Reflection -----------------

def check_syntax_sandbox(filename: str, proposed_code: str) -> tuple[bool, str]:
    """
    Deploys code to a local static analysis sandbox to check syntax.
    Returns (is_valid, error_msg).
    """
    ext = os.path.splitext(filename)[1].lower()
    
    # Ensure temporary sandbox folder exists inside the workspace
    sandbox_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "temp_sandbox"))
    os.makedirs(sandbox_dir, exist_ok=True)
    
    if ext == ".py":
        temp_file = tempfile.NamedTemporaryFile(suffix=".py", dir=sandbox_dir, delete=False)
        temp_path = temp_file.name
        try:
            temp_file.write(proposed_code.encode("utf-8"))
            temp_file.close()
            
            # Run py_compile compilation check
            result = subprocess.run(
                [sys.executable, "-m", "py_compile", temp_path],
                capture_output=True,
                text=True
            )
            if result.returncode != 0:
                # Compile error, clean up absolute path references to avoid leaking info
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
        # Default fallback: check compile using build-in Python compile for .py files or assume pass
        return True, ""

def fetch_file_content_from_github(repo_name: str, commit_sha: str, path: str) -> str:
    """Attempts to fetch the entire original file contents from GitHub."""
    if not GITHUB_TOKEN:
        return ""
    url = f"https://api.github.com/repos/{repo_name}/contents/{path}?ref={commit_sha}"
    headers = {
        "Authorization": f"Bearer {GITHUB_TOKEN}",
        "Accept": "application/vnd.github.v3.raw", 
        "X-GitHub-Api-Version": "2022-11-28"
    }
    try:
        with httpx.Client() as client:
            response = client.get(url, headers=headers)
            if response.status_code == 200:
                return response.text
    except Exception as e:
        print(f"Error fetching file {path} from GitHub: {e}")
    return ""

def apply_refactor_patch(original_content: str, start_line: int, end_line: int, suggested_code: str) -> str:
    """Replaces a range of lines (1-indexed, inclusive) with the suggested code."""
    lines = original_content.splitlines()
    # 1-indexed adjust
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

    # Fetch entire original file to build complete patched content for sandbox testing
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
        try:
            response_text = query_llm(system_prompt, user_prompt)
            result = parse_json_safely(response_text)
            refactors = result.get("refactors", [])
            
            if not refactors:
                return []

            # Perform verification on each refactor block
            all_valid = True
            failed_error = ""
            
            for ref in refactors:
                start_line = ref["start_line"]
                end_line = ref["end_line"]
                suggested_code = ref["suggested_code"]
                
                # Verify that start_line and end_line are valid integers
                if not isinstance(start_line, int) or not isinstance(end_line, int):
                    all_valid = False
                    failed_error = "start_line and end_line must be integers."
                    break

                # If we have the full file, let's patch it and check syntax in the sandbox
                if original_full_content:
                    patched = apply_refactor_patch(original_full_content, start_line, end_line, suggested_code)
                    valid, err = check_syntax_sandbox(filename, patched)
                    if not valid:
                        all_valid = False
                        failed_error = err
                        break
                else:
                    # Fallback sandbox check: compile the snippet itself
                    valid, err = check_syntax_sandbox(filename, suggested_code)
                    if not valid:
                        all_valid = False
                        failed_error = err
                        break

            if all_valid:
                print(f"[Refactor Success] Refactor patches compiled successfully for {filename} on attempt {attempt+1}")
                return refactors
            else:
                print(f"[Refactor Sandbox Fail] Attempt {attempt+1} failed with error: {failed_error}")
                # Update prompts to reflect compilation error (Reflection Loop)
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

# ----------------- Wave 4: Post-Processor & Fan-In -----------------

def submit_github_comments(repo_name: str, pr_number: int, commit_sha: str, comments: list) -> bool:
    """Submits a single batch PR review containing all comments."""
    if not GITHUB_TOKEN:
        print("[GitHub API Error] GITHUB_TOKEN not set. Skipping submission.")
        return False

    url = f"https://api.github.com/repos/{repo_name}/pulls/{pr_number}/reviews"
    headers = {
        "Authorization": f"Bearer {GITHUB_TOKEN}",
        "Accept": "application/vnd.github.v3+json",
        "X-GitHub-Api-Version": "2022-11-28"
    }

    # Deduplicate comments on the same file and line/range to keep review clean
    seen = set()
    unique_comments = []
    for c in comments:
        # Create a key representing path + line + body
        key = (c["path"], c.get("line"), c.get("start_line"), c["body"])
        if key not in seen:
            seen.add(key)
            unique_comments.append(c)

    if not unique_comments:
        print("[Post-Processor] No comments/suggestions generated for this PR.")
        return True

    payload = {
        "commit_id": commit_sha,
        "event": "COMMENT",
        "body": "**GitHub Code Auditor Bot**\nCompleted code analysis waves. Inline reviews and suggestions have been published.",
        "comments": unique_comments
    }

    print(f"[Post-Processor] Posting batch review with {len(unique_comments)} comments to {repo_name} PR #{pr_number}")
    
    with httpx.Client() as client:
        response = client.post(url, headers=headers, json=payload)
        if response.status_code in (200, 201):
            print("[Post-Processor] GitHub batch review submitted successfully!")
            return True
        else:
            print(f"[GitHub API Error] Failed to submit review ({response.status_code}): {response.text}")
            return False

# ----------------- Main Pipeline Orchestrator -----------------

def run_agent_pipeline(repo_name: str, pr_number: int, commit_sha: str, raw_diff: str):
    """Orchestrates the entire Router-Worker and Reflection Loop pipeline."""
    print(f"\n=== Wave 1: Parsing Git Diff ===")
    parsed_files = parse_git_diff(raw_diff)
    print(f"Parsed {len(parsed_files)} modified files.")

    # We will accumulate all alerts and style violations to run parallel checks
    all_violations = []
    all_alerts = []

    # Map file name and hunks to their issues for Wave 3 refactoring
    # Struct: { filename: { hunk_index: [ issues ] } }
    file_hunk_issues = {}

    print(f"\n=== Wave 2: Parallel Analysis ===")
    
    # We use ThreadPoolExecutor to run Linter and Security Agents concurrently
    with ThreadPoolExecutor(max_workers=8) as executor:
        lint_futures = []
        sec_futures = []
        
        # Keep track of which future corresponds to which file and hunk
        hunk_references = []

        for filename, file_data in parsed_files.items():
            file_hunk_issues[filename] = {}
            for hunk_idx, hunk in enumerate(file_data["hunks"]):
                file_hunk_issues[filename][hunk_idx] = []
                
                # Build representation of hunk code context
                hunk_text = ""
                for type_char, line_no, content in hunk["lines"]:
                    prefix = type_char if type_char != " " else " "
                    hunk_text += f"{prefix}{content}\n"

                # Schedule concurrent runs
                lint_futures.append(executor.submit(run_linter_agent, filename, hunk_text))
                sec_futures.append(executor.submit(run_security_agent, filename, hunk_text))
                hunk_references.append((filename, hunk_idx, hunk))

        # Retrieve results
        for idx, (filename, hunk_idx, hunk) in enumerate(hunk_references):
            violations = lint_futures[idx].result()
            alerts = sec_futures[idx].result()

            all_violations.extend(violations)
            all_alerts.extend(alerts)

            # Associate issues with the correct file hunk
            file_hunk_issues[filename][hunk_idx].extend(violations)
            file_hunk_issues[filename][hunk_idx].extend(alerts)

    print(f"Wave 2 complete: Found {len(all_violations)} lint violations and {len(all_alerts)} security alerts.")

    # Filter out issues that request refactoring
    refactored_comments = []
    non_refactored_issues = []

    print(f"\n=== Wave 3: Refactoring & Sandbox Reflection ===")
    
    for filename, hunks_dict in file_hunk_issues.items():
        for hunk_idx, issues in enumerate(hunks_dict.values()):
            # Check if any issue requires refactoring
            needs_refactor = any(issue.get("needs_refactor") is True for issue in issues)
            
            if needs_refactor:
                hunk = parsed_files[filename]["hunks"][hunk_idx]
                # Run the refactor agent (runs compilation reflection internally)
                refactors = run_refactor_agent(repo_name, commit_sha, filename, hunk, issues)
                
                for ref in refactors:
                    start_line = ref["start_line"]
                    end_line = ref["end_line"]
                    suggested_code = ref["suggested_code"]
                    
                    # Construct GitHub code suggestion body
                    explanation = "\n".join([f"- {issue.get('warning')}" for issue in issues])
                    body = (
                        f"### 🤖 Refactoring Suggestion\n"
                        f"{explanation}\n\n"
                        f"```suggestion\n"
                        f"{suggested_code}\n"
                        f"```"
                    )
                    
                    comment = {
                        "path": filename,
                        "body": body,
                        "side": "RIGHT"
                    }
                    if start_line == end_line:
                        comment["line"] = start_line
                    else:
                        comment["start_line"] = start_line
                        comment["line"] = end_line
                        comment["start_side"] = "RIGHT"
                        
                    refactored_comments.append(comment)
            else:
                # Accumulate issues that do not require code rewrite (warnings/info only)
                non_refactored_issues.extend(issues)

    print(f"Wave 3 complete: Generated {len(refactored_comments)} refactored suggestion comments.")

    # ----------------- Wave 4: Fan-in & Submission -----------------
    print(f"\n=== Wave 4: Post-Processor (Fan-in) ===")
    
    # Process issues that did not undergo inline refactor
    comments_payload = list(refactored_comments)

    for issue in non_refactored_issues:
        line = issue.get("line")
        warning = issue.get("warning")
        severity = issue.get("severity") # Present for security alerts
        
        if severity:
            body = f"🛡️ **Security Alert ({severity})**\n{warning}"
        else:
            body = f"📝 **Style Warning**\n{warning}"
            
        comments_payload.append({
            "path": issue["file"],
            "line": line,
            "body": body,
            "side": "RIGHT"
        })

    # Submit to GitHub
    success = submit_github_comments(repo_name, pr_number, commit_sha, comments_payload)
    return success

from concurrent.futures import ThreadPoolExecutor

from .utils.parser import parse_git_diff
from .agents.linter_agent import run_linter_agent
from .agents.security_agent import run_security_agent
from .agents.refactor_agent import run_refactor_agent
from .utils.post_processor import submit_github_comments

def run_agent_pipeline(repo_name: str, pr_number: int, commit_sha: str, raw_diff: str):
    """Orchestrates the entire Router-Worker and Reflection Loop pipeline."""
    print(f"\n=== Wave 1: Parsing Git Diff ===")
    parsed_files = parse_git_diff(raw_diff)
    print(f"Parsed {len(parsed_files)} modified files.")

    all_violations = []
    all_alerts = []
    file_hunk_issues = {}

    print(f"\n=== Wave 2: Parallel Analysis ===")
    
    with ThreadPoolExecutor(max_workers=8) as executor:
        lint_futures = []
        sec_futures = []
        hunk_references = []

        for filename, file_data in parsed_files.items():
            file_hunk_issues[filename] = {}
            for hunk_idx, hunk in enumerate(file_data["hunks"]):
                file_hunk_issues[filename][hunk_idx] = []
                
                hunk_text = ""
                for type_char, line_no, content in hunk["lines"]:
                    prefix = type_char if type_char != " " else " "
                    hunk_text += f"{prefix}{content}\n"

                lint_futures.append(executor.submit(run_linter_agent, filename, hunk_text))
                sec_futures.append(executor.submit(run_security_agent, filename, hunk_text))
                hunk_references.append((filename, hunk_idx, hunk))

        for idx, (filename, hunk_idx, hunk) in enumerate(hunk_references):
            violations = lint_futures[idx].result()
            alerts = sec_futures[idx].result()

            all_violations.extend(violations)
            all_alerts.extend(alerts)

            file_hunk_issues[filename][hunk_idx].extend(violations)
            file_hunk_issues[filename][hunk_idx].extend(alerts)

    print(f"Wave 2 complete: Found {len(all_violations)} lint violations and {len(all_alerts)} security alerts.")

    refactored_comments = []
    non_refactored_issues = []

    print(f"\n=== Wave 3: Refactoring & Sandbox Reflection ===")
    
    for filename, hunks_dict in file_hunk_issues.items():
        for hunk_idx, issues in enumerate(hunks_dict.values()):
            needs_refactor = any(issue.get("needs_refactor") is True for issue in issues)
            
            if needs_refactor:
                hunk = parsed_files[filename]["hunks"][hunk_idx]
                refactors = run_refactor_agent(repo_name, commit_sha, filename, hunk, issues)
                
                for ref in refactors:
                    start_line = ref["start_line"]
                    end_line = ref["end_line"]
                    suggested_code = ref["suggested_code"]
                    
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
                non_refactored_issues.extend(issues)

    print(f"Wave 3 complete: Generated {len(refactored_comments)} refactored suggestion comments.")

    print(f"\n=== Wave 4: Post-Processor (Fan-in) ===")
    
    comments_payload = list(refactored_comments)

    for issue in non_refactored_issues:
        line = issue.get("line")
        warning = issue.get("warning")
        severity = issue.get("severity")
        
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

    success = submit_github_comments(repo_name, pr_number, commit_sha, comments_payload)
    return success

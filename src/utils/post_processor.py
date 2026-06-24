import os
import httpx
from dotenv import load_dotenv

# Look for .env two directories up (project root)
env_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".env"))
load_dotenv(dotenv_path=env_path)

GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
if not GITHUB_TOKEN:
    if os.path.exists(env_path):
        with open(env_path, "r") as f:
            for line in f:
                if "GITHUB_TOKEN" in line:
                    parts = line.split("=", 1)
                    GITHUB_TOKEN = parts[1].strip().strip('"').strip("'")
                    break

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

    seen = set()
    unique_comments = []
    for c in comments:
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
        "body": "🤖 **GitHub Code Auditor Bot**\nCompleted code analysis waves. Inline reviews and suggestions have been published.",
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

import os
import sys
import httpx
from dotenv import load_dotenv

# Add src to python path so we can import from src
sys.path.append(os.path.join(os.path.dirname(__file__), "src"))

from src.pipeline import run_agent_pipeline

env_path = os.path.join(os.path.dirname(__file__), ".env")
load_dotenv(dotenv_path=env_path)

GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
if not GITHUB_TOKEN:
    with open(env_path, "r") as f:
        for line in f:
            if "GITHUB_TOKEN" in line:
                parts = line.split("=", 1)
                GITHUB_TOKEN = parts[1].strip().strip('"').strip("'")
                break

def fetch_pr_diff(repo_name: str, pr_number: int) -> str:
    """Fetches the raw git diff text for a specific Pull Request."""
    url = f"https://api.github.com/repos/{repo_name}/pulls/{pr_number}"
    headers = {
        "Authorization": f"Bearer {GITHUB_TOKEN}",
        "Accept": "application/vnd.github.v3.diff", 
        "X-GitHub-Api-Version": "2022-11-28"
    }
    with httpx.Client() as client:
        response = client.get(url, headers=headers)
        if response.status_code != 200:
            raise Exception(f"Failed to fetch diff from GitHub: {response.status_code} - {response.text}")
        return response.text

def fetch_pr_head_sha(repo_name: str, pr_number: int) -> str:
    """Fetches the head commit SHA for a specific Pull Request."""
    url = f"https://api.github.com/repos/{repo_name}/pulls/{pr_number}"
    headers = {
        "Authorization": f"Bearer {GITHUB_TOKEN}",
        "Accept": "application/vnd.github.v3+json", 
        "X-GitHub-Api-Version": "2022-11-28"
    }
    with httpx.Client() as client:
        response = client.get(url, headers=headers)
        if response.status_code != 200:
            raise Exception(f"Failed to fetch PR details from GitHub: {response.status_code} - {response.text}")
        return response.json()["head"]["sha"]

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python trigger_audit.py <PR_NUMBER> [REPO_NAME]")
        sys.exit(1)

    pr_number = int(sys.argv[1])
    repo_name = sys.argv[2] if len(sys.argv) > 2 else "Singh-Ishu/Github-Code-Auditor"

    print(f"Starting audit trigger for PR #{pr_number} in {repo_name}...")
    try:
        # 1. Fetch diff
        raw_diff = fetch_pr_diff(repo_name, pr_number)
        print(f"[Success] Retrieved diff ({len(raw_diff)} characters)")

        # 2. Fetch head commit SHA
        commit_sha = fetch_pr_head_sha(repo_name, pr_number)
        print(f"[Success] Retrieved Head SHA: {commit_sha}")

        # 3. Run Pipeline Orchestrator
        run_agent_pipeline(repo_name, pr_number, commit_sha, raw_diff)
        print("\n[Success] PR Audit Pipeline completed successfully!")

    except Exception as e:
        print(f"\n[Error] Audit failed: {e}")

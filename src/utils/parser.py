import re
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

def parse_git_diff(raw_diff: str) -> dict:
    """
    Parses a raw unified git diff.
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

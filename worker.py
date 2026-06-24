import os
import json
import time
import redis
import httpx
from dotenv import load_dotenv

load_dotenv()

redis_client = redis.Redis(host='localhost', port=6379, db=0, decode_responses=True)
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")

print("Worker is running. Waiting for commits...")

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

while True:
    queue_name, data = redis_client.blpop("commit_queue", timeout=0)
    job = json.loads(data)
    
    repo_name = job['repo_name']
    pr_number = job['pr_number']
    
    print(f"\n[Processing] PR #{pr_number} in {repo_name}")
    
    try:
        # Fetch only the code changes
        raw_diff = fetch_pr_diff(repo_name, pr_number)
        
        print(f"[Success] Retrieved diff ({len(raw_diff)} characters)")
        
        # Pass to Orchestrator Agent
        from src.pipeline import run_agent_pipeline
        commit_sha = job.get('commit_sha', 'head')
        run_agent_pipeline(repo_name, pr_number, commit_sha, raw_diff)
        
    except Exception as e:
        print(f"[Error] Failed to process job: {e}")
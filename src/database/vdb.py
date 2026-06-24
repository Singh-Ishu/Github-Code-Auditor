import json
import os
import re

DB_PATH = os.path.join(os.path.dirname(__file__), "vulnerabilities_db.json")

class VulnerabilityDB:
    def __init__(self, db_path=DB_PATH):
        self.db_path = db_path
        self.vulnerabilities = []
        self.load_db()

    def load_db(self):
        if os.path.exists(self.db_path):
            try:
                with open(self.db_path, "r") as f:
                    self.vulnerabilities = json.load(f)
            except Exception as e:
                print(f"Error loading vulnerability database: {e}")
                self.vulnerabilities = []
        else:
            print(f"Vulnerability database file not found at {self.db_path}")
            self.vulnerabilities = []

    def tokenize(self, text):
        tokens = re.findall(r'[a-zA-Z_0-9\-\.\*\/]+', text.lower())
        return set(tokens)

    def search(self, code_block: str, top_k: int = 2) -> list:
        if not self.vulnerabilities:
            return []

        code_tokens = self.tokenize(code_block)
        scored_vulnerabilities = []

        for vuln in self.vulnerabilities:
            score = 0
            for keyword in vuln.get("matching_keywords", []):
                k_lower = keyword.lower()
                if k_lower in code_tokens:
                    score += 2.0
                elif k_lower in code_block.lower():
                    score += 1.0

            example_flaw = vuln.get("example_flaw", "").lower()
            flaw_tokens = self.tokenize(example_flaw)
            overlap = code_tokens.intersection(flaw_tokens)
            if overlap:
                meaningful_overlap = {t for t in overlap if len(t) > 3 and t not in {"from", "import", "with", "open", "read", "users"}}
                score += len(meaningful_overlap) * 0.5

            if score > 0:
                scored_vulnerabilities.append((score, vuln))

        scored_vulnerabilities.sort(key=lambda x: x[0], reverse=True)
        return [vuln for score, vuln in scored_vulnerabilities[:top_k]]

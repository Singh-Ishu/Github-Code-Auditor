import unittest
from unittest.mock import patch, MagicMock
import json
import os

from src.pipeline import run_agent_pipeline
from src.utils.parser import parse_git_diff
from src.agents.refactor_agent import check_syntax_sandbox
from src.database.vdb import VulnerabilityDB

class TestAgentPipeline(unittest.TestCase):

    def test_parse_git_diff(self):
        sample_diff = (
            "diff --git a/test.py b/test.py\n"
            "index e69de29..1234567 100644\n"
            "--- a/test.py\n"
            "+++ b/test.py\n"
            "@@ -1,4 +1,6 @@\n"
            " import os\n"
            "+import sys\n"
            "+\n"
            " def hello():\n"
            "-    pass\n"
            "+    print(\"Hello World\")\n"
        )
        parsed = parse_git_diff(sample_diff)
        self.assertIn("test.py", parsed)
        file_data = parsed["test.py"]
        
        # Verify added lines
        added_lines = file_data["added_lines"]
        self.assertEqual(len(added_lines), 3)
        self.assertEqual(added_lines[0], {"line": 2, "content": "import sys"})
        self.assertEqual(added_lines[1], {"line": 3, "content": ""})
        self.assertEqual(added_lines[2], {"line": 5, "content": "    print(\"Hello World\")"})

        # Verify hunk structure
        hunks = file_data["hunks"]
        self.assertEqual(len(hunks), 1)
        self.assertEqual(hunks[0]["start_line"], 1)
        self.assertEqual(len(hunks[0]["lines"]), 6)

    def test_vulnerability_db_search(self):
        db = VulnerabilityDB()
        
        # Test SQL Injection match
        sql_code = "query = 'SELECT * FROM users WHERE name = ' + user_input\ncursor.execute(query)"
        matches = db.search(sql_code, top_k=1)
        self.assertTrue(len(matches) > 0)
        self.assertEqual(matches[0]["id"], "sql_injection")

        # Test Hardcoded Secret match
        secrets_code = "API_KEY = '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'"
        matches_sec = db.search(secrets_code, top_k=1)
        self.assertTrue(len(matches_sec) > 0)
        self.assertEqual(matches_sec[0]["id"], "hardcoded_secrets")

    def test_check_syntax_sandbox(self):
        # Valid python code
        valid_code = "def test():\n    return 42\n"
        valid, err = check_syntax_sandbox("test.py", valid_code)
        self.assertTrue(valid)
        self.assertEqual(err, "")

        # Invalid python code
        invalid_code = "def test():::\n    return 42"
        valid, err = check_syntax_sandbox("test.py", invalid_code)
        self.assertFalse(valid)
        self.assertIn("invalid syntax", err.lower() or "expected" in err.lower())

    @patch("src.utils.llm.query_llm")
    @patch("src.pipeline.submit_github_comments")
    @patch("src.agents.refactor_agent.fetch_file_content_from_github")
    def test_run_agent_pipeline_e2e(self, mock_fetch_file, mock_submit_github, mock_query_llm):
        mock_fetch_file.return_value = "def hello():\n    pass\n"
        
        # Mock LLM outputs
        mock_query_llm.side_effect = [
            # Linter output
            json.dumps({
                "violations": [
                    {"line": 2, "warning": "Avoid pass statement in functions", "needs_refactor": True}
                ]
            }),
            # Security output
            json.dumps({
                "alerts": []
            }),
            # Refactor output
            json.dumps({
                "refactors": [
                    {"start_line": 2, "end_line": 2, "suggested_code": "    print(\"Hello\")"}
                ]
            })
        ]

        mock_submit_github.return_value = True

        sample_diff = (
            "diff --git a/test.py b/test.py\n"
            "--- a/test.py\n"
            "+++ b/test.py\n"
            "@@ -1,2 +1,2 @@\n"
            " def hello():\n"
            "-    pass\n"
            "+    pass\n"
        )

        success = run_agent_pipeline("test-owner/test-repo", 1, "test_sha", sample_diff)
        
        self.assertTrue(success)
        self.assertTrue(mock_submit_github.called)
        
        args, kwargs = mock_submit_github.call_args
        comments = args[3]
        self.assertEqual(len(comments), 1)
        self.assertEqual(comments[0]["path"], "test.py")
        self.assertIn("suggestion", str(comments[0]["body"]).lower())

if __name__ == "__main__":
    unittest.main()

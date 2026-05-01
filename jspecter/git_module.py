"""
JSPECTER Git Intelligence Module
Scans local git repositories for historical secrets and exposed endpoints.
"""

import os
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from .secrets_engine import SecretsEngine, SecretFinding
from .utils import Icon, CYAN, DIM, GREEN, RED, RESET, YELLOW, logger, truncate

try:
    import git
    GIT_AVAILABLE = True
except ImportError:
    GIT_AVAILABLE = False


@dataclass
class GitFinding:
    """A finding from git history analysis."""
    commit_hash: str
    commit_message: str
    author: str
    date: str
    file_path: str
    finding_type: str  # "secret" | "endpoint" | "config"
    details: str
    severity: str = "MEDIUM"


class GitIntelligence:
    """
    Scans git repositories for historical secrets and misconfigurations.
    Only works on local repositories. Does NOT push, pull, or modify.
    """

    def __init__(self, repo_path: str, verbose: bool = False) -> None:
        if not GIT_AVAILABLE:
            raise ImportError(
                "GitPython is required for git scanning: pip install gitpython"
            )
        self.repo_path = repo_path
        self.verbose = verbose
        self.secrets_engine = SecretsEngine(verbose=verbose)

    def _open_repo(self):
        """Open git repository safely."""
        try:
            return git.Repo(self.repo_path)
        except git.InvalidGitRepositoryError:
            raise ValueError(f"Not a valid git repository: {self.repo_path}")
        except Exception as e:
            raise ValueError(f"Cannot open repository: {e}")

    def _analyze_commit_diff(
        self, commit, parent
    ) -> List[SecretFinding]:
        """Analyze diff between two commits for secrets."""
        findings = []
        try:
            diffs = parent.diff(commit, create_patch=True)
            for diff in diffs:
                try:
                    patch = diff.diff.decode("utf-8", errors="replace")
                    # Only analyze added lines
                    added = "\n".join(
                        line[1:] for line in patch.splitlines()
                        if line.startswith("+") and not line.startswith("+++")
                    )
                    if added:
                        source = f"git:{commit.hexsha[:8]}:{diff.b_path or 'unknown'}"
                        found = self.secrets_engine.scan_content(added, source)
                        findings.extend(found)
                except Exception:
                    pass
        except Exception as e:
            logger.debug(f"Error diffing commit {commit.hexsha[:8]}: {e}")
        return findings

    def scan(self, max_commits: int = 200) -> List[GitFinding]:
        """
        Scan git history for secrets.

        Args:
            max_commits: maximum number of commits to scan

        Returns:
            List of GitFinding objects
        """
        print(f"  {Icon.INFO} Opening repository: {CYAN}{self.repo_path}{RESET}")
        repo = self._open_repo()

        findings: List[GitFinding] = []
        commits = list(repo.iter_commits("--all", max_count=max_commits))
        total = len(commits)

        print(f"  {Icon.INFO} Scanning {total} commits for historical secrets...")

        for i, commit in enumerate(commits):
            parents = commit.parents
            if not parents:
                # Root commit — check tree directly
                try:
                    for item in commit.tree.traverse():
                        if hasattr(item, "data_stream"):
                            try:
                                content = item.data_stream.read().decode("utf-8", errors="replace")
                                source = f"git:{commit.hexsha[:8]}:{item.path}"
                                secret_findings = self.secrets_engine.scan_content(content, source)
                                for sf in secret_findings:
                                    findings.append(GitFinding(
                                        commit_hash=commit.hexsha[:8],
                                        commit_message=commit.message.strip()[:80],
                                        author=str(commit.author),
                                        date=str(commit.authored_datetime),
                                        file_path=item.path,
                                        finding_type="secret",
                                        details=f"{sf.secret_type}: {sf.redacted_value()}",
                                        severity=sf.severity,
                                    ))
                            except Exception:
                                pass
                except Exception:
                    pass
            else:
                for parent in parents:
                    secret_findings = self._analyze_commit_diff(commit, parent)
                    for sf in secret_findings:
                        path = sf.source_js.split(":", 2)[-1] if ":" in sf.source_js else ""
                        findings.append(GitFinding(
                            commit_hash=commit.hexsha[:8],
                            commit_message=commit.message.strip()[:80],
                            author=str(commit.author),
                            date=str(commit.authored_datetime),
                            file_path=path,
                            finding_type="secret",
                            details=f"{sf.secret_type}: {sf.redacted_value()}",
                            severity=sf.severity,
                        ))

            if self.verbose and (i + 1) % 50 == 0:
                logger.debug(f"  Processed {i+1}/{total} commits...")

        # Also scan .env files in working tree
        for root, dirs, files in os.walk(self.repo_path):
            # Skip .git directory
            dirs[:] = [d for d in dirs if d != ".git"]
            for filename in files:
                if filename in (".env", ".env.local", ".env.production", ".env.staging"):
                    filepath = os.path.join(root, filename)
                    try:
                        with open(filepath, "r", errors="replace") as f:
                            content = f.read()
                        secret_findings = self.secrets_engine.scan_content(
                            content, filepath
                        )
                        for sf in secret_findings:
                            findings.append(GitFinding(
                                commit_hash="WORKING_TREE",
                                commit_message="(working tree — not committed)",
                                author="",
                                date="",
                                file_path=filepath,
                                finding_type="secret",
                                details=f"{sf.secret_type}: {sf.redacted_value()}",
                                severity=sf.severity,
                            ))
                    except Exception:
                        pass

        if findings:
            print(
                f"  {Icon.SECRET} {RED}Git scan found {len(findings)} issues "
                f"across {total} commits.{RESET}"
            )
        else:
            print(f"  {Icon.SUCCESS} {GREEN}No historical secrets found in git history.{RESET}")

        return findings

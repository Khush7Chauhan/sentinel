import re
from pathlib import Path
import yaml
from src.models import Finding, Severity

SHA_PATTERN = re.compile(r"^[0-9a-f]{40}$")

def audit_github_workflows(repo_path: Path) -> list[Finding]:
    """Inspects GitHub Actions workflow definitions against security rules W1-W5."""
    findings = []
    workflows_dir = repo_path / ".github" / "workflows"
    if not workflows_dir.exists():
        return findings

    for wf_file in workflows_dir.glob("*.y*ml"):
        try:
            raw_text = wf_file.read_text(encoding="utf-8")
            data = yaml.safe_load(raw_text)
            if not isinstance(data, dict):
                continue
        except Exception:
            continue

        rel_path = str(wf_file.relative_to(repo_path))
        triggers = data.get("on", data.get(True, []))
        has_pr_target = "pull_request_target" in triggers if isinstance(triggers, (list, dict, str)) else False

        # W5: permissions: write-all check
        permissions = data.get("permissions")
        if permissions == "write-all" or (isinstance(permissions, dict) and permissions.get("contents") == "write"):
            findings.append(Finding(
                id="L3-W5-PERMISSIONS",
                layer="L3",
                package=None,
                type="WORKFLOW_OVERLY_PERMISSIVE",
                severity=Severity.INFO,
                confidence=0.85,
                evidence={"file": rel_path},
                human_explanation="Workflow declares elevated 'write-all' permissions, violating the principle of least privilege.",
                mitigation="Restrict workflow permissions to read-only where possible.",
                points=0.0
            ))

        jobs = data.get("jobs", {})
        if not isinstance(jobs, dict):
            continue

        for job_name, job_data in jobs.items():
            if not isinstance(job_data, dict):
                continue

            # W4: Self-hosted runner reachable from pull_request
            runs_on = str(job_data.get("runs-on", ""))
            if "self-hosted" in runs_on and (has_pr_target or "pull_request" in str(triggers)):
                findings.append(Finding(
                    id=f"L3-W4-SELFHOSTED-{job_name}",
                    layer="L3",
                    package=None,
                    type="WORKFLOW_SELF_HOSTED_RUNNER",
                    severity=Severity.MEDIUM,
                    confidence=0.90,
                    evidence={"file": rel_path, "job": job_name},
                    human_explanation=f"Job '{job_name}' runs on a self-hosted runner and responds to pull requests, exposing host infrastructure to external untrusted code.",
                    mitigation="Isolate self-hosted runners in ephemeral environments or limit to internal branches.",
                    points=8.0
                ))

            steps = job_data.get("steps", [])
            if not isinstance(steps, list):
                continue

            for idx, step in enumerate(steps, start=1):
                if not isinstance(step, dict):
                    continue

                uses = step.get("uses", "")
                # W3: Action refs not pinned to full 40-character commit SHA
                if uses and not uses.startswith("./") and not uses.startswith("docker://"):
                    if "@" in uses:
                        action_name, ref = uses.split("@", 1)
                        if not SHA_PATTERN.match(ref):
                            findings.append(Finding(
                                id=f"L3-W3-UNPINNED-ACTION-{job_name}-{idx}",
                                layer="L3",
                                package=None,
                                type="WORKFLOW_UNPINNED_ACTION",
                                severity=Severity.MEDIUM,
                                confidence=0.95,
                                evidence={"file": rel_path, "action": uses},
                                human_explanation=f"Action '{uses}' uses a mutable tag (@{ref}) instead of an immutable commit SHA. Upstream tag rewrites can silently introduce malicious updates.",
                                mitigation=f"Pin '{uses}' to an exact 40-character SHA hash.",
                                points=8.0
                            ))

                # W1: pull_request_target + checkout of PR head
                with_params = step.get("with", {}) or {}
                ref_param = str(with_params.get("ref", ""))
                if has_pr_target and "actions/checkout" in uses:
                    if "github.event.pull_request.head" in ref_param:
                        findings.append(Finding(
                            id=f"L3-W1-PR-TARGET-CHECKOUT-{job_name}",
                            layer="L3",
                            package=None,
                            type="WORKFLOW_PWN_REQUEST_TARGET",
                            severity=Severity.CRITICAL,
                            confidence=0.98,
                            evidence={"file": rel_path, "step": step.get("name", uses)},
                            human_explanation="Combines 'pull_request_target' with checking out untrusted PR head code. Untrusted pull requests can execute malicious code in the context of repository secrets.",
                            mitigation="Do not check out pull request head code in 'pull_request_target' workflows.",
                            points=25.0
                        ))

                # W2: Script injection via github.event context in run:
                run_command = step.get("run", "")
                if run_command:
                    bad_contexts = re.findall(r"\$\{\{\s*github\.event\.(?:pull_request|issue|comment)\.(?:title|body|head|label)[^\}]*\}\}", run_command)
                    if bad_contexts:
                        findings.append(Finding(
                            id=f"L3-W2-SCRIPT-INJECTION-{job_name}-{idx}",
                            layer="L3",
                            package=None,
                            type="WORKFLOW_SCRIPT_INJECTION",
                            severity=Severity.HIGH,
                            confidence=0.90,
                            evidence={"file": rel_path, "expressions": bad_contexts},
                            human_explanation="Untrusted context expressions used directly in shell execution (`run:`), enabling shell script injection via attacker-controlled issue/PR text.",
                            mitigation="Assign the expression to an intermediate environment variable (`env:`) before consuming it in the shell.",
                            points=15.0
                        ))

    return findings
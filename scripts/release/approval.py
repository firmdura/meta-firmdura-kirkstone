#!/usr/bin/env python3
"""Fail closed if the human-controlled release environment is unprotected."""

import json
import os
import subprocess
import sys

from verify import REPOSITORY, InvalidRelease, require


ENVIRONMENT = "release-signing"


def check_policy(environment, branches):
    require(environment.get("name") == ENVIRONMENT, "wrong approval environment")
    reviewers = [rule for rule in environment.get("protection_rules", [])
                 if rule.get("type") == "required_reviewers"]
    require(len(reviewers) == 1, "required human reviewers are not configured")
    rule = reviewers[0]
    configured = rule.get("reviewers", [])
    require(configured and all(reviewer.get("type") == "User"
                              and reviewer.get("reviewer", {}).get("type") == "User"
                              for reviewer in configured), "explicit human reviewers are required")
    require(environment.get("deployment_branch_policy") == {
        "protected_branches": False, "custom_branch_policies": True,
    }, "environment must use an explicit main-only deployment policy")
    policies = branches.get("branch_policies", [])
    require(branches.get("total_count") == 1 and len(policies) == 1
            and policies[0].get("name") == "main" and policies[0].get("type") == "branch",
            "environment must allow only the main branch, not tags or wildcards")


def github_json(path):
    result = subprocess.run(
        ["gh", "api", f"repos/{REPOSITORY}/{path}"],
        check=True, capture_output=True, text=True)
    return json.loads(result.stdout)


def main():
    try:
        require(os.environ.get("GITHUB_REPOSITORY") == REPOSITORY, "wrong workflow repository")
        require(os.environ.get("GITHUB_REF") == "refs/heads/main", "workflow must run from main")
        require(os.environ.get("GITHUB_EVENT_NAME") == "workflow_dispatch",
                "only an explicit trusted dispatch can sign")
        path = f"environments/{ENVIRONMENT}"
        environment = github_json(path)
        check_policy(environment, github_json(f"{path}/deployment-branch-policies?per_page=100"))
    except (InvalidRelease, OSError, json.JSONDecodeError, subprocess.CalledProcessError) as error:
        print(f"release approval policy blocked: {error}", file=sys.stderr)
        return 1
    print("Human-review and main-only environment policy checked; approval is still required.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

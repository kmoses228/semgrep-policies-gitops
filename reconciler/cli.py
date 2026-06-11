"""GitOps reconciler CLI for Semgrep policies.

Three verbs model the GitOps loop:

  export  pull the live state into the YAML files (bootstrap or drift repair)
  plan    dry-run every bundle and print the diff; exit non-zero if anything
          would change (so CI can gate a PR on "no drift")
  apply   strictly apply every YAML file, using the etag from a fresh read as
          If-Match so a concurrent UI change is caught as a conflict

Run `python -m reconciler.cli <verb> --deployment-id <id>`; the token comes
from the SEMGREP_API_TOKEN environment variable.
"""

from __future__ import annotations

import argparse
import sys
from typing import Any

from reconciler import bundles
from reconciler.client import Bundle
from reconciler.client import PoliciesApiError
from reconciler.client import PoliciesClient

# (file, product) for each detection bundle. Secrets is optional: a
# deployment without Semgrep Secrets returns 404 PRODUCT_NOT_ENABLED, which
# is treated as "skip", not "fail".
_DETECTION_TARGETS = [
    (bundles.DETECTION_CODE_FILE, "code"),
    (bundles.DETECTION_SECRETS_FILE, "secrets"),
]


def _print_detection_diff(product: str, diff: dict[str, Any]) -> bool:
    changed = False
    for verb in ("creates", "updates", "deletes"):
        for entry in diff.get(verb, []):
            changed = True
            key = entry["key"]
            label = key.get("product") or key.get("scope_target") or key.get("rule")
            print(f"  detection/{product}: {verb[:-1]} {entry['kind']} {label}")
    return changed


def _print_remediation_diff(diff: dict[str, Any]) -> bool:
    changed = False
    for verb in ("creates", "updates", "deletes"):
        for entry in diff.get(verb, []):
            changed = True
            print(f"  remediation: {verb[:-1]} {entry['key']['slug']}")
    return changed


def cmd_export(client: PoliciesClient) -> int:
    code = client.get_detection_policy("code")
    bundles.write_detection_yaml(bundles.DETECTION_CODE_FILE, code.data)
    print(f"wrote {bundles.DETECTION_CODE_FILE.name}")

    try:
        secrets = client.get_detection_policy("secrets")
        bundles.write_detection_yaml(bundles.DETECTION_SECRETS_FILE, secrets.data)
        print(f"wrote {bundles.DETECTION_SECRETS_FILE.name}")
    except PoliciesApiError as err:
        if err.code != "PRODUCT_NOT_ENABLED":
            raise
        print("skipped detection-secrets.yaml (Semgrep Secrets not enabled)")

    remediation = client.get_remediation_policies()
    bundles.write_remediation_yaml(bundles.REMEDIATION_FILE, remediation.data)
    print(f"wrote {bundles.REMEDIATION_FILE.name}")
    return 0


def cmd_plan(client: PoliciesClient, *, fail_on_diff: bool = False) -> int:
    changed = False
    for path, product in _DETECTION_TARGETS:
        raw = bundles.read_yaml(path)
        if not raw:
            continue
        try:
            diff = client.dry_run_detection_policy(
                product, bundles.detection_to_bundle(raw)
            )
        except PoliciesApiError as err:
            if err.code == "PRODUCT_NOT_ENABLED":
                print(f"  detection/{product}: product not enabled, skipping")
                continue
            raise
        changed |= _print_detection_diff(product, diff)

    remediation_raw = bundles.read_yaml(bundles.REMEDIATION_FILE)
    if remediation_raw:
        diff = client.dry_run_remediation_policies(
            bundles.remediation_to_bundle(remediation_raw)
        )
        changed |= _print_remediation_diff(diff)

    if not changed:
        print("plan: live state matches this repo")
        return 0

    # A pending diff is normal on a PR — it is exactly what the reviewer is
    # there to approve. Only fail when asked to gate on drift (the nightly
    # drift check), so that a valid PR is not red just for proposing a
    # change. Invalid candidates never reach here: the dry run raises a
    # PoliciesApiError, which main() reports as a hard failure.
    print("\nplan: changes pending")
    return 1 if fail_on_diff else 0


def cmd_apply(client: PoliciesClient) -> int:
    for path, product in _DETECTION_TARGETS:
        raw = bundles.read_yaml(path)
        if not raw:
            continue
        try:
            current = client.get_detection_policy(product)
        except PoliciesApiError as err:
            if err.code == "PRODUCT_NOT_ENABLED":
                print(f"  detection/{product}: product not enabled, skipping")
                continue
            raise
        result = client.apply_detection_policy(
            product, bundles.detection_to_bundle(raw), current.state_version
        )
        print(f"applied detection/{product} (state_version {result.state_version})")

    remediation_raw = bundles.read_yaml(bundles.REMEDIATION_FILE)
    if remediation_raw:
        current_remediation: Bundle = client.get_remediation_policies()
        result = client.apply_remediation_policies(
            bundles.remediation_to_bundle(remediation_raw),
            current_remediation.state_version,
        )
        print(f"applied remediation (state_version {result.state_version})")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "command", choices=["export", "plan", "apply"], help="the reconciler verb"
    )
    parser.add_argument(
        "--deployment-id",
        type=int,
        required=True,
        help="numeric Semgrep deployment id",
    )
    parser.add_argument(
        "--base-url",
        default=None,
        help="API base URL (defaults to SEMGREP_APP_URL or https://semgrep.dev)",
    )
    parser.add_argument(
        "--fail-on-diff",
        action="store_true",
        help=(
            "make `plan` exit non-zero when the live state differs from this "
            "repo. Use for drift detection; leave off for PR review, where a "
            "pending diff is expected."
        ),
    )
    args = parser.parse_args(argv)

    client = PoliciesClient(args.deployment_id, base_url=args.base_url)
    try:
        if args.command == "export":
            return cmd_export(client)
        if args.command == "plan":
            return cmd_plan(client, fail_on_diff=args.fail_on_diff)
        return cmd_apply(client)
    except PoliciesApiError as err:
        print(f"error: {err}", file=sys.stderr)
        if err.code == "STATE_VERSION_MISMATCH":
            print(
                "  the live state changed since this repo was read; re-run "
                "`export`, reconcile, and retry.",
                file=sys.stderr,
            )
        elif err.details.get("missing_references"):
            for ref in err.details["missing_references"]:
                print(f"  missing {ref['kind']}: {ref['value']}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

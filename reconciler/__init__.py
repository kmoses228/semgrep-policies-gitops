"""A thin GitOps reconciler for the Semgrep Policies V2 API.

The server owns the diff, the dry run, and concurrency control, so this
client stays small: it serializes desired state to/from YAML and drives the
read -> plan -> apply loop.
"""

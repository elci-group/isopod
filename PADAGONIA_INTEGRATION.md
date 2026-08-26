# PADAGONIA Integration Roadmap

See `/home/sal/padagonia/docs/enterprise-integration-directives.md`.

## Modules

- `control_ontology`: version controls, assets, scopes, and obligations.
- `scan_ingest`: write bounded scan observations with source and tool provenance.
- `finding_deduplicator`: use hashes and exact lookup to avoid duplicate findings.
- `exception_lifecycle`: record approvals, owners, expiry, remediation, and
  superseding decisions append-only.
- `compliance_export`: produce deterministic evidence packages and metrics.

## Acceptance gates

Audit history is immutable at the logical level, exceptions expire explicitly,
and reports are reproducible after restore.

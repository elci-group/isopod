# Isopod Enterprise SOTA Directive

## Mission

Isopod must produce an evidence-backed, reproducible compliance posture—not a
collection of optimistic artifact matches. Every claim must be traceable to a
control, a scoped evidence item, a collection time, an integrity hash, and an
explicit effectiveness decision.

## Non-negotiable product requirements

1. **Honest scoring.** Report control coverage separately from posture. Unknown
   controls never disappear from the denominator: publish assessed, unknown,
   pass, warning, fail, and coverage percentages. An all-unknown assessment is
   ungraded, not healthy.
2. **Control-specific evaluation.** A generic artifact (for example a CA bundle,
   `/etc/passwd`, or a Git commit) may not satisfy an unrelated requirement.
   Evaluators must declare their accepted evidence types and metadata fields.
3. **Effectiveness over existence.** Distinguish `observed`, `configured`, and
   `effective`. Logging requires active collection, retention, integrity, and
   monitoring evidence; access management requires lifecycle and authorization
   evidence; backup requires a recent successful restore test.
4. **Audit-grade provenance.** Evidence includes absolute scope, collector,
   source path or API, timestamp, freshness window, content hash, and collection
   status. Missing provenance lowers confidence and blocks a PASS.
5. **Fail safely.** Stale, contradictory, malformed, or low-confidence evidence
   produces WARNING/UNKNOWN with remediation, never PASS. Confidence is a
   calibrated evidence-quality indicator, not a probability of compliance.
6. **Deterministic operation.** Identical inputs produce identical JSON, scores,
   remediation ordering, and exit status. Human output is presentation only.
7. **Enterprise controls.** Support policy packs, version pinning, tenant/project
   scope, RBAC for evidence access, encrypted-at-rest storage, retention and
   purge policy, exportable audit bundles, and signed report manifests.
8. **Continuous assurance.** Daemon scans are incremental, observable, rate
   limited, and drift-aware. Every remediation is idempotent, reviewable, and
   reversible; automatic changes require explicit opt-in.

## Delivery gates

- Unit and integration tests cover every evaluator, status transition, score edge
  case, stale-evidence path, and malformed-input path.
- Golden JSON fixtures verify schema compatibility and deterministic ordering.
- `cargo fmt --check`, offline Clippy with warnings denied, tests, docs, and
  release build pass before a release.
- Uni is run before and after material changes. Findings are triaged by impact;
  score improvements are not accepted if they reduce evidence coverage or hide
  unknowns.
- Release artifacts include an SBOM/license manifest, changelog, provenance
  report, and a signed verification summary.

## Roadmap

**Now:** correct score semantics, strengthen provenance, add negative and stale
fixtures, and remove evidence-to-control mismatches.

**Next:** implement effectiveness adapters for logging, backup, access review,
cloud encryption, and monitoring; add policy-pack validation and signed exports.

**Then:** multi-tenant RBAC, encrypted evidence vault, external attestation
adapters, historical trend analytics, and continuously verified control SLAs.

## Definition of done

No control is reported PASS without control-specific, fresh, attributable
evidence; coverage is visible beside posture; unknowns are actionable; reports
are reproducible by an independent reviewer; and all delivery gates pass.

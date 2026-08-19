<!-- SPDX-License-Identifier: AGPL-3.0-only -->

# Preview roadmap

`v0.1.0-preview.1` remains blocked until all of these work together:

- [x] Web Foundations organizations and scoped access are published and
      integrated for generated one-time bootstrap, forced password rotation,
      session revocation, and bounded query explanation.
- [x] Complete tail-cursor recovery and enrollment around the implemented
      native collector adapters and durable 72-hour/5-GiB spool.
- [x] Caddy, requestlog, and Tend event file adapters plus authenticated,
      bounded OTLP/HTTP protobuf ingestion for logs, metrics, and traces.
- [x] Linux host, cgroup v2, filesystem, network, and explicitly selected
      process metrics in the durable unprivileged agent pipeline.
- [x] Logs, metrics, traces, and deployment events projected and queryable.
- [x] Add execution to the implemented unified builder/text AST, explain plan,
      sensitive-field permission, and hard planning budgets.
- [x] Idempotent descriptive schema proposal persistence with organization-
      scoped review permission and no observed values in proposal metadata.
- [x] Reviewed descriptor activation and atomic beside-current projection/index switching.
- [x] Sandwich Hime dashboards, accessible alternatives, SSE, durable alert
      rules, an online incident inbox, installable shell, badge state, and an
      explicit opt-in read-only offline incident snapshot.
- [x] Generic privacy-preserving Web Push with explicit browser opt-in,
      fixed encrypted content, reauthorization at delivery, and a bounded
      non-blocking queue.
- [x] Strict Tend activation and rollback annotations whose identity, event-file,
      agent, network, or Observatory failures cannot control a release.
- [x] Enforced hot/cold raw and evidence retention, approved organization
      overrides, serialized storage quotas, crash-recoverable archival and
      indefinite forensic preservation by default, explicitly enabled final
      retirement, budgeted forensic queries, projection compaction, and
      five-minute metric rollups with privacy-safe dimensions.
- [ ] Security, corruption recovery, migration, and projection rebuild campaigns.
- [ ] 4-vCPU/8-GiB capacity campaign and medium-fleet soak.
- [ ] Sanitized public root snapshot, reproducible package, SBOM, and signed checksums.

## Post-preview direction

- [ ] Public-safe status dashboards backed by separately approved aggregate
      projections, coarse buckets, minimum group sizes, publication delay, and
      no unauthenticated path to internal or sensitive evidence.
- [ ] An additive structured-frame source path for byte-faithful preservation
      of permitted producer records while retaining bounded framing,
      compression, authentication, tenant scope, and asynchronous parsing.
      Existing typed metrics and OTLP ingestion remain typed.

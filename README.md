
## V3.47 — Complete Integration & Assurance Campaign

The current release includes the V3.43 capability-contract lab, V3.44 realistic vulnerability fixtures, V3.45 multi-domain isolated integration range, V3.46 campaign quality scoring, and V3.47 deterministic resilience checks. Run the full local campaign with:

```bash
python tools/run_complete_test_campaign.py
```

Results are written under `artifacts/complete-test-campaign/` (or the directory passed with `--output-dir`). These labs are local/disposable and do not establish universal real-world vulnerability-detection accuracy.
# V3.43 — Complete Testing Lab

Run the entire capability validation campaign with one command:

```bash
python -m security_platform fabric --client lab --target 127.0.0.1 --output-dir ./artifacts/v343-lab --action complete-testing-lab
```

See `V343_COMPLETE_TESTING_LAB.md` for interpretation and outputs.

# V3.41 — Unified Assurance Expansion

V3.37–V3.41 adds the unified specialist adapter lifecycle, deeper web/API assurance catalog, bounded fuzz-campaign planning, durable engagement analytics, and identity protocol assurance. The platform remains scope-controlled, evidence-driven and delegation-only for consequential execution.

# V3.31 — Reliability & Execution Integrity

V3.31 hardens the V3.30 unified assessment control plane with transactional operation state, global execution budgets, crash/interruption recovery, state lineage digests, strict invariants, atomic evidence persistence, and structured failure recovery. It remains delegation-only and does not introduce unrestricted exploit generation or scope/authorization bypass.

Current release: **3.41.0**.

# Security Platform V3.30

See `ARCHITECTURE_FINAL.md` and `ENGINE_AUDIT_V329.md` for the current architecture and latest engineering audit.

# Security Platform Architecture

This project is now a modular Security Platform with multiple specialist engines (pentest, OSINT, bounty, mobile, wireless and remote) plus a shared governed control plane. The current release also includes universal attack-surface assessment, capability runtime, adversarial reasoning, temporal/digital-twin analysis, V3.29 unified adversary simulation and the V3.30 unified execution fabric.

All engines share hardened infrastructure for scope, authorization, tool execution, state, evidence, provenance and artifacts. Shared infrastructure does **not** mean shared authority: an engine handoff is untrusted intelligence and the receiving engine re-applies its own controls.

Run independently:

```bash
python securityctl.py pentest ...
python securityctl.py osint ...
python securityctl.py bounty ...
```

Optional platform coordination:

```bash
python securityctl.py platform --engines osint,pentest,bounty ...
```

See `ARCHITECTURE_REFACTOR_V2.md` for the architecture contract.

---

# Current Architecture (V3.30)

The current source of truth is `ARCHITECTURE_FINAL.md`, `docs/ARCHITECTURE.md`, `MODULE_STATUS.md`, and the latest V3.30 audit/changelog. Older versioned README files are historical release notes.

The preferred execution path is: authorization → scope → registered ToolManager → evidence collection → normalization → intelligence → operator-approved controlled validation → reporting/retest. The platform must never treat module count, import success, or scanner output alone as proof that a capability works.

Current Python dependencies are declared in `pyproject.toml`, `requirements.txt`, and `requirements-dev.txt`.

# Pentest Automation Framework v20

A local, safety-first assessment assistant for **authorized** penetration tests. V11 unifies reconnaissance, findings, evidence, asset inventory, attack-path correlation, controlled validation, assessment intelligence, engagement lifecycle tracking, professional reporting, and investigation prioritization.

## V11 architecture

```text
Recon / API / Server / Internal artifacts
                ↓
        Finding Intelligence
                ↓
       Asset + Evidence Index
                ↓
       Correlation / Attack Graph
                ↓
   What Should I Investigate Next?
                ↓
     Human Validation + Impact
                ↓
      Remediation → Retest
                ↓
       Dashboard + Reports
```

### New in V9

- Unified engagement manifest: `evidence/engagement.json`
- Asset inventory: `evidence/assets.json`
- Evidence index with SHA-256 metadata: `evidence/evidence-index.json`
- Engagement timeline: `evidence/timeline.json` + `reports/timeline.md`
- Evidence-aware attack graph and candidate chains
- Explicit finding states, capabilities, prerequisites, impacts and evidence quality
- Investigation prioritization: `evidence/next-investigation.json` + `reports/next-investigation.md`
- Self-contained local dashboard: `reports/dashboard.html`
- Expanded professional report pack
- Resume support remains available

## Safety model

This framework is intended for systems for which you have explicit authorization. Active testing requires an authorization confirmation and an allowlisted scope. The intelligence layer is **decision support**: it does not autonomously exploit, pivot, steal credentials, establish persistence, or exfiltrate data.

Automated findings are leads until manually validated. Hypothesis edges are never treated as proof of access, trust, reachability, exploitability, or impact.

## Quick start

```bash
python3 run.py
```

Or use the orchestrator directly:

```bash
python3 orchestrator.py -c client -t example.com --full --chain --report-pack --dashboard --next-investigation
```

For an existing engagement:

```bash
python3 orchestrator.py -c client -t example.com --output-dir output/client-YYYYMMDD-HHMMSS --chain --report-pack --dashboard --next-investigation
```

Keep secrets out of YAML and command-line arguments. Prefer the environment variables documented in `USER_GUIDE.md`.


## Controlled Validation Mode (V10)

Use `--validate-finding F-... --validation-mode verify` to perform an authorization-gated, scope-checked, non-destructive observation for a single finding. CVM records a validation ledger and report. It does not execute exploit payloads, arbitrary commands, persistence, credential access, lateral movement, or exfiltration. `impact` mode is documentation-only and produces a manual validation instruction.

### V10 Controlled Validation

V10 adds a bounded Controlled Validation Mode (CVM): authorization gate → scope check → explicit operator approval → non-destructive observation → validation ledger → manual review. It intentionally does not provide arbitrary command execution or autonomous exploitation.

## V11 Assessment Intelligence

V11 adds a human-in-the-loop assessment intelligence layer:

- Priority scoring using severity, evidence quality, review state, graph relationships, business context, and validation value.
- A controlled validation queue at `evidence/validation-queue.json`.
- Business-impact metadata at `evidence/business-impact.json`; it stores context, not secrets.
- Manual retest ledger at `evidence/retest-ledger.json`. Retest recording performs no network testing.
- Assessment report at `reports/assessment-intelligence.md` and queue report at `reports/validation-queue.md`.
- Finding states can include `candidate`, `validating`, `validated`, `inconclusive`, and `blocked`, alongside the existing review states.

Example metadata-only business context:

```bash
python3 orchestrator.py -c client -t example.com --output-dir output/client-engagement \
  --set-business-impact F-abc123 --asset-importance critical \
  --data-sensitivity confidential --business-function authentication
```

Example manual retest record:

```bash
python3 orchestrator.py -c client -t example.com --output-dir output/client-engagement \
  --retest-finding F-abc123 --retest-result fixed --retest-note "Manual retest passed"
```

The retest command asks for explicit `YES` approval and records only the tester's supplied result; it does not execute a retest against the target.


### V11 workflow

```text
Discover → Correlate → Prioritize → Controlled Validation
        → Evidence → Business Impact → Remediation
        → Manual Retest → Recalculate → Report
```

The assessment intelligence layer is intentionally advisory. It ranks uncertainty and potential consequence, builds a validation queue, and records business context and manual retests. It never turns a recommendation into autonomous exploitation.

## V15–V17 Intelligence Layer

- `modules/technology_intelligence.py` builds artifact-derived technology and asset intelligence without network activity.
- `modules/correlation_engine.py` normalizes findings and records duplicate/cross-surface hypotheses for analyst review.
- `modules/engagement_governance.py` records chained audit events and produces an engagement-readiness report.

CLI additions: `--technology-intelligence`, `--correlation`, and `--governance`.


## V18–V20

### V18 — Advanced Investigation Engine
- Prioritizes findings using severity, evidence quality, confidence, graph relationships, asset importance, uncertainty, and validation value.
- Produces `evidence/investigation-priorities-v18.json` and `reports/investigation-priorities-v18.md`.
- Recommendations are advisory and human-in-the-loop.

### V19 — Engagement Knowledge Base
- Builds a persistent file-backed knowledge graph from assets, findings, technologies, correlations, validations, retests, and attack-graph relationships.
- Explicitly preserves hypothesis status and excludes secrets/raw credentials.
- Produces `evidence/knowledge-base.json` and `reports/knowledge-base.md`.

### V20 — Operator Workspace
- Adds a consolidated local operator workspace linking investigation priorities, findings, control center, and dashboard.
- Produces `reports/operator-workspace.html`.
- Interactive launcher options now include Advanced Investigation, Knowledge Base, and Operator Workspace.

### V18–V20 workflow

```text
Discover → Correlate → Understand → Prioritize
        → Controlled Validation → Evidence
        → Business Impact → Retest → Knowledge Base
        → Operator Workspace → Reporting
```

## V27–V29 Lifecycle Intelligence

- **V27 Remediation Tracking:** metadata-only ownership, priority, due-date, status, and notes.
- **V28 Retest Intelligence:** correlates recorded retest outcomes with remediation state and residual risk.
- **V29 Closure Readiness:** evaluates whether required engagement artifacts and unresolved-risk conditions support closure.

These features do not modify target systems. Remediation and retest records are operator-entered assessment metadata.

## V42–V44 — Unified Assessment Pipeline
- **V42 Pipeline Graph:** converts the mission into a dependency-aware executable assessment graph.
- **V43 Result Collector:** captures sanitized tool results with integrity hashes and structured records.
- **V44 Pipeline Runner:** executes only registered tools through the V40 manager, one dependency-ready task at a time.
- No arbitrary shell commands are accepted by the pipeline runner.
- Existing authorization, scope and controlled-proof gates remain mandatory.


## V54–V56
See `README_V54_V56.md` for Session & Identity Intelligence, bounded session observations, and identity transition decision support.


## V60–V62 Business Logic & Workflow Intelligence
- V60: structured workflow/state model from existing web endpoint intelligence.
- V61: non-executing sequence and state-transition hypotheses.
- V62: prioritized business-logic review decisions.
- Planning/decision support only; no transaction replay, state-changing requests, credential collection, or autonomous exploitation.
- CLI: `--business-logic-engine`, `--workflow-intelligence`, `--workflow-sequences`, `--business-logic-decisions`.
Artifacts: `evidence/workflow-intelligence-v60.json`, `evidence/workflow-sequences-v61.json`, `evidence/business-logic-decisions-v62.json` plus matching reports.

## V77–V82 Unified Security Operator
The platform now includes a central Security Brain, evidence memory, task router, bounded operator loop, unified assessment controller, and final intelligence pack. See `README_V77_V82.md`.

## V83–V90 — Intelligent Security Operator Expansion

The operator now includes eight higher-level capabilities:
- V83 AI reasoning interface with heuristic fallback and optional OpenAI-compatible provider via `SECURITY_AI_URL` / `SECURITY_AI_MODEL`; no unrestricted tool access.
- V84 evidence-derived target profiling and adaptive priority areas.
- V85 deeper web/API intelligence from normalized artifacts.
- V86 opt-in passive public-source OSINT collection (`--osint-collect`), with no private access or active probing.
- V87 cross-engagement evidence memory with secret redaction and hashes.
- V88 bug-bounty prioritization and duplicate/reportability review support.
- V89 professional reporting structure plus continuous-monitoring triggers.
- V90 safe training/lab plans (`--training`).

Running `--operator` now builds V77–V90 together. Consequential actions remain authorization-, scope-, policy-, and operator-gated.
- V91 master operator state synthesizes the complete V77–V90 stack into one auditable operator artifact.


## Latest milestone
See `README_V92_V100.md` for the integrated real-tool orchestration architecture (V92–V100).

## V101–V110 Reliability & Production Quality

See `README_V101_V110.md` for the reliability, normalization, verification, smart tool selection, role-testing, advanced API intelligence, correlation, change detection, evidence vault, and quality-gate layer. The preferred real-assessment entry point is `--integrated-mission`.

- V111–V145 excellence expansion: see README_V111_V145.md.

V146–V160 adds the consent-first OSINT workspace and expanded security-tool catalog. Device recovery/tracking was later separated into its own project in V233.

## V233-V240 — OSINT & Bug-Bounty Excellence

Adds an evidence-driven OSINT investigation pipeline and adaptive bug-bounty planning/quality layer. Tool outputs can be ingested, normalized, correlated, scored, gap-analysed and synthesized into analyst-ready intelligence. Bug-bounty mode models program policy, scope, exclusions, authorization, testing coverage, evidence and report readiness.

Device tracking/recovery is no longer part of this pentest engine; it is maintained as a separate project.

Example:
`python3 orchestrator.py -c Recovery -t authorized-device --location-recovery --device-platform android --location-data locations.json`

Important: GNSS satellites provide positioning signals; they do not provide a public query interface for locating arbitrary devices. SIM-free/offline finding is conditional on the device/vendor ecosystem. Powered-off finding is only possible on hardware/ecosystems that explicitly support it; it is not universal and cannot be created by software alone.

## V196–V210 Excellence Expansion
The framework includes additional legitimate location/recovery and OSINT capabilities documented in `README_V196_V210.md`.

## 1.8 Full Assessment + Autonomous Governance Layer

The 1.8 platform expands the specialist pentest engine into a full authorized assessment workflow covering: web applications, APIs, authentication/session/authorization, external infrastructure, network/service discovery, host assessment, read-only Active Directory enumeration, read-only AWS inventory, evidence-backed coverage, final readiness and reporting.

Default pentest phases are:
`recon,probe,ports,web,api,authenticated,ad,aws,intelligence,final`

The platform also maintains dedicated OSINT and Bug Bounty engines. Capability declarations are not treated as proof of execution: actual coverage depends on authorized scope, target technology, installed/verified tools, evidence, and human review.

## Security Platform Architecture (v1.0.0)

The project now exposes multiple specialist engines over a shared hardened core, plus the V3.30 unified adversary-simulation planning layer. Use `python securityctl.py --help` to access the dedicated interface. The historical `orchestrator.py` remains available for compatibility while migration continues.

See `SECURITY_PLATFORM_ARCHITECTURE.md` and `ARCHITECTURE_REFACTOR_V1.md` for boundaries and engine responsibilities.

## 1.8 Autonomous Controller

The platform includes a policy-controlled autonomous controller with default-deny behavior, bounded budgets, durable single-use approval tokens, and machine-readable Rules of Engagement (ROE). R4 actions require an explicit engagement ROE plus operator approval; R5 actions remain permanently denied.

Example: `python securityctl.py autonomy -c CLIENT -t TARGET -o OUTPUT --scope SCOPE --profile assess`

ROE example: `config_roe.example.json`. Never treat a candidate asset or intelligence handoff as permission to test it.


## V2.5 Mobile and Wireless

V2.5 adds first-class `mobile` and `wireless` specialist engines. Android assessment supports APK structure/static analysis, manifest/permissions/component review, common security heuristics, native-library inventory, redacted embedded-secret markers, and optional read-only emulator/device inspection. Wireless assessment supports interface/radio inventory and bounded PCAP analysis.

Examples:

```bash
python securityctl.py mobile -c LAB -t android-lab -o ./output --apk ./sample.apk
python securityctl.py mobile -c LAB -t android-lab -o ./output --apk ./sample.apk --dynamic --serial emulator-5554
python securityctl.py wireless -c LAB -t wireless-lab -o ./output --interface wlan0
python securityctl.py wireless -c LAB -t wireless-lab -o ./output --pcap ./capture.pcapng
```

The wireless engine intentionally does not automate deauthentication, frame injection, credential cracking, rogue-AP operation, or uncontrolled capture.

## V2.5 Remote Adversarial Lab
The platform includes a disposable remote-system regression lab and a dedicated `remote` specialist. See `V24_ADVERSARIAL_TEST_PLAN.md` and `lab/adversarial-remote-lab/README.md`.


## V3.2 Coverage Expansion

V3.2 closes several previously identified capability gaps without weakening the platform's safety model:

- **Azure, GCP and Kubernetes:** fixed read-only CLI catalogs plus offline JSON-export analysis. No resource mutation, workload execution, secret-value retrieval, or IAM changes.
- **Active Directory relationships:** offline ACL/delegation/Kerberos relationship analysis from JSON/CSV exports.
- **iOS:** IPA static analysis for metadata, ATS configuration, native Mach-O presence, URLs and redacted secret markers.
- **Bluetooth/BLE:** passive scan-export analysis and GATT/service review from supplied evidence.

These additions improve breadth, but do not make the platform omnipotent. Business-logic judgment, physical/social engineering, final attribution, malware/C2 operations, stealth/evasion tradecraft and destructive exercises remain human-led or separately governed.

The correct claim is therefore **broad, extensible authorized assessment automation**, not “can literally perform every pentest or red-team operation.”

## V2.8 Adaptive Assessment & Unusual-Target Reasoning

V2.8 adds an evidence-driven adaptive assessment layer. It observes existing engagement artifacts, classifies recognizable environment signals, creates explicit hypotheses, selects bounded low-risk experiments, and escalates unknown or human-dependent situations.

The adaptive layer does **not** expand scope, grant authority, guess credentials, execute arbitrary payloads, or automate high-impact actions. Hypotheses are never findings until independently validated.

CLI:
```bash
python securityctl.py adaptive -c CLIENT -t TARGET -o OUTPUT --scope SCOPE
```

The platform maturity report also includes the adaptive assessment.

### V3.2 CLI examples

Read-only cloud inventory (requires the provider CLI and authorized credentials/configuration):

```bash
python -m security_platform cloud -c CLIENT -t TARGET -o ./output --provider azure
python -m security_platform cloud -c CLIENT -t TARGET -o ./output --provider gcp
python -m security_platform cloud -c CLIENT -t TARGET -o ./output --provider kubernetes
```

Offline evidence analysis:

```bash
python -m security_platform cloud -c CLIENT -t TARGET -o ./output --provider azure --export ./azure-export.json
python -m security_platform ad-relationships -c CLIENT -t TARGET -o ./output --input ./ad-relationships.json
python -m security_platform ios -c CLIENT -t TARGET -o ./output --ipa ./app.ipa
python -m security_platform ble -c CLIENT -t TARGET -o ./output --input ./ble-scan.json
```

All new live cloud commands are read-only and pass through the same allowlisted tool boundary as the existing assessment toolchain.


## V3.9 Open-Source Ecosystem Integration

The platform can now ingest and normalize evidence from BloodHound CE, MobSF and Nuclei/ProjectDiscovery-style findings, and maintains a capability/gap matrix for Metasploit, Sliver, Havoc, Impacket, NetExec, Frida, Hashcat and Responder. See `V39_ECOSYSTEM_INTEGRATION.md`.

## V3.11 Superior Capability Fabric

The current platform also includes a cross-ecosystem capability fabric that combines
agentic planning, source/runtime correlation, browser-trace evidence, continuous
assurance, provider-agnostic AI routing, ATT&CK/emulation metadata planning and
benchmark-quality measurement. These capabilities sit above specialist tools and
remain governed by the platform's authorization, scope and evidence controls.

Use `python securityctl.py fabric --help` to inspect the available actions.

## V3.15 Specialist Domain Fabric
V3.15 adds a unified specialist-domain control plane for wireless, mobile devices, remote systems, and RCE/exploitability validation. Specialist tools remain external executors; the platform owns authorization, scope, approvals, evidence normalization, correlation, verdicts and retesting.

## V3.60 — Final Engine Closure

V3.60 closes the remaining architecture gaps identified by the capability audit. The final control plane adds deterministic task identity, duplicate/branch convergence, single-owner task leases, stale-lease recovery, scope/authorization-bound execution receipts, provider-independent reasoning boundaries, final capability-closure reporting, and explicit specialist/testbed envelopes for capabilities that cannot safely be universalized.

The final engine is validated by the complete regression suite and a dedicated 24-scenario autonomous-control-plane matrix. It remains deliberately governed: the model cannot grant authority, expand scope, become canonical memory, or bypass specialist execution controls.

See `FINAL_ENGINE_V360.md` and `CHANGELOG_V360_FINAL.md`.

## V3.36 — Capability Benchmark & Gap Audit

V3.36 adds an evidence-oriented capability benchmark across 15 professional security-assessment families. It compares capability families rather than claiming vendor feature parity, records local implementation depth, and keeps genuine gaps explicit. The benchmark is read-only and does not execute targets.

Use `capability-benchmark` for the machine-readable benchmark and `capability-benchmark-suite` for its regression matrix.

## V3.42 — Capability Closure

V3.42 gives every current capability-family entry a concrete governed contract. Dangerous adversary behaviors are represented by deterministic lab-simulation envelopes rather than unrestricted weaponized execution, with synthetic evidence, approval gates, scope/authorization preconditions and validation linkage.

## V3.44 Realistic Vulnerability Validation Laboratory

V3.44 adds disposable local vulnerable fixtures, hidden ground truth, bounded dynamic detection, and true-positive/miss/false-positive accounting. Run `python -m security_platform fabric --client lab --target 127.0.0.1 --output-dir ./artifacts/v344 --action realistic-vulnerability-campaign` for the focused campaign.


## V3.61 — Exploitation Assurance Fabric

V3.61 makes exploitation reasoning a first-class capability. It ranks proof techniques from evidence, builds deterministic exploit-candidate graphs, supports differential proof planning across web/API classes, and continuously refreshes exploitation candidates as new evidence arrives.

Execution is still owned by the existing governed specialist adapters, authorization gates, scope checks, and execution guards. The assurance layer does not grant authority or provide unrestricted arbitrary-command execution.

## V3.62 — Exploitation Loop & Benchmark Fabric

V3.62 strengthens the exploitation path with deterministic exploit-class coverage,
evidence-ranked candidate generation, source/dynamic correlation, branch convergence,
bounded proof-state management, and local benchmark scoring. It is planning and
assurance infrastructure; consequential execution remains delegated to existing
specialist adapters and policy/authorization gates.

New optional pentest phase:
```text
exploitation-loop
```

The V3.62 layer also provides a source-analysis helper that parses supplied source
without executing it, and a benchmark scorer for local challenge manifests.

## V3.63 — Offensive AI Reasoning & Agent Loop

V3.63 adds the adaptive AI layer. The AI can form attacker-style hypotheses, correlate source/runtime evidence, select registered tools, sequence multi-step validation, interpret observations and replan. The new `agentic-exploitation` phase closes the model → tool → observation → model loop.

The AI is not the authority layer: scope, authorization, approval, registered-tool constraints, structured argv and evidence receipts remain deterministic. This preserves the ability to reason aggressively without turning natural-language output into arbitrary shell execution.

## V3.64 — Tri-Modal Offensive Assessment + GUI

V3.64 adds Python-first, AI-first and Hybrid operating modes without removing existing Python capabilities. The AI can ingest an operator's natural-language pentest narrative and combine it with collected evidence to form hypotheses, select registered capabilities and replan after observations. A standard-library Tkinter GUI exposes the workflow for non-terminal users with authorization confirmation, command preview, Python assessment, AI testing, hybrid autopilot, exploitation and report buttons.

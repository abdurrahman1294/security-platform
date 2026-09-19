# V92–V100: Real Integrated Security Operator

This milestone changes the framework from a collection of modules into a coordinated, scope-checked assessment workflow.

## V92 Capability Registry
Registered capabilities describe purpose, risk, approvals, expected outputs and tool chains.

## V93 Self Verification
Scanner results are treated as evidence rather than proof. Findings remain hypotheses until validated.

## V94 Security Knowledge Graph
Assets, targets and evidence artifacts are represented as a relationship graph for cross-module reasoning.

## V95 Hypothesis Engine
Evidence produces explicit hypotheses with recommended validation steps instead of silently promoting observations to confirmed vulnerabilities.

## V96 Experiment Planner
Ranks safe, high-information investigations while keeping operator approval mandatory.

## V97 Capability Reliability
Tracks operational reliability of registered tools from the execution ledger. It does not claim vulnerability accuracy.

## V98 Plugin Contract
Defines a plugin manifest so future integrations can extend the platform without bypassing the capability registry or safety policy.

## V99 Operator Dashboard
Generates a local HTML dashboard listing evidence artifacts and engagement state.

## V100 Integrated Toolchain
Runs the registered tool chain against one authorized target and validated scope using the existing ToolManager. The flow is:

1. Subdomain discovery
2. Scope filtering
3. HTTP probing
4. Port discovery
5. Service enumeration
6. Web crawling
7. Vulnerability discovery
8. Evidence collection
9. Normalization and intelligence synthesis

Missing tools are skipped and recorded rather than causing fabricated results. Every execution is auditable through the tool ledger and result collector.

## Important
This is a real orchestration layer, not a claim of perfect autonomy. Tool output is collected, normalized and analyzed, while controlled validation, controlled proof and consequential decisions remain human-approved.

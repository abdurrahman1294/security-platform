# V3.72 — Web Precheck Repair

- Fixed the V3.71 web Action Center PRECHECK route.
- The web layer now calls the canonical `security_platform.core.preflight.check()` instead of assuming `PentestEngine.preflight()` exists.
- Added regression coverage for `/api/mission/action/precheck`.
- No change to authorization, scope policy, or active execution gates.

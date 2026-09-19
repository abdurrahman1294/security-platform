# V3.52–V3.53 — Tool Evidence + Tool-Aware Planning

## V3.52
- Added canonical normalization for Nmap XML, HTTPX JSONL, Nuclei JSONL, Naabu lines, Katana lines, and NetExec observations.
- Preserves provenance and keeps scanner findings at candidate/observed status rather than self-upgrading to compromise.
- File inputs are sandboxed to the engagement output root.
- No command execution or command synthesis occurs.

## V3.53
- Added a bounded domain-to-registered-tool planning layer.
- Explicitly reports unavailable tools and safe framework-local fallbacks.
- Planning remains separate from execution; no generic command path is introduced.
- Added platform APIs, CLI actions, and regression matrices.

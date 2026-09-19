# V3.72 Web Precheck Fix

The V3.71 browser PRECHECK failed because `webapp/app.py` mapped `precheck` to a nonexistent `PentestEngine.preflight` method. The platform already has a canonical preflight implementation at `security_platform.core.preflight.check`. V3.72 routes the web PRECHECK action directly to that canonical check.

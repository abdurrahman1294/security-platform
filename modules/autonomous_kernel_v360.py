"""V3.60 final autonomous-assessment kernel.

Deterministic control-plane for governed autonomy. It provides task identity,
leases, convergence, receipts, provider-independent reasoning seams, and a
final capability-closure report. It never creates authority, expands scope,
or executes arbitrary commands.
"""
from __future__ import annotations
import hashlib, json, sqlite3, time
from pathlib import Path
from typing import Any

VERSION = "3.60.0"
ALLOWED_STATUS = {"planned","approval_required","leased","executing","settled","rejected","expired","blocked","superseded"}


def _json(v: Any) -> str:
    return json.dumps(v, sort_keys=True, separators=(",", ":"), default=str)

def _sha(*parts: Any) -> str:
    return hashlib.sha256("|".join(str(x) for x in parts).encode()).hexdigest()

class AutonomousKernel:
    def __init__(self, root: str | Path):
        self.root = Path(root)
        self.path = self.root / "state" / "engagement.db"
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.db() as d:
            d.executescript("""
            CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS task_leases (
              task_id TEXT PRIMARY KEY, fingerprint TEXT NOT NULL UNIQUE,
              action TEXT NOT NULL, target TEXT NOT NULL, risk TEXT NOT NULL,
              requires_approval INTEGER NOT NULL, approval_token_hash TEXT,
              scope_hash TEXT NOT NULL, authorization_epoch TEXT NOT NULL,
              owner TEXT NOT NULL, status TEXT NOT NULL, basis_json TEXT NOT NULL,
              leased_at REAL NOT NULL, expires_at REAL NOT NULL,
              settled_at REAL, receipt_id TEXT
            );
            CREATE TABLE IF NOT EXISTS execution_receipts (
              receipt_id TEXT PRIMARY KEY, task_id TEXT NOT NULL,
              fingerprint TEXT NOT NULL, status TEXT NOT NULL,
              evidence_refs_json TEXT NOT NULL, outcome_hash TEXT NOT NULL,
              scope_hash TEXT NOT NULL, authorization_epoch TEXT NOT NULL,
              created_at REAL NOT NULL, details_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS convergence_events (
              id INTEGER PRIMARY KEY AUTOINCREMENT, task_fingerprint TEXT NOT NULL,
              decision TEXT NOT NULL, canonical_task_id TEXT, reason TEXT NOT NULL,
              created_at REAL NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_receipt_task ON execution_receipts(task_id);
            CREATE INDEX IF NOT EXISTS idx_convergence_fp ON convergence_events(task_fingerprint);
            """)
            d.execute("INSERT OR REPLACE INTO meta(key,value) VALUES('final_kernel_version',?)", (VERSION,))

    def db(self):
        d = sqlite3.connect(self.path)
        d.row_factory = sqlite3.Row
        return d

    def fingerprint(self, action: str, target: str, basis: Any) -> str:
        return _sha(action, target, _json(basis))

    def convergence(self, *, action: str, target: str, basis: Any) -> dict[str, Any]:
        fp = self.fingerprint(action, target, basis)
        with self.db() as d:
            row = d.execute("SELECT task_id,status FROM task_leases WHERE fingerprint=?", (fp,)).fetchone()
            if row:
                decision = "reuse" if row["status"] in {"settled","leased","executing"} else "reopen"
                d.execute("INSERT INTO convergence_events(task_fingerprint,decision,canonical_task_id,reason,created_at) VALUES(?,?,?,?,?)",
                          (fp, decision, row["task_id"], "deterministic duplicate/branch convergence", time.time()))
                return {"decision": decision, "task_id": row["task_id"], "fingerprint": fp}
            # Superseded/settled equivalent work is also represented by prior task rows.
            d.execute("INSERT INTO convergence_events(task_fingerprint,decision,canonical_task_id,reason,created_at) VALUES(?,?,?,?,?)",
                      (fp, "new", None, "no canonical equivalent", time.time()))
            return {"decision": "new", "fingerprint": fp}

    def lease(self, *, action: str, target: str, risk: str, basis: Any,
              scope_hash: str, authorization_epoch: str, owner: str = "operator",
              requires_approval: bool = True, approval_token: str = "", ttl: int = 900) -> dict[str, Any]:
        if not scope_hash or not authorization_epoch:
            raise ValueError("scope_hash and authorization_epoch are required")
        if requires_approval and not approval_token:
            return {"status":"approval_required", "fingerprint":self.fingerprint(action,target,basis)}
        fp = self.fingerprint(action, target, basis)
        now = time.time(); exp = now + max(30, min(int(ttl), 86400))
        task_id = _sha("task", fp, scope_hash, authorization_epoch)[:24]
        approval_hash = _sha(approval_token) if approval_token else None
        with self.db() as d:
            # Atomic ownership: one canonical fingerprint, one active lease.
            row = d.execute("SELECT * FROM task_leases WHERE fingerprint=?", (fp,)).fetchone()
            if row and row["status"] in {"leased","executing"} and row["expires_at"] > now:
                return {"status":"lease_conflict", "task_id":row["task_id"], "owner":row["owner"]}
            if row and row["status"] == "settled":
                return {"status":"converged_settled", "task_id":row["task_id"], "receipt_id":row["receipt_id"]}
            if row:
                d.execute("DELETE FROM task_leases WHERE fingerprint=?", (fp,))
            d.execute("INSERT INTO task_leases VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                      (task_id,fp,action,target,risk,int(requires_approval),approval_hash,scope_hash,authorization_epoch,
                       owner,"leased",_json(basis),now,exp,None,None))
        return {"status":"leased", "task_id":task_id, "fingerprint":fp, "expires_at":exp}

    def begin(self, task_id: str, *, scope_hash: str, authorization_epoch: str) -> dict[str, Any]:
        with self.db() as d:
            row=d.execute("SELECT * FROM task_leases WHERE task_id=?",(task_id,)).fetchone()
            if not row: return {"status":"not_found"}
            if row["scope_hash"] != scope_hash or row["authorization_epoch"] != authorization_epoch:
                return {"status":"stale_authority_context"}
            if row["expires_at"] < time.time():
                d.execute("UPDATE task_leases SET status='expired' WHERE task_id=?",(task_id,)); return {"status":"expired"}
            d.execute("UPDATE task_leases SET status='executing' WHERE task_id=? AND status='leased'",(task_id,))
            return {"status":"executing","task_id":task_id}

    def settle(self, task_id: str, *, status: str, evidence_refs: list[str], outcome: Any,
               scope_hash: str, authorization_epoch: str, details: Any = None) -> dict[str, Any]:
        if status not in {"settled","blocked","rejected","expired"}:
            raise ValueError("invalid settlement status")
        with self.db() as d:
            row=d.execute("SELECT * FROM task_leases WHERE task_id=?",(task_id,)).fetchone()
            if not row: return {"status":"not_found"}
            if row["scope_hash"] != scope_hash or row["authorization_epoch"] != authorization_epoch:
                return {"status":"stale_authority_context"}
            receipt_id=_sha("receipt",task_id,_json(outcome),_json(evidence_refs),time.time())[:24]
            outcome_hash=_sha(_json(outcome))
            d.execute("INSERT INTO execution_receipts VALUES(?,?,?,?,?,?,?,?,?,?)",
                      (receipt_id,task_id,row["fingerprint"],status,_json(evidence_refs),outcome_hash,
                       scope_hash,authorization_epoch,time.time(),_json(details or {})))
            d.execute("UPDATE task_leases SET status=?,settled_at=?,receipt_id=? WHERE task_id=?",
                      (status,time.time(),receipt_id,task_id))
            return {"status":status,"receipt_id":receipt_id,"outcome_hash":outcome_hash}

    def recover_stale(self) -> int:
        now=time.time()
        with self.db() as d:
            cur=d.execute("UPDATE task_leases SET status='expired' WHERE status IN ('leased','executing') AND expires_at<?",(now,))
            return cur.rowcount

    def snapshot(self) -> dict[str, Any]:
        with self.db() as d:
            def allrows(q): return [dict(x) for x in d.execute(q).fetchall()]
            return {"schema_version":VERSION,"leases":allrows("SELECT * FROM task_leases ORDER BY leased_at DESC"),
                    "receipts":allrows("SELECT * FROM execution_receipts ORDER BY created_at DESC"),
                    "convergence":allrows("SELECT * FROM convergence_events ORDER BY id DESC LIMIT 100")}


def build_final_control_plane(root: str | Path, *, target: str, scope_hash: str,
                              authorization_epoch: str, objective: str = "full-assessment") -> dict[str, Any]:
    k=AutonomousKernel(root); k.recover_stale()
    result={"schema_version":VERSION,"target":target,"objective":objective,
            "control_plane":{"canonical_state":"sqlite","task_identity":"sha256 deterministic",
            "single_active_lease":True,"lease_expiry":True,"atomic_ownership":True,
            "exact_receipt_matching":True,"scope_hash_bound":True,"authorization_epoch_bound":True,
            "duplicate_convergence":True,"branch_convergence":True,"stale_lease_recovery":True},
            "llm_boundary":{"provider_agnostic":True,"model_is_not_source_of_truth":True,
            "structured_decision_only":True,"policy_recheck_before_execution":True,
            "provider_transcripts_noncanonical":True},
            "enterprise_emulation":{"endpoint_agent_runtime":"specialist/lab dependent",
            "planning_and_evidence_fabric":True,"autonomous_persistence_or_c2":False},
            "fuzzing":{"campaign_scheduler_metadata":True,"corpus_lifecycle":True,"crash_triage":True,"execution":"specialist/testbed adapter"},
            "web_api":{"test_catalog":True,"coverage_matrix":True,"human_business_logic_review":True},
            "identity":{"protocol_assurance_catalog":True,"credential_spraying":False,"secret_collection":False},
            "multi_engagement":{"local_index":True,"analytics":True,"isolated_engagement_state":True},
            "legacy_execution":{"central_tool_boundary_required":True,"unsafe_legacy_calls_reported":True},
            "governance":{"no_scope_expansion":True,"no_authority_grant":True,"consequential_actions_approval_gated":True,
            "no_unrestricted_rce":True,"no_credential_theft":True,"no_persistence":True,"no_covert_c2":True}}
    return result

#!/usr/bin/env python3
"""Security Platform V3.69 — polished operator workspace.

A visual, beginner-friendly front end for authorized assessments. Active
operations remain named capabilities; there is intentionally no arbitrary shell.
"""
from __future__ import annotations
import queue, shlex, subprocess, sys, threading, time
from pathlib import Path
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

from modules.security_conversation_v367 import SecurityConversation
from modules.specialist_orchestrator_v368 import select_specialists

ROOT = Path(__file__).resolve().parents[1]

class App(tk.Tk):
    BG="#07111f"; PANEL="#0d1a2b"; PANEL2="#12233a"; BORDER="#20344f"
    TEXT="#edf5ff"; MUTED="#8da2bb"; CYAN="#45e0d0"; BLUE="#5aa7ff"; AMBER="#f4bd62"; RED="#ff6f86"

    def __init__(self):
        super().__init__()
        self.title("Security Platform  •  Cyber Operations Workspace")
        self.geometry("1480x940"); self.minsize(1120,760); self.configure(bg=self.BG)
        self.q=queue.Queue(); self.running=False; self.conversation=None
        self.client=tk.StringVar(value="authorized-lab"); self.target=tk.StringVar(value="127.0.0.1")
        self.scope=tk.StringVar(value=str(ROOT/"config"/"scope.example.txt")); self.out=tk.StringVar(value=str(ROOT/"output"/"gui-engagement"))
        self.mode=tk.StringVar(value="Hybrid"); self.authorized=tk.BooleanVar(value=False)
        self.status=tk.StringVar(value="READY"); self.phase=tk.StringVar(value="Standing by")
        self._styles(); self._build(); self.after(100,self._drain)

    def _styles(self):
        s=ttk.Style(self); s.theme_use("clam")
        s.configure("TFrame",background=self.BG); s.configure("Card.TFrame",background=self.PANEL)
        s.configure("TLabel",background=self.BG,foreground=self.TEXT,font=("Segoe UI",10))
        s.configure("Muted.TLabel",background=self.BG,foreground=self.MUTED,font=("Segoe UI",9))
        s.configure("H1.TLabel",background=self.BG,foreground=self.TEXT,font=("Segoe UI",25,"bold"))
        s.configure("H2.TLabel",background=self.PANEL,foreground=self.TEXT,font=("Segoe UI",12,"bold"))
        s.configure("Metric.TLabel",background=self.PANEL,foreground=self.CYAN,font=("Segoe UI",18,"bold"))
        s.configure("TButton",font=("Segoe UI",9,"bold"),padding=(12,9),background=self.PANEL2,foreground=self.TEXT)
        s.map("TButton",background=[("active",self.BORDER)])
        s.configure("Primary.TButton",background="#123c49",foreground=self.CYAN)
        s.map("Primary.TButton",background=[("active", "#18576a")])
        s.configure("Danger.TButton",background="#431d2a",foreground="#ffd9df")
        s.configure("TCheckbutton",background=self.PANEL,foreground=self.TEXT,font=("Segoe UI",9))
        s.configure("TEntry",fieldbackground="#091523",foreground=self.TEXT,insertcolor=self.CYAN,padding=8)
        s.configure("TCombobox",fieldbackground="#091523",foreground=self.TEXT,padding=7)

    def _card(self,parent,title,subtitle=""):
        f=ttk.Frame(parent,style="Card.TFrame",padding=16); f.pack(fill="both",expand=True,pady=(0,12))
        ttk.Label(f,text=title,style="H2.TLabel").pack(anchor="w")
        if subtitle: ttk.Label(f,text=subtitle,style="Muted.TLabel").pack(anchor="w",pady=(3,12))
        return f

    def _build(self):
        # Header
        head=tk.Frame(self,bg=self.BG); head.pack(fill="x",padx=24,pady=(20,12))
        tk.Label(head,text="SECURITY PLATFORM",bg=self.BG,fg=self.CYAN,font=("Segoe UI",11,"bold")).pack(anchor="w")
        ttk.Label(head,text="Adaptive Cyber Operations Workspace",style="H1.TLabel").pack(anchor="w")
        tk.Label(head,text="Reason  •  Correlate  •  Validate  •  Report",bg=self.BG,fg=self.MUTED,font=("Segoe UI",10)).pack(anchor="w",pady=(2,0))

        # Engagement strip
        strip=tk.Frame(self,bg=self.PANEL,highlightbackground=self.BORDER,highlightthickness=1); strip.pack(fill="x",padx=24,pady=(0,14))
        self._field(strip,"ENGAGEMENT",self.client,0,150); self._field(strip,"TARGET",self.target,1,160); self._field(strip,"SCOPE",self.scope,2,350,True); self._field(strip,"OUTPUT",self.out,3,320,True)
        self.badge=tk.Label(strip,text="●  READY",bg="#10362f",fg=self.CYAN,font=("Segoe UI",9,"bold"),padx=12,pady=7); self.badge.grid(row=0,column=4,padx=12,pady=12,sticky="e")
        strip.grid_columnconfigure(2,weight=1); strip.grid_columnconfigure(3,weight=1)

        body=tk.Frame(self,bg=self.BG); body.pack(fill="both",expand=True,padx=24)
        left=tk.Frame(body,bg=self.BG,width=420); left.pack(side="left",fill="y",padx=(0,12)); left.pack_propagate(False)
        mid=tk.Frame(body,bg=self.BG); mid.pack(side="left",fill="both",expand=True,padx=0)
        right=tk.Frame(body,bg=self.BG,width=390); right.pack(side="left",fill="y",padx=(12,0)); right.pack_propagate(False)

        # Left: mission story + mode
        c=self._card(left,"MISSION CONTEXT","Tell the platform what you are seeing. This becomes reasoning context.")
        self.story=tk.Text(c,height=11,bg="#091523",fg=self.TEXT,insertbackground=self.CYAN,relief="flat",wrap="word",font=("Segoe UI",10),padx=10,pady=10)
        self.story.pack(fill="both",expand=True); self.story.insert("1.0","Example: The API returns different data for two roles. Login works, but one endpoint behaves strangely when object IDs change.")
        row=tk.Frame(c,bg=self.PANEL); row.pack(fill="x",pady=(10,0)); ttk.Label(row,text="OPERATING MODE",style="Muted.TLabel").pack(side="left"); ttk.Combobox(row,textvariable=self.mode,values=["Python","AI","Hybrid"],state="readonly",width=10).pack(side="right")
        ttk.Checkbutton(c,text="I confirm this engagement is authorized and the target is in scope",variable=self.authorized).pack(anchor="w",pady=(12,0))

        c=self._card(left,"SPECIALIST MAP","Live routing preview based on your story and objective.")
        self.spec_frame=tk.Frame(c,bg=self.PANEL); self.spec_frame.pack(fill="x")
        self._refresh_specialists()
        ttk.Button(c,text="REFRESH SPECIALIST MAP",command=self._refresh_specialists).pack(fill="x",pady=(12,0))

        # Middle: intelligence workspace
        c=self._card(mid,"INTELLIGENCE WORKSPACE","Your reasoning surface — advisor, attack paths, rare cases and specialist debate.")
        tabs=ttk.Notebook(c); tabs.pack(fill="both",expand=True)
        self.advice_tab=tk.Frame(tabs,bg=self.PANEL); self.path_tab=tk.Frame(tabs,bg=self.PANEL); self.rare_tab=tk.Frame(tabs,bg=self.PANEL); self.debate_tab=tk.Frame(tabs,bg=self.PANEL)
        tabs.add(self.advice_tab,text="  ADVISOR  "); tabs.add(self.path_tab,text="  ATTACK PATH  "); tabs.add(self.rare_tab,text="  RARE CASE  "); tabs.add(self.debate_tab,text="  SPECIALIST LOOP  ")
        self._build_advisor(); self._build_path(); self._build_rare(); self._build_debate()

        # Right: action center + telemetry
        c=self._card(right,"ACTION CENTER","Named capabilities only. No arbitrary shell execution.")
        buttons=[("PRECHECK","preflight"),("DISCOVER","python"),("AI REASON","ai"),("HYBRID AUTOPILOT","hybrid"),("EXPLOIT ASSURANCE","exploit"),("BUILD REPORT","report")]
        for label,kind in buttons:
            style="Primary.TButton" if kind in ("hybrid","exploit") else "TButton"
            ttk.Button(c,text=label,style=style,command=lambda k=kind:self._action(k)).pack(fill="x",pady=3)
        self.stop_btn=ttk.Button(c,text="STOP / RETURN TO READY",style="Danger.TButton",command=self._stop); self.stop_btn.pack(fill="x",pady=(10,0))

        c=self._card(right,"RUN TELEMETRY","Transparent activity stream.")
        row=tk.Frame(c,bg=self.PANEL); row.pack(fill="x",pady=(0,10)); ttk.Label(row,text="CURRENT PHASE",style="Muted.TLabel").pack(side="left"); ttk.Label(row,textvariable=self.phase,style="Metric.TLabel").pack(side="right")
        self.progress=ttk.Progressbar(c,mode="indeterminate"); self.progress.pack(fill="x",pady=(0,10))
        self.output=tk.Text(c,height=18,bg="#06101b",fg="#cbd9e8",insertbackground=self.CYAN,relief="flat",wrap="word",font=("Consolas",9),padx=10,pady=10)
        self.output.pack(fill="both",expand=True)
        self._write("V3.69 workspace online.\nReady for an authorized engagement.\n")

        footer=tk.Frame(self,bg="#050c15"); footer.pack(fill="x",side="bottom")
        tk.Label(footer,text="GOVERNED EXECUTION",bg="#050c15",fg=self.CYAN,font=("Segoe UI",8,"bold")).pack(side="left",padx=24,pady=8)
        tk.Label(footer,text="scope  •  authorization  •  approvals  •  registered tools  •  evidence  •  audit",bg="#050c15",fg=self.MUTED,font=("Segoe UI",8)).pack(side="left")
        ttk.Label(footer,textvariable=self.status,style="Muted.TLabel").pack(side="right",padx=24)

    def _field(self,parent,label,var,col,width,browse=False):
        box=tk.Frame(parent,bg=self.PANEL); box.grid(row=0,column=col,padx=8,pady=10,sticky="ew")
        tk.Label(box,text=label,bg=self.PANEL,fg=self.MUTED,font=("Segoe UI",7,"bold")).pack(anchor="w")
        e=ttk.Entry(box,textvariable=var,width=width); e.pack(side="left",fill="x",expand=True,pady=(3,0))
        if browse: ttk.Button(box,text="…",width=3,command=lambda:self._browse(var,label)).pack(side="right",padx=(4,0))

    def _text(self,parent,height=20):
        t=tk.Text(parent,bg="#091523",fg=self.TEXT,insertbackground=self.CYAN,relief="flat",wrap="word",font=("Segoe UI",10),padx=12,pady=12,height=height)
        t.pack(fill="both",expand=True); return t

    def _build_advisor(self):
        top=tk.Frame(self.advice_tab,bg=self.PANEL); top.pack(fill="x",padx=12,pady=12)
        self.question=tk.StringVar(value="Is this approach feasible, and what should I test first?")
        ttk.Entry(top,textvariable=self.question).pack(side="left",fill="x",expand=True); ttk.Button(top,text="ASK AI",style="Primary.TButton",command=self._ask).pack(side="left",padx=(8,0))
        self.advice=self._text(self.advice_tab); self.advice.insert("1.0","Ask the advisor about feasibility, approach, attack paths, unusual behavior, or what evidence you need.")

    def _build_path(self):
        row=tk.Frame(self.path_tab,bg=self.PANEL); row.pack(fill="x",padx=12,pady=12); ttk.Button(row,text="BUILD ATTACK PATH",style="Primary.TButton",command=self._attack_path).pack(side="left")
        self.path=self._text(self.path_tab); self.path.insert("1.0","Attack-path intelligence will appear here.")

    def _build_rare(self):
        row=tk.Frame(self.rare_tab,bg=self.PANEL); row.pack(fill="x",padx=12,pady=12); ttk.Button(row,text="INVESTIGATE RARE CASE",style="Primary.TButton",command=self._rare).pack(side="left")
        self.rare=self._text(self.rare_tab); self.rare.insert("1.0","Describe strange, intermittent, contradictory, or previously unseen behavior in Mission Context.")

    def _build_debate(self):
        row=tk.Frame(self.debate_tab,bg=self.PANEL); row.pack(fill="x",padx=12,pady=12); ttk.Button(row,text="RUN SPECIALIST REASONING LOOP",style="Primary.TButton",command=self._debate).pack(side="left")
        self.debate=self._text(self.debate_tab); self.debate.insert("1.0","Specialists will challenge, corroborate and refine one another here.")

    def _refresh_specialists(self):
        for w in self.spec_frame.winfo_children(): w.destroy()
        selected=select_specialists(story=self.story.get("1.0","end").strip() if hasattr(self,"story") else "", objective=self.question.get() if hasattr(self,"question") else "adaptive security assessment", max_specialists=6)
        for x in selected:
            chip=tk.Frame(self.spec_frame,bg="#10263a",highlightbackground=self.BORDER,highlightthickness=1); chip.pack(fill="x",pady=3)
            tk.Label(chip,text=x["specialist"].upper(),bg="#10263a",fg=self.CYAN,font=("Segoe UI",8,"bold")).pack(side="left",padx=8,pady=7)
            tk.Label(chip,text=f"score {x['score']}  |  {', '.join(x['signals'][:4]) or 'broad coverage'}",bg="#10263a",fg=self.MUTED,font=("Segoe UI",8)).pack(side="left")

    def _workspace(self):
        root=self.out.get().strip() or str(ROOT/"output"/"gui-engagement")
        if self.conversation is None or self.conversation.root != Path(root): self.conversation=SecurityConversation(root,target=self.target.get().strip(),engagement=self.client.get().strip())
        return self.conversation

    def _ask(self):
        q=self.question.get().strip()
        if not q: return
        try:
            d=self._workspace().ask(q,story=self.story.get("1.0","end").strip())
            text=d.get("answer","")+"\n\nRECOMMENDED APPROACH\n"+"\n".join("• "+x for x in d.get("recommendation",[]))
            self._set(self.advice,text); self._set(self.path,"Advisor updated. Build the attack path when you are ready."); self._refresh_specialists()
        except Exception as e: messagebox.showerror("Advisor",str(e))

    def _attack_path(self):
        try:
            d=self._workspace().attack_path(story=self.story.get("1.0","end").strip())
            lines=[f"Coverage: {d['coverage']['node_count']} nodes / {d['coverage']['edge_count']} edges",""]
            for p in d.get("next_paths",[])[:8]: lines.append(f"{p['priority'].upper():6}  {p['class']:<16}  gain={p['information_gain']}  {p['objective']}")
            self._set(self.path,"\n".join(lines) or "No candidate path yet.")
        except Exception as e: messagebox.showerror("Attack path",str(e))

    def _rare(self):
        problem=self.story.get("1.0","end").strip() or self.question.get().strip()
        try:
            d=self._workspace().investigate_rare(problem,story=problem)
            lines=["ANALOGOUS CASES"]+[f"• {x.get('case_id')}  similarity={x.get('similarity')}  {x.get('lesson')}" for x in d.get("analogous_cases",[])][:6]
            lines += ["","NOVEL HYPOTHESES"]+[f"• {x.get('hypothesis')}\n  Test: {x.get('test')}" for x in d.get("novel_hypotheses",[])[:6]]
            self._set(self.rare,"\n".join(lines))
        except Exception as e: messagebox.showerror("Rare case",str(e))

    def _debate(self):
        if not self.authorized.get(): messagebox.showwarning("Authorization required","Confirm the engagement is authorized first."); return
        self._start_ai_loop("reasoning")

    def _set(self,w,text): w.delete("1.0","end"); w.insert("1.0",text)

    def _browse(self,var,label):
        p=filedialog.askopenfilename(initialdir=str(ROOT),filetypes=[("Text","*.txt"),("All","*.*")]) if label=="SCOPE" else filedialog.askdirectory(initialdir=str(ROOT))
        if p: var.set(p)

    def _base(self): return [sys.executable,str(ROOT/"securityctl.py"),"pentest","-c",self.client.get().strip(),"-t",self.target.get().strip(),"-o",self.out.get().strip(),"--scope",self.scope.get().strip()]
    def _preflight(self): return [sys.executable,str(ROOT/"securityctl.py"),"preflight","-c",self.client.get().strip(),"-t",self.target.get().strip(),"-o",self.out.get().strip(),"--scope",self.scope.get().strip()]

    def _action(self,kind):
        if self.running: return messagebox.showinfo("Assessment running","An assessment is already running.")
        if kind in {"python","ai","hybrid","exploit","report"} and not self.authorized.get(): return messagebox.showwarning("Authorization required","Confirm the engagement is authorized and the target is in scope.")
        if kind=="preflight": return self._start(self._preflight(),"Preflight")
        if kind=="python": return self._start(self._base()+["--phases","recon,probe,ports,dns,tls,web,api,authenticated,adaptive,intelligence,final","--authorize"],"Python assessment")
        if kind=="exploit": return self._start(self._base()+["--phases","exploitation-assurance,exploitation-loop","--authorize"],"Exploitation assurance")
        if kind=="report": return self._start(self._base()+["--phases","report","--authorize"],"Reporting")
        return self._start_ai_loop(kind)

    def _start_ai_loop(self,mode):
        story=self.story.get("1.0","end").strip(); objective=self.question.get().strip() or "adaptive security assessment"
        code='''from pathlib import Path\nfrom security_platform.core.engagement import Engagement\nfrom security_platform.core.policy import ScopePolicy\nfrom security_platform.engines import PentestEngine\nfrom modules.specialist_reasoning_loop_v369 import run_loop\nimport os\ne=Engagement(CLIENT,TARGET,Path(OUT).resolve(),Path(SCOPE).resolve())\np=ScopePolicy.from_file(e.scope_file,e.target_host)\nengine=PentestEngine(e,p)\nprint(run_loop(engine=engine,objective=OBJECTIVE,story=STORY,max_rounds=3,max_specialists=5,approval_token=os.getenv("SECURITY_AI_APPROVAL_TOKEN",""),authorized=True))\n'''
        vals={"CLIENT":self.client.get().strip(),"TARGET":self.target.get().strip(),"OUT":self.out.get().strip(),"SCOPE":self.scope.get().strip(),"OBJECTIVE":objective,"STORY":story}
        for k,v in vals.items(): code=code.replace(k,repr(v))
        self._start([sys.executable,"-c",code],"Specialist reasoning loop")

    def _start(self,argv,label):
        self.running=True; self.status.set("RUNNING"); self.phase.set(label); self.progress.start(12); self.badge.config(text="●  RUNNING",bg="#3a2d12",fg=self.AMBER); self.command_text=" ".join(shlex.quote(str(x)) for x in argv); self._write("\n$ "+self.command_text+"\n")
        def worker():
            try:
                p=subprocess.run(argv,cwd=str(ROOT),text=True,capture_output=True,timeout=7200); self.q.put(("done",p.returncode,p.stdout,p.stderr))
            except Exception as e: self.q.put(("error",-1,"",repr(e)))
        threading.Thread(target=worker,daemon=True).start()

    def _stop(self):
        # subprocesses are not force-killed here; this is a UI state reset and
        # avoids pretending that a named capability can be safely interrupted at any point.
        self.status.set("READY"); self.phase.set("Standing by"); self.progress.stop(); self.badge.config(text="●  READY",bg="#10362f",fg=self.CYAN); self._write("\n[UI returned to READY; active child work, if any, is governed by its process lifecycle.]\n")

    def _write(self,s): self.output.insert("end",s); self.output.see("end")
    def _drain(self):
        try:
            while True:
                typ,code,out,err=self.q.get_nowait(); self.running=False; self.progress.stop(); self.status.set("READY" if code==0 else "FAILED"); self.phase.set("Completed" if code==0 else "Needs attention"); self.badge.config(text="●  READY" if code==0 else "●  FAILED",bg="#10362f" if code==0 else "#431d2a",fg=self.CYAN if code==0 else self.RED)
                if out: self._write(out[-30000:])
                if err: self._write("\n[stderr]\n"+err[-12000:])
                self._write(f"\n[exit code: {code}]\n")
        except queue.Empty: pass
        self.after(100,self._drain)

if __name__=="__main__": App().mainloop()

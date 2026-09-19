#!/usr/bin/env python3
"""
Interactive Menu System for the Pentest Framework
"""

import os
import sys
from pathlib import Path

def clear():
    print('\033[2J\033[H', end='') if os.name != 'nt' else None

def print_header():
    print("=" * 60)
    print("   SECURITY PLATFORM v2.0")
    print("   Professional Authorized Testing Assistant")
    print("=" * 60)

def main_menu():
    while True:
        clear()
        print_header()
        print("""
[1] Web Application Assessment (Full)
[2] Web + API Assessment
[3] Authenticated Web Scan
[4] External Server Enumeration
[5] Internal Network Scan
[6] Active Directory Guidance
[7] Engagement Workspace + Intelligence
[8] Assessment Intelligence + Validation Queue
[9] Controlled Validation
[10] Advanced Investigation Engine
[11] Knowledge Base
[12] Operator Workspace
[13] Case Management
[14] Risk & Attack-Path Analytics
[15] Engagement Workflow
[16] V24–V26 Data Intelligence
[17] V27–V29 Remediation / Retest / Closure
[18] V30–V32 Controlled Exploitation / Evidence / Risk
[19] V33–V35 Controlled Proof Adapters / Policy / Planner
[20] V36–V38 Proof Expansion / Guard / Analytics
[21] V39–V41 Pentest Mission Engine
[22] V45–V47 Deep Web/API Assessment
[23] V48–V50 Adaptive Web/API Assessment Engine
[24] V51–V53 Authentication & Authorization Intelligence
[25] V54–V56 Session & Identity Intelligence
[26] V57–V59 API Security Intelligence
[27] V60–V62 Business Logic & Workflow Intelligence
[28] V63–V70 COMPLETE ASSESSMENT PLATFORM
[29] Run Custom Command Line
[30] Exit
""")
        choice = input("Select option → ").strip()

        if choice == "1":
            return "web-full"
        elif choice == "2":
            return "web-api"
        elif choice == "3":
            return "auth-web"
        elif choice == "4":
            return "server"
        elif choice == "5":
            return "internal"
        elif choice == "6":
            return "ad"
        elif choice == "7":
            return "report"
        elif choice == "8":
            return "assessment"
        elif choice == "9":
            return "validate"
        elif choice == "10":
            return "investigation"
        elif choice == "11":
            return "knowledge"
        elif choice == "12":
            return "workspace"
        elif choice == "13":
            return "case"
        elif choice == "14":
            return "risk"
        elif choice == "15":
            return "workflow"
        elif choice == "16":
            return "data-intelligence"
        elif choice == "17":
            return "lifecycle"
        elif choice == "18":
            return "controlled-exploit"
        elif choice == "19":
            return "proof-plan"
        elif choice == "20":
            return "proof-v38"
        elif choice == "21":
            return "mission"
        elif choice == "22":
            return "web-deep"
        elif choice == "23":
            return "web-adaptive"
        elif choice == "24":
            return "auth-intelligence"
        elif choice == "25":
            return "session-intelligence"
        elif choice == "26":
            return "api-security"
        elif choice == "27":
            return "business-logic"
        elif choice == "28":
            return "complete"
        elif choice == "29":
            return "custom"
        elif choice == "30":
            print("Exiting.")
            sys.exit(0)
        else:
            input("Invalid choice. Press Enter to continue...")

def get_target_info():
    print("\n--- Engagement Details ---")
    client = input("Client name: ").strip() or "client"
    target = input("Target (domain / IP / CIDR): ").strip()
    if not target:
        print("Target is required.")
        sys.exit(1)
    return client, target

def get_auth_info():
    print("\n--- Authentication (optional) ---")
    cookie = input("Session Cookie (leave empty if none): ").strip()
    bearer = input("Bearer Token (leave empty if none): ").strip()
    return cookie, bearer

# V57–V59 API Security Intelligence is exposed through orchestrator.py --api-engine.

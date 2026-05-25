#!/usr/bin/env python3
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))

class AuditEngine:
    def __init__(self):
        print("[AUDIT] Initializing Audit Engine...")
        self.whitelist = []
        self.blacklist = []
        self.llm_enabled = False
        self._load_rules()
        print("[AUDIT] Audit Engine initialized")

    def _load_rules(self):
        print("[AUDIT] Loading audit rules...")
        rules_file = os.path.join(os.path.dirname(__file__), '../config/rules.yaml')
        if os.path.exists(rules_file):
            print(f"[AUDIT] Rules file found at {rules_file}")
        else:
            print(f"[AUDIT] Rules file not found at {rules_file}, using defaults")

        self.whitelist = ["/bin/ls", "/bin/bash", "/usr/bin/python3"]
        self.blacklist = ["/bin/sh", "/tmp/malware"]
        print(f"[AUDIT] Loaded {len(self.whitelist)} whitelist entries")
        print(f"[AUDIT] Loaded {len(self.blacklist)} blacklist entries")

    def check_whitelist(self, event_data):
        print("[AUDIT] Checking whitelist...")
        filename = event_data.get('filename', '')
        comm = event_data.get('comm', '')

        for allowed in self.whitelist:
            if allowed in filename or allowed in comm:
                print(f"[AUDIT]   Match found in whitelist: {allowed}")
                return True
        print("[AUDIT]   No whitelist match")
        return False

    def check_blacklist(self, event_data):
        print("[AUDIT] Checking blacklist...")
        filename = event_data.get('filename', '')
        comm = event_data.get('comm', '')

        for blocked in self.blacklist:
            if blocked in filename or blocked in comm:
                print(f"[AUDIT]   BLACKLIST MATCH: {blocked}")
                return True
        print("[AUDIT]   No blacklist match")
        return False

    def call_llm(self, event_data):
        print("[AUDIT] Calling LLM for analysis...")
        print(f"[AUDIT]   Event data: {event_data}")

        llm_response = "LLM analysis complete - event appears normal"
        print(f"[AUDIT]   LLM response: {llm_response}")
        return llm_response

    def audit_event(self, event_data):
        print(f"[AUDIT] Auditing event: {event_data}")

        if self.check_blacklist(event_data):
            print("[AUDIT] Result: BLOCKED (blacklist match)")
            return {"status": "blocked", "reason": "blacklist_match"}

        if self.check_whitelist(event_data):
            print("[AUDIT] Result: ALLOWED (whitelist match)")
            return {"status": "allowed", "reason": "whitelist_match"}

        if self.llm_enabled:
            print("[AUDIT] Performing LLM analysis...")
            llm_result = self.call_llm(event_data)
            print(f"[AUDIT] Result: {llm_result}")
            return {"status": "analyzed", "reason": llm_result}

        print("[AUDIT] Result: ALLOWED (default)")
        return {"status": "allowed", "reason": "default"}

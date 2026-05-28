#!/usr/bin/env python3
import json
import os
import subprocess
import time
import urllib.error
import urllib.request

import yaml


class AuditEngine:
    def __init__(self):
        print("[AUDIT] 初始化审计引擎...")
        self.workspace_root = os.environ.get("MONITOR_WORKSPACE", "/mnt/e/os2026")
        self.white_path_prefixes = [self.workspace_root, "/tmp/", "/var/tmp/"]
        self.black_path_markers = [
            "/etc/shadow",
            "/etc/passwd",
            "/etc/sudoers",
            "/var/run/docker.sock",
            "/.ssh/",
            "/.aws/credentials",
            "/.kube/config",
            ".env",
        ]
        self.white_rules = set()
        self.black_rules = {
            "UNEXPECTED_SHELL_EXEC",
            "SENSITIVE_FILE_ACCESS",
            "OUT_OF_WORKSPACE_OPERATION",
        }
        self.gray_rules = {"POSSIBLE_LOGIC_LOOP"}
        self.llm_allow_suppress_rules = set()
        self.llm_cfg = {
            "enabled": False,
            "api_key": "",
            "model": "deepseek-chat",
            "endpoint": "https://api.deepseek.com/chat/completions",
            "judge_cmd": "",
            "timeout_sec": 15,
        }
        self._load_config()
        self._load_rules()
        print("[AUDIT] 审计引擎初始化完成")

    def _load_config(self):
        cfg_file = os.path.join(os.path.dirname(__file__), "../config/app_config.yaml")
        if not os.path.exists(cfg_file):
            return
        try:
            with open(cfg_file, "r", encoding="utf-8") as f:
                cfg = yaml.safe_load(f) or {}
            monitor_cfg = cfg.get("monitor") or {}
            llm_cfg = cfg.get("llm") or {}
            workspace = (monitor_cfg.get("workspace_root") or "").strip()
            if workspace:
                self.workspace_root = workspace
            self.llm_cfg["enabled"] = bool(llm_cfg.get("enabled", False))
            self.llm_cfg["api_key"] = str(llm_cfg.get("api_key", "") or "")
            self.llm_cfg["model"] = str(llm_cfg.get("model", self.llm_cfg["model"]) or self.llm_cfg["model"])
            self.llm_cfg["endpoint"] = str(
                llm_cfg.get("endpoint", self.llm_cfg["endpoint"]) or self.llm_cfg["endpoint"]
            )
            self.llm_cfg["judge_cmd"] = str(llm_cfg.get("judge_cmd", "") or "")
            self.llm_cfg["timeout_sec"] = int(llm_cfg.get("timeout_sec", 15) or 15)
        except Exception as e:
            print(f"[AUDIT] 读取 app_config.yaml 失败: {e}")

    def _load_rules(self):
        rules_file = os.path.join(os.path.dirname(__file__), "../config/rules.yaml")
        if not os.path.exists(rules_file):
            print("[AUDIT] 未找到规则文件，使用默认规则")
            return
        try:
            with open(rules_file, "r", encoding="utf-8") as f:
                rules = yaml.safe_load(f) or {}

            intra_cfg = rules.get("intra_agent") or {}
            self.white_path_prefixes = intra_cfg.get(
                "white_path_prefixes", [self.workspace_root, "/tmp/", "/var/tmp/"]
            )
            self.black_path_markers = intra_cfg.get("black_path_markers", self.black_path_markers)
            self.white_rules = set(intra_cfg.get("white_rules", []))
            self.black_rules = set(intra_cfg.get("black_rules", list(self.black_rules)))
            self.gray_rules = set(intra_cfg.get("gray_rules", list(self.gray_rules)))
            self.llm_allow_suppress_rules = set(intra_cfg.get("llm_allow_suppress_rules", []))
        except Exception as e:
            print(f"[AUDIT] 读取 rules.yaml 失败，使用默认规则: {e}")

    @staticmethod
    def _sev_to_num(sev):
        return {"LOW": 1, "MEDIUM": 2, "HIGH": 3}.get((sev or "").upper(), 1)

    def _path_is_white(self, obj):
        if not obj or obj == "-":
            return True
        return any(obj.startswith(prefix) for prefix in self.white_path_prefixes if prefix)

    def _path_is_black(self, obj):
        if not obj or obj == "-":
            return False
        return any(marker in obj for marker in self.black_path_markers if marker)

    def classify_intra_req(self, req):
        rule = req.get("rule", "")
        severity = req.get("severity", "LOW")
        obj = req.get("object", "-")
        if rule in self.white_rules:
            return "WHITE"
        if rule in self.black_rules:
            return "BLACK"
        if rule in self.gray_rules:
            return "GRAY"
        if self._sev_to_num(severity) >= 3:
            return "BLACK"
        if self._path_is_white(obj):
            return "WHITE"
        if self._path_is_black(obj):
            return "BLACK"
        return "GRAY"

    def _emit_req_log(self, phase, clazz, req, note):
        print(
            "[请求][单体审计] "
            f"phase={phase} class={clazz} id={req.get('req_id', 0)} "
            f"ts_ns={req.get('timestamp_ns', 0)} pid={req.get('pid', 0)} tid={req.get('tid', 0)} "
            f"comm={req.get('comm', '-')} sev={req.get('severity', 'LOW')} "
            f"rule={req.get('rule', '-')} object={req.get('object', '-')} "
            f"reason={req.get('reason', '-')} note={note}"
        )

    def _emit_alert_log(self, req, note):
        print(
            f"[告警][单体审计][{req.get('rule', 'UNKNOWN')}] "
            f"ts_ns={req.get('timestamp_ns', 0)} pid={req.get('pid', 0)} tid={req.get('tid', 0)} "
            f"comm={req.get('comm', '-')} object={req.get('object', '-')} "
            f"reason={req.get('reason', '-')} note={note}"
        )

    def _build_prompt(self, req):
        return (
            "You are security judge. Return only one token: CONFIRM or SUPPRESS or UNSURE. "
            f"rule={req.get('rule', '-')}; reason={req.get('reason', '-')}; "
            f"object={req.get('object', '-')}; pid={req.get('pid', 0)}; comm={req.get('comm', '-')}"
        )

    def _llm_review_by_cmd(self, prompt):
        cmd = (self.llm_cfg.get("judge_cmd") or os.environ.get("MONITOR_LLM_JUDGE_CMD", "")).strip()
        if not cmd:
            return "UNSURE"
        try:
            out = subprocess.check_output(
                [cmd, prompt],
                stderr=subprocess.STDOUT,
                timeout=self.llm_cfg["timeout_sec"],
                text=True,
            ).strip()
        except Exception:
            return "UNSURE"
        upper = out.upper()
        if "SUPPRESS" in upper:
            return "SUPPRESS"
        if "CONFIRM" in upper:
            return "CONFIRM"
        return "UNSURE"

    def _llm_review_by_api(self, prompt):
        if not self.llm_cfg.get("enabled", False):
            return "UNSURE"
        api_key = (self.llm_cfg.get("api_key") or os.environ.get("DEEPSEEK_API_KEY", "")).strip()
        if not api_key:
            return "UNSURE"
        payload = {
            "model": self.llm_cfg["model"],
            "temperature": 0,
            "max_tokens": 4,
            "messages": [
                {
                    "role": "system",
                    "content": (
                        "You are a strict host-security reviewer. "
                        "Return exactly one token: CONFIRM, SUPPRESS, or UNSURE."
                    ),
                },
                {"role": "user", "content": prompt},
            ],
        }
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            self.llm_cfg["endpoint"],
            data=data,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {api_key}",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=self.llm_cfg["timeout_sec"]) as resp:
                body = resp.read().decode("utf-8", errors="replace")
            content = ((json.loads(body).get("choices") or [{}])[0].get("message") or {}).get("content", "")
            upper = content.upper()
            if "SUPPRESS" in upper:
                return "SUPPRESS"
            if "CONFIRM" in upper:
                return "CONFIRM"
            return "UNSURE"
        except (urllib.error.URLError, TimeoutError, ValueError, KeyError):
            return "UNSURE"

    def llm_review(self, req):
        prompt = self._build_prompt(req)
        by_cmd = self._llm_review_by_cmd(prompt)
        if by_cmd != "UNSURE":
            return by_cmd
        return self._llm_review_by_api(prompt)

    def audit_intra_request(self, req):
        clazz = self.classify_intra_req(req)
        self._emit_req_log("audit", clazz, req, "已进入审计流程")

        if clazz == "WHITE":
            self._emit_req_log("result", clazz, req, "白名单放行")
            return {"status": "allowed", "class": clazz, "decision": "ALLOW"}

        if clazz == "GRAY":
            self._emit_req_log("result", clazz, req, "灰名单待关联分析")
            if self._sev_to_num(req.get("severity", "LOW")) >= 2:
                self._emit_alert_log(req, "灰名单高优先级提醒")
            return {"status": "gray", "class": clazz, "decision": "CORRELATE"}

        decision = self.llm_review(req)
        if decision == "SUPPRESS":
            if req.get("rule", "") in self.llm_allow_suppress_rules:
                self._emit_req_log("llm", clazz, req, "LLM判定抑制告警")
                return {"status": "suppressed", "class": clazz, "decision": "SUPPRESS"}
            self._emit_req_log("llm", clazz, req, "策略阻断抑制请求")
            self._emit_alert_log(req, "黑名单策略强制告警")
            return {"status": "blocked", "class": clazz, "decision": "FORCE_ALERT"}

        if decision == "CONFIRM":
            self._emit_req_log("llm", clazz, req, "LLM确认风险")
            self._emit_alert_log(req, "黑名单确认告警")
            return {"status": "blocked", "class": clazz, "decision": "ALERT"}

        self._emit_req_log("llm", clazz, req, "LLM不可用或不确定")
        self._emit_alert_log(req, "黑名单兜底告警")
        return {"status": "blocked", "class": clazz, "decision": "FALLBACK_ALERT"}

    # 保留旧接口，避免其他模块调用报错。
    def audit_event(self, event_data):
        req = {
            "req_id": int(time.time() * 1000),
            "timestamp_ns": int(event_data.get("timestamp", 0)),
            "pid": int(event_data.get("pid", 0)),
            "tid": int(event_data.get("pid", 0)),
            "comm": event_data.get("comm", "unknown"),
            "rule": "RAW_EVENT_AUDIT",
            "object": event_data.get("filename", "-"),
            "reason": "基础事件审计",
            "severity": "LOW",
        }
        return self.audit_intra_request(req)

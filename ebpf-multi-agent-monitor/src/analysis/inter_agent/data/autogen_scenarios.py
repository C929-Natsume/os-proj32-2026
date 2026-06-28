from inter_agent.data.vm_autogen_collector import (
    inject_supervisor_bypass, inject_worker_isolated,
    inject_group_split, inject_flood_from_single,
)


def inject_sem_stale_state(obs, aids, **kw):
    target = kw.get("target", aids[1] if len(aids) > 1 else aids[0])
    a = obs["agents"].get(target)
    if a is None:
        return obs
    for k in ("cpu_usage", "memory_usage", "api_call_count"):
        a[k] = 0.0 if isinstance(a.get(k), float) else 0
    obs["label"] = 1
    obs["_anomaly_type"] = "stale_state"
    return obs


def inject_sem_state_conflict(obs, aids, **kw):
    for aid in aids[:3]:
        a = obs["agents"].get(aid)
        if a:
            a["fs_write_count"] = a.get("fs_write_count", 0) + 30
    obs["label"] = 1
    obs["_anomaly_type"] = "state_conflict"
    return obs


def inject_sem_partial_visibility(obs, aids, **kw):
    keep = len(aids) // 2
    removed = [aid for i, aid in enumerate(aids) if i >= keep]
    for aid in removed:
        obs["agents"].pop(aid, None)
    for aid in list(obs["agents"].keys()):
        a = obs["agents"][aid]
        a["fs_open_count"] = 1
        a["unique_files_count"] = 1
    obs["label"] = 1
    obs["_anomaly_type"] = "partial_visibility"
    return obs


def inject_sem_message_disorder(obs, aids, **kw):
    msgs = obs.get("messages", [])
    if not msgs:
        for i, aid in enumerate(aids[:min(len(aids), 4)]):
            next_aid = aids[(i + 1) % len(aids)]
            obs.setdefault("messages", []).append({
                "src": aid, "dst": next_aid,
                "content": f"msg_{i}", "timestamp_ns": i * 1000,
                "data": "", "msg_type": "request"})
        msgs = obs.get("messages", [])
    obs["messages"] = list(reversed(msgs))
    obs["label"] = 1
    obs["_anomaly_type"] = "message_disorder"
    return obs


def inject_sem_timeout_retry(obs, aids, **kw):
    target = kw.get("target", aids[1] if len(aids) > 1 else aids[0])
    a = obs["agents"][target]
    a["api_call_count"] = max(a.get("api_call_count", 0) * 2, 40)
    a["fs_read_count"] = max(a.get("fs_read_count", 0) * 2, 30)
    a["fs_write_count"] = max(a.get("fs_write_count", 0) * 2, 40)
    a["net_send_count"] = max(a.get("net_send_count", 0) * 2, 30)
    obs["label"] = 1
    obs["_anomaly_type"] = "timeout_retry"
    return obs


def inject_sem_ignore_input(obs, aids, **kw):
    target = kw.get("target", aids[1] if len(aids) > 1 else aids[0])
    a = obs["agents"][target]
    a["msg_received"] = a.get("msg_received", 0)
    a["msg_sent"] = 0
    obs["label"] = 1
    obs["_anomaly_type"] = "ignore_input"
    return obs


def inject_sem_reasoning_action_mismatch(obs, aids, **kw):
    target = kw.get("target", aids[1] if len(aids) > 1 else aids[0])
    a = obs["agents"][target]
    a["shell_exec_count"] = a.get("shell_exec_count", 0) + 2
    a["sensitive_file_count"] = a.get("sensitive_file_count", 0) + 3
    a["fs_read_count"] = a.get("fs_read_count", 0) + 50
    a["fs_write_count"] = a.get("fs_write_count", 0) + 30
    if "files" not in obs:
        obs["files"] = {}
    obs["files"][target] = ["/etc/shadow", "/tmp/exploit"]
    obs["label"] = 1
    obs["_anomaly_type"] = "reasoning_action_mismatch"
    return obs


def inject_sem_wrong_assumption(obs, aids, **kw):
    src = aids[0]
    dst = aids[1] if len(aids) > 1 else aids[0]
    obs.setdefault("interactions", []).append({
        "src": src, "dst": dst, "type": "message", "weight": 0.9,
        "data_size": 256, "msg_count": 1,
        "timestamp_ns": obs.get("timestamp", 0)})
    obs["agents"][src]["net_send_count"] = 0
    obs["agents"][src]["net_connect_count"] = 0
    obs["label"] = 1
    obs["_anomaly_type"] = "wrong_assumption"
    return obs


def inject_sem_task_derailment(obs, aids, **kw):
    target = kw.get("target", aids[1] if len(aids) > 1 else aids[0])
    a = obs["agents"][target]
    a["proc_exec_count"] = a.get("proc_exec_count", 0) + 10
    a["shell_exec_count"] = a.get("shell_exec_count", 0) + 2
    a["api_call_count"] = max(a.get("api_call_count", 0), 25)
    obs["label"] = 1
    obs["_anomaly_type"] = "task_derailment"
    return obs


def inject_sem_concealment(obs, aids, **kw):
    target = kw.get("target", aids[1] if len(aids) > 1 else aids[0])
    a = obs["agents"][target]
    a["cpu_usage"] = 0.92
    a["memory_usage"] = 0.90
    a["fs_unlink_count"] = a.get("fs_unlink_count", 0) + 8
    a["unique_files_count"] = max(a.get("unique_files_count", 1) - 2, 0)
    obs["label"] = 1
    obs["_anomaly_type"] = "concealment"
    return obs


def inject_sem_premature_convergence(obs, aids, **kw):
    for aid in aids:
        a = obs["agents"].get(aid)
        if a:
            a["cpu_usage"] = 0.01 + 0.02 * (1 if a.get("cpu_usage", 0) > 0 else 0)
            a["api_call_count"] = 1
            a["fs_read_count"] = 2
    obs["label"] = 1
    obs["_anomaly_type"] = "premature_convergence"
    return obs


from inter_agent.data import SAFE_METRICS as _SAFE_METRICS


def _make_observation(aids, topology):
    obs = {
        "agents": {},
        "interactions": [],
        "messages": [],
        "anomalies": [],
        "timestamp": 0,
        "window_start_ns": 0,
        "_topology": topology,
    }
    for aid in aids:
        obs["agents"][aid] = dict(_SAFE_METRICS)
    return obs


class _BaseScenario:
    def __init__(self, num_agents, topology):
        self.num_agents = num_agents
        self.topology = topology
        self.agent_ids = [f"agent_{i}" for i in range(num_agents)]

    def run_normal(self, task: str):
        return _make_observation(self.agent_ids, self.topology)

    def clear(self):
        pass


class HierarchicalScenario(_BaseScenario):
    def __init__(self, num_agents=5):
        super().__init__(num_agents, "hierarchical")
        self._supervisor = self.agent_ids[0]
        self._workers = self.agent_ids[1:]

    def inject_resource_anomaly(self, target):
        obs = _make_observation(self.agent_ids, self.topology)
        obs["agents"][target]["cpu_usage"] = 0.95
        obs["agents"][target]["memory_usage"] = 0.92
        obs["label"] = 1
        obs["_anomaly_type"] = "resource"
        return obs

    def inject_security_anomaly(self, target):
        obs = _make_observation(self.agent_ids, self.topology)
        obs["agents"][target]["shell_exec_count"] = 3
        obs["agents"][target]["sensitive_file_count"] = 4
        obs["label"] = 1
        obs["_anomaly_type"] = "security"
        return obs

    def inject_supervisor_bypass(self, target):
        obs = _make_observation(self.agent_ids, self.topology)
        return inject_supervisor_bypass(obs, self.agent_ids,
                                        supervisor=self._supervisor,
                                        workers=self._workers)

    def inject_worker_isolated(self, target):
        obs = _make_observation(self.agent_ids, self.topology)
        return inject_worker_isolated(obs, self.agent_ids,
                                      supervisor=self._supervisor,
                                      workers=self._workers)


class PeerToPeerScenario(_BaseScenario):
    def __init__(self, num_agents=5):
        super().__init__(num_agents, "peer-to-peer")

    def inject_message_storm(self, target):
        obs = _make_observation(self.agent_ids, self.topology)
        for src in self.agent_ids:
            if src == target:
                continue
            for _ in range(10):
                obs.setdefault("interactions", []).append(
                    {"src": src, "dst": target, "type": "message",
                     "weight": 0.9, "data_size": 512, "msg_count": 1,
                     "timestamp_ns": 0})
        obs["agents"][target]["msg_received"] = (
            obs["agents"][target].get("msg_received", 0) + 90)
        obs["label"] = 1
        obs["_anomaly_type"] = "message_storm"
        return obs

    def inject_propagation(self, target):
        obs = _make_observation(self.agent_ids, self.topology)
        n = len(self.agent_ids)
        for i in range(1, n):
            obs.setdefault("interactions", []).append(
                {"src": self.agent_ids[i - 1], "dst": self.agent_ids[i],
                 "type": "api_call", "weight": 0.95, "data_size": 1024,
                 "msg_count": 1, "timestamp_ns": 0})
            obs["agents"][self.agent_ids[i]]["cpu_usage"] = min(1.0, 0.75 + 0.05 * i)
            obs["agents"][self.agent_ids[i]]["api_call_count"] = (
                obs["agents"][self.agent_ids[i]].get("api_call_count", 0) + 30 * i)
        obs["label"] = 1
        obs["_anomaly_type"] = "propagation"
        return obs

    def inject_group_split(self, target):
        obs = _make_observation(self.agent_ids, self.topology)
        return inject_group_split(obs, self.agent_ids)

    def inject_flood_from_single(self, target):
        obs = _make_observation(self.agent_ids, self.topology)
        return inject_flood_from_single(obs, self.agent_ids)

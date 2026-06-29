def inject_supervisor_bypass(obs, aids, **kw):
    supervisor = kw.get("supervisor", aids[0] if aids else "agent_0")
    workers = kw.get("workers",
                     [a for a in aids if a != supervisor][:3])
    for w in workers:
        for w2 in workers:
            if w < w2:
                obs.setdefault("interactions", []).append({
                    "src": w, "dst": w2, "type": "bypass",
                    "weight": 0.9, "data_size": 512, "msg_count": 1,
                    "timestamp_ns": obs.get("timestamp", 0)})
    obs["label"] = 1
    obs["_anomaly_type"] = "supervisor_bypass"
    return obs


def inject_worker_isolated(obs, aids, **kw):
    supervisor = kw.get("supervisor", aids[0] if aids else "agent_0")
    workers = kw.get("workers",
                     [a for a in aids if a != supervisor][:3])
    isolated = workers[0] if workers else aids[-1]
    a = obs["agents"].get(isolated, {})
    for k in ("msg_sent", "msg_received", "net_send_count",
              "net_recv_count", "net_connect_count"):
        a[k] = 0
    obs["label"] = 1
    obs["_anomaly_type"] = "worker_isolated"
    return obs


def inject_group_split(obs, aids, **kw):
    if len(aids) < 2:
        raise ValueError("group_split needs >= 2 agents")
    mid = len(aids) // 2
    group_a = aids[:mid]
    group_b = aids[mid:]
    for src in group_a:
        for dst in group_b:
            obs.setdefault("interactions", []).append({
                "src": src, "dst": dst, "type": "api_call",
                "weight": 0.1, "data_size": 32, "msg_count": 1,
                "timestamp_ns": obs.get("timestamp", 0)})
    obs["label"] = 1
    obs["_anomaly_type"] = "group_split"
    return obs


def inject_flood_from_single(obs, aids, **kw):
    src = aids[0] if aids else "agent_0"
    dsts = [a for a in aids if a != src]
    if len(dsts) < 2:
        raise ValueError("flood_from_single needs >= 3 agents")
    for dst in dsts:
        for _ in range(5):
            obs.setdefault("messages", []).append({
                "src": src, "dst": dst, "msg_type": "request",
                "data_size": 128,
                "timestamp_ns": obs.get("timestamp", 0)})
    if src in obs.setdefault("agents", {}):
        obs["agents"][src]["msg_sent"] = obs["agents"][src].get("msg_sent", 0) + 5 * len(aids)
    obs["label"] = 1
    obs["_anomaly_type"] = "flood_from_single"
    return obs

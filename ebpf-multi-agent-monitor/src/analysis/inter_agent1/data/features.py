import logging
import numpy as np
from typing import Dict, List, Optional, Tuple

CONTENT_FEATURE_DIM = 16
NODE_FEATURE_DIM = 14 + CONTENT_FEATURE_DIM  # 14 base + 16 content = 30
EDGE_FEATURE_DIM = 6

# Normalization divisors for magnitude features
_API_DIVISOR = 100.0
_MSG_DIVISOR = 100.0
_IO_DIVISOR = 200.0
_UF_DIVISOR = 10.0
_DATA_SIZE_DIVISOR = 8192.0
_MSG_COUNT_DIVISOR = 100.0

# Clip limits for ratio features
_MSG_TO_API_CLIP = 2.0
_IO_TO_FSOPEN_CLIP = 5.0
_NET_TO_PROC_CLIP = 3.0


def extract_node_features(
    agents_data: Dict[str, dict],
    agent_ids: List[str],
    interactions: Optional[List[dict]] = None,
) -> np.ndarray:
    x = np.zeros((len(agent_ids), NODE_FEATURE_DIM), dtype=np.float32)
    content_feats = {}
    if interactions is not None:
        try:
            from inter_agent.data.text_encoder import ContentFeatureExtractor
            content_feats = ContentFeatureExtractor().extract(
                agents_data, agent_ids, interactions
            )
        except Exception:
            logger = logging.getLogger(__name__)
            logger.debug("ContentFeatureExtractor failed, using zeros")
    for i, aid in enumerate(agent_ids):
        info = agents_data.get(aid, {})
        cpu = float(info.get("cpu_usage", 0))
        mem = float(info.get("memory_usage", 0))
        api = float(info.get("api_call_count", 0))
        msg_s = float(info.get("msg_sent", 0))
        msg_r = float(info.get("msg_received", 0))
        msg = msg_s + msg_r
        shell = float(info.get("shell_exec_count", 0))
        sensitive = float(info.get("sensitive_file_count", 0))
        fs_r = float(info.get("fs_read_count", 0))
        fs_w = float(info.get("fs_write_count", 0))
        io_total = fs_r + fs_w
        uf = float(info.get("unique_files_count", 0))
        fs_open = float(info.get("fs_open_count", 0))
        proc_exec = float(info.get("proc_exec_count", 0))
        net_conn = float(info.get("net_connect_count", 0))

        x[i, 0] = min(cpu, 1.0)
        x[i, 1] = min(mem, 1.0)
        x[i, 2] = min(api / _API_DIVISOR, 1.0)
        x[i, 3] = min(msg / _MSG_DIVISOR, 1.0)
        x[i, 4] = min(shell, 1.0)
        x[i, 5] = min(sensitive, 1.0)
        x[i, 6] = min(io_total / _IO_DIVISOR, 1.0)
        x[i, 7] = min(uf / _UF_DIVISOR, 1.0)

        x[i, 8] = min(msg / (api + 1.0), _MSG_TO_API_CLIP) / _MSG_TO_API_CLIP
        x[i, 9] = min(io_total / (fs_open + 1.0), _IO_TO_FSOPEN_CLIP) / _IO_TO_FSOPEN_CLIP
        x[i, 10] = min(shell / (proc_exec + 1.0), 1.0)
        x[i, 11] = min(sensitive / (fs_open + 1.0), 1.0)
        x[i, 12] = abs(msg_s - msg_r) / (msg + 1.0)
        net_total = net_conn + msg
        x[i, 13] = min(net_total / (fs_open + proc_exec + 1.0), _NET_TO_PROC_CLIP) / _NET_TO_PROC_CLIP

        if aid in content_feats:
            cf = content_feats[aid]
            for k in range(min(len(cf), CONTENT_FEATURE_DIM)):
                x[i, 14 + k] = min(float(cf[k]), 1.0)
    return x


def extract_edge_attributes(
    interactions: List[dict],
    aid_to_idx: Dict[str, int],
) -> Optional[np.ndarray]:
    type_map = {"message": 0, "api_call": 1, "file_share": 2, "bypass": 1}
    if not interactions:
        return None
    attrs = []
    for e in interactions:
        i = aid_to_idx.get(e["src"])
        j = aid_to_idx.get(e["dst"])
        if i is None or j is None:
            continue
        t = type_map.get(e.get("type", "message"), 0)
        w = float(e.get("weight", 0.5))
        ds = float(e.get("data_size", 0)) / _DATA_SIZE_DIVISOR
        mc = float(e.get("msg_count", 0)) / _MSG_COUNT_DIVISOR
        onehot = [0.0, 0.0, 0.0]
        onehot[t] = 1.0
        attrs.append(onehot + [w, min(ds, 1.0), min(mc, 1.0)])
    if not attrs:
        return None
    return np.array(attrs, dtype=np.float32)

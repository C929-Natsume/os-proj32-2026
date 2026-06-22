import numpy as np


class FeatureExtractor:
    """Extracts node and edge features from observation data.

    Node features (22-dim):
      8 magnitude + 6 ratio + 8 content features

    Edge features (6-dim):
      [type_onehot(3), weight, frequency, data_size]
    """

    def extract_node_features(self, agents_data: dict, agent_ids: list,
                              interactions: list = None):
        use_content = interactions is not None
        content_feats = {}
        if use_content:
            from inter_agent.data.text_encoder import ContentFeatureExtractor
            content_feats = ContentFeatureExtractor().extract(agents_data, agent_ids, interactions)

        features = {}
        for aid in agent_ids:
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

            f0 = min(cpu, 1.0)
            f1 = min(mem, 1.0)
            f2 = min(api / 100.0, 1.0)
            f3 = min(msg / 100.0, 1.0)
            f4 = min(shell, 1.0)
            f5 = min(sensitive, 1.0)
            f6 = min(io_total / 200.0, 1.0)
            f7 = min(uf / 10.0, 1.0)
            f8 = min(msg / (api + 1.0), 2.0) / 2.0
            f9 = min(io_total / (fs_open + 1.0), 5.0) / 5.0
            f10 = min(shell / (proc_exec + 1.0), 1.0)
            f11 = min(sensitive / (fs_open + 1.0), 1.0)
            f12 = abs(msg_s - msg_r) / (msg + 1.0)
            net_total = net_conn + msg
            f13 = min(net_total / (fs_open + proc_exec + 1.0), 3.0) / 3.0

            arr = [f0, f1, f2, f3, f4, f5, f6, f7,
                   f8, f9, f10, f11, f12, f13]
            if aid in content_feats:
                arr.extend(min(float(content_feats[aid][k]), 1.0) for k in range(8))
            features[aid] = np.array(arr, dtype=np.float32)
        return features

    def extract_edge_features(self, interactions: list):
        features = {}
        type_map = {"api_call": 0, "message": 1, "file_share": 2}
        for it in interactions:
            src, dst = it["src"], it["dst"]
            t = type_map.get(it.get("type", "message"), 1)
            w = float(it.get("weight", 1.0))
            one_hot = np.zeros(3, dtype=np.float32)
            one_hot[t] = 1.0
            features[(src, dst)] = np.concatenate([
                one_hot,
                [w, 0.0, 0.0]
            ]).astype(np.float32)
        return features

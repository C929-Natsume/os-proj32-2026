import numpy as np
import os
from typing import Optional, Dict, Tuple

try:
    import torch
    import torch.nn as nn
    import torch.nn.functional as F
    HAS_TORCH = True
except ImportError:
    HAS_TORCH = False
    nn = None


def build_adjacency_matrix(num_nodes, edge_index):
    """Build dense adjacency matrix from edge_index with self-loops.

    Returns [N, N] tensor with 1.0 where edge exists or on diagonal, 0 elsewhere.
    """
    adj = torch.eye(num_nodes, device=edge_index.device, dtype=torch.float)
    if edge_index.size(1) > 0:
        adj[edge_index[0], edge_index[1]] = 1.0
    return adj


if HAS_TORCH:
    class StructureDecoder(nn.Module):
        """Dot-product adjacency decoder (GUARDIAN style).

        Takes node embeddings [N, D], produces [N, N] adjacency logits.
        Decode(z) = Linear(z) @ Linear(z).T
        """
        def __init__(self, hidden_dim):
            super().__init__()
            self.linear = nn.Linear(hidden_dim, hidden_dim)

        def forward(self, z):
            z_t = self.linear(z)
            return z_t @ z_t.t()

    class EdgeDecoder(nn.Module):
        """Reconstruct edge attributes from paired node embeddings.

        For each edge (u,v): concat(z_u, z_v) → MLP → [edge_dim]
        """
        def __init__(self, hidden_dim, edge_dim):
            super().__init__()
            self.mlp = nn.Sequential(
                nn.Linear(hidden_dim * 2, 32),
                nn.ReLU(),
                nn.Linear(32, edge_dim),
            )

        def forward(self, z, edge_index):
            z_u = z[edge_index[0]]
            z_v = z[edge_index[1]]
            return self.mlp(torch.cat([z_u, z_v], dim=1))

    # ── Encoders ────────────────────────────────────────────────────────

    class GCNEncoder(nn.Module):
        """Multi-layer GCN encoder with optional skip connections.

        Supports 1-3 layers. When n_layers > 1, intermediate layers use
        hidden_dim and skip connections sum layer outputs.
        """
        def __init__(self, in_dim, hidden_dim, n_layers=1, dropout=0.1):
            super().__init__()
            from torch_geometric.nn import GCNConv
            self.n_layers = n_layers
            self.dropout = dropout
            layers = []
            layers.append(GCNConv(in_dim, hidden_dim))
            for _ in range(1, n_layers):
                layers.append(GCNConv(hidden_dim, hidden_dim))
            self.convs = nn.ModuleList(layers)

        def forward(self, x, edge_index, edge_attr=None):
            xs = []
            for i, conv in enumerate(self.convs):
                x = conv(x, edge_index)
                x = F.relu(x)
                x = F.dropout(x, p=self.dropout, training=self.training)
                xs.append(x)
            if self.n_layers > 1:
                x = torch.stack(xs).sum(dim=0)
            return x

    class GATEncoder(nn.Module):
        """Multi-layer GAT encoder with multi-head attention.

        Uses GATv2Conv (dynamic attention). First layer uses heads=4,
        later layers use heads=1 (for consistent output dim).
        """
        def __init__(self, in_dim, hidden_dim, n_layers=1, dropout=0.1,
                     heads=4, edge_dim=None):
            super().__init__()
            from torch_geometric.nn import GATv2Conv
            self.n_layers = n_layers
            self.dropout = dropout

            layers = []
            first_heads = heads
            if edge_dim is not None and edge_dim > 0:
                layers.append(GATv2Conv(
                    in_dim, hidden_dim // first_heads,
                    heads=first_heads, dropout=dropout, edge_dim=edge_dim,
                ))
            else:
                layers.append(GATv2Conv(
                    in_dim, hidden_dim // first_heads,
                    heads=first_heads, dropout=dropout,
                ))
            for _ in range(1, n_layers):
                layers.append(GATv2Conv(
                    hidden_dim, hidden_dim, heads=1, dropout=dropout,
                ))
            self.convs = nn.ModuleList(layers)

        def forward(self, x, edge_index, edge_attr=None):
            xs = []
            for i, conv in enumerate(self.convs):
                if i == 0 and edge_attr is not None:
                    x = conv(x, edge_index, edge_attr)
                else:
                    x = conv(x, edge_index)
                x = F.relu(x)
                x = F.dropout(x, p=self.dropout, training=self.training)
                xs.append(x)
            if self.n_layers > 1:
                x = torch.stack(xs).sum(dim=0)
            return x

    ENCODER_REGISTRY = {
        "gcn": GCNEncoder,
        "gat": GATEncoder,
    }

    # ── DOMINANT ────────────────────────────────────────────────────────

    class DOMINANT(nn.Module):
        """Deep Graph Anomaly Detection model with optional VGAE variant.

        Supports:
          - GCN or GAT encoder
          - variable encoder depth (1-3 layers)
          - edge features (passed to encoder if supported)
          - VGAE variant with KL loss
        """
        def __init__(self, in_dim=8, hidden_dim=64, latent_dim=64,
                     feature_weight=0.65, struct_weight=None,
                     edge_weight=0.2,
                     encoder_type="gcn", n_layers=1,
                     variant="deterministic", edge_dim=None):
            super().__init__()
            self.variant = variant
            self.feature_weight = feature_weight
            self.struct_weight = struct_weight if struct_weight is not None else (1.0 - feature_weight - 0.2)
            self.edge_weight = edge_weight
            self.edge_dim = edge_dim

            EncoderClass = ENCODER_REGISTRY.get(encoder_type, GCNEncoder)
            if encoder_type == "gat":
                self.encoder = EncoderClass(
                    in_dim, hidden_dim, n_layers=n_layers,
                    edge_dim=edge_dim,
                )
            else:
                self.encoder = EncoderClass(
                    in_dim, hidden_dim, n_layers=n_layers,
                )

            out_dim = hidden_dim
            self.attr_decoder = nn.Sequential(
                nn.Linear(out_dim, 32),
                nn.ReLU(),
                nn.Linear(32, in_dim),
            )
            self.struct_decoder = StructureDecoder(out_dim)
            if edge_dim and edge_dim > 0:
                self.edge_decoder = EdgeDecoder(out_dim, edge_dim)
            else:
                self.edge_decoder = None

            if variant == "variational":
                self.mu_proj = nn.Linear(out_dim, latent_dim)
                self.log_var_proj = nn.Linear(out_dim, latent_dim)
            else:
                self.latent_proj = nn.Linear(out_dim, latent_dim)

        def reparameterize(self, mu, log_var):
            std = torch.exp(0.5 * log_var)
            eps = torch.randn_like(std)
            return mu + eps * std

        def encode(self, x, edge_index, edge_attr=None):
            kwargs = {}
            if edge_attr is not None and self.edge_dim:
                kwargs["edge_attr"] = edge_attr
            z = self.encoder(x, edge_index, **kwargs)
            return z

        def forward(self, x, edge_index, edge_attr=None):
            z = self.encode(x, edge_index, edge_attr)
            if self.variant == "variational":
                mu = self.mu_proj(z)
                log_var = self.log_var_proj(z)
                z = self.reparameterize(mu, log_var)
                x_recon = self.attr_decoder(z)
                adj_recon = self.struct_decoder(z)
                edge_recon = self.edge_decoder(z, edge_index) if self.edge_decoder and edge_attr is not None else None
                return x_recon, adj_recon, edge_recon, z, mu, log_var
            else:
                z = self.latent_proj(z)
                x_recon = self.attr_decoder(z)
                adj_recon = self.struct_decoder(z)
                edge_recon = self.edge_decoder(z, edge_index) if self.edge_decoder and edge_attr is not None else None
                return x_recon, adj_recon, edge_recon, z

        def compute_loss(self, x, edge_index, edge_attr=None, topology=None):
            """Compute DOMINANT loss with feat + struct + edge terms.

            For VGAE variant, adds KL divergence loss.
            """
            if self.variant == "variational":
                x_recon, adj_recon, edge_recon, _, mu, log_var = self.forward(x, edge_index, edge_attr)
            else:
                x_recon, adj_recon, edge_recon, _ = self.forward(x, edge_index, edge_attr)

            feat_var = x.var(dim=0).mean().detach() + 1e-8
            feat_loss = F.mse_loss(x_recon, x, reduction="mean") / feat_var

            adj_true = build_adjacency_matrix(x.size(0), edge_index)
            n_pos = adj_true.sum()
            n_neg = adj_true.numel() - n_pos
            pos_weight = (n_neg / n_pos).detach() if n_pos > 0 else torch.tensor(1.0)
            struct_loss = F.binary_cross_entropy_with_logits(
                adj_recon, adj_true, pos_weight=pos_weight, reduction="mean"
            )

            loss = self.feature_weight * feat_loss.clamp(max=1e3) + self.struct_weight * struct_loss

            edge_loss = torch.tensor(0.0)
            if edge_recon is not None and edge_attr is not None:
                edge_loss = F.mse_loss(edge_recon, edge_attr, reduction="mean")
                loss = loss + self.edge_weight * edge_loss.clamp(max=1e3)

            if self.variant == "variational":
                kl_loss = -0.5 * torch.mean(1 + log_var - mu.pow(2) - log_var.exp())
                loss = loss + kl_loss
                return loss, feat_loss, struct_loss, edge_loss, kl_loss

            return loss, feat_loss, struct_loss, edge_loss

        def compute_anomaly_scores(self, x, edge_index, edge_attr=None, topology=None):
            """Per-node anomaly scores based on reconstruction error.

            Args:
                x: node features [N, F]
                edge_index: [2, E]
                edge_attr: edge attributes [E, D] or None
                topology: "hierarchical", "peer-to-peer", or None for uniform weighting.

            Returns (node_scores, feat_err_mean, struct_err_mean, edge_err_mean, z).
            """
            if self.variant == "variational":
                x_recon, adj_recon, edge_recon, z, _, _ = self.forward(x, edge_index, edge_attr)
            else:
                x_recon, adj_recon, edge_recon, z = self.forward(x, edge_index, edge_attr)

            adj_true = build_adjacency_matrix(x.size(0), edge_index)
            feat_err = (x - x_recon).pow(2).mean(dim=1).detach().cpu().numpy()
            adj_probs = torch.sigmoid(adj_recon)
            struct_err = (adj_probs - adj_true).pow(2).mean(dim=1).detach().cpu().numpy()

            scores = self.feature_weight * feat_err + self.struct_weight * struct_err

            edge_err_mean = 0.0
            if edge_recon is not None and edge_attr is not None:
                edge_err = (edge_recon - edge_attr).pow(2).mean(dim=1).detach().cpu().numpy()
                edge_err_mean = float(edge_err.mean())

                # Topology-aware edge weights
                edge_weights = np.ones(edge_err.shape[0], dtype=np.float32)
                if topology == "hierarchical":
                    # Hierarchical: supervisor is agent_0 (index 0), workers are 1..N-1
                    # Worker↔Worker edges (bypass) get 3x weight; Supervisor↔Worker edges get 1x
                    for k in range(edge_index.size(1)):
                        u = edge_index[0, k].item()
                        v = edge_index[1, k].item()
                        if u > 0 and v > 0:
                            edge_weights[k] = 3.0
                elif topology == "peer-to-peer":
                    # P2P: all edges equally expected; flood patterns (high msg_count)
                    # already encoded in edge_attr; missing edges penalized via struct_err
                    pass

                # Map per-edge error back to nodes: each node gets mean of incident edge errors
                edge_node_err = np.zeros(x.size(0), dtype=np.float32)
                edge_node_count = np.zeros(x.size(0), dtype=np.int32)
                for k in range(edge_index.size(1)):
                    u = edge_index[0, k].item()
                    v = edge_index[1, k].item()
                    err_k = edge_err[k] * edge_weights[k]
                    edge_node_err[u] += err_k
                    edge_node_err[v] += err_k
                    edge_node_count[u] += 1
                    edge_node_count[v] += 1
                edge_node_err = np.divide(edge_node_err, np.maximum(edge_node_count, 1),
                                          out=np.zeros_like(edge_node_err))
                scores = scores + self.edge_weight * edge_node_err

            return scores, float(feat_err.mean()), float(struct_err.mean()), edge_err_mean, z

    class AnomalyClassifier(nn.Module):
        """Per-node anomaly classifier.

        Takes [N, latent_dim] node embeddings, returns [N] logits.
        Each node independently classified as normal(0) or anomalous(1).
        """
        def __init__(self, latent_dim=16, hidden_dim=8):
            super().__init__()
            self.mlp = nn.Sequential(
                nn.Linear(latent_dim, hidden_dim),
                nn.ReLU(),
                nn.Linear(hidden_dim, 1),
            )

        def forward(self, z):
            return self.mlp(z).squeeze(-1)

else:
    class DOMINANT:
        def __init__(self, **kwargs):
            pass
        def forward(self, *args, **kwargs):
            raise RuntimeError("PyTorch not available")
        def compute_loss(self, *args, **kwargs):
            raise RuntimeError("PyTorch not available")
        def compute_anomaly_scores(self, *args, **kwargs):
            raise RuntimeError("PyTorch not available")

    class AnomalyClassifier:
        def __init__(self, **kwargs):
            pass
        def forward(self, *args, **kwargs):
            raise RuntimeError("PyTorch not available")


# ── Feature extraction ──────────────────────────────────────────────────────

def extract_features(agents_data: Dict[str, dict], agent_ids: list,
                     interactions: list = None) -> np.ndarray:
    """Extract node features: 14-dim (no content) or 22-dim (with content)."""
    use_content = interactions is not None
    dim = 22 if use_content else 14
    x = np.zeros((n := len(agent_ids), dim), dtype=np.float32)

    content_feats = {}
    if use_content:
        from inter_agent.data.text_encoder import ContentFeatureExtractor
        content_feats = ContentFeatureExtractor().extract(agents_data, agent_ids, interactions)

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

        # Magnitude features (8 dims)
        x[i, 0] = min(cpu, 1.0)
        x[i, 1] = min(mem, 1.0)
        x[i, 2] = min(api / 100.0, 1.0)
        x[i, 3] = min(msg / 100.0, 1.0)
        x[i, 4] = min(shell, 1.0)
        x[i, 5] = min(sensitive, 1.0)
        x[i, 6] = min(io_total / 200.0, 1.0)
        x[i, 7] = min(uf / 10.0, 1.0)

        # Ratio features (6 dims)
        x[i, 8] = min(msg / (api + 1.0), 2.0) / 2.0
        x[i, 9] = min(io_total / (fs_open + 1.0), 5.0) / 5.0
        x[i,10] = min(shell / (proc_exec + 1.0), 1.0)
        x[i,11] = min(sensitive / (fs_open + 1.0), 1.0)
        x[i,12] = abs(msg_s - msg_r) / (msg + 1.0)
        net_total = net_conn + msg
        x[i,13] = min(net_total / (fs_open + proc_exec + 1.0), 3.0) / 3.0

        if aid in content_feats:
            cf = content_feats[aid]
            for k in range(8):
                x[i, 14 + k] = min(float(cf[k]), 1.0)
    return x


def extract_edge_attr(interactions: list, aid_to_idx: dict) -> Optional[np.ndarray]:
    """Extract 6-dim edge attributes: [type_onehot(3), weight, data_size_norm, msg_count_norm].

    Returns None if no edges.
    """
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
        ds = float(e.get("data_size", 0)) / 8192.0
        mc = float(e.get("msg_count", 0)) / 100.0
        onehot = [0.0, 0.0, 0.0]
        onehot[t] = 1.0
        attrs.append(onehot + [w, min(ds, 1.0), min(mc, 1.0)])
    if not attrs:
        return None
    return np.array(attrs, dtype=np.float32)


# ── AnomalyDetector ─────────────────────────────────────────────────────────

class AnomalyDetector:
    def __init__(self, node_dim=14, hidden_dim=64, latent_dim=64,
                 feature_weight=0.3, model_path=None,
                 encoder_type="gcn", n_layers=1, variant="deterministic"):
        self._node_dim = node_dim
        self._latent_dim = latent_dim
        self._feature_weight = feature_weight
        self._model = None
        self._classifier = None
        self._loaded = False

        if HAS_TORCH:
            self._model = DOMINANT(
                node_dim, hidden_dim, latent_dim, feature_weight,
                encoder_type=encoder_type, n_layers=n_layers,
                variant=variant, edge_dim=6,
            )
            self._classifier = AnomalyClassifier(latent_dim)
            if model_path and os.path.isfile(model_path):
                self.load_pretrained(model_path)

    def load_pretrained(self, model_path: str):
        if not HAS_TORCH:
            return False
        try:
            ckpt = torch.load(model_path, map_location="cpu", weights_only=False)
            self._model.load_state_dict(ckpt["model_state_dict"])
            self._classifier.load_state_dict(ckpt["classifier_state_dict"])
            self._model.eval()
            self._classifier.eval()
            self._loaded = True
            return True
        except Exception as e:
            import logging
            logging.getLogger(__name__).warning(
                "Failed to load model from %s: %s", model_path, e
            )
            return False

    @property
    def is_loaded(self):
        return self._loaded

    def detect(self, x, edge_index, edge_attr=None, topology=None):
        if not HAS_TORCH or self._model is None:
            scores = np.zeros(x.shape[0])
            return {"anomaly_scores": scores, "anomaly_nodes": [], "recon_error": 0.0,
                    "edge_error": 0.0, "cls_probability": [], "graph_score": 0.0}
        try:
            x_t = torch.from_numpy(x).float() if isinstance(x, np.ndarray) else x.float()
            ei = edge_index
            if isinstance(ei, np.ndarray):
                ei = torch.from_numpy(ei).long()
            ea = None
            if edge_attr is not None:
                ea = torch.from_numpy(edge_attr).float() if isinstance(edge_attr, np.ndarray) else edge_attr.float()

            if not self._loaded:
                return {"anomaly_scores": np.zeros(x_t.size(0)),
                        "anomaly_nodes": [], "recon_error": 0.0,
                        "edge_error": 0.0, "cls_probability": [], "graph_score": 0.0}

            self._model.eval()
            self._classifier.eval()
            with torch.no_grad():
                kw = {}
                if ea is not None:
                    kw["edge_attr"] = ea
                anom_scores, feat_err, struct_err, edge_err, z = self._model.compute_anomaly_scores(
                    x_t, ei, topology=topology, **kw
                )
                cls_logits = self._classifier(z).cpu()
                cls_probs = torch.sigmoid(cls_logits).numpy()

            final_scores = anom_scores * 0.5 + cls_probs * 0.5
            threshold = np.percentile(final_scores, 90) if len(final_scores) > 0 and np.max(final_scores) > 0 else 0.5
            anom_nodes = [i for i, s in enumerate(final_scores) if s > threshold]
            return {
                "anomaly_scores": final_scores,
                "anomaly_nodes": anom_nodes,
                "recon_error": float(feat_err),
                "edge_error": float(edge_err),
                "cls_probability": cls_probs.tolist(),
                "graph_score": float(final_scores.max()) if len(final_scores) > 0 else 0.0,
            }
        except Exception as e:
            scores = np.zeros(x.shape[0])
            return {"anomaly_scores": scores, "anomaly_nodes": [], "recon_error": 0.0,
                    "edge_error": 0.0, "cls_probability": [], "graph_score": 0.0}


# ── RuleBasedDetector ───────────────────────────────────────────────────────

class RuleBasedDetector:
    def __init__(self, config: Optional[dict] = None):
        cfg = config or {}
        self._cpu_max = cfg.get("cpu_usage_max", 0.8)
        self._mem_max = cfg.get("memory_usage_max", 0.8)
        self._api_max = cfg.get("api_call_freq_max", 50)
        self._msg_max = cfg.get("msg_freq_max", 30)
        self._loop_window = cfg.get("loop_window_ns", 30_000_000_000)

    def detect(self, agents_data: dict) -> dict:
        scores = {}
        anomalies = {}
        for aid, info in agents_data.items():
            risk = 0.0
            reasons = []

            cpu = float(info.get("cpu_usage", 0))
            if cpu > self._cpu_max:
                risk = max(risk, min((cpu - self._cpu_max) / 0.2, 1.0) * 0.8)
                reasons.append(f"cpu={cpu:.2f}>{self._cpu_max}")

            mem = float(info.get("memory_usage", 0))
            if mem > self._mem_max:
                risk = max(risk, min((mem - self._mem_max) / 0.2, 1.0) * 0.8)
                reasons.append(f"mem={mem:.2f}>{self._mem_max}")

            api = int(info.get("api_call_count", 0))
            if api > self._api_max:
                risk = max(risk, min((api - self._api_max) / 100.0, 1.0) * 0.7)
                reasons.append(f"api={api}>{self._api_max}")

            msg = int(info.get("msg_sent", 0)) + int(info.get("msg_received", 0))
            if msg > self._msg_max:
                risk = max(risk, min((msg - self._msg_max) / 100.0, 1.0) * 0.6)
                reasons.append(f"msg={msg}>{self._msg_max}")

            shell = int(info.get("shell_exec_count", 0))
            if shell > 0:
                risk = max(risk, 0.9)
                reasons.append(f"shell_exec={shell}")

            sensitive = int(info.get("sensitive_file_count", 0))
            if sensitive > 0:
                risk = max(risk, 0.85)
                reasons.append(f"sensitive_file={sensitive}")

            io_total = (int(info.get("fs_read_count", 0)) +
                        int(info.get("fs_write_count", 0)))
            unique = int(info.get("unique_files_count", 0))
            if io_total > 120 and unique <= 3:
                risk = max(risk, 0.6)
                reasons.append(f"io_loop: io={io_total},files={unique}")

            scores[aid] = min(risk, 1.0)
            if reasons:
                anomalies[aid] = "; ".join(reasons)

        return {"scores": scores, "anomalies": anomalies}

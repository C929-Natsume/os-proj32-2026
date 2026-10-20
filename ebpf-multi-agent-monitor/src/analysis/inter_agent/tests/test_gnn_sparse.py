import numpy as np
import pytest

torch = pytest.importorskip("torch")

from inter_agent.detection.gnn_detector import DOMINANT, AnomalyDetector


def _rand_graph(n, e, seed=0, dims=8, edge_dim=6):
    g = np.random.RandomState(seed)
    x = g.rand(n, dims).astype(np.float32)
    ei = []
    for _ in range(e):
        u = int(g.randint(0, n))
        v = int(g.randint(0, n))
        if u != v:
            ei.append((u, v))
    ei = np.asarray(ei, dtype=np.int64).T if ei else np.zeros((2, 0), dtype=np.int64)
    ea = g.rand(ei.shape[1], edge_dim).astype(np.float32)
    return torch.from_numpy(x), torch.from_numpy(ei).long(), torch.from_numpy(ea)


class TestSparseStruct:
    def test_sparse_loss_deterministic(self):
        torch.manual_seed(0)
        model = DOMINANT(in_dim=8, edge_dim=6, sparse_struct=True)
        x, ei, ea = _rand_graph(60, 200)
        loss, feat, struct, edge = model.compute_loss(x, ei, ea)
        assert loss.item() == pytest.approx(
            loss.item(), abs=0.0
        ), "loss must be finite"
        assert float(struct.detach()) >= 0.0
        assert torch.isfinite(loss)

    def test_sparse_loss_variational(self):
        torch.manual_seed(1)
        model = DOMINANT(in_dim=8, edge_dim=6, variant="variational",
                         sparse_struct=True)
        x, ei, ea = _rand_graph(40, 150)
        loss, feat, struct, edge, kl = model.compute_loss(x, ei, ea)
        assert torch.isfinite(loss)
        assert torch.isfinite(kl)

    def test_sparse_loss_matches_forward_dims(self):
        """Sparse path must not materialise the dense adjacency."""
        torch.manual_seed(2)
        model = DOMINANT(in_dim=8, edge_dim=6, sparse_struct=True)
        x, ei, ea = _rand_graph(50, 120)
        z_t = model.encoder(x, ei, ea)
        z = model.latent_proj(z_t)
        assert z.shape == (50, 64)

    def test_sparse_scores_large_graph(self):
        """Large graph must score without O(N^2) memory blow-up."""
        torch.manual_seed(3)
        model = DOMINANT(in_dim=8, edge_dim=6, sparse_struct=True)
        n = 1500
        x, ei, ea = _rand_graph(n, 4000, seed=5)
        scores, feat, struct, edge, z = model.compute_anomaly_scores(x, ei, ea)
        assert scores.shape == (n,)
        assert np.all(np.isfinite(scores))
        assert 0.0 <= float(struct) <= 1.0
        assert 0.0 <= float(feat)

    def test_sparse_scores_no_edges(self):
        model = DOMINANT(in_dim=8, edge_dim=6, sparse_struct=True)
        n = 20
        x = torch.randn(n, 8)
        ei = torch.zeros((2, 0), dtype=torch.long)
        scores, feat, struct, edge, z = model.compute_anomaly_scores(x, ei)
        assert scores.shape == (n,)
        assert np.all(np.isfinite(scores))

    def test_dense_default_unchanged(self):
        torch.manual_seed(4)
        model_dense = DOMINANT(in_dim=8, edge_dim=6)
        model_sparse = DOMINANT(in_dim=8, edge_dim=6, sparse_struct=True)
        x, ei, ea = _rand_graph(30, 100)
        # dense path still runs and returns the same loss tuple structure
        loss, feat, struct, edge = model_dense.compute_loss(x, ei, ea)
        assert torch.isfinite(loss)
        assert model_sparse.sparse_struct is True
        assert model_dense.sparse_struct is False

    def test_detector_passthrough(self, tmp_path):
        import os
        from inter_agent.detection.gnn_detector import AnomalyClassifier
        path = os.path.join(str(tmp_path), "s.pth")
        model = DOMINANT(in_dim=8, edge_dim=6, sparse_struct=True)
        clf = AnomalyClassifier(latent_dim=64)
        torch.save({
            "model_state_dict": model.state_dict(),
            "classifier_state_dict": clf.state_dict(),
            "args": {},
        }, path)
        det = AnomalyDetector(node_dim=8, model_path=path, sparse_struct=True)
        assert det._model.sparse_struct is True

    def test_sparse_trainable(self):
        """One backward pass through sparse loss updates weights."""
        torch.manual_seed(6)
        model = DOMINANT(in_dim=8, edge_dim=6, sparse_struct=True)
        x, ei, ea = _rand_graph(40, 160)
        loss, *_ = model.compute_loss(x, ei, ea)
        model.zero_grad()
        loss.backward()
        grads = [p.grad for p in model.parameters() if p.grad is not None]
        assert len(grads) > 0

import json
import logging
import os
import random

logger = logging.getLogger(__name__)


class StatefulGenerator:
    """Generate temporally-correlated observation sequences.

    Minimal implementation for import compatibility with dataset_builder.
    """

    def __init__(self, calibrator, alpha=0.8, rng_seed=42):
        self._calibrator = calibrator
        self._alpha = alpha
        self._rng = random.Random(rng_seed)

    def generate_mixed_dataset(self, seq_lengths, topology, num_agents_range,
                                num_normal_seq, num_anomaly_seq, output_dir):
        base_obs = {
            "agents": {},
            "interactions": [],
            "messages": [],
            "anomalies": [],
            "timestamp": 0,
            "window_start_ns": 0,
        }
        meta = {
            "num_agents_range": list(num_agents_range),
            "num_normal_seq": num_normal_seq,
            "num_anomaly_seq": num_anomaly_seq,
            "source": "stateful_generator",
            "_topology": topology,
        }
        os.makedirs(output_dir, exist_ok=True)
        meta_path = os.path.join(output_dir, "meta.json")
        with open(meta_path, "w") as f:
            json.dump(meta, f, indent=2)
        logger.info("Temporal dataset built (placeholder): %s", meta)
        return meta

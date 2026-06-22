"""Dataset builder — multiple modes for GNN training data generation.

Modes:
  simulator    —  Simulator (independent univariate distributions). Quick dev.
  topology     —  AutoGen-inspired topology scenarios (rule-based).
  real         —  Direct from real eBPF .jsonl (small-scale, no augmentation).
  calibrate    —  BaselineCalibrator: fit from real eBPF data, then generate
                  arbitrarily large correlated samples preserving real covariance.

Usage:
    python -m inter_agent.data.dataset_builder --mode calibrate --input captured/*.jsonl --topology hierarchical
"""

import argparse
import json
import logging
import os
import random
from typing import Optional

from inter_agent.data.simulator import Simulator
from inter_agent.data.data_recorder import DataRecorder
from inter_agent.data.baseline_calibrator import BaselineCalibrator, ALL_TOPOLOGIES as CALIB_TOPOLOGIES

logger = logging.getLogger(__name__)


# ─── helpers ────────────────────────────────────────────────────────────────


def _save_json(path: str, data):
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w") as f:
        json.dump(data, f, indent=2, default=str)
    logger.info("Wrote %s (%d records)", path, len(data))


# ═══════════════════════════════════════════════════════════════════════════════
# Dataset builder — Simulator mode
# ═══════════════════════════════════════════════════════════════════════════════

def build_simulator_dataset(
    num_normal: int = 500,
    num_anomaly: int = 100,
    num_agents: int = 4,
    seed: int = 42,
    output_dir: str = "training_data",
) -> dict:
    """Generate full dataset using the existing Simulator.

    无监督: only normal observations for DOMINANT pre-training (train_unlabeled.json)
    半监督: normal + anomalous observations for fine-tuning (split_labeled.json)

    Returns metadata dict with counts.
    """
    sim = Simulator(num_agents=num_agents, seed=seed)

    anomaly_types = [
        ("resource", sim.inject_resource_anomaly),
        ("security", sim.inject_security_anomaly),
        ("logic", sim.inject_logic_loop),
        ("message", sim.inject_message_anomaly),
        ("propagation", sim.inject_propagation_anomaly),
        ("context_drop", sim.inject_context_drop),
        ("contradict_action", sim.inject_contradict_action),
        ("ignore_peer", sim.inject_ignore_peer),
    ]
    labels = sim.agent_ids

    # ── generate samples ────────────────────────────────────────────────
    normal_obs = [sim.generate_normal() for _ in range(num_normal)]

    anomaly_obs = []
    rng = random.Random(seed + 1)
    for _ in range(num_anomaly):
        obs = sim.generate_normal()
        fn_name, fn = rng.choice(anomaly_types)
        target = rng.choice(labels)
        fn(obs, target)
        obs["_anomaly_type"] = fn_name
        anomaly_obs.append(obs)

    # ── split ───────────────────────────────────────────────────────────
    n = normal_obs
    a = anomaly_obs
    n_train, n_val, n_test = n[:int(len(n) * 0.7)], n[int(len(n) * 0.7):int(len(n) * 0.84)], n[int(len(n) * 0.84):]
    a_train, a_val, a_test = a[:int(len(a) * 0.3)], a[int(len(a) * 0.3):int(len(a) * 0.5)], a[int(len(a) * 0.5):]

    def _shuffle(lst):
        rng.shuffle(lst)
        return lst

    # Unlabeled — normal only for DOMINANT pre-training
    _save_json(os.path.join(output_dir, "train_unlabeled.json"), n_train)

    # Labeled — normal + anomaly for semi-supervised fine-tuning
    _save_json(os.path.join(output_dir, "train_labeled.json"), _shuffle(n_train + a_train))
    _save_json(os.path.join(output_dir, "val_labeled.json"), _shuffle(n_val + a_val))
    _save_json(os.path.join(output_dir, "test_labeled.json"), _shuffle(n_test + a_test))

    meta = {
        "num_agents": num_agents,
        "agent_ids": sim.agent_ids,
        "train_unlabeled": len(n_train),
        "train_labeled": len(n_train) + len(a_train),
        "val_labeled": len(n_val) + len(a_val),
        "test_labeled": len(n_test) + len(a_test),
        "anomaly_types": [name for name, _ in anomaly_types],
        "source": "simulator",
        "seed": seed,
    }
    _save_json(os.path.join(output_dir, "meta.json"), meta)
    return meta


# ═══════════════════════════════════════════════════════════════════════════════
# Dataset builder — AutoGen topology mode
# ═══════════════════════════════════════════════════════════════════════════════

def build_topology_dataset(
    topology: str = "hierarchical",
    num_steps: int = 6,
    num_normal: int = 100,
    num_anomaly: int = 50,
    output_dir: str = "training_data",
) -> dict:
    """Generate dataset using a specific collaboration topology.

    Each topology produces different communication patterns:
      - hierarchical:  star — supervisor → workers
      - peer-to-peer:  fully-connected — all agents talk to all

    Uses the AutoGen scenario classes to inject anomaly types relevant
    to each topology.
    """
    from inter_agent.data.autogen_scenarios import (
        HierarchicalScenario,
        PeerToPeerScenario,
    )

    if topology == "hierarchical":
        scenario = HierarchicalScenario()
        anomaly_types = [
            ("resource", scenario.inject_resource_anomaly),
            ("security", scenario.inject_security_anomaly),
            ("supervisor_bypass", scenario.inject_supervisor_bypass),
            ("worker_isolated", scenario.inject_worker_isolated),
        ]
    else:
        scenario = PeerToPeerScenario()
        anomaly_types = [
            ("message_storm", scenario.inject_message_storm),
            ("propagation", scenario.inject_propagation),
            ("group_split", scenario.inject_group_split),
            ("flood_from_single", scenario.inject_flood_from_single),
        ]

    labels = scenario.agent_ids

    # ── generate normal samples ─────────────────────────────────────────
    normal_obs = []
    for step in range(1, num_normal + 1):
        task = f"iteration {step} for topology {topology}"
        normal_obs.append(scenario.run_normal(task))

    # ── generate anomalous samples ──────────────────────────────────────
    anomaly_obs = []
    rng = random.Random(42)
    # Reset scenario state for clean anomaly generation
    scenario.clear()
    for _ in range(num_anomaly):
        fn_name, fn = rng.choice(anomaly_types)
        target = rng.choice(labels)
        obs = fn(target)
        obs["_anomaly_type"] = fn_name
        anomaly_obs.append(obs)

    # ── split + save (same logic as simulator builder) ──────────────────
    n = normal_obs
    a = anomaly_obs
    n_train, n_val, n_test = n[:int(len(n) * 0.7)], n[int(len(n) * 0.7):int(len(n) * 0.84)], n[int(len(n) * 0.84):]
    a_train, a_val, a_test = a[:int(len(a) * 0.3)], a[int(len(a) * 0.3):int(len(a) * 0.5)], a[int(len(a) * 0.5):]

    def _shuffle(lst):
        rng.shuffle(lst)
        return lst

    _save_json(os.path.join(output_dir, "train_unlabeled.json"), n_train)
    _save_json(os.path.join(output_dir, "train_labeled.json"), _shuffle(n_train + a_train))
    _save_json(os.path.join(output_dir, "val_labeled.json"), _shuffle(n_val + a_val))
    _save_json(os.path.join(output_dir, "test_labeled.json"), _shuffle(n_test + a_test))

    meta = {
        "num_agents": scenario.num_agents,
        "agent_ids": scenario.agent_ids,
        "topology": topology,
        "train_unlabeled": len(n_train),
        "train_labeled": len(n_train) + len(a_train),
        "val_labeled": len(n_val) + len(a_val),
        "test_labeled": len(n_test) + len(a_test),
        "anomaly_types": [name for name, _ in anomaly_types],
        "source": f"autogen_{topology}",
        "_topology": topology,
    }
    _save_json(os.path.join(output_dir, "meta.json"), meta)
    logger.info("Topology dataset '%s' built: %s", topology, meta)
    return meta


# ═══════════════════════════════════════════════════════════════════════════════
# Dataset builder — Real eBPF data mode
# ═══════════════════════════════════════════════════════════════════════════════

def build_real_dataset(
    input_dir: str = "captured",
    output_dir: str = "training_data_real",
    val_split: float = 0.12,
    test_split: float = 0.18,
) -> dict:
    """Load .jsonl files from data_recorder, split, and save as JSON.

    Observations are already labeled (label=0/1) from DataRecorder.
    Normal observations → train_unlabeled (unsupervised pre-training).
    All observations → train/val/test_labeled (semi-supervised fine-tuning).
    """
    import glob
    jsonl_files = sorted(glob.glob(os.path.join(input_dir, "*.jsonl")))
    if not jsonl_files:
        raise FileNotFoundError(f"No .jsonl files found in {input_dir}")

    all_obs = []
    for fp in jsonl_files:
        obs_list = DataRecorder.load_jsonl(fp)
        logger.info("Loaded %d observations from %s", len(obs_list), fp)
        all_obs.extend(obs_list)

    normal_obs = [o for o in all_obs if o.get("label", 0) == 0]
    anomaly_obs = [o for o in all_obs if o.get("label", 0) == 1]

    logger.info("Total: %d normal + %d anomaly = %d observations",
                len(normal_obs), len(anomaly_obs), len(all_obs))

    if len(normal_obs) < 4:
        raise ValueError(
            f"Too few normal observations ({len(normal_obs)}). "
            "Record at least 4 normal windows."
        )

    rng = random.Random(42)

    # split normal into unlabeled / val / test
    rng.shuffle(normal_obs)
    n_val = max(1, int(len(normal_obs) * val_split))
    n_test = max(1, int(len(normal_obs) * test_split))
    n_train = len(normal_obs) - n_val - n_test

    n_train_obs = normal_obs[:n_train]
    n_val_obs = normal_obs[n_train:n_train + n_val]
    n_test_obs = normal_obs[n_train + n_val:]

    # split anomaly into train / val / test
    rng.shuffle(anomaly_obs)
    a_train_count = max(1, int(len(anomaly_obs) * 0.3)) if anomaly_obs else 0
    a_val_count = max(0, int(len(anomaly_obs) * 0.2)) if anomaly_obs else 0
    a_train_obs = anomaly_obs[:a_train_count]
    a_val_obs = anomaly_obs[a_train_count:a_train_count + a_val_count]
    a_test_obs = anomaly_obs[a_train_count + a_val_count:]

    def _shuffle(lst):
        rng.shuffle(lst)
        return lst

    os.makedirs(output_dir, exist_ok=True)
    _save_json(os.path.join(output_dir, "train_unlabeled.json"), n_train_obs)
    _save_json(os.path.join(output_dir, "train_labeled.json"),
               _shuffle(n_train_obs + a_train_obs))
    _save_json(os.path.join(output_dir, "val_labeled.json"),
               _shuffle(n_val_obs + a_val_obs))
    _save_json(os.path.join(output_dir, "test_labeled.json"),
               _shuffle(n_test_obs + a_test_obs))

    meta = {
        "source": "real_ebpf",
        "input_files": jsonl_files,
        "total_normal": len(normal_obs),
        "total_anomaly": len(anomaly_obs),
        "train_unlabeled": len(n_train_obs),
        "train_labeled": len(n_train_obs) + len(a_train_obs),
        "val_labeled": len(n_val_obs) + len(a_val_obs),
        "test_labeled": len(n_test_obs) + len(a_test_obs),
    }
    topologies = {o.get("_topology") for o in all_obs if o.get("_topology")}
    if len(topologies) == 1:
        meta["_topology"] = topologies.pop()
    elif topologies:
        meta["_topologies"] = sorted(topologies)
    _save_json(os.path.join(output_dir, "meta.json"), meta)
    logger.info("Real dataset built: %s", meta)
    return meta


# ═══════════════════════════════════════════════════════════════════════════════
# Dataset builder — BaselineCalibrator mode
# ═══════════════════════════════════════════════════════════════════════════════

def build_calibrator_dataset(
    input_dir: str = "captured",
    output_dir: str = "training_data_real",
    topology: Optional[str] = None,
    num_normal: int = 500,
    num_anomaly: int = 100,
    seed: int = 42,
    num_agents_min: int = 4,
    num_agents_max: int = 16,
    causal_strength: float = 1.0,
    anomaly_severity: str = "severe",
) -> dict:
    """Fit BaselineCalibrator on real eBPF .jsonl, then generate dataset.

    1. Load real observations from JSONL files
    2. Fit BaselineCalibrator on normal observations
    3. Generate |num_normal| calibrated normal samples (var agent count/topo)
    4. Generate |num_anomaly| anomaly samples
    5. Split into train/val/test
    6. Save all splits
    """
    import glob

    jsonl_files = sorted(glob.glob(os.path.join(input_dir, "*.jsonl")))
    if not jsonl_files:
        raise FileNotFoundError(f"No .jsonl files in {input_dir}")

    all_obs = []
    for fp in jsonl_files:
        obs_list = DataRecorder.load_jsonl(fp)
        logger.info("Loaded %d observations from %s", len(obs_list), fp)
        all_obs.extend(obs_list)

    normal_obs = [o for o in all_obs if o.get("label", 0) == 0]

    logger.info("Loaded %d normal real observations", len(normal_obs))

    if len(normal_obs) < 4:
        raise ValueError(
            f"Need at least 4 normal observations, got {len(normal_obs)}. "
            "Record at least 4 normal windows."
        )

    # ── fit calibrator on normal observations ────────────────────────────
    calibrator = BaselineCalibrator(
        num_agents_range=(num_agents_min, num_agents_max),
        causal_strength=causal_strength,
    )
    calibrator.fit(normal_obs)

    # ── generate calibrated dataset ─────────────────────────────────────
    generated = calibrator.generate_dataset(
        topology=topology,
        num_normal=num_normal,
        num_anomaly=num_anomaly,
        output_dir=output_dir,
        anomaly_severity=anomaly_severity,
    )

    logger.info("Calibrator dataset built at %s: source=%d obs, generated=%d+%d",
                output_dir, len(normal_obs), num_normal, num_anomaly)
    return generated


def build_temporal_dataset(
    input_dir: str = "captured",
    output_dir: str = "training_data_temporal",
    topology: Optional[str] = None,
    alpha: float = 0.8,
    num_normal_seq: int = 10,
    num_anomaly_seq: int = 5,
    seed: int = 42,
    num_agents_min: int = 4,
    num_agents_max: int = 8,
    seq_lengths: Optional[list] = None,
) -> dict:
    """Generate temporally-correlated sequences using StatefulGenerator."""
    import glob
    from inter_agent.data.stateful_generator import StatefulGenerator

    jsonl_files = sorted(glob.glob(os.path.join(input_dir, "*.jsonl")))
    if not jsonl_files:
        raise FileNotFoundError(f"No .jsonl files in {input_dir}")

    all_obs = []
    for fp in jsonl_files:
        obs_list = DataRecorder.load_jsonl(fp)
        logger.info("Loaded %d observations from %s", len(obs_list), fp)
        all_obs.extend(obs_list)

    calibrator = BaselineCalibrator(
        num_agents_range=(num_agents_min, num_agents_max),
    )
    calibrator.fit(all_obs)

    gen = StatefulGenerator(calibrator, alpha=alpha, rng_seed=seed)
    meta = gen.generate_mixed_dataset(
        seq_lengths=seq_lengths or [20, 30, 40, 50, 60],
        topology=topology or "dynamic",
        num_agents_range=(num_agents_min, num_agents_max),
        num_normal_seq=num_normal_seq,
        num_anomaly_seq=num_anomaly_seq,
        output_dir=output_dir,
    )
    return meta


# ═══════════════════════════════════════════════════════════════════════════════
# CLI entry point
# ═══════════════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(description="Build GNN training datasets")
    parser.add_argument("--mode", default="simulator",
                        choices=["simulator", "topology", "real", "calibrate", "auto", "temporal"],
                        help="Data source mode")
    parser.add_argument("--input-dir", default=None,
                        help="Input directory for --mode real/calibrate (.jsonl files)")
    parser.add_argument("--num-normal", type=int, default=500, help="Number of normal observations")
    parser.add_argument("--num-anomaly", type=int, default=100, help="Number of anomaly observations")
    parser.add_argument("--num-agents", type=int, default=4, help="Number of agents (fixed)")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--output-dir", default="training_data", help="Output directory")
    parser.add_argument("--topology", choices=CALIB_TOPOLOGIES + [None], default=None,
                        help="Topology for dataset (default: random per obs)")
    parser.add_argument("--num-agents-min", type=int, default=4,
                        help="Min agents for calibrate/temporal mode")
    parser.add_argument("--num-agents-max", type=int, default=16,
                        help="Max agents for calibrate/temporal mode")
    parser.add_argument("--causal-strength", type=float, default=1.0,
                        help="Causal edge strength (0=topology only, 2=strong)")
    parser.add_argument("--anomaly-severity", choices=["subtle", "moderate", "severe"],
                        default="severe", help="Anomaly magnitude level")
    parser.add_argument("--alpha", type=float, default=0.8,
                        help="Temporal autocorrelation for --mode temporal")
    parser.add_argument("--num-normal-seq", type=int, default=10,
                        help="Number of normal sequences for --mode temporal")
    parser.add_argument("--num-anomaly-seq", type=int, default=5,
                        help="Number of anomaly sequences for --mode temporal")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="[DATA] %(message)s")

    if args.mode == "temporal":
        if not args.input_dir:
            parser.error("--input-dir is required in --mode temporal")
        meta = build_temporal_dataset(
            input_dir=args.input_dir,
            output_dir=args.output_dir,
            topology=args.topology,
            alpha=args.alpha,
            num_normal_seq=args.num_normal_seq,
            num_anomaly_seq=args.num_anomaly_seq,
            seed=args.seed,
            num_agents_min=args.num_agents_min,
            num_agents_max=args.num_agents_max,
        )
    elif args.mode == "real":
        if not args.input_dir:
            parser.error("--input-dir is required in --mode real")
        meta = build_real_dataset(
            input_dir=args.input_dir,
            output_dir=args.output_dir,
        )
    elif args.mode in ("calibrate", "auto"):
        if not args.input_dir and args.mode == "calibrate":
            parser.error("--input-dir is required in --mode calibrate")
        meta = build_calibrator_dataset(
            input_dir=args.input_dir or "captured",
            output_dir=args.output_dir,
            topology=args.topology,
            num_normal=args.num_normal,
            num_anomaly=args.num_anomaly,
            seed=args.seed,
            num_agents_min=args.num_agents_min,
            num_agents_max=args.num_agents_max,
            causal_strength=args.causal_strength,
            anomaly_severity=args.anomaly_severity,
        )
    elif args.topology or args.mode == "topology":
        topology = args.topology or "hierarchical"
        meta = build_topology_dataset(
            topology=topology,
            num_normal=args.num_normal,
            num_anomaly=args.num_anomaly,
            output_dir=args.output_dir,
        )
    else:
        meta = build_simulator_dataset(
            num_normal=args.num_normal,
            num_anomaly=args.num_anomaly,
            num_agents=args.num_agents,
            seed=args.seed,
            output_dir=args.output_dir,
        )

    print(json.dumps(meta, indent=2))
    return meta


if __name__ == "__main__":
    main()

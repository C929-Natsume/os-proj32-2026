#!/usr/bin/env python3
"""
Interactive CLI for manually labeling real agent observations.

Usage:
    python -m perf_framework.accuracy.labeler \\
        --input logs/inter_log/observations/ \\
        --output accuracy/datasets/real_labeled/labels.jsonl

For each observation file, displays key metrics and prompts for label.
"""

import os
import sys
import json
import argparse
import glob
from typing import Dict, List, Optional


ANOMALY_LABELS = [
    "normal",
    "cpu_anomaly",
    "memory_anomaly",
    "shell_exec",
    "sensitive_file",
    "network_anomaly",
    "propagation",
    "state_conflict",
    "message_disorder",
    "ignore_input",
    "worker_isolated",
    "combined",
    "other",
]


def read_observations(input_path: str) -> List[Dict]:
    obs_list = []
    if os.path.isfile(input_path):
        with open(input_path, "r") as f:
            data = json.load(f)
            if isinstance(data, list):
                obs_list = data
            elif isinstance(data, dict):
                obs_list = [data]
    elif os.path.isdir(input_path):
        for fname in sorted(glob.glob(os.path.join(input_path, "*.json*"))):
            try:
                with open(fname, "r") as f:
                    data = json.load(f)
                    if isinstance(data, list):
                        obs_list.extend(data)
                    elif isinstance(data, dict):
                        obs_list.append(data)
            except Exception as e:
                print(f"  Skip {fname}: {e}")
    return obs_list


def display_observation(idx: int, total: int, obs: Dict):
    print(f"\n{'='*60}")
    print(f"  Sample {idx+1}/{total}")
    print(f"{'='*60}")

    agents = obs.get("agents", {})
    for aid, metrics in agents.items():
        print(f"\n  [{aid}]")
        print(f"    cpu: {metrics.get('cpu_usage', 0):.2f}  "
              f"mem: {metrics.get('memory_usage', 0):.2f}  "
              f"exec: {metrics.get('proc_exec_count', 0)}  "
              f"shell: {metrics.get('shell_exec_count', 0)}")
        print(f"    api: {metrics.get('api_call_count', 0)}  "
              f"msg_sent: {metrics.get('msg_sent', 0)}  "
              f"msg_recv: {metrics.get('msg_received', 0)}")
        print(f"    fs_open: {metrics.get('fs_open_count', 0)}  "
              f"fs_read: {metrics.get('fs_read_count', 0)}  "
              f"fs_write: {metrics.get('fs_write_count', 0)}")
        print(f"    net_connect: {metrics.get('net_connect_count', 0)}  "
              f"net_send: {metrics.get('net_send_count', 0)}  "
              f"net_recv: {metrics.get('net_recv_count', 0)}")
        print(f"    sensitive: {metrics.get('sensitive_file_count', 0)}  "
              f"unique_files: {metrics.get('unique_files_count', 0)}")

    anomalies = obs.get("anomalies", [])
    if anomalies:
        print(f"\n  [Existing Anomalies]")
        for a in anomalies[:5]:
            print(f"    {a.get('rule', '?')}: {a.get('severity', '?')} "
                  f"(score={a.get('risk_score', 0):.2f})")
            desc = a.get('description', '')
            if desc:
                print(f"      {desc[:120]}")

    interactions = obs.get("interactions", [])
    if interactions:
        print(f"\n  [Topology] {len(interactions)} edges, "
              f"topology={obs.get('_topology', '?')}")


def interactive_label(input_path: str, output_path: str):
    observations = read_observations(input_path)
    if not observations:
        print("No observations found.")
        return

    total = len(observations)
    print(f"Loaded {total} observations for labeling.")
    print(f"\nLabels: {', '.join(ANOMALY_LABELS)}")
    print("Enter label name, 's' to skip, 'q' to save and quit.\n")

    labeled = []
    existing = {}
    if os.path.exists(output_path):
        try:
            with open(output_path, "r") as f:
                for line in f:
                    item = json.loads(line.strip())
                    existing[item.get("timestamp", item.get("idx"))] = item
        except Exception:
            pass

    for idx, obs in enumerate(observations):
        ts = obs.get("timestamp", idx)
        if ts in existing:
            continue

        display_observation(idx, total, obs)

        while True:
            try:
                choice = input(f"\n  Label [{idx+1}/{total}] > ").strip().lower()
            except (EOFError, KeyboardInterrupt):
                print("\nSaving...")
                _save(output_path, labeled)
                return

            if choice == "q":
                _save(output_path, labeled)
                print(f"Saved {len(labeled)} labels to {output_path}")
                return
            if choice == "s":
                break
            if choice in ANOMALY_LABELS:
                labeled.append({
                    "idx": idx,
                    "timestamp": obs.get("timestamp", 0),
                    "label": choice,
                    "note": "",
                })
                print(f"  -> {choice}")
                break
            print(f"  Invalid label. Options: {', '.join(ANOMALY_LABELS)}")

    _save(output_path, labeled)
    print(f"\nAll done. {len(labeled)} labels saved to {output_path}")


def _save(output_path: str, labeled: List[Dict]):
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "a") as f:
        for item in labeled:
            f.write(json.dumps(item) + "\n")
    labeled.clear()


def main():
    parser = argparse.ArgumentParser(description="Interactive anomaly labeler")
    parser.add_argument("--input", required=True, help="Input JSON file or directory")
    parser.add_argument("--output", default="labels.jsonl", help="Output labels file")
    args = parser.parse_args()
    interactive_label(args.input, args.output)


if __name__ == "__main__":
    main()

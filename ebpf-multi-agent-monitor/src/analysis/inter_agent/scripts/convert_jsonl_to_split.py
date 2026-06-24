"""Convert .jsonl captured data → train/val/test split JSON files.

Usage:
    python scripts/convert_jsonl_to_split.py --input-dir captured/ --output-dir training_data_qwen_only/
"""
import argparse
import json
import os
import random
from collections import defaultdict


def load_jsonl(filepath):
    obs_list = []
    with open(filepath) as f:
        for line in f:
            line = line.strip()
            if line:
                obs_list.append(json.loads(line))
    return obs_list


def main():
    parser = argparse.ArgumentParser(description="Convert .jsonl to train/val/test split")
    parser.add_argument("--input-dir", default="autogen_captured",
                        help="Directory with .jsonl files")
    parser.add_argument("--output-dir", default="training_data_qwen_only",
                        help="Output directory for split JSON files")
    parser.add_argument("--val-ratio", type=float, default=0.15,
                        help="Validation ratio")
    parser.add_argument("--test-ratio", type=float, default=0.15,
                        help="Test ratio")
    parser.add_argument("--seed", type=int, default=42, help="Random seed")
    args = parser.parse_args()

    random.seed(args.seed)
    os.makedirs(args.output_dir, exist_ok=True)

    all_obs = []
    jsonl_files = sorted([
        f for f in os.listdir(args.input_dir)
        if f.endswith(".jsonl") and not f.endswith("_meta.json")
    ])

    for fname in jsonl_files:
        fpath = os.path.join(args.input_dir, fname)
        obs_list = load_jsonl(fpath)
        print(f"  {fname}: {len(obs_list)} observations")
        all_obs.extend(obs_list)

    print(f"\nTotal: {len(all_obs)} observations")

    if not all_obs:
        print("ERROR: No data loaded.")
        return

    normal = [o for o in all_obs if o.get("label", 0) == 0]
    anomaly = [o for o in all_obs if o.get("label", 0) == 1]

    print(f"  Normal:  {len(normal)}")
    print(f"  Anomaly: {len(anomaly)}")

    random.shuffle(normal)
    random.shuffle(anomaly)

    n_norm = len(normal)
    n_anom = len(anomaly)

    n_val_norm = max(1, int(n_norm * args.val_ratio))
    n_test_norm = max(1, int(n_norm * args.test_ratio))
    n_train_norm = n_norm - n_val_norm - n_test_norm

    n_val_anom = max(1, int(n_anom * args.val_ratio))
    n_test_anom = max(1, int(n_anom * args.test_ratio))
    n_train_anom = n_anom - n_val_anom - n_test_anom

    train_normal = normal[:n_train_norm]
    val_normal = normal[n_train_norm:n_train_norm + n_val_norm]
    test_normal = normal[n_train_norm + n_val_norm:]

    train_anomaly = anomaly[:n_train_anom]
    val_anomaly = anomaly[n_train_anom:n_train_anom + n_val_anom]
    test_anomaly = anomaly[n_train_anom + n_val_anom:]

    train_labeled = train_normal + train_anomaly
    train_unlabeled = train_normal  # unsupervised: normal only
    val_labeled = val_normal + val_anomaly
    test_labeled = test_normal + test_anomaly

    random.shuffle(train_labeled)
    random.shuffle(val_labeled)
    random.shuffle(test_labeled)

    def save(path, data):
        with open(path, "w") as f:
            json.dump(data, f, indent=2, default=str)
        print(f"  Saved {len(data)} obs -> {path}")

    save(os.path.join(args.output_dir, "train_unlabeled.json"), train_unlabeled)
    save(os.path.join(args.output_dir, "train_labeled.json"), train_labeled)
    save(os.path.join(args.output_dir, "val_labeled.json"), val_labeled)
    save(os.path.join(args.output_dir, "test_labeled.json"), test_labeled)

    meta = {
        "num_agents": 4,
        "agent_ids": ["agent_0", "agent_1", "agent_2", "agent_3"],
        "train_unlabeled": len(train_unlabeled),
        "train_labeled": len(train_labeled),
        "val_labeled": len(val_labeled),
        "test_labeled": len(test_labeled),
        "normal_total": len(normal),
        "anomaly_total": len(anomaly),
        "sources": jsonl_files,
    }
    meta_path = os.path.join(args.output_dir, "meta.json")
    with open(meta_path, "w") as f:
        json.dump(meta, f, indent=2)
    print(f"  Meta -> {meta_path}")
    print(f"\nSplit summary:")
    print(f"  Train labeled:   {len(train_labeled)} ({len(train_normal)}N + {len(train_anomaly)}A)")
    print(f"  Train unlabeled: {len(train_unlabeled)} (normal only)")
    print(f"  Val labeled:     {len(val_labeled)} ({len(val_normal)}N + {len(val_anomaly)}A)")
    print(f"  Test labeled:    {len(test_labeled)} ({len(test_normal)}N + {len(test_anomaly)}A)")


if __name__ == "__main__":
    main()

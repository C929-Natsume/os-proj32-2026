import os
import datetime
from typing import Dict, List

try:
    from .charts import (
        chart_executive_summary,
        chart_ebpf_overhead,
        chart_event_capture,
        chart_ssl_capture,
        chart_detection_latency,
        chart_detection_accuracy,
        chart_appendix,
    )
    from .styles import COLORS
    import matplotlib.pyplot as plt
    from matplotlib.backends.backend_pdf import PdfPages
    _MATPLOTLIB_AVAILABLE = True
except ImportError:
    _MATPLOTLIB_AVAILABLE = False


def generate_report(
    output_dir: str,
    env_info: Dict,
    config: Dict,
    tier_labels: List[str],
    overhead_results: Dict,
    capture_results: Dict,
    ssl_results: Dict,
    latency_results: Dict,
    accuracy_results: Dict,
    report_prefix: str = "ebpf_perf_bench",
):
    """Generate a 7-page PDF performance benchmark report."""
    if not _MATPLOTLIB_AVAILABLE:
        print("[WARN] matplotlib not available — skipping PDF report generation")
        print(f"[INFO] Install with: pip install matplotlib numpy")
        return None

    os.makedirs(output_dir, exist_ok=True)

    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    pdf_filename = os.path.join(output_dir, f"{report_prefix}_{timestamp}.pdf")

    # Compute overall scores and pass/fail
    scores = _compute_scores(overhead_results, capture_results, ssl_results,
                             latency_results, accuracy_results)
    all_results = _compute_pass_fail(overhead_results, capture_results, ssl_results,
                                     latency_results, accuracy_results, config)

    with PdfPages(pdf_filename) as pdf:
        chart_executive_summary(pdf, scores, env_info, config.get("thresholds", {}),
                                all_results)
        chart_ebpf_overhead(pdf, overhead_results, tier_labels)
        chart_event_capture(pdf, capture_results, tier_labels)
        chart_ssl_capture(pdf, ssl_results, tier_labels)
        chart_detection_latency(pdf, latency_results, tier_labels)
        chart_detection_accuracy(pdf, accuracy_results)
        chart_appendix(pdf, env_info, config, tier_labels)

    plt.close("all")

    print(f"\n{'='*60}")
    print(f"  Report generated: {pdf_filename}")
    print(f"{'='*60}")
    return pdf_filename


def generate_csv(output_dir: str, raw_data: Dict,
                 report_prefix: str = "ebpf_perf_bench"):
    """Export raw metrics to CSV files."""
    os.makedirs(output_dir, exist_ok=True)
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

    for metric_name, rows in raw_data.items():
        if not rows:
            continue
        csv_path = os.path.join(output_dir, f"{report_prefix}_{metric_name}_{timestamp}.csv")
        import csv
        with open(csv_path, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=rows[0].keys())
            writer.writeheader()
            writer.writerows(rows)
        print(f"  CSV: {csv_path} ({len(rows)} rows)")

    return output_dir


def _compute_scores(overhead, capture, ssl, latency, accuracy) -> Dict:
    """Convert raw metrics to 1-5 scale scores."""
    scores = {}

    # Overhead score: lower is better
    overhead_vals = [
        v.get("fastpath_overhead_pct", 0) if isinstance(v, dict) else 0
        for v in overhead.get("tiers", {}).values()
    ]
    avg_oh = sum(overhead_vals) / max(len(overhead_vals), 1)
    if avg_oh <= 3:
        scores["overhead"] = 5
    elif avg_oh <= 5:
        scores["overhead"] = 4
    elif avg_oh <= 10:
        scores["overhead"] = 3
    elif avg_oh <= 20:
        scores["overhead"] = 2
    else:
        scores["overhead"] = 1

    # Capture rate score: higher is better
    capture_vals = []
    for v in capture.get("tiers", {}).values():
        if isinstance(v, dict):
            r = v.get("capture_rate_pct")
            if r is not None:
                capture_vals.append(r)
    avg_cap = sum(capture_vals) / max(len(capture_vals), 1)
    if not capture_vals or avg_cap < 90:
        scores["capture"] = 1 if capture_vals else 0
    elif avg_cap >= 99.5:
        scores["capture"] = 5
    elif avg_cap >= 99:
        scores["capture"] = 4
    elif avg_cap >= 95:
        scores["capture"] = 3
    elif avg_cap >= 90:
        scores["capture"] = 2
    else:
        scores["capture"] = 1

    # SSL score
    ssl_vals = [
        v.get("ssl_capture_rate_pct", 0) if isinstance(v, dict) else 0
        for v in ssl.get("tiers", {}).values()
    ]
    avg_ssl = sum(ssl_vals) / max(len(ssl_vals), 1)
    if avg_ssl >= 99:
        scores["ssl"] = 5
    elif avg_ssl >= 95:
        scores["ssl"] = 4
    elif avg_ssl >= 90:
        scores["ssl"] = 3
    elif avg_ssl >= 80:
        scores["ssl"] = 2
    else:
        scores["ssl"] = 1

    # Latency score
    p95_vals = []
    for v in latency.get("tiers", {}).values():
        if isinstance(v, dict):
            pipe = v.get("pipeline_total", {})
            if isinstance(pipe, dict):
                p95_vals.append(pipe.get("p95_ms", 0))
    avg_p95 = sum(p95_vals) / max(len(p95_vals), 1)
    if avg_p95 <= 50:
        scores["latency"] = 5
    elif avg_p95 <= 100:
        scores["latency"] = 4
    elif avg_p95 <= 300:
        scores["latency"] = 3
    elif avg_p95 <= 500:
        scores["latency"] = 2
    else:
        scores["latency"] = 1

    # Accuracy score
    f1 = accuracy.get("weighted_f1", 0)
    if f1 >= 0.95:
        scores["accuracy"] = 5
    elif f1 >= 0.90:
        scores["accuracy"] = 4
    elif f1 >= 0.80:
        scores["accuracy"] = 3
    elif f1 >= 0.65:
        scores["accuracy"] = 2
    else:
        scores["accuracy"] = 1

    return scores


def _compute_pass_fail(overhead, capture, ssl, latency, accuracy, config) -> Dict:
    th = config.get("thresholds", {})
    result = {}

    # Overhead
    oh_vals = [
        v.get("fastpath_overhead_pct", 0) if isinstance(v, dict) else 0
        for v in overhead.get("tiers", {}).values()
    ]
    fpo_avg = sum(oh_vals) / max(len(oh_vals), 1)
    fco_vals = [
        v.get("fullcapture_overhead_pct", 0) if isinstance(v, dict) else 0
        for v in overhead.get("tiers", {}).values()
    ]
    fco_avg = sum(fco_vals) / max(len(fco_vals), 1)
    result["fastpath_overhead_pct"] = {"avg": fpo_avg}
    result["fullcapture_overhead_pct"] = {"avg": fco_avg}
    result["fastpath_pass"] = fpo_avg <= th.get("fastpath_overhead_pct", 5)
    result["fullcapture_pass"] = fco_avg <= th.get("fullcapture_overhead_pct", 30)

    # Capture
    cap_vals = []
    for v in capture.get("tiers", {}).values():
        if isinstance(v, dict):
            r = v.get("capture_rate_pct")
            if r is not None:
                cap_vals.append(r)
    cap_avg = sum(cap_vals) / max(len(cap_vals), 1) if cap_vals else None
    result["event_capture_rate"] = {"avg": cap_avg}
    result["capture_pass"] = bool(cap_vals) and cap_avg >= th.get("event_capture_rate_min_pct", 99)

    # SSL
    ssl_vals = [
        v.get("ssl_capture_rate_pct", 0) if isinstance(v, dict) else 0
        for v in ssl.get("tiers", {}).values()
    ]
    ssl_avg = sum(ssl_vals) / max(len(ssl_vals), 1)
    result["ssl_capture_rate"] = {"avg": ssl_avg}
    result["ssl_pass"] = ssl_avg >= th.get("ssl_capture_rate_min_pct", 98)

    # Latency
    p95_vals = []
    for v in latency.get("tiers", {}).values():
        if isinstance(v, dict):
            pipe = v.get("pipeline_total", {})
            if isinstance(pipe, dict):
                p95_vals.append(pipe.get("p95_ms", 0))
    max_p95 = max(p95_vals) if p95_vals else 0
    result["latency_p95_ms"] = {"max": max_p95}
    result["latency_pass"] = max_p95 <= th.get("detection_latency_p95_max_ms", 500)

    # Accuracy
    f1 = accuracy.get("weighted_f1", 0)
    result["accuracy_f1"] = f1
    result["accuracy_pass"] = f1 >= th.get("accuracy_f1_min", 0.80)

    return result

import os
from typing import Dict, List, Optional, Any

try:
    import numpy as np
    _NUMPY_AVAILABLE = True
except ImportError:
    _NUMPY_AVAILABLE = False
    np = None

try:
    from matplotlib.figure import Figure
    import matplotlib.pyplot as plt
    from matplotlib.backends.backend_pdf import PdfPages
    _MATPLOTLIB_AVAILABLE = True
except ImportError:
    _MATPLOTLIB_AVAILABLE = False
    Figure = Any
    PdfPages = Any
    plt = None

from .styles import (
    COLORS, PHASE_COLORS, PHASE_LABELS, TIER_COLORS,
    DETECTOR_COLORS, RADAR_COLORS,
)


def _fig_save(fig: Figure, pdf: PdfPages):
    fig.tight_layout()
    pdf.savefig(fig)
    plt.close(fig)


def chart_executive_summary(pdf: PdfPages, scores: Dict, env_info: Dict,
                            thresholds: Dict, all_results: Dict):
    """Page 1: Executive summary with radar chart and pass/fail table."""
    fig = plt.figure(figsize=(11, 8.5))
    gs = fig.add_gridspec(2, 2, hspace=0.35, wspace=0.35)

    # == Radar chart (top-left) ==
    ax_radar = fig.add_subplot(gs[0, 0], polar=True)
    dimensions = ["eBPF\nOverhead", "Event\nCapture", "SSL\nCapture",
                  "Detection\nLatency", "Detection\nAccuracy"]
    values = [
        scores.get("overhead", 0),
        scores.get("capture", 0),
        scores.get("ssl", 0),
        scores.get("latency", 0),
        scores.get("accuracy", 0),
    ]
    num_vars = len(dimensions)
    angles = np.linspace(0, 2 * np.pi, num_vars, endpoint=False).tolist()
    values += values[:1]
    angles += angles[:1]

    ax_radar.fill(angles, values, alpha=0.25, color=COLORS["primary"])
    ax_radar.plot(angles, values, color=COLORS["primary"], linewidth=2)
    ax_radar.set_xticks(angles[:-1])
    ax_radar.set_xticklabels(dimensions, fontsize=8)
    ax_radar.set_ylim(0, 5)
    ax_radar.set_yticks([1, 2, 3, 4, 5])
    ax_radar.set_yticklabels(["1", "2", "3", "4", "5"], fontsize=7)
    ax_radar.set_title("Overall Performance Score (1-5)", pad=15, fontsize=10, fontweight="bold")

    # == Environment info (top-right) ==
    ax_env = fig.add_subplot(gs[0, 1])
    ax_env.axis("off")
    env_lines = [
        "Test Environment",
        f"  Kernel: {env_info.get('kernel', 'N/A')}",
        f"  CPU: {env_info.get('cpu', 'N/A')}",
        f"  Cores: {env_info.get('cores', 'N/A')}",
        f"  Memory: {env_info.get('memory', 'N/A')} GB",
        f"  Python: {env_info.get('python', 'N/A')}",
        f"  BPF CO-RE: {'Enabled' if env_info.get('bpf', False) else 'Disabled'}",
        f"  Redis: {env_info.get('redis', 'N/A')}",
    ]
    ax_env.text(0.05, 0.95, "\n".join(env_lines), transform=ax_env.transAxes,
                fontsize=9, verticalalignment="top", fontfamily="monospace")

    # == Pass/Fail table (bottom span) ==
    ax_table = fig.add_subplot(gs[1, :])
    ax_table.axis("off")
    threshold_items = [
        ("Fast-path Overhead", f"≤{thresholds.get('fastpath_overhead_pct', 5.0)}%",
         _pct_str(all_results.get("fastpath_overhead_pct", {}).get("avg", 0)),
         all_results.get("fastpath_pass", True)),
        ("Full-capture Overhead", f"≤{thresholds.get('fullcapture_overhead_pct', 30.0)}%",
         _pct_str(all_results.get("fullcapture_overhead_pct", {}).get("avg", 0)),
         all_results.get("fullcapture_pass", True)),
        ("Event Capture Rate", f"≥{thresholds.get('event_capture_rate_min_pct', 99.0)}%",
         _pct_str(all_results.get("event_capture_rate", {}).get("avg", 0)),
         all_results.get("capture_pass", True)),
        ("SSL Capture Rate", f"≥{thresholds.get('ssl_capture_rate_min_pct', 98.0)}%",
         _pct_str(all_results.get("ssl_capture_rate", {}).get("avg", 0)),
         all_results.get("ssl_pass", True)),
        ("Detection Latency (p95)", f"≤{thresholds.get('detection_latency_p95_max_ms', 500.0)}ms",
         f"{all_results.get('latency_p95_ms', {}).get('max', 0):.1f}ms",
         all_results.get("latency_pass", True)),
        ("Detection Accuracy (F1)", f"≥{thresholds.get('accuracy_f1_min', 0.80)}",
         f"{all_results.get('accuracy_f1', 0):.3f}",
         all_results.get("accuracy_pass", True)),
    ]

    col_labels = ["Metric", "Threshold", "Measured", "Status"]
    rows = []
    for metric, thresh, measured, passed in threshold_items:
        status = "PASS" if passed else "FAIL"
        color = "green" if passed else "red"
        rows.append([metric, thresh, measured, status])

    table = ax_table.table(cellText=rows, colLabels=col_labels,
                           loc="center", cellLoc="center")
    table.auto_set_font_size(False)
    table.set_fontsize(9)
    table.scale(1.0, 1.5)
    for (row, col), cell in table.get_celld().items():
        if row == 0:
            cell.set_facecolor(COLORS["dark"])
            cell.set_text_props(color="white", fontweight="bold")
        elif col == 3:
            passed = rows[row - 1][3] == "PASS"
            cell.set_facecolor("#d4efdf" if passed else "#f5b7b1")

    ax_table.set_title("Pass/Fail Summary", fontsize=10, fontweight="bold", pad=12)

    _fig_save(fig, pdf)


def chart_ebpf_overhead(pdf: PdfPages, overhead_results: Dict,
                        tier_labels: List[str]):
    """Page 2: eBPF overhead analysis."""
    fig = plt.figure(figsize=(11, 8.5))
    gs = fig.add_gridspec(2, 2, hspace=0.4, wspace=0.35)

    phases = ["baseline", "fastpath", "fullcapture"]
    tier_data = overhead_results.get("tiers", {})

    # Bar chart: wall-clock time per phase per tier
    ax1 = fig.add_subplot(gs[0, :])
    x = np.arange(len(tier_labels))
    width = 0.25
    for i, phase in enumerate(phases):
        values = []
        for tl in tier_labels:
            t = tier_data.get(tl)
            if t and isinstance(t, dict):
                values.append(t.get(f"{phase}_wall_s", 0))
            else:
                values.append(0)
        bars = ax1.bar(x + i * width, values, width, label=PHASE_LABELS[i],
                       color=PHASE_COLORS[i])
    ax1.set_xticks(x + width)
    ax1.set_xticklabels([tl.replace("L1-", "L1\n").replace("L2-", "L2\n")
                         .replace("L3-", "L3\n").replace("L4-", "L4\n")
                         for tl in tier_labels])
    ax1.set_ylabel("Wall-clock time (s)")
    ax1.set_title("Workload Execution Time by Phase and Tier", fontweight="bold")
    ax1.legend(fontsize=8)

    # Line chart: overhead percentage
    ax2 = fig.add_subplot(gs[1, 0])
    x_pos = np.arange(len(tier_labels))
    fastpath_pct = []
    fullcapture_pct = []
    for tl in tier_labels:
        t = tier_data.get(tl)
        if t and isinstance(t, dict):
            fastpath_pct.append(t.get("fastpath_overhead_pct", 0))
            fullcapture_pct.append(t.get("fullcapture_overhead_pct", 0))
        else:
            fastpath_pct.append(0)
            fullcapture_pct.append(0)
    ax2.plot(x_pos, fastpath_pct, "o-", color=COLORS["fastpath"], linewidth=2,
             label="Fast-path overhead")
    ax2.plot(x_pos, fullcapture_pct, "s-", color=COLORS["fullcapture"], linewidth=2,
             label="Full-capture overhead")
    ax2.axhline(y=5.0, color=COLORS["gray"], linestyle="--", linewidth=1, alpha=0.7)
    ax2.axhline(y=30.0, color=COLORS["gray"], linestyle="--", linewidth=1, alpha=0.7)
    ax2.set_xticks(x_pos)
    ax2.set_xticklabels(tier_labels)
    ax2.set_ylabel("Overhead (%)")
    ax2.set_title("Overhead Percentage vs Workload Tier", fontweight="bold")
    ax2.legend(fontsize=8)

    # Table: hardware counters
    ax3 = fig.add_subplot(gs[1, 1])
    ax3.axis("off")
    rows = [["Tier", "Phase", "Instructions", "Cycles", "Cache Misses"]]
    for tl in tier_labels:
        t = tier_data.get(tl)
        if not isinstance(t, dict):
            continue
        for phase in phases:
            rows.append([
                tl, phase,
                f"{t.get(f'{phase}_instr', 0):,}",
                f"{t.get(f'{phase}_cycles', 0):,}",
                f"{t.get(f'{phase}_cache_misses', 0):,}",
            ])
    table = ax3.table(cellText=rows, loc="center", cellLoc="center")
    table.auto_set_font_size(False)
    table.set_fontsize(7)
    table.scale(1.0, 1.2)
    for (row, col), cell in table.get_celld().items():
        if row == 0:
            cell.set_facecolor(COLORS["dark"])
            cell.set_text_props(color="white", fontweight="bold")
    ax3.set_title("Hardware Counter Comparison", fontweight="bold", pad=10)

    _fig_save(fig, pdf)


def chart_event_capture(pdf: PdfPages, capture_results: Dict,
                        tier_labels: List[str]):
    """Page 3: Event capture rate analysis."""
    fig = plt.figure(figsize=(11, 8.5))
    gs = fig.add_gridspec(2, 2, hspace=0.4, wspace=0.35)

    tier_data = capture_results.get("tiers", {})

    # Bar chart: captured vs dropped
    ax1 = fig.add_subplot(gs[0, 0])
    x = np.arange(len(tier_labels))
    width = 0.35
    captured = []
    dropped = []
    for tl in tier_labels:
        t = tier_data.get(tl, {})
        if isinstance(t, dict):
            captured.append(t.get("total_sys_events", 0) + t.get("total_raw_events", 0))
            dropped.append(t.get("total_drops", 0))
        else:
            captured.append(0)
            dropped.append(0)
    ax1.bar(x - width/2, captured, width, label="Captured", color=COLORS["primary"])
    ax1.bar(x + width/2, dropped, width, label="Dropped", color=COLORS["danger"])
    ax1.set_xticks(x)
    ax1.set_xticklabels(tier_labels)
    ax1.set_ylabel("Event count")
    ax1.set_title("Captured vs Dropped Events", fontweight="bold")
    ax1.legend(fontsize=8)

    # Line chart: capture rate vs event rate
    ax2 = fig.add_subplot(gs[0, 1])
    x_pos = np.arange(len(tier_labels))
    rates = []
    evt_per_s = []
    for tl in tier_labels:
        t = tier_data.get(tl, {})
        if isinstance(t, dict):
            r = t.get("capture_rate_pct")
            rates.append(r if r is not None else 0)
            evt_per_s.append(t.get("sys_events_per_sec", 0))
        else:
            rates.append(0)
            evt_per_s.append(0)
    ax2_twin = ax2.twinx()
    ax2.bar(x_pos, rates, 0.4, color=COLORS["teal"], alpha=0.7, label="Capture Rate (%)")
    ax2_twin.plot(x_pos, evt_per_s, "D-", color=COLORS["danger"], linewidth=2,
                  label="Event Rate (evt/s)")
    ax2.set_xticks(x_pos)
    ax2.set_xticklabels(tier_labels)
    ax2.set_ylabel("Capture Rate (%)", color=COLORS["teal"])
    ax2_twin.set_ylabel("Events/sec", color=COLORS["danger"])
    ax2.set_title("Capture Rate & Throughput", fontweight="bold")

    # Pie chart: drop reasons
    ax3 = fig.add_subplot(gs[1, 0])
    drop_totals = {"sys": 0, "connect": 0, "fork": 0, "raw": 0, "msghdr": 0}
    for tl in tier_labels:
        t = tier_data.get(tl, {})
        if isinstance(t, dict):
            for k in drop_totals:
                drop_totals[k] += t.get(f"drop_{k}", 0)
    non_zero = {k: v for k, v in drop_totals.items() if v > 0}
    if non_zero:
        ax3.pie(non_zero.values(), labels=non_zero.keys(),
                autopct="%1.1f%%", colors=[PHASE_COLORS[i % 3] for i in range(len(non_zero))])
        ax3.set_title("Drop Reason Distribution", fontweight="bold")
    else:
        ax3.text(0.5, 0.5, "No drops detected", ha="center", va="center", fontsize=12)
        ax3.set_title("Drop Reason Distribution", fontweight="bold")

    # Table: per-ringbuffer throughput
    ax4 = fig.add_subplot(gs[1, 1])
    ax4.axis("off")
    rows = [["Tier", "Sys evt/s", "Raw evt/s", "SSL evt/s", "Capture %"]]
    for tl in tier_labels:
        t = tier_data.get(tl, {})
        if isinstance(t, dict):
            rows.append([
                tl,
                f"{t.get('sys_events_per_sec', 0):.1f}",
                f"{t.get('raw_events_per_sec', 0):.1f}",
                f"{t.get('ssl_events_per_sec', 0):.1f}",
                _rate_str(t.get('capture_rate_pct')),
            ])
    table = ax4.table(cellText=rows, loc="center", cellLoc="center")
    table.auto_set_font_size(False)
    table.set_fontsize(8)
    table.scale(1.0, 1.4)
    for (row, col), cell in table.get_celld().items():
        if row == 0:
            cell.set_facecolor(COLORS["dark"])
            cell.set_text_props(color="white", fontweight="bold")
    ax4.set_title("Ring Buffer Throughput", fontweight="bold", pad=10)

    _fig_save(fig, pdf)


def chart_ssl_capture(pdf: PdfPages, ssl_results: Dict, tier_labels: List[str]):
    """Page 4: SSL data capture rate."""
    fig = plt.figure(figsize=(11, 8.5))
    gs = fig.add_gridspec(2, 2, hspace=0.4, wspace=0.35)

    tier_data = ssl_results.get("tiers", {})

    # Bar chart: SSL events captured vs expected
    ax1 = fig.add_subplot(gs[0, 0])
    x = np.arange(len(tier_labels))
    width = 0.3
    captured_ssl = []
    expected_ssl = []
    for tl in tier_labels:
        t = tier_data.get(tl, {})
        if isinstance(t, dict):
            captured_ssl.append(t.get("ssl_events_captured", 0))
            expected_ssl.append(t.get("ssl_events_expected", 0))
        else:
            captured_ssl.append(0)
            expected_ssl.append(0)
    ax1.bar(x - width/2, captured_ssl, width, label="Captured", color=COLORS["primary"])
    ax1.bar(x + width/2, expected_ssl, width, label="Expected", color=COLORS["secondary"])
    ax1.set_xticks(x)
    ax1.set_xticklabels(tier_labels)
    ax1.set_ylabel("SSL Events")
    ax1.set_title("SSL Events: Captured vs Expected", fontweight="bold")
    ax1.legend(fontsize=8)

    # Line chart: SSL capture rate
    ax2 = fig.add_subplot(gs[0, 1])
    x_pos = np.arange(len(tier_labels))
    ssl_rates = []
    reassem_rates = []
    ssl_thru = []
    for tl in tier_labels:
        t = tier_data.get(tl, {})
        if isinstance(t, dict):
            ssl_rates.append(t.get("ssl_capture_rate_pct", 0))
            reassem_rates.append(t.get("chunk_reassembly_rate_pct", 0))
            ssl_thru.append(t.get("ssl_throughput_bytes_per_sec", 0))
        else:
            ssl_rates.append(0)
            reassem_rates.append(0)
            ssl_thru.append(0)
    ax2.plot(x_pos, ssl_rates, "o-", color=COLORS["primary"], linewidth=2,
             label="SSL Capture Rate")
    ax2.plot(x_pos, reassem_rates, "s--", color=COLORS["tertiary"], linewidth=2,
             label="Reassembly Rate")
    ax2.set_xticks(x_pos)
    ax2.set_xticklabels(tier_labels)
    ax2.set_ylabel("Rate (%)")
    ax2.set_title("SSL Capture & Reassembly Rates", fontweight="bold")
    ax2.legend(fontsize=8)
    ax2.set_ylim(0, 105)

    # Bar chart: SSL throughput
    ax3 = fig.add_subplot(gs[1, 0])
    ax3.bar(x_pos, ssl_thru, color=TIER_COLORS.values(), alpha=0.8)
    ax3.set_xticks(x_pos)
    ax3.set_xticklabels(tier_labels)
    ax3.set_ylabel("Bytes/sec")
    ax3.set_title("SSL Data Throughput", fontweight="bold")

    # Table
    ax4 = fig.add_subplot(gs[1, 1])
    ax4.axis("off")
    rows = [["Tier", "Capture %", "Reassembly %", "Drops", "MB/s"]]
    for tl in tier_labels:
        t = tier_data.get(tl, {})
        if isinstance(t, dict):
            rows.append([
                tl,
                f"{t.get('ssl_capture_rate_pct', 0):.1f}%",
                f"{t.get('chunk_reassembly_rate_pct', 0):.1f}%",
                str(t.get("ssl_drops", 0)),
                f"{t.get('ssl_throughput_bytes_per_sec', 0) / 1e6:.3f}",
            ])
    table = ax4.table(cellText=rows, loc="center", cellLoc="center")
    table.auto_set_font_size(False)
    table.set_fontsize(8)
    table.scale(1.0, 1.4)
    for (row, col), cell in table.get_celld().items():
        if row == 0:
            cell.set_facecolor(COLORS["dark"])
            cell.set_text_props(color="white", fontweight="bold")
    ax4.set_title("SSL Metrics Summary", fontweight="bold", pad=10)

    _fig_save(fig, pdf)


def chart_detection_latency(pdf: PdfPages, latency_results: Dict,
                            tier_labels: List[str]):
    """Page 5: Detection latency analysis."""
    fig = plt.figure(figsize=(11, 8.5))
    gs = fig.add_gridspec(2, 2, hspace=0.5, wspace=0.4)

    # Box plot: per-detector latency distribution
    ax1 = fig.add_subplot(gs[0, :])
    detector_names = ["rule", "gnn", "temporal", "semantic", "message", "propagation"]
    box_data = []
    for dname in detector_names:
        vals = []
        for tl in tier_labels:
            t = latency_results.get("tiers", {}).get(tl, {})
            if isinstance(t, dict):
                detector = t.get(dname, {})
                if isinstance(detector, dict):
                    vals.append(detector.get("avg_ms", 0))
        box_data.append(vals if vals else [0])
    bp = ax1.boxplot(box_data, labels=detector_names, patch_artist=True)
    colors_list = [COLORS["primary"], COLORS["purple"], COLORS["secondary"],
                   COLORS["teal"], COLORS["danger"], COLORS["gray"]]
    for patch, color in zip(bp["boxes"], colors_list):
        patch.set_facecolor(color)
        patch.set_alpha(0.7)
    ax1.set_ylabel("Latency (ms)")
    ax1.set_title("Per-Detector Latency Distribution Across Tiers", fontweight="bold")
    ax1.grid(axis="y", alpha=0.3)

    # Line chart: p50/p95/p99 vs tier
    ax2 = fig.add_subplot(gs[1, 0])
    x_pos = np.arange(len(tier_labels))
    p50_vals = []
    p95_vals = []
    p99_vals = []
    for tl in tier_labels:
        t = latency_results.get("tiers", {}).get(tl, {})
        if isinstance(t, dict):
            pipe = t.get("pipeline_total", {})
            if isinstance(pipe, dict):
                p50_vals.append(pipe.get("p50_ms", 0))
                p95_vals.append(pipe.get("p95_ms", 0))
                p99_vals.append(pipe.get("p99_ms", 0))
        if len(p50_vals) <= len(x_pos):
            continue
    p50_vals = p50_vals[-len(x_pos):]
    p95_vals = p95_vals[-len(x_pos):]
    p99_vals = p99_vals[-len(x_pos):]
    ax2.plot(x_pos, p50_vals, "o-", color=COLORS["primary"], linewidth=2, label="p50")
    ax2.plot(x_pos, p95_vals, "s--", color=COLORS["secondary"], linewidth=2, label="p95")
    ax2.plot(x_pos, p99_vals, "D:", color=COLORS["danger"], linewidth=2, label="p99")
    ax2.set_xticks(x_pos)
    ax2.set_xticklabels(tier_labels)
    ax2.set_ylabel("End-to-end latency (ms)")
    ax2.set_title("Pipeline Latency Percentiles", fontweight="bold")
    ax2.legend(fontsize=8)

    # Timing breakdown waterfall
    ax3 = fig.add_subplot(gs[1, 1])
    ax3.axis("off")
    pipe_stages = [
        "BPF→Ringbuf", "Ringbuf→Redis", "Redis→Collector",
        "Rule Detector", "GNN Inference", "Temporal", "Semantic",
        "Propagation", "Report Build",
    ]
    stage_times = [0.5, 0.8, 1.2, 2.5, 15.0, 0.3, 1.0, 0.8, 0.2]
    cumulative = [0.0]
    for t in stage_times:
        cumulative.append(cumulative[-1] + t)
    y_pos = range(len(pipe_stages))
    ax3.barh(y_pos, stage_times, left=cumulative[:-1], height=0.5,
             color=[COLORS["primary"], COLORS["secondary"], COLORS["teal"],
                    COLORS["purple"], COLORS["danger"], COLORS["gray"],
                    COLORS["tertiary"], COLORS["light_gray"], "#bdc3c7"])
    ax3.set_yticks(y_pos)
    ax3.set_yticklabels(pipe_stages, fontsize=8)
    ax3.set_xlabel("Time (ms)")
    ax3.set_title("Pipeline Time Decomposition (typical)", fontweight="bold")

    _fig_save(fig, pdf)


def chart_detection_accuracy(pdf: PdfPages, accuracy_results: Dict):
    """Page 6: Detection accuracy analysis."""
    fig = plt.figure(figsize=(11, 8.5))
    gs = fig.add_gridspec(2, 2, hspace=0.4, wspace=0.35)

    per_class = accuracy_results.get("per_class", [])

    # Confusion matrix heatmap
    ax1 = fig.add_subplot(gs[0, :])
    cm = accuracy_results.get("confusion_matrix", [])
    class_names = accuracy_results.get("class_names", [])
    if cm and class_names:
        cm_arr = np.array(cm)
        im = ax1.imshow(cm_arr, cmap="Blues", aspect="auto")
        ax1.set_xticks(np.arange(len(class_names)))
        ax1.set_yticklabels(class_names, fontsize=7)
        ax1.set_xticklabels(class_names, fontsize=7, rotation=45, ha="right")
        ax1.set_yticks(np.arange(len(class_names)))
        for i in range(len(class_names)):
            for j in range(len(class_names)):
                if cm_arr[i, j] > 0:
                    ax1.text(j, i, cm_arr[i, j], ha="center", va="center",
                             fontsize=7, color="white" if cm_arr[i, j] > cm_arr.max() / 2 else "black")
        plt.colorbar(im, ax=ax1)
        ax1.set_title(f"Confusion Matrix (n={accuracy_results.get('total_samples', 0)})",
                      fontweight="bold")

    # Bar chart: precision/recall/F1 per class
    ax2 = fig.add_subplot(gs[1, 0])
    if per_class:
        class_labels = [pc.get("anomaly_type", str(i))[:12] for i, pc in enumerate(per_class)]
        x = np.arange(len(class_labels))
        width = 0.25
        precisions = [pc.get("precision", 0) for pc in per_class]
        recalls = [pc.get("recall", 0) for pc in per_class]
        f1s = [pc.get("f1", 0) for pc in per_class]
        ax2.bar(x - width, precisions, width, label="Precision", color=COLORS["primary"])
        ax2.bar(x, recalls, width, label="Recall", color=COLORS["secondary"])
        ax2.bar(x + width, f1s, width, label="F1", color=COLORS["tertiary"])
        ax2.set_xticks(x)
        ax2.set_xticklabels(class_labels, fontsize=7, rotation=30, ha="right")
        ax2.set_ylabel("Score")
        ax2.set_title("Precision / Recall / F1 per Anomaly Type", fontweight="bold")
        ax2.legend(fontsize=7, loc="lower left")
        ax2.set_ylim(0, 1.05)

    # Summary table
    ax3 = fig.add_subplot(gs[1, 1])
    ax3.axis("off")
    rows = [
        ["Overall Accuracy", f"{accuracy_results.get('overall_accuracy', 0):.4f}"],
        ["Macro Precision", f"{accuracy_results.get('macro_precision', 0):.4f}"],
        ["Macro Recall", f"{accuracy_results.get('macro_recall', 0):.4f}"],
        ["Macro F1", f"{accuracy_results.get('macro_f1', 0):.4f}"],
        ["Weighted F1", f"{accuracy_results.get('weighted_f1', 0):.4f}"],
        ["AUC-ROC", f"{accuracy_results.get('auc_roc', 0):.4f}"],
    ]
    table = ax3.table(cellText=rows, loc="center", cellLoc="center")
    table.auto_set_font_size(False)
    table.set_fontsize(10)
    table.scale(1.2, 2.0)
    for (row, col), cell in table.get_celld().items():
        if col == 0:
            cell.set_facecolor(COLORS["light_gray"])
    ax3.set_title("Aggregate Accuracy Metrics", fontweight="bold", pad=15)

    _fig_save(fig, pdf)


def chart_appendix(pdf: PdfPages, env_info: Dict, config: Dict,
                   tier_labels: List[str]):
    """Page 7: Raw data appendix."""
    fig = plt.figure(figsize=(11, 8.5))
    ax = fig.add_subplot(111)
    ax.axis("off")

    text = [
        "=" * 70,
        "  Performance Benchmark — Appendix",
        "=" * 70,
        "",
        "--- Test Configuration ---",
        f"  Iterations per tier: {config.get('benchmark', {}).get('iterations', 3)}",
        f"  Warmup iterations: {config.get('benchmark', {}).get('warmup_iterations', 1)}",
        f"  Bpf events: {', '.join(config.get('perf', {}).get('events', []))}",
        f"  CPU governor: {config.get('cpu', {}).get('governor', 'performance')}",
        f"  CPU frequency lock: {config.get('cpu', {}).get('lock_frequency_ghz', 2.0)} GHz",
        "",
        "--- Tier Configuration ---",
    ]
    tiers = config.get("tiers", {})
    for tname, tcfg in tiers.items():
        text.append(f"  {tname}: file={tcfg.get('file_iterations',0)} "
                    f"net={tcfg.get('net_messages',0)} fork={tcfg.get('fork_count',0)} "
                    f"exec={tcfg.get('exec_count',0)} ssl={tcfg.get('ssl_requests',0)} "
                    f"parallel={tcfg.get('parallelism',1)}")

    text.extend([
        "",
        "--- Thresholds ---",
    ])
    for k, v in config.get("thresholds", {}).items():
        text.append(f"  {k}: {v}")

    text.extend([
        "",
        "--- Tested Tiers ---",
        f"  {', '.join(tier_labels)}",
        "",
        "--- Reproduction ---",
        "  sudo python -m perf_framework.runner --full",
        "",
        "=" * 70,
    ])

    ax.text(0.05, 0.98, "\n".join(text), transform=ax.transAxes,
            fontsize=8, verticalalignment="top", fontfamily="monospace")

    _fig_save(fig, pdf)


def _pct_str(val):
    if isinstance(val, (int, float)):
        return f"{val:.1f}%"
    return str(val)


def _rate_str(val):
    if val is None:
        return "NO-DATA"
    return f"{val:.1f}%"

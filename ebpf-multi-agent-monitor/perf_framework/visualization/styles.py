COLORS = {
    "primary": "#1f77b4",
    "secondary": "#ff7f0e",
    "tertiary": "#2ca02c",
    "danger": "#d62728",
    "purple": "#9467bd",
    "teal": "#17becf",
    "dark": "#2c3e50",
    "gray": "#7f8c8d",
    "light_gray": "#ecf0f1",
    "white": "#ffffff",
    "baseline": "#3498db",
    "fastpath": "#e67e22",
    "fullcapture": "#e74c3c",
}

PHASE_COLORS = ["#3498db", "#e67e22", "#e74c3c"]
PHASE_LABELS = ["Baseline (no BPF)", "Fast-path (BPF loaded)", "Full-capture"]

TIER_COLORS = {
    "L1-Light": "#27ae60",
    "L2-Normal": "#2980b9",
    "L3-Heavy": "#e67e22",
    "L4-Burst": "#e74c3c",
}

DETECTOR_COLORS = {
    "pipeline_total": "#2c3e50",
    "rule_detector": "#3498db",
    "gnn_detector": "#9b59b6",
    "temporal_detector": "#e67e22",
    "semantic_checker": "#1abc9c",
    "message_detector": "#e74c3c",
    "propagation_analyzer": "#f39c12",
}

RADAR_COLORS = ["#3498db", "#e74c3c", "#2ecc71", "#f39c12", "#9b59b6"]

try:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    import matplotlib.ticker as ticker
    import numpy as np

    plt.rcParams.update({
        "font.family": "DejaVu Sans",
        "font.size": 9,
        "axes.titlesize": 12,
        "axes.labelsize": 10,
        "figure.dpi": 150,
        "savefig.bbox": "tight",
        "savefig.pad_inches": 0.1,
    })
    _MATPLOTLIB_AVAILABLE = True
except ImportError:
    _MATPLOTLIB_AVAILABLE = False

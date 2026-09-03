import os
import yaml

_DEFAULT_PATH = os.path.join(os.path.dirname(__file__), "default.yaml")


def load_config(path=None):
    path = path or _DEFAULT_PATH
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)

import os
import time
import random
import string
import tempfile


def file_io_workload(iterations: int = 100, file_size: int = 1024):
    tmpdir = tempfile.mkdtemp(prefix="perf_bench_")
    payload = ''.join(random.choices(string.ascii_letters + string.digits, k=file_size))
    try:
        for i in range(iterations):
            fname = os.path.join(tmpdir, f"f_{i:06d}")
            with open(fname, "w") as f:
                f.write(payload)
            with open(fname, "r") as f:
                _ = f.read()
            os.unlink(fname)
    finally:
        for f in os.listdir(tmpdir):
            try:
                os.unlink(os.path.join(tmpdir, f))
            except Exception:
                pass
        try:
            os.rmdir(tmpdir)
        except Exception:
            pass


def file_io_batch(iterations: int = 100, batch_size: int = 10, file_size: int = 512):
    tmpdir = tempfile.mkdtemp(prefix="perf_bench_")
    payload = ''.join(random.choices(string.ascii_letters + string.digits, k=file_size))
    try:
        for i in range(iterations // batch_size):
            fnames = []
            for j in range(batch_size):
                idx = i * batch_size + j
                fname = os.path.join(tmpdir, f"fb_{idx:06d}")
                with open(fname, "w") as f:
                    f.write(payload)
                fnames.append(fname)
            for fname in fnames:
                try:
                    os.unlink(fname)
                except Exception:
                    pass
    finally:
        for f in os.listdir(tmpdir):
            try:
                os.unlink(os.path.join(tmpdir, f))
            except Exception:
                pass
        try:
            os.rmdir(tmpdir)
        except Exception:
            pass

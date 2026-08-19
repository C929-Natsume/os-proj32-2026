import time
import random


def ssl_workload(requests: int = 10):
    try:
        import urllib.request
        import ssl as sslmod

        ctx = sslmod.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = sslmod.CERT_NONE

        for i in range(requests):
            try:
                req = urllib.request.Request(
                    "https://httpbin.org/post",
                    data=b'{"test": "perf_bench_ssl_%d"}' % i,
                    headers={"Content-Type": "application/json"},
                    method="POST",
                )
                urllib.request.urlopen(req, context=ctx, timeout=3).read()
            except Exception:
                pass
            time.sleep(0.01)
    except ImportError:
        pass

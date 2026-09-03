import base64
import numpy as np

DEFAULT_CONTENT_DIM = 16

def entropy_bytes(data: bytes) -> float:
    if not data:
        return 0.0
    counts = np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256)
    probs = counts / counts.sum()
    return -np.sum(probs * np.log2(probs + 1e-12))

def printable_ratio(data: bytes) -> float:
    if not data:
        return 0.0
    printable = sum(32 <= b < 127 for b in data)
    return printable / len(data)

def compress_ratio(data: bytes) -> float:
    if not data:
        return 0.0
    runs = 1
    for i in range(1, len(data)):
        if data[i] != data[i - 1]:
            runs += 1
    return runs / len(data)

def char_ngram_overlap(a: bytes, b: bytes) -> float:
    if not a or not b:
        return 0.0
    set_a = set(a[i:i+3] for i in range(len(a) - 2))
    set_b = set(b[i:i+3] for i in range(len(b) - 2))
    if not set_a or not set_b:
        return 0.0
    inter = len(set_a & set_b)
    return inter / max(len(set_a | set_b), 1)

CONTRADICT_PAIRS = [
    (b"OPEN_FILE", b"CLOSE_FILE"),
    (b"LOCK", b"UNLOCK"),
    (b"START", b"STOP"),
    (b"WRITE", b"DELETE"),
]

def _contradiction_score(a: bytes, b: bytes) -> float:
    for x, y in CONTRADICT_PAIRS:
        if (x in a and y in b) or (y in a and x in b):
            return 1.0
    return 0.0


class ContentFeatureExtractor:
    def __init__(self, content_dim: int = DEFAULT_CONTENT_DIM):
        self.content_dim = content_dim

    def extract(self, agents_data: dict, agent_ids: list,
                interactions: list, messages: list = None) -> dict:
        msgs_by_agent = {aid: [] for aid in agent_ids}
        for it in interactions:
            src = it.get("src")
            dst = it.get("dst")
            raw = it.get("data", "")
            if src in msgs_by_agent:
                msgs_by_agent[src].append({"data": raw, "type": it.get("type", "message")})
            if dst in msgs_by_agent:
                msgs_by_agent[dst].append({"data": raw, "type": it.get("type", "message")})
        for msg in (messages or []):
            src = msg.get("src")
            dst = msg.get("dst")
            raw = msg.get("data", "")
            if src in msgs_by_agent:
                msgs_by_agent[src].append({"data": raw, "type": msg.get("msg_type", "request")})
            if dst in msgs_by_agent:
                msgs_by_agent[dst].append({"data": raw, "type": msg.get("msg_type", "request")})

        self._agent_ids = agent_ids
        features = {}
        for aid in agent_ids:
            msgs = msgs_by_agent[aid]
            features[aid] = self._agent_features(msgs)
        return features

    def _decode(self, raw: str) -> bytes:
        if not raw:
            return b""
        try:
            return base64.b64decode(raw)
        except Exception:
            import logging
            logging.getLogger(__name__).debug("fallback to raw bytes for non-base64 data")
            return raw.encode("utf-8", errors="replace")

    def _agent_features(self, msg_list: list) -> np.ndarray:
        decoded = [self._decode(m["data"]) for m in msg_list]
        types = [m.get("type", "message") for m in msg_list]
        n = len(decoded)
        if n == 0:
            return np.zeros(self.content_dim, dtype=np.float32)

        # ── Static features (dims 0-7) ──────────────────────────────────
        lengths = np.array([len(d) for d in decoded], dtype=np.float32)
        avg_len = float(lengths.mean()) / 2048.0
        std_len = (float(lengths.std()) / 2048.0) if n > 1 else 0.0

        ents = np.array([entropy_bytes(d) for d in decoded], dtype=np.float32)
        avg_ent = float(ents.mean()) / 8.0

        prints = np.array([printable_ratio(d) for d in decoded], dtype=np.float32)
        avg_print = float(prints.mean())

        unique_payloads = len(set(m["data"] for m in msg_list if m["data"]))
        unique_ratio = unique_payloads / max(n, 1)

        null_count = sum(1 for m in msg_list if not m["data"])
        null_ratio = null_count / n

        comps = np.array([compress_ratio(d) for d in decoded], dtype=np.float32)
        avg_comp = float(comps.mean())

        has_any_data = 1.0 if any(bool(m["data"]) for m in msg_list) else 0.0

        # ── Semantic features (dims 8-15) ───────────────────────────────
        # 8: topic_similarity — avg char-3-gram overlap between consecutive msgs
        if n > 1:
            overlaps = [char_ngram_overlap(decoded[i], decoded[i+1]) for i in range(n - 1)]
            topic_sim = float(np.mean(overlaps))
        else:
            topic_sim = 1.0

        # 9: repetition_rate — ratio of messages with identical payload
        raw_datas = [m["data"] for m in msg_list]
        if n > 1:
            rep_count = sum(1 for i in range(n) if raw_datas[i] and raw_datas.count(raw_datas[i]) > 1)
            repetition_rate = rep_count / max(n, 1)
        else:
            repetition_rate = 0.0

        # 10: sentiment_variance — keyword-based sentiment spread
        pos_words = [b"OPEN", b"SUCCESS", b"COMPLETE", b"WRITE"]
        neg_words = [b"CLOSE", b"FAIL", b"ERROR", b"DELETE"]
        sentiments = []
        for d in decoded:
            pos = sum(1 for w in pos_words if w in d)
            neg = sum(1 for w in neg_words if w in d)
            sentiments.append(float(pos - neg))
        sentiment_var = float(np.var(sentiments)) / 4.0 if sentiments else 0.0

        # 11: question_ratio — messages containing "?"
        texts = [d.decode("utf-8", errors="replace") for d in decoded]
        question_count = sum(1 for t in texts if "?" in t)
        question_ratio = question_count / n

        # 12: command_ratio — messages with uppercase action words
        cmd_words = [b"OPEN", b"CLOSE", b"EXEC", b"REPEATED", b"LOCK", b"UNLOCK",
                     b"START", b"STOP", b"WRITE", b"DELETE", b"READ"]
        cmd_count = sum(1 for d in decoded if any(w in d for w in cmd_words))
        cmd_ratio = cmd_count / n

        # 13: entity_diversity — unique prefix entities
        entities = set()
        for d in decoded:
            text = d.decode("utf-8", errors="replace")
            parts = text.split("_")
            if parts:
                entities.add(parts[0])
        entity_div = len(entities) / max(len(self._agent_ids) if hasattr(self, '_agent_ids') else 4, 1)
        entity_div = min(entity_div, 1.0)

        # 14: response_ratio — ratio of response-type messages
        response_count = sum(1 for t in types if t == "response")
        response_ratio = response_count / n

        # 15: contradiction_score — adjacent contradictory pairs
        if n > 1:
            contra_scores = [_contradiction_score(decoded[i], decoded[i+1]) for i in range(n - 1)]
            contradiction_score = float(np.mean(contra_scores))
        else:
            contradiction_score = 0.0

        out = np.zeros(self.content_dim, dtype=np.float32)
        out[0] = min(avg_len, 1.0)
        out[1] = min(std_len, 1.0)
        out[2] = min(avg_ent, 1.0)
        out[3] = min(avg_print, 1.0)
        out[4] = min(unique_ratio, 1.0)
        out[5] = min(null_ratio, 1.0)
        out[6] = min(avg_comp, 1.0)
        out[7] = min(has_any_data, 1.0)
        out[8] = min(topic_sim, 1.0)
        out[9] = min(repetition_rate, 1.0)
        out[10] = min(sentiment_var, 1.0)
        out[11] = min(question_ratio, 1.0)
        out[12] = min(cmd_ratio, 1.0)
        out[13] = min(entity_div, 1.0)
        out[14] = min(response_ratio, 1.0)
        out[15] = min(contradiction_score, 1.0)
        return out

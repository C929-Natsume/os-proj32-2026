from typing import Dict, List, Optional


class UtteranceGraph:
    def __init__(self, max_agents: int = 16):
        self.max_agents = max_agents
        self.message_count = 0
        self._edges = []

    def update_from_observation(self, obs: dict):
        messages = obs.get("messages", [])
        self.message_count = len(messages)
        self._edges = [(m.get("src"), m.get("dst")) for m in messages]

    def get_frequency(self, src: str, dst: str) -> int:
        return sum(1 for s, d in self._edges if s == src and d == dst)

    def get_utterance_graph(self):
        return self._edges

    def clear(self):
        self.message_count = 0
        self._edges = []

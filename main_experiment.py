import time
from typing import Dict, Type, Optional, Counter as TypingCounter, Set
from collections import Counter

from fuzzer_core.recon import ReconModule, ReconError
from fuzzer_core.oracle import DetectionOracle
from fuzzer_core.mutation_engine import (
    RandomMutator,
    RuleBasedMutator,
    LlmMutator,
    MutatorBase,
)
from fuzzer_core.graph_model import ProtocolGraph, State

TARGET_URL = "http://127.0.0.1:5000"
MAX_REQUESTS = 25


def run_experiment(mutator_cls: Type[MutatorBase]) -> Dict:
    print(f"\n{'='*50}")
    print(f"=== ЗАПУСК ФАЗЗЕРА: {mutator_cls.__name__} ===")
    print(f"{'='*50}")

    graph = ProtocolGraph()
    oracle = DetectionOracle(TARGET_URL)
    recon = ReconModule(TARGET_URL)

    try:
        header, payload, _, public_key = recon.get_initial_state()
        graph.transition_to(State.USER)
    except ReconError as e:
        print(f"[FATAL] Recon failed: {e}")
        return {}

    mutator = mutator_cls(public_key)
    stats: TypingCounter[str] = Counter()
    unique_statuses: Set[str] = set()
    ttfe: Optional[int] = None
    total_requests = 0
    start_time = time.time()

    while total_requests < MAX_REQUESTS:
        attacks = mutator.generate_attacks(header, payload)
        if not attacks:
            continue

        for token, description in attacks:
            if total_requests >= MAX_REQUESTS:
                break

            total_requests += 1
            result = oracle.evaluate_admin_access(token)

            stats[result.status] += 1
            unique_statuses.add(result.status)

            mutator.process_feedback(description, result)

            print(
                f"[{total_requests:02d}] {description:<45} -> "
                f"[{result.status}] (HTTP {result.http_code})"
            )

            if result.status == "SUCCESS" and ttfe is None:
                ttfe = total_requests
                graph.transition_to(State.ADMIN)

    elapsed = time.time() - start_time
    success_rate = stats["SUCCESS"] / total_requests if total_requests else 0.0
    coverage_score = len(unique_statuses)

    print("\n--- ИТОГИ ПРОГОНА ---")
    print(f"Запросов: {total_requests} | Время: {elapsed:.2f}s")
    print(f"Статусы: {dict(stats)}")

    return {
        "success_rate": success_rate,
        "ttfe": ttfe or -1,
        "total_requests": total_requests,
        "execution_time": elapsed,
        "coverage": coverage_score,
    }


def main():
    print("=== Исследование Нейро-Символьного Фаззинга JWT ===")
    results = {}

    results["Random"] = run_experiment(RandomMutator)
    results["RuleBased"] = run_experiment(RuleBasedMutator)
    results["LLM (Neuro)"] = run_experiment(LlmMutator)

    print("\n\n" + "=" * 80)
    print("И Т О Г О В А Я   С Р А В Н И Т Е Л Ь Н А Я   Т А Б Л И Ц А")
    print("=" * 80)
    print(
        f"{'Mutator Type':<15} | {'Success Rate':<12} | {'TTFE':<6} | {'Coverage':<8} | {'Reqs':<6} | {'Time (s)':<8}"
    )
    print("-" * 80)
    for name, res in results.items():
        if not res:
            continue
        sr = f"{res['success_rate']:.2f}"
        ttfe = f"{res['ttfe']}" if res["ttfe"] != -1 else "N/A"
        cov = f"{res['coverage']}/4"
        req = f"{int(res['total_requests'])}"
        t = f"{res['execution_time']:.2f}"
        print(f"{name:<15} | {sr:<12} | {ttfe:<6} | {cov:<8} | {req:<6} | {t:<8}")
    print("=" * 80)


if __name__ == "__main__":
    main()

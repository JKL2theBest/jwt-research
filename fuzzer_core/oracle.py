import requests
from dataclasses import dataclass


@dataclass
class OracleResult:
    """Структура для сбора метрик фаззинга"""

    status: str  # 'SUCCESS', 'AUTH_FAIL', 'PARSE_FAIL', 'SERVER_ERROR', 'TIMEOUT'
    http_code: int  # 200, 401, 403, 500
    flag_found: bool  # Нашли ли уязвимость
    response_body: str  # Сырой ответ сервера
    latency_ms: float  # Время ответа (пригодится для анализа Time-based уязвимостей)


class DetectionOracle:
    """Модуль, оценивающий успешность атаки по реакции сервера"""

    def __init__(self, target_url: str) -> None:
        self.target_url = target_url

    def evaluate_admin_access(self, token: str) -> OracleResult:
        """Отправляет JWT токен на сервер и классифицирует результат"""
        headers = {"Authorization": f"Bearer {token}"}

        try:
            resp = requests.get(
                f"{self.target_url}/admin", headers=headers, timeout=5.0
            )
            latency = resp.elapsed.total_seconds() * 1000  # Переводим в мс

            flag_found = "FLAG{" in resp.text

            # Классификация ошибки (Predicate logic)
            if resp.status_code == 200 and flag_found:
                status = "SUCCESS"
            elif resp.status_code in (401, 403):
                status = "AUTH_FAIL"  # Сервер корректно отбил атаку
            elif resp.status_code == 400:
                status = "PARSE_FAIL"  # Токен структурно сломан (плохой Base64/JSON)
            else:
                status = (
                    "SERVER_ERROR"  # Сервер упал (500) - это тоже интересная находка!
                )

            return OracleResult(
                status=status,
                http_code=resp.status_code,
                flag_found=flag_found,
                response_body=resp.text.strip(),
                latency_ms=latency,
            )

        except requests.exceptions.Timeout:
            return OracleResult("TIMEOUT", 0, False, "", 5000.0)
        except Exception as e:
            return OracleResult("CONNECTION_ERROR", 0, False, str(e), 0.0)


if __name__ == "__main__":
    print("[*] Тест Оракула (без валидного токена ожидается AUTH_FAIL)...")
    oracle = DetectionOracle("http://127.0.0.1:5000")
    res = oracle.evaluate_admin_access("invalid.token.123")
    print(f"Status: {res.status}, Code: {res.http_code}, Flag: {res.flag_found}")

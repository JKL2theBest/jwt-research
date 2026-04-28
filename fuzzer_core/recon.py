import requests
import json
import base64
from typing import Dict, Tuple, Any


class ReconError(Exception):
    """Кастомное исключение для ошибок разведки"""

    pass


class ReconModule:
    """Модуль сбора исходных данных для начала фаззинга"""

    def __init__(self, target_url: str) -> None:
        self.target_url = target_url

    def _base64url_decode(self, data: str) -> str:
        padding = "=" * (4 - (len(data) % 4))
        return base64.urlsafe_b64decode(data + padding).decode("utf-8")

    def get_initial_state(self) -> Tuple[Dict[str, Any], Dict[str, Any], str, str]:
        """
        Возвращает кортеж: (header_dict, payload_dict, raw_token, public_key).
        В случае любой ошибки выбрасывает ReconError.
        """
        try:
            # 1. Получаем публичный ключ
            pubkey_resp = requests.get(f"{self.target_url}/public_key", timeout=2)
            pubkey_resp.raise_for_status()
            server_public_key = pubkey_resp.json().get("public_key")

            if not server_public_key:
                raise ValueError("Сервер не вернул public_key")

            # 2. Логинимся как обычный пользователь
            login_resp = requests.post(f"{self.target_url}/login", timeout=2)
            login_resp.raise_for_status()
            raw_token = login_resp.json().get("token")

            if not raw_token:
                raise ValueError("Сервер не вернул token")

            # 3. Парсим токен
            parts = raw_token.split(".")
            if len(parts) < 2:
                raise ValueError("Неверный формат токена от сервера")

            header = json.loads(self._base64url_decode(parts[0]))
            payload = json.loads(self._base64url_decode(parts[1]))

            return header, payload, raw_token, server_public_key

        except Exception as e:
            # Оборачиваем любую ошибку в наше кастомное исключение
            raise ReconError(f"Сбой этапа разведки: {str(e)}")


if __name__ == "__main__":
    print("[*] Тест модуля Разведки...")
    recon = ReconModule("http://127.0.0.1:5000")

    try:
        h, p, t, key = recon.get_initial_state()
        print(f"[+] Токен получен. Алгоритм: {h.get('alg')}, Роль: {p.get('role')}")
    except ReconError as err:
        print(f"[-] {err}")

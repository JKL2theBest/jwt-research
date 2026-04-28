from typing import List, Dict


class State:
    """Определение узлов графа (состояний протокола)"""

    UNAUTH = "UNAUTH"  # Состояние 0: Нет токена
    USER = "USER"  # Состояние 1: Получен легитимный токен гостя
    ADMIN = "ADMIN"  # Состояние 2: Доступ к секретному эндпоинту


class ProtocolGraph:
    """
    Ориентированный граф состояний протокола.
    Контролирует логику переходов (макро-уровень фаззинга).
    """

    def __init__(self) -> None:
        self.states: List[str] = [State.UNAUTH, State.USER, State.ADMIN]
        # Разрешенные переходы (Edges)
        self.transitions: Dict[str, List[str]] = {
            State.UNAUTH: [State.USER],
            State.USER: [State.ADMIN],
            State.ADMIN: [],  # Конечное состояние
        }
        self.current_state: str = State.UNAUTH

    def can_transition(self, target_state: str) -> bool:
        """Проверяет, существует ли ребро между текущим и целевым состоянием"""
        return target_state in self.transitions.get(self.current_state, [])

    def transition_to(self, target_state: str) -> bool:
        """Выполняет переход по графу, если он разрешен"""
        if self.can_transition(target_state):
            self.current_state = target_state
            return True
        return False

    def reset(self) -> None:
        """Сброс сессии фаззинга в начальное состояние"""
        self.current_state = State.UNAUTH


if __name__ == "__main__":
    # Проверка работы графа
    graph = ProtocolGraph()
    print(f"[*] Начальное состояние: {graph.current_state}")

    if graph.transition_to(State.USER):
        print(f"[+] Успешный переход в {graph.current_state}")

    if not graph.transition_to(State.UNAUTH):
        print("[-] Ожидаемая ошибка: Переход USER -> UNAUTH запрещен графом.")

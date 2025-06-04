from abc import ABC, abstractmethod

class ScanStrategy(ABC):
    @abstractmethod
    def scan(self, host: str, port: int) -> tuple[int, dict] | None:
        pass
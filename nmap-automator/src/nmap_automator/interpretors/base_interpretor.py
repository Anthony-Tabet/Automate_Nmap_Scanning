from abc import ABC, abstractmethod

class BaseInterpretor(ABC):
    def __init__(
        self,
        name: str,
        model_flavor: str,
        api_key: str=None
    ) -> None:
        self.name = name
        self.api_key = api_key
        self.model_flavor = model_flavor
        self.results = None
        self.is_configured = False

    @abstractmethod
    def configure(self) -> None:
        self.is_configured = True

    @abstractmethod
    def save_results(self, results: dict, save_dir: str) -> None:
        pass
    
    @abstractmethod
    def interpret(self, scan_results: str, save_dir: str) -> dict:
        pass

    @abstractmethod
    def interpret_restricted(self, scan_results: str, save_dir: str) -> dict:
        pass

    @abstractmethod
    def interpret_with_suggestions(self, scan_results: str, save_dir: str) -> dict:
        pass

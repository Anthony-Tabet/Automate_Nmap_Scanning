from abc import ABC, abstractmethod

class BaseInterpretor(ABC):
    def __init__(
        self,
        target: str,
        name: str,
        model_flavor: str,
        api_key: str=None
    ) -> None:
        self.target = target
        self.name = name
        self.api_key = api_key
        self.model_flavor = model_flavor
        self.results = None
        self.is_configured = False

    @abstractmethod
    def configure(self) -> None:
        pass
    
    @abstractmethod
    def interpret(self, scan_results: str) -> dict:
        pass

    @abstractmethod
    def interpret_restricted(self, scan_results: str) -> dict:
        pass

    @abstractmethod
    def interpret_with_suggestions(self, scan_results: str) -> dict:
        pass

from abc import ABC, abstractmethod
import io
import os
import json

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

    def save_results(self, results: dict, save_dir: str) -> None:
        # Save the results to a file
        with io.open(os.path.join(save_dir, f"{self.name}_results.json"), "w") as f:
            f.write(json.dumps(results, indent=4))

    @abstractmethod
    def configure(self) -> None:
        self.is_configured = True

    @abstractmethod
    def _interpret(self, scan_results: str, save_dir: str, prompt: str, deterministic: bool = False) -> dict:
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
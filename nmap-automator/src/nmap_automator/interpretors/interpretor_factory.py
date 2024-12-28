from .gpt_based_interpretor import GPTInterpretor
from .ollama_interpretor import OllamaInterpretor
from .gemini_based_interpretor import GeminiInterpretor
from .base_interpretor import BaseInterpretor

class InterpretorFactory:
    @staticmethod
    def create_interpretor(
        interpretor_type: str,
        name: str,
        model_flavor: str="models/gemini-1.5-pro",
        api_key: str=None
    ) -> BaseInterpretor:
        if interpretor_type == "ollama":
            return OllamaInterpretor(name, model_flavor, api_key)
        elif interpretor_type == "gpt":
            return GPTInterpretor(name, model_flavor, api_key)
        elif interpretor_type == "gemini":
            return GeminiInterpretor(name, model_flavor, api_key)
        else:
            raise ValueError("Interpretor type not supported.")

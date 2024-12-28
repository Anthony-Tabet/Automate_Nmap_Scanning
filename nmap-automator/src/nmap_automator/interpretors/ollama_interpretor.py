from abc import ABC
from .base_interpretor import BaseInterpretor
from ollama import chat

class OllamaInterpretor(BaseInterpretor):
    def __init__(
        self,
        name: str,
        model_flavor: str="gemma2",
        api_key: str=None
    ):
        self.__client = None
        super().__init__(name, model_flavor, api_key)

    
    def configure(self):
        super().configure()
    
    
    def interpret(self, scan_results: str) -> dict:
        classifications = {
            "error": None,
            "result": None
        }

        if not self.is_configured:
            classifications["error"] =  "Interpretor not configured."
        else:
            prompt = (
                f"""
                Classify the following scan results as Completed,
                Incomplete, or False Positive Rich:\n\n{scan_results}
                """
            )
            try:
                response = chat(
                    model=self.model_flavor, 
                    messages=[{"role": "user", "content": prompt}]
                )
                classification = response.message.content.strip() 
                classifications["result"] = classification
            except Exception as e:
                classifications["error"] = f"Error with Llama API: {e}"
        
        return classifications

    
    def interpret_restricted(self, scan_results: str) -> dict:
        classifications = {
            "error": None,
            "result": None
        }

        if not self.is_configured:
            classifications["error"] =  "Interpretor not configured."
        else:
            try:
                prompt = (
                    f"""
                    Classify the following scan results into one of the following categories:
                    'Completed', 'Incomplete', or 'False Positive Rich'.
                    Do not provide any details, only return the category name.
                    \n\n{scan_results}
                    """
                )
                response = chat(
                    model=self.model_flavor, 
                    messages=[{"role": "user", "content": prompt}]
                )
                classification = response.message.content.strip() 
                classifications["result"] = classification
            except Exception as e:
                classifications["error"] = f"Error with Llama API: {e}"        
        return classifications

    
    def interpret_with_suggestions(self, scan_results: str) -> dict:
        classifications = {
            "error": None,
            "result": None
        }

        if not self.is_configured:
            classifications["error"] =  "Interpretor not configured."
        else:
            try:
                prompt = (
                    f"""
                    Classify the following scan results as Completed, Incomplete,
                    or False Positive Rich. 
                    Also, recommend the next scan type (e.g., -sS, -T2, etc.)
                    based on your analysis:\n\n{scan_results}
                    """
                )
                response = chat(
                    model=self.model_flavor, 
                    messages=[{"role": "user", "content": prompt}]
                )
                classification = response.message.content.strip() 
                classifications["result"] = classification
            except Exception as e:
                classifications["error"] = f"Error with Llama API: {e}"
                
        return classifications
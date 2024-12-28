from abc import ABC
from .base_interpretor import BaseInterpretor
import os
import io
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

    def save_results(self, results: dict, save_dir: str) -> None:
        # Save the results to a file
        with io.open(os.path.join(save_dir, "ollama_results.json"), "w") as f:
            results = str(results)
            f.write(results)
    
    def interpret(self, scan_results: str, save_dir: str) -> dict:
        classifications = {
            "error": None,
            "result": None
        }

        if not self.is_configured:
            classifications["error"] = "Interpretor not configured."
        else:
            prompt = (
                f"""
                Classify the following nmap scan results as Completed,
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
                classifications["error"] = f"Error with ollama API: {e}"
        
        self.save_results(classifications, save_dir)
        return classifications

    def interpret_restricted(self, scan_results: str, save_dir: str) -> dict:
        classifications = {
            "error": None,
            "result": None
        }

        if not self.is_configured:
            classifications["error"] = "Interpretor not configured."
        else:
            try:
                prompt = (
                    f"""
                    Classify the following nmap scan results into one of the following categories:
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
                classifications["error"] = f"Error with ollama API: {e}" 

        self.save_results(classifications, save_dir)
        return classifications
    
    def interpret_with_suggestions(self, scan_results: str, save_dir: str) -> dict:
        classifications = {
            "error": None,
            "result": None,
            "next_scan": None
        }

        if not self.is_configured:
            classifications["error"] = "Interpretor not configured."
        else:
            try:
                prompt = (
                    f"""
                    Classify the following nmap scan results as Completed, Incomplete,
                    or False Positive Rich. 
                    Also, recommend the next scan type (e.g., -sS, -T2, etc.)
                    and write the command to run in the end within a "```" block.
                    based on your analysis:\n\n{scan_results}
                    """
                )
                response = chat(
                    model=self.model_flavor, 
                    messages=[{"role": "user", "content": prompt}]
                )
                classification, next_scan = (
                    response.message.content.strip(), 
                    response.message.content.strip().split('\n```\n')[1].replace('```', '').replace('\n', '')
                )
                classification = response.message.content.strip()
                classifications["result"] = classification
                classifications["next_scan"] = next_scan
            except Exception as e:
                classifications["error"] = f"Error with ollama API: {e}"

        self.save_results(classifications, save_dir)                
        return classifications
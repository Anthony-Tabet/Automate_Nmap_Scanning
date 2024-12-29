from abc import ABC
from .base_interpretor import BaseInterpretor
import io
import os
import google.generativeai as genai

class GeminiInterpretor(BaseInterpretor):
    def __init__(
        self,
        name: str,
        model_flavor: str="models/gemini-1.5-pro",
        api_key: str=None
    ):
        self.__client = None
        self.__model = None
        self.__safety_settings = [
            {
                "category": "HARM_CATEGORY_DANGEROUS",
                "threshold": "BLOCK_NONE"
            },
            {
                "category": "HARM_CATEGORY_HARASSMENT",
                "threshold": "BLOCK_NONE"
            },
            {
                "category": "HARM_CATEGORY_HATE_SPEECH",
                "threshold": "BLOCK_NONE"
            },
            {
                "category": "HARM_CATEGORY_SEXUALLY_EXPLICIT",
                "threshold": "BLOCK_NONE"
            },
            {
                "category": "HARM_CATEGORY_DANGEROUS_CONTENT",
                "threshold": "BLOCK_NONE"
            },
        ]
        super().__init__(name, model_flavor, api_key)
    
    
    def configure(self) -> None:
        self.__client = genai.configure(api_key=self.api_key)
        self.__model = genai.GenerativeModel(self.model_flavor)
        super().configure()

    def save_results(self, results: dict, save_dir: str) -> None:
        # Save the results to a file
        with io.open(os.path.join(save_dir, "gemini_results.json"), "w") as f:
            results = str(results)
            f.write(results)
    
    def interpret(self, scan_results: str, save_dir: str) -> dict:
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
                    Classify the following scan results as Completed, 
                    Incomplete, or False Positive Rich:\n\n{scan_results}
                    """
                ).strip()

                print(f"Prompting { self.model_flavor.upper() }:", prompt)
                
                response = self.__model.generate_content([prompt], safety_settings=self.__safety_settings)
                classification = response.text.strip() 
                classifications["result"] = classification
            except Exception as e:
                classifications["error"] = f"Error with Gemini API: {e}"

        self.save_results(classifications, save_dir)
        return classifications  
    
    def interpret_restricted(self, scan_results: str, save_dir: str) -> dict:
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
                    'Completed', 'Incomplete', or 'False Positive Rich'. Do not provide any details,
                    only return the category name.\n\n{scan_results}
                    """
                ).strip()

                print(f"Prompting { self.model_flavor.upper() }:", prompt)

                response = self.__model.generate_content([prompt], safety_settings=self.__safety_settings)
                classification = response.text.strip() 
                classifications["result"] = classification
            except Exception as e:
                classifications["error"] = f"Error with Gemini API: {e}"

        self.save_results(classifications, save_dir)
        return classifications 
    
    def interpret_with_suggestions(self, scan_results: str, save_dir: str) -> dict:
        classifications = {
            "error": None,
            "result": None,
            "next_scan": None
        }

        if not self.is_configured:
            classifications["error"] =  "Interpretor not configured."
        else:
            try:
                prompt = (
                    f"""
                    Classify the following scan results as Completed, Incomplete, or False Positive Rich. 
                    Also, recommend the next scan type (e.g., -sS, -T2, etc.) based on your analysis:
                    \n\n{scan_results}
                    """
                ).strip()

                print(f"Prompting { self.model_flavor.upper() }:", prompt)

                response = self.__model.generate_content([prompt], safety_settings=self.__safety_settings)
                classification, next_scan = (
                    response.text.strip().split('\n')[0], 
                    response.text.strip().split('\n')[1]
                )
                classifications["result"] = classification
                classifications["next_scan"] = next_scan
            except Exception as e:
                classifications["error"] = f"Error with Gemini API: {e}"

        self.save_results(classifications, save_dir)
        return classifications
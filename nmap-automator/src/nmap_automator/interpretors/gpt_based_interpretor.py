from abc import ABC
from .base_interpretor import BaseInterpretor
import io
import os
from openai import OpenAI

class GPTInterpretor(BaseInterpretor):
    def __init__(
        self,
        name: str,
        model_flavor: str="gpt-4",
        api_key: str=None
    ):
        self.__client = None
        super().__init__(name, model_flavor, api_key)

    
    def configure(self):
        self.__client = OpenAI(api_key=self.api_key)
        super().configure()

    def save_results(self, results: dict, save_dir: str) -> None:
        # Save the results to a file
        with io.open(os.path.join(save_dir, "gpt_results.json"), "w") as f:
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
                )
                
                user_msg_input_class = self.__client.chat.completions.create(
                    model=self.model_flavor,
                    messages=[
                        {
                            "role": "system",
                            "content": (
                                """
                                You are a system that classifies scan results as 'Completed', 
                                'Incomplete', or 'False Positive Rich' based
                                on the scan data provided.
                                """
                            )
                        },
                        {
                            "role": "user",
                            "content": prompt
                        },
                    ],
                    temperature=1,
                    top_p=1
                )
                classification = user_msg_input_class.choices[0].message.content.strip()
                classifications["result"] = classification
            except Exception as e:
                classifications["error"] = f"Error with OpenAI API: {e}"
        
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
                    'Completed', 'Incomplete', or 'False Positive Rich'.
                    Do not provide any details, only return the category name.
                    \n\n{scan_results}
                    """
                )

                print(f"Prompting { self.model_flavor.upper() }:", prompt)

                user_msg_input_class = self.__client.chat.completions.create(
                    model=self.model_flavor,
                    messages=[
                        {
                            "role": "system", 
                            "content": (
                                """
                                You are a system that classifies scan results into one of
                                the following categories:
                                'Completed', 'Incomplete', or 'False Positive Rich'.
                                Do not provide any details, only return the category name.
                                """
                            )
                        },
                        {
                            "role": "user", 
                            "content": prompt
                        },
                    ],
                    temperature=0,  # Set temperature to 0 for deterministic responses
                    top_p=1
                )
                classification = (
                    user_msg_input_class.choices[0].message.content.strip()
                )
                classifications["result"] = classification
            except Exception as e:
                classifications["error"] = f"Error with OpenAI API: {e}"
        
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
                    Classify the following scan results as Completed, Incomplete,
                    or False Positive Rich. 
                    Also, recommend the next scan type (e.g., -sS, -T2, etc.)
                    based on your analysis:\n\n{scan_results}
                    """
                )

                print(f"Prompting { self.model_flavor.upper() }:", prompt)

                user_msg_input_class = self.__client.chat.completions.create(
                    model=self.model_flavor,
                    messages=[
                        {
                            "role": "system", 
                            "content": (
                                """
                                You are a system that classifies scan results as
                                'Completed', 'Incomplete', or 'False Positive Rich'
                                and recommends the next nmap scan type.
                                """
                            )
                        },
                        {
                            "role": "user", 
                            "content": prompt
                        },
                    ],
                    temperature=1,
                    top_p=1
                )
                classification, next_scan = (
                    user_msg_input_class.choices[0].message.content.strip().split('\n')
                )
                classifications["result"] = classification
                classifications["next_scan"] = next_scan      
            except Exception as e:
                classifications["error"] = f"Error with OpenAI API: {e}"
                
        self.save_results(classifications, save_dir) 
        return classifications
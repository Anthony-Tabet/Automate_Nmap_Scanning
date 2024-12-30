from .base_interpretor import BaseInterpretor
import io
import os
import json
from openai import OpenAI

PROMPTS = {
    "default": (
        "Classify the following scan results as Completed, Incomplete, or False Positive Rich:\n\n{scan_results}"
    ),
    "restricted": (
        "Classify the following scan results into one of the following categories:\n"
        "'Completed', 'Incomplete', or 'False Positive Rich'.\n"
        "Do not provide any details, only return the category name.\n\n{scan_results}"
    ),
    "with_suggestions": (
        "Classify the following scan results as Completed, Incomplete, or False Positive Rich.\n"
        "Provide a JSON response with the following fields:\n"
        "1. 'classification': The classification result.\n"
        "2. 'analysis_description': A detailed explanation of the classification decision.\n"
        "3. 'next_arguments': An array of recommended arguments for the next scan.\n\n{scan_results}"
    ),
}

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

    def _interpret(self, scan_results: str, save_dir: str, prompt_key: str, deterministic: bool = False) -> dict:
        classifications = {
            "error": None,
            "result": None,
            "next_scan": None
        }

        if not self.is_configured:
            classifications["error"] = "Interpretor not configured."
        else:
            try:
                prompt = PROMPTS[prompt_key].format(scan_results=scan_results)
                messages = [
                    {
                        "role": "system",
                        "content": (
                            "You are a system that classifies scan results as 'Completed', "
                            "'Incomplete', or 'False Positive Rich', optionally providing additional "
                            "recommendations based on your analysis."
                        )
                    },
                    {
                        "role": "user",
                        "content": prompt
                    }
                ]

                response = self.__client.chat.completions.create(
                    model=self.model_flavor,
                    messages=messages,
                    temperature=0 if deterministic else 1,
                    top_p=1
                )
                output = response.choices[0].message.content.strip()

                # Attempt to extract JSON from response
                json_start = output.find('{')  # Find the first '{' character
                json_end = output.rfind('}')  # Find the last '}' character

                if json_start != -1 and json_end != -1:
                    sanitized_output = output[json_start:json_end + 1]  # Extract JSON part
                    parsed_output = json.loads(sanitized_output)  # Parse as JSON
                    classifications["result"] = parsed_output.get("classification", None)
                    classifications["analysis_description"] = parsed_output.get("analysis_description", None)
                    classifications["next_arguments"] = parsed_output.get("next_arguments", [])
                else:
                    classifications["error"] = "No valid JSON found in LLM response."

            except json.JSONDecodeError:
                classifications["error"] = "Failed to parse JSON response from LLM."
            except Exception as e:
                classifications["error"] = f"Error with OpenAI API: {e}"

        self.save_results(classifications, save_dir)
        return classifications
    
    def interpret(self, scan_results: str, save_dir: str) -> dict:
        return self._interpret(scan_results, save_dir, "default")
    
    def interpret_restricted(self, scan_results: str, save_dir: str) -> dict:
       return self._interpret(scan_results, save_dir, "restricted", deterministic=True)

    def interpret_with_suggestions(self, scan_results: str, save_dir: str) -> dict:
        return self._interpret(scan_results, save_dir, "with_suggestions")
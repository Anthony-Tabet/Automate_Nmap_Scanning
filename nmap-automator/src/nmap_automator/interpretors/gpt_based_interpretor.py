from .base_interpretor import BaseInterpretor
from .prompts import PROMPTS

import json
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
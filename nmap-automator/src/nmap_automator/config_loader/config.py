import os
from typing import Literal

from pydantic import BaseModel, field_validator, model_validator, Field
from omegaconf import OmegaConf

class ScannerConfig(BaseModel):
    nmap_args: list[str]
    save_dir: str
    target: str

    @field_validator("nmap_args")
    @classmethod
    def validate_nmap_args(cls, v):
        if not isinstance(v, list):
            raise ValueError("nmap_args must be a list")
        for arg in v:
            if not isinstance(arg, str):
                raise ValueError("nmap-args must be a list of strings")
            if arg not in ['-sS', '-sV', '-sT', '-A', '-T3', '-v', '-p', '-T4']:
                raise ValueError("nmap-args must be one of '-sS', '-sT', '-A', '-T3', '-T4', '-v'")
        return v
    
    @field_validator("save_dir")
    @classmethod
    def validate_save_dir(cls, v):
        if not isinstance(v, str):
            raise ValueError("save-dir must be a string")
        return v
    
    @field_validator("target")
    @classmethod
    def validate_target(cls, v):
        if not isinstance(v, str):
            raise ValueError("target must be a string")
        return v
    
class InterpretorConfig(BaseModel):
    interpretor_type: Literal["ollama", "gpt", "gemini"]
    model_flavor: str
    interpret_runner: Literal["normal", "restricted", "suggest"]

    @model_validator(mode='before')
    def validate_interpretor_config(cls, values):
        interpretor_type = values.get('interpretor_type')
        model_flavor = values.get('model_flavor')
        interpret_runner = values.get('interpret_runner')

        model_model_flavor = {
            "gpt": ["gpt-4", "gpt-4o", "gpt-4o-mini", "o1", "o1-mini"],
            "gemini": [
                "models/gemini-1.5-pro", "models/gemini-1.5-flash",
                "models/gemini-1.5-flash-8b", "models/gemini-1.0-pro"
            ],
            "ollama": [
                "llama3.3", "llama3.2", "llama3.1", "llama3", 
                "llama2", "gemma2", "gemma",
                "jimscard/whiterabbit-neo", "ALIENTELLIGENCE/cybersecuritythreatanalysis"
            ]
        }
        
        if interpretor_type not in ["ollama", "gpt", "gemini"]:
            raise ValueError("interpretor_type must be one of 'ollama', 'gpt', 'gemini'")
        
        valid_flavors = model_model_flavor.get(interpretor_type, [])

        if model_flavor not in valid_flavors:
            raise ValueError(f"model_flavor must be one of {valid_flavors} for interpretor_type '{interpretor_type}'")
        
        if interpret_runner not in ["normal", "restricted", "suggest"]:
            raise ValueError("interpret_runner must be one of 'normal', 'restricted', 'suggest'")
        
        return values

class NmapScanRequest(BaseModel):
    """Request model for the /nmap_scan endpoint."""
    scanner: ScannerConfig = Field(..., description="Scanner configuration for the Nmap scan.")

class LLMInterpretRequest(BaseModel):
    """Request model for the /llm_interpret endpoint."""
    scanner: ScannerConfig = Field(..., description="Scanner configuration for the saved directory.")
    interpretor: InterpretorConfig = Field(..., description="Interpreter configuration for the LLM.")
    file_path: str = Field(..., description="Path to the CSV file with scan results.")

class Config(BaseModel):
    scanner: ScannerConfig
    interpretor: InterpretorConfig

    @classmethod
    def load(cls, path: str):
        if not os.path.exists(path):
            raise FileNotFoundError(f"Config file not found at '{path}'")
        config = OmegaConf.load(path)
        return cls(**config)
    
    @classmethod
    def from_json(cls, json: dict):
        config = OmegaConf.create(json)
        return cls(**config)

    def save(self, path: str):
        OmegaConf.save(self.model_dump(), path)

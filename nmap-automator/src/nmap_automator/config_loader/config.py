import os
from typing import Literal

from pydantic import BaseModel, field_validator, model_validator
from omegaconf import OmegaConf

class ScannerConfig(BaseModel):
    nmap_args: list[str]
    save_dir: str
    target: str
    @field_validator("nmap-args")
    @classmethod
    def validate_nmap_args(cls, v):
        if not isinstance(v, list):
            raise ValueError("nmap_args must be a list")
        for arg in v:
            if not isinstance(arg, str):
                raise ValueError("nmap-args must be a list of strings")
            if arg not in ['-sS', '-sT', '-A', '-T3', '-v', '-p', '-T4']:
                raise ValueError("nmap-args must be one of '-sS', '-sT', '-A', '-T3', '-T4', '-v'")
        return v
    
    @field_validator("save-dir")
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
    name: str
    model_flavor: Literal[
        "gpt-4", "gpt-4o", "gpt-4o-mini", "o1", "o1-mini",
        "models/gemini-1.5-pro", "models/gemini-1.5-flash",
        "models/gemini-1.5-flash-8b", "models/gemini-1.0-pro",
        "llama3.3", "llama3.2", "llama3.1", "llama3", "llama2",
        "gemma2", "gemma", "shieldgemma"
    ]
    model_model_flavor: dict = {
        "gpt": ["gpt-4", "gpt-4o", "gpt-4o-mini", "o1", "o1-mini"],
        "gemini": [
            "models/gemini-1.5-pro", "models/gemini-1.5-flash",
            "models/gemini-1.5-flash-8b", "models/gemini-1.0-pro"
        ],
        "ollama": [
            "llama3.3", "llama3.2", "llama3.1", "llama3", 
            "llama2", "gemma2", "gemma",
            "jimscard/whiterabbit-neo", "monotykamary/whiterabbitneo-v1.5a"
        ]
    }
    api_key: str

    @model_validator(mode='before')
    def validate_interpretor_config(cls, values):
        interpretor_type = values.get('interpretor_type')
        model_flavor = values.get('model_flavor')
        
        if interpretor_type not in ["ollama", "gpt", "gemini"]:
            raise ValueError("interpretor_type must be one of 'ollama', 'gpt', 'gemini'")
        
        valid_flavors = cls.model_model_flavor.get(interpretor_type, [])
        if model_flavor not in valid_flavors:
            raise ValueError(f"model_flavor must be one of {valid_flavors} for interpretor_type '{interpretor_type}'")
        
        if not isinstance(values.get('api_key'), str):
            raise ValueError("api_key must be a string")
        
        return values
    
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

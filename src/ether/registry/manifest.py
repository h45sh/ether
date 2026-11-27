"""Pydantic models for Ether-native tool manifests."""

from __future__ import annotations

from typing import Dict, List, Literal

from pydantic import BaseModel, Field, field_validator


class ToolMeta(BaseModel):
    """Core metadata identifying a tool adapter."""

    name: str
    description: str
    one_line_summary: str = ""
    category: str = "Misc"
    categories: List[str] = Field(default_factory=list)
    binary: str = ""
    execution_tier: str = "subprocess"  # "coroutine" | "subprocess"
    theory: str = ""


class FlagsConfig(BaseModel):
    """Declarative CLI flag contract enforced by FlagFirewall under GatePolicy.SAFE."""

    allowed: List[str] = Field(default_factory=list)
    blocked: List[str] = Field(default_factory=list)
    value_types: Dict[str, str] = Field(default_factory=dict)
    compound_delimiters: List[str] = Field(default_factory=lambda: ["=", ":", ","])


class ExecutionConfig(BaseModel):
    """Execution tier and stream-parsing hints for the Ether supervisor."""

    tier: Literal["coroutine", "subprocess"] = "subprocess"
    output_format: Literal["ndjson", "json", "xml", "text", "coroutine"] = "text"
    supports_streaming_parse: bool = True
    default_timeout_sec: float = 120.0


class Manifest(BaseModel):
    """Structure of tools/<name>/manifest.toml."""

    meta: ToolMeta
    input: Dict[str, List[str]]
    output: Dict[str, List[str]]
    flags: FlagsConfig = Field(default_factory=FlagsConfig)
    execution: ExecutionConfig = Field(default_factory=ExecutionConfig)
    profiles: Dict[str, List[str]] = Field(default_factory=dict)

    @field_validator("profiles")
    @classmethod
    def _validate_profiles(cls, v: Dict[str, List[str]]) -> Dict[str, List[str]]:
        if len(v) > 3:
            raise ValueError("Manifest [profiles] must contain at most 3 concise preset vectors.")
        return v

from __future__ import annotations

from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict, Field


class ScoringWeights(BaseModel):
    CRITICAL: int = Field(alias="CRITICAL")
    HIGH: int = Field(alias="HIGH")
    MEDIUM: int = Field(alias="MEDIUM")
    LOW: int = Field(alias="LOW")
    INFO: int = Field(alias="INFO")

    model_config = ConfigDict(extra="forbid", populate_by_name=True)


class CategoryCaps(BaseModel):
    typosquat: int
    behavior: int
    cve: int
    maintainer: int

    model_config = ConfigDict(extra="forbid")


class BehaviorLimits(BaseModel):
    max_tarball_mb: int
    entropy_threshold: float
    raw_ip_whitelist: list[str]

    model_config = ConfigDict(extra="forbid")


class TyposquatDistanceThresholds(BaseModel):
    high_confidence_max_distance: int
    medium_confidence_max_distance: int
    low_confidence_max_distance: int

    model_config = ConfigDict(extra="forbid")


class RulesConfig(BaseModel):
    schema_version: int = 1
    scoring_weights: ScoringWeights
    category_caps: CategoryCaps
    behavior_limits: BehaviorLimits
    typosquat_distance_thresholds: TyposquatDistanceThresholds

    model_config = ConfigDict(extra="forbid")


DEFAULT_RULES: RulesConfig = RulesConfig(
    schema_version=1,
    scoring_weights=ScoringWeights(
        CRITICAL=25,
        HIGH=15,
        MEDIUM=8,
        LOW=3,
        INFO=0,
    ),
    category_caps=CategoryCaps(
        typosquat=30,
        behavior=60,
        cve=25,
        maintainer=20,
    ),
    behavior_limits=BehaviorLimits(
        max_tarball_mb=50,
        entropy_threshold=4.5,
        raw_ip_whitelist=["127.0.0.1", "localhost"],
    ),
    typosquat_distance_thresholds=TyposquatDistanceThresholds(
        high_confidence_max_distance=1,
        medium_confidence_max_distance=2,
        low_confidence_max_distance=3,
    ),
)


def load_config(path: str = "rules.yaml") -> RulesConfig:
    config_path = Path(path).expanduser()
    if not config_path.exists():
        return DEFAULT_RULES

    try:
        raw = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as e:
        raise ValueError(f"Failed to read/parse rules YAML at {config_path!s}: {e}") from e

    if raw is None:
        raw = {}

    return RulesConfig.model_validate(raw)

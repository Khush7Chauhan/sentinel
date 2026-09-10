from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Literal

from pydantic import BaseModel, Field


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class PackageRecord(BaseModel):
    name: str
    version: str
    ecosystem: Literal["npm", "pypi", "go", "cargo"]
    direct: bool
    depth: int
    source_file: str
    resolved_url: str | None


class Finding(BaseModel):
    id: str
    layer: Literal["L1", "L2", "L3"]
    package: str | None
    type: str
    severity: Severity
    confidence: float
    evidence: dict
    human_explanation: str
    mitigation: str
    points: float


class PackageVerdict(BaseModel):
    record: PackageRecord
    score: float
    findings: list[Finding]


class ScanReport(BaseModel):
    target: str
    started_at: datetime
    finished_at: datetime
    project_score: float
    packages: list[PackageVerdict]
    repo_findings: list[Finding]
    tool_version: str


class DependencyGraph(BaseModel):
    nodes: list[PackageRecord]
    edges: list[tuple[str, str]]

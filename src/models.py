from enum import Enum
from typing import Any, Optional, Literal
from datetime import datetime
from pydantic import BaseModel, Field

class Severity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

class PackageRecord(BaseModel):
    name: str
    version: str
    ecosystem: Literal["npm", "pypi", "go", "cargo"] = "pypi"
    direct: bool = True
    depth: int = 0
    source_file: str
    resolved_url: Optional[str] = None

class Finding(BaseModel):
    id: str
    layer: Literal["L1", "L2", "L3"]
    package: Optional[str] = None
    type: str
    severity: Severity
    confidence: float
    evidence: dict[str, Any] = Field(default_factory=dict)
    human_explanation: str = ""
    mitigation: str = ""
    points: float = 0.0

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
    config_hash: str
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, field_validator


class Credentials(BaseModel):
    email: str = Field(min_length=3, max_length=255)
    password: str = Field(min_length=8, max_length=128)

    @field_validator("email")
    @classmethod
    def _email(cls, v: str) -> str:
        v = v.strip().lower()
        if "@" not in v:
            raise ValueError("Enter a valid email address")
        return v


class TokenOut(BaseModel):
    access_token: str
    token_type: str = "bearer"


class ScanCreate(BaseModel):
    repo_url: str
    name: str | None = None
    sensitive: bool = False


class ScanOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    name: str
    source_type: str
    repo_url: str | None
    sensitive: bool
    status: str
    error: str | None
    summary: dict | None
    created_at: datetime


class FindingOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    package_key: str
    package: str
    version: str
    ecosystem: str
    vuln_id: str
    aliases: list
    summary: str
    cvss: float
    severity: str
    fixed_versions: list
    recommended_fix: str | None
    is_direct: bool
    is_dev: bool
    reachable: bool
    path: list
    apps: list
    anomaly: bool
    risk_score: float
    risk_level: str
    reasons: list
    ai_explanation: str | None


class Upgrade(BaseModel):
    key: str  # package_key of the finding, e.g. npm:lodash@4.17.15
    version: str


class SimulateIn(BaseModel):
    upgrades: list[Upgrade] = Field(min_length=1, max_length=200)

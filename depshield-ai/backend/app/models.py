from datetime import datetime, timezone

from sqlalchemy import JSON, Boolean, DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .db import Base


def utcnow():
    return datetime.now(timezone.utc)


class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Scan(Base):
    __tablename__ = "scans"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    name: Mapped[str] = mapped_column(String(255))
    source_type: Mapped[str] = mapped_column(String(20))  # github | upload
    repo_url: Mapped[str | None] = mapped_column(String(500), nullable=True)
    manifests: Mapped[dict | None] = mapped_column(JSON, nullable=True)  # {path: file text}
    sensitive: Mapped[bool] = mapped_column(Boolean, default=False)  # e.g. payment / auth service
    status: Mapped[str] = mapped_column(String(20), default="queued")
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    graph: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    summary: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    findings: Mapped[list["Finding"]] = relationship(
        back_populates="scan", cascade="all, delete-orphan", order_by="Finding.risk_score.desc()"
    )


class Finding(Base):
    __tablename__ = "findings"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id"), index=True)
    package_key: Mapped[str] = mapped_column(String(500), index=True)
    package: Mapped[str] = mapped_column(String(300))
    version: Mapped[str] = mapped_column(String(100))
    ecosystem: Mapped[str] = mapped_column(String(30))
    vuln_id: Mapped[str] = mapped_column(String(100))
    aliases: Mapped[list] = mapped_column(JSON, default=list)
    summary: Mapped[str] = mapped_column(Text, default="")
    cvss: Mapped[float] = mapped_column(Float, default=0.0)
    severity: Mapped[str] = mapped_column(String(20), default="MEDIUM")
    fixed_versions: Mapped[list] = mapped_column(JSON, default=list)
    recommended_fix: Mapped[str | None] = mapped_column(String(100), nullable=True)
    is_direct: Mapped[bool] = mapped_column(Boolean, default=False)
    is_dev: Mapped[bool] = mapped_column(Boolean, default=False)
    reachable: Mapped[bool] = mapped_column(Boolean, default=True)
    path: Mapped[list] = mapped_column(JSON, default=list)  # app -> ... -> package
    apps: Mapped[list] = mapped_column(JSON, default=list)  # apps that use this package
    anomaly: Mapped[bool] = mapped_column(Boolean, default=False)
    risk_score: Mapped[float] = mapped_column(Float, default=0.0, index=True)
    risk_level: Mapped[str] = mapped_column(String(20), default="low")
    reasons: Mapped[list] = mapped_column(JSON, default=list)
    ai_explanation: Mapped[str | None] = mapped_column(Text, nullable=True)

    scan: Mapped[Scan] = relationship(back_populates="findings")

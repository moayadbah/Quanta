"""Configuration: ``config/default.toml`` plus environment overrides (§8.1).

Nested settings use a ``__`` delimiter, so ``QUANTA_INGEST__MAX_FILES=100`` overrides
``[ingest].max_files``. Pydantic validation here is a *security control*, not a
convenience — every constant below bounds untrusted input.
"""

from __future__ import annotations

import tomllib
from functools import lru_cache
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic_settings.sources import PydanticBaseSettingsSource

from quanta.resources import asset_path

_DEFAULT_CONFIG = asset_path("config/default.toml")


class IngestSettings(BaseModel):
    allowed_hosts: tuple[str, ...] = ("github.com",)
    max_repo_kb: int = 200_000
    clone_timeout_s: int = 180
    max_files: int = 20_000
    max_file_bytes: int = 2_000_000
    max_total_bytes: int = 500_000_000
    max_depth: int = 40
    deny_dirs: tuple[str, ...] = (
        ".git",
        ".venv",
        "venv",
        "site-packages",
        "node_modules",
        "build",
        "dist",
        ".tox",
        ".mypy_cache",
        ".pytest_cache",
    )


class AnalysisSettings(BaseModel):
    parse_timeout_s: int = 5
    max_job_seconds: int = 600
    blast_radius_max: int = 25


class WorkerSettings(BaseModel):
    concurrency: int = 2
    poll_interval_s: int = 2
    claim_ttl_s: int = 900
    max_attempts: int = 2


class ApiSettings(BaseModel):
    rate_limit_per_ip_hour: int = 10
    max_queue_depth: int = 50


class RetentionSettings(BaseModel):
    artifact_ttl_days: int = 7


class StatsSettings(BaseModel):
    collinearity_threshold: float = 0.80
    sensitivity_delta: float = 0.30
    bootstrap_iterations: int = 10_000


class Weights(BaseModel):
    """Pre-registered Agility Score weights (§8.2).

    Committed and git-tagged ``weights-v1`` before any engine result was observed.
    Tuning these after observing results is overfitting and would invalidate the score
    entirely (§11.2) — hence :meth:`validate_sum`, which fails loudly rather than
    silently renormalising.
    """

    version: str = "weights-v1"
    f_sites: float = 0.30
    f_isolation: float = 0.30
    f_config: float = 0.20
    f_propagation: float = 0.20

    def validate_sum(self) -> None:
        total = self.f_sites + self.f_isolation + self.f_config + self.f_propagation
        if abs(total - 1.0) > 1e-9:
            raise ValueError(f"agility score weights must sum to 1.00, got {total!r}")


class ReportSettings(BaseModel):
    #: "builtin" is a deterministic pure-Python SVG emitter (ADR-018). "graphviz" uses
    #: pydot and requires the `dot` binary on PATH.
    renderer: Literal["builtin", "graphviz"] = "builtin"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="QUANTA_",
        env_nested_delimiter="__",
        extra="ignore",
    )

    ingest: IngestSettings = Field(default_factory=IngestSettings)
    analysis: AnalysisSettings = Field(default_factory=AnalysisSettings)
    worker: WorkerSettings = Field(default_factory=WorkerSettings)
    api: ApiSettings = Field(default_factory=ApiSettings)
    retention: RetentionSettings = Field(default_factory=RetentionSettings)
    stats: StatsSettings = Field(default_factory=StatsSettings)
    weights: Weights = Field(default_factory=Weights)
    report: ReportSettings = Field(default_factory=ReportSettings)

    db: Path = Path.home() / ".quanta" / "quanta.db"
    artifact_root: Path = Path.home() / ".quanta" / "artifacts"
    scratch_root: Path = Path.home() / ".quanta" / "scratch"
    require_sandbox: bool = False

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> tuple[PydanticBaseSettingsSource, ...]:
        # TOML is passed as initial data. Environment overrides must take precedence.
        return env_settings, init_settings, dotenv_settings, file_secret_settings


def _read_toml(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {}
    with path.open("rb") as fh:
        data: dict[str, Any] = tomllib.load(fh)
    return data


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Load settings from ``config/default.toml``, then apply environment overrides."""
    settings = Settings(**_read_toml(_DEFAULT_CONFIG))
    settings.weights.validate_sum()
    return settings

"""Estruturas compartilhadas entre as duas versões do bot (regras e IA generativa)."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class EngineResponse:
    texto: str
    cves: list[dict] = field(default_factory=list)
    ok: bool = True
    erro: str | None = None

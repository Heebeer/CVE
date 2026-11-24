"""Registro de cada consulta em CSV. Esses dados alimentam o capítulo de resultados do TCC."""

from __future__ import annotations

import csv
from datetime import datetime
from pathlib import Path

from .models import EngineResponse

LOG_PATH = Path("logs/consultas.csv")
CAMPOS = [
    "timestamp", "modo", "pergunta", "tempo_ms", "ok", "n_resultados",
    "erro", "tokens_entrada", "tokens_saida",
]


def _preparar_arquivo() -> bool:
    """Garante o cabeçalho correto. Retorna True se o arquivo precisa de cabeçalho."""
    LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    if not LOG_PATH.exists():
        return True
    with LOG_PATH.open(encoding="utf-8") as f:
        cabecalho = f.readline().strip()
    if cabecalho == ",".join(CAMPOS):
        return False
    # Log de uma versão anterior (colunas diferentes): guarda de lado e recomeça.
    backup = LOG_PATH.with_name(f"consultas_antigo_{datetime.now():%Y%m%d_%H%M%S}.csv")
    LOG_PATH.rename(backup)
    return True


def registrar(modo: str, pergunta: str, tempo_ms: float, resp: EngineResponse) -> None:
    precisa_cabecalho = _preparar_arquivo()
    with LOG_PATH.open("a", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=CAMPOS)
        if precisa_cabecalho:
            writer.writeheader()
        writer.writerow(
            {
                "timestamp": datetime.now().isoformat(timespec="seconds"),
                "modo": modo,
                "pergunta": pergunta,
                "tempo_ms": round(tempo_ms),
                "ok": resp.ok,
                "n_resultados": len(resp.cves),
                "erro": resp.erro or "",
                "tokens_entrada": resp.tokens_entrada,
                "tokens_saida": resp.tokens_saida,
            }
        )

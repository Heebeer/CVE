"""Registro de cada consulta em CSV. Esses dados alimentam o capítulo de resultados do TCC."""

from __future__ import annotations

import csv
from datetime import datetime
from pathlib import Path

from .models import EngineResponse

LOG_PATH = Path("logs/consultas.csv")
CAMPOS = ["timestamp", "modo", "pergunta", "tempo_ms", "ok", "n_resultados", "erro"]


def registrar(modo: str, pergunta: str, tempo_ms: float, resp: EngineResponse) -> None:
    LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    novo = not LOG_PATH.exists()
    with LOG_PATH.open("a", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=CAMPOS)
        if novo:
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
            }
        )

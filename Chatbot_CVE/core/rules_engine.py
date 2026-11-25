"""Versão A do bot: baseada em regras.

Entende apenas padrões fixos. Isso é intencional: as limitações desta versão
(só reconhece formatos exatos) são o ponto de comparação com a versão com IA.

Padrões reconhecidos:
1. Um ID de CVE em qualquer parte do texto      -> ex.: "CVE-2021-44228 é crítico?"
2. Um CPE 2.3 completo                          -> ex.: "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*"
3. O comando "buscar <termo> [severidade]"      -> ex.: "buscar openssl crítica"
4. "ajuda"
"""

from __future__ import annotations

import re

from .models import EngineResponse
from .nvd_client import NVDClient, NVDError, ResultadoBusca

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
CPE_RE = re.compile(r"cpe:2\.3:[aho]:\S+", re.IGNORECASE)

SEVERIDADES = {
    "crítica": "CRITICAL", "critica": "CRITICAL", "crítico": "CRITICAL",
    "critico": "CRITICAL", "critical": "CRITICAL",
    "alta": "HIGH", "alto": "HIGH", "high": "HIGH",
    "média": "MEDIUM", "media": "MEDIUM", "médio": "MEDIUM",
    "medio": "MEDIUM", "medium": "MEDIUM",
    "baixa": "LOW", "baixo": "LOW", "low": "LOW",
}
COMANDOS_BUSCA = {"buscar", "/buscar", "search"}
COMANDOS_AJUDA = {"ajuda", "/ajuda", "help", "/help"}

TEXTO_AJUDA = (
    "Eu entendo apenas estes formatos:\n\n"
    "- **ID do CVE:** `CVE-2021-44228`\n"
    "- **Busca por termo:** `buscar log4j` ou `buscar openssl crítica`\n"
    "- **CPE 2.3 completo:** `cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*`"
)


class RulesEngine:
    def __init__(self, nvd: NVDClient) -> None:
        self.nvd = nvd

    def responder(self, pergunta: str, historico: list[dict] | None = None) -> EngineResponse:
        # `historico` é ignorado de propósito: a versão por regras não tem memória da conversa.
        texto = pergunta.strip()
        if not texto:
            return EngineResponse("Digite uma pergunta.", ok=False, erro="entrada_vazia")

        try:
            # 1) ID de CVE
            m = CVE_RE.search(texto)
            if m:
                cve = self.nvd.get_cve(m.group(0))
                if cve is None:
                    return EngineResponse(
                        f"Não encontrei o {m.group(0).upper()} na NVD.", ok=False, erro="cve_nao_encontrado"
                    )
                return EngineResponse(f"Encontrei o {cve['id']}.", [cve])

            # 2) CPE completo
            m = CPE_RE.search(texto)
            if m:
                res = self.nvd.search_cpe(m.group(0), severidade=self._severidade(texto))
                return self._resposta_lista(res, "esse CPE")

            # 3) Comando "buscar"
            tokens = re.findall(r"[\w/çáéíóúãõâêôà.-]+", texto.lower())
            if tokens and tokens[0] in COMANDOS_BUSCA:
                severidade = self._severidade(texto)
                termo = " ".join(t for t in tokens[1:] if t not in SEVERIDADES)
                if not termo:
                    return EngineResponse(TEXTO_AJUDA, ok=False, erro="termo_vazio")
                res = self.nvd.search_keyword(termo, severidade=severidade)
                return self._resposta_lista(res, f"“{termo}”")

            # 4) Ajuda ou formato não reconhecido
            if tokens and tokens[0] in COMANDOS_AJUDA:
                return EngineResponse(TEXTO_AJUDA)
            return EngineResponse(
                "Não entendi essa pergunta.\n\n" + TEXTO_AJUDA, ok=False, erro="nao_entendido"
            )

        except NVDError as exc:
            return EngineResponse(f"Erro ao consultar a NVD: {exc}", ok=False, erro="nvd_error")

    @staticmethod
    def _severidade(texto: str) -> str | None:
        for token in re.findall(r"[\wçáéíóúãõâêô]+", texto.lower()):
            if token in SEVERIDADES:
                return SEVERIDADES[token]
        return None

    @staticmethod
    def _resposta_lista(res: ResultadoBusca, alvo: str) -> EngineResponse:
        if not res.cves:
            return EngineResponse(f"Nenhum CVE encontrado para {alvo}.", ok=False, erro="sem_resultados")
        periodo = f"nos últimos {res.dias} dias" if res.dias else "no total (sem filtro de período)"
        return EngineResponse(
            f"A NVD tem {res.total} resultado(s) para {alvo} {periodo}. "
            f"Mostrando os {len(res.cves)} de maior pontuação entre os mais recentes.",
            res.cves,
        )

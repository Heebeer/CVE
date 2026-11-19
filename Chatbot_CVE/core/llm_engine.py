"""Versão B do bot: IA generativa (ainda não implementada).

Plano de implementação (function calling):

1. Escolher o provedor de IA e instalar o SDK dele.
2. Definir as "ferramentas" que o modelo pode chamar, todas apoiadas no NVDClient:
   - buscar_cve_por_id(cve_id)
   - buscar_cves_por_palavra_chave(palavra_chave, severidade)
   - buscar_cves_por_cpe(cpe_name, severidade)
3. Enviar a pergunta do usuário + a lista de ferramentas ao modelo.
4. Executar a ferramenta que o modelo pedir e devolver o resultado a ele.
5. Instruir o modelo (prompt de sistema) a responder APENAS com base nos dados
   retornados pela NVD, citando o ID do CVE, e a dizer que não sabe quando não houver dados.
6. Retornar EngineResponse(texto=resposta_do_modelo, cves=cves_usados).

A chave do provedor deve vir de variável de ambiente (.env), nunca do código.
"""

from __future__ import annotations

from .models import EngineResponse
from .nvd_client import NVDClient


class LLMEngine:
    def __init__(self, nvd: NVDClient) -> None:
        self.nvd = nvd

    def responder(self, pergunta: str) -> EngineResponse:
        return EngineResponse(
            "A versão com IA generativa ainda não foi implementada. "
            "Use o modo **Regras** por enquanto.",
            ok=False,
            erro="nao_implementado",
        )

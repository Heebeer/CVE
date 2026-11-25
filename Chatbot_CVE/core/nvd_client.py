"""Cliente da API 2.0 da NVD (National Vulnerability Database).

Responsabilidades:
- consultar CVEs por ID, palavra-chave ou CPE;
- respeitar o limite de requisições da NVD (janela deslizante de 30 s);
- guardar respostas em cache na memória para reduzir chamadas repetidas;
- converter o JSON bruto em um dicionário simples, usado pelas duas versões do bot.

Limites públicos da NVD (podem mudar, confira em https://nvd.nist.gov/developers):
- sem chave de API: 5 requisições a cada 30 segundos;
- com chave de API gratuita: 50 requisições a cada 30 segundos.
"""

from __future__ import annotations

import os
import threading
import time
from collections import deque
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

import requests

BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
JANELA_SEGUNDOS = 30
LIMITE_SEM_CHAVE = 5
LIMITE_COM_CHAVE = 50
SEVERIDADES_VALIDAS = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}

# Busca por recência: a NVD limita filtros de data a 120 dias consecutivos, então
# consultamos "janelas" de 119 dias, da mais recente para trás, até achar resultados.
JANELA_DIAS = 119
MAX_JANELAS = 3  # ~1 ano de histórico
PAGINA = 100  # resultados por requisição

# Ordem de preferência ao escolher qual pontuação CVSS exibir.
_METRICAS_PREFERIDAS = (
    ("cvssMetricV40", "4.0"),
    ("cvssMetricV31", "3.1"),
    ("cvssMetricV30", "3.0"),
    ("cvssMetricV2", "2.0"),
)


class NVDError(Exception):
    """Erro ao consultar a NVD (rede, limite de requisições, chave inválida etc.)."""


@dataclass
class ResultadoBusca:
    cves: list[dict]  # até `limite` CVEs, já ordenados
    total: int  # total de correspondências no período consultado
    dias: int | None  # período consultado em dias (None = sem filtro de data)


def _fmt_data(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%S.000")  # UTC, formato aceito pela NVD


class NVDClient:
    def __init__(
        self,
        api_key: str | None = None,
        cache_ttl: int = 3600,
        timeout: int = 30,
        max_tentativas: int = 3,
    ) -> None:
        self.api_key = api_key or os.getenv("NVD_API_KEY") or None
        self.cache_ttl = cache_ttl
        self.timeout = timeout
        self.max_tentativas = max_tentativas

        self._limite = LIMITE_COM_CHAVE if self.api_key else LIMITE_SEM_CHAVE
        self._chamadas: deque[float] = deque()
        self._lock = threading.Lock()
        self._cache: dict[tuple, tuple[float, dict]] = {}

        # Contadores úteis para o capítulo de resultados do TCC.
        self.stats = {"requisicoes": 0, "cache_hits": 0}

    # ------------------------------------------------------------------
    # Consultas públicas
    # ------------------------------------------------------------------
    def get_cve(self, cve_id: str) -> dict | None:
        """Retorna um CVE pelo ID (ex.: CVE-2021-44228) ou None se não existir."""
        dados = self._get({"cveId": cve_id.upper()})
        itens = dados.get("vulnerabilities", [])
        return self._simplificar(itens[0]) if itens else None

    def search_keyword(
        self, palavra_chave: str, severidade: str | None = None, limite: int = 10
    ) -> ResultadoBusca:
        """Busca CVEs por palavra-chave na descrição, priorizando os mais RECENTES.

        A NVD não ordena por relevância nem por data: devolve os mais antigos primeiro.
        Por isso a busca é feita em janelas de datas, da mais recente para trás, e os
        candidatos encontrados são ordenados por pontuação CVSS (e, em empate, por data).
        """
        return self._buscar_recentes({"keywordSearch": palavra_chave}, severidade, limite)

    def search_cpe(
        self, cpe_name: str, severidade: str | None = None, limite: int = 10
    ) -> ResultadoBusca:
        """Busca CVEs que afetam um CPE 2.3 completo, sem filtro de data.

        Exemplo: cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*
        O resultado são os CVEs daquele produto/versão, então a data não é filtrada.
        """
        params = self._com_severidade({"cpeName": cpe_name}, severidade)
        itens, total = self._pagina_final(params)
        cves = [self._simplificar(i) for i in itens]
        return ResultadoBusca(_melhores(cves, limite), total, None)

    # ------------------------------------------------------------------
    # Internos
    # ------------------------------------------------------------------
    @staticmethod
    def _com_severidade(params: dict, severidade: str | None) -> dict:
        params = dict(params)
        if severidade:
            severidade = severidade.upper()
            if severidade not in SEVERIDADES_VALIDAS:
                raise NVDError(f"Severidade inválida: {severidade}")
            params["cvssV3Severity"] = severidade
        return params

    def _pagina_final(self, params: dict) -> tuple[list[dict], int]:
        """Retorna (itens, total). Se houver mais de PAGINA resultados, pega a ÚLTIMA página.

        Como a NVD devolve em ordem cronológica crescente, a última página tem os mais novos.
        """
        dados = self._get({**params, "resultsPerPage": PAGINA, "startIndex": 0})
        total = int(dados.get("totalResults", 0))
        itens = dados.get("vulnerabilities", [])
        if total > PAGINA:
            dados = self._get({**params, "resultsPerPage": PAGINA, "startIndex": total - PAGINA})
            itens = dados.get("vulnerabilities", [])
        return itens, total

    def _buscar_recentes(
        self, params: dict, severidade: str | None, limite: int
    ) -> ResultadoBusca:
        base = self._com_severidade(params, severidade)
        # Arredondado para a hora, para as chaves de cache se repetirem dentro da mesma hora.
        fim = datetime.now(timezone.utc).replace(minute=0, second=0, microsecond=0, tzinfo=None)

        coletados: dict[str, dict] = {}
        total_periodo = 0
        janelas = 0
        for _ in range(MAX_JANELAS):
            inicio = fim - timedelta(days=JANELA_DIAS)
            janela = {**base, "pubStartDate": _fmt_data(inicio), "pubEndDate": _fmt_data(fim)}
            itens, total = self._pagina_final(janela)
            janelas += 1
            total_periodo += total
            for item in itens:
                cve = self._simplificar(item)
                coletados[cve["id"]] = cve
            if len(coletados) >= limite:
                break
            fim = inicio - timedelta(seconds=1)

        if coletados:
            return ResultadoBusca(
                _melhores(list(coletados.values()), limite), total_periodo, janelas * JANELA_DIAS
            )

        # Nada no último ano: busca sem filtro de data, pegando os mais novos disponíveis.
        itens, total = self._pagina_final(base)
        cves = [self._simplificar(i) for i in itens]
        return ResultadoBusca(_melhores(cves, limite), total, None)

    def _aguardar_vaga(self) -> None:
        """Bloqueia até haver vaga na janela de requisições."""
        with self._lock:
            while True:
                agora = time.monotonic()
                while self._chamadas and agora - self._chamadas[0] >= JANELA_SEGUNDOS:
                    self._chamadas.popleft()
                if len(self._chamadas) < self._limite:
                    self._chamadas.append(agora)
                    return
                espera = JANELA_SEGUNDOS - (agora - self._chamadas[0]) + 0.1
                time.sleep(max(espera, 0.1))

    def _get(self, params: dict) -> dict:
        chave_cache = tuple(sorted(params.items()))
        em_cache = self._cache.get(chave_cache)
        if em_cache and time.monotonic() - em_cache[0] < self.cache_ttl:
            self.stats["cache_hits"] += 1
            return em_cache[1]

        headers = {"Accept": "application/json"}
        if self.api_key:
            headers["apiKey"] = self.api_key

        ultimo_erro = "erro desconhecido"
        for tentativa in range(self.max_tentativas):
            self._aguardar_vaga()
            self.stats["requisicoes"] += 1
            try:
                resp = requests.get(
                    BASE_URL, params=params, headers=headers, timeout=self.timeout
                )
            except requests.RequestException as exc:
                ultimo_erro = f"falha de rede: {exc}"
            else:
                if resp.status_code == 200:
                    try:
                        dados = resp.json()
                    except ValueError as exc:
                        raise NVDError("A NVD retornou uma resposta inválida (JSON).") from exc
                    self._cache[chave_cache] = (time.monotonic(), dados)
                    return dados
                if resp.status_code == 404:
                    raise NVDError("Consulta rejeitada pela NVD (404). Verifique o formato do ID/CPE.")
                if resp.status_code in (403, 429, 500, 502, 503, 504):
                    # A NVD usa 403 tanto para limite excedido quanto para chave inválida.
                    ultimo_erro = f"HTTP {resp.status_code} (limite de requisições, chave inválida ou instabilidade)"
                else:
                    raise NVDError(f"Erro inesperado da NVD: HTTP {resp.status_code}.")

            time.sleep(2 ** tentativa)  # espera progressiva entre tentativas

        raise NVDError(f"Não foi possível consultar a NVD: {ultimo_erro}.")

    @staticmethod
    def _extrair_cvss(metricas: dict) -> tuple[float | None, str, str]:
        for chave, versao in _METRICAS_PREFERIDAS:
            lista = metricas.get(chave)
            if not lista:
                continue
            # Prefere a avaliação "Primary" (feita pela NVD) quando existir.
            escolhida = next((m for m in lista if m.get("type") == "Primary"), lista[0])
            dados = escolhida.get("cvssData", {})
            severidade = dados.get("baseSeverity") or escolhida.get("baseSeverity") or "N/A"
            return dados.get("baseScore"), str(severidade).upper(), versao
        return None, "N/A", "-"

    def _simplificar(self, item: dict) -> dict:
        cve = item.get("cve", {})
        descricao = next(
            (d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"),
            "Sem descrição disponível.",
        )
        score, severidade, versao = self._extrair_cvss(cve.get("metrics", {}))
        cve_id = cve.get("id", "?")
        return {
            "id": cve_id,
            "descricao": descricao,
            "score": score,
            "severidade": severidade,
            "versao_cvss": versao,
            "publicado": (cve.get("published") or "")[:10],
            "status": cve.get("vulnStatus", "-"),
            "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
        }


def _melhores(cves: list[dict], limite: int) -> list[dict]:
    """Ordena por pontuação CVSS (maior primeiro) e, em empate, pelos mais recentes."""
    return sorted(
        cves,
        key=lambda c: (c["score"] if c["score"] is not None else -1, c["publicado"]),
        reverse=True,
    )[:limite]

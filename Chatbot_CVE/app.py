"""Interface Streamlit. Contém apenas a tela; toda a lógica fica em core/."""

import time

import streamlit as st
from dotenv import load_dotenv

load_dotenv()  # lê o arquivo .env antes de criar o cliente da NVD

from core.llm_engine import LLMEngine  # noqa: E402
from core.logger import registrar  # noqa: E402
from core.nvd_client import NVDClient  # noqa: E402
from core.rules_engine import RulesEngine  # noqa: E402

st.set_page_config(page_title="Consulta de CVEs", page_icon="🛡️")

CORES = {"CRITICAL": "red", "HIGH": "orange", "MEDIUM": "yellow", "LOW": "green"}
EXEMPLOS = [
    "CVE-2021-44228 é crítico?",
    "buscar log4j crítica",
    "buscar openssl alta",
]


@st.cache_resource
def get_nvd() -> NVDClient:
    return NVDClient()


@st.cache_resource
def get_motores() -> dict:
    nvd = get_nvd()
    return {"Regras": RulesEngine(nvd), "IA generativa": LLMEngine(nvd)}


def render_cve(cve: dict) -> None:
    cor = CORES.get(cve["severidade"], "gray")
    score = cve["score"] if cve["score"] is not None else "sem pontuação"
    with st.container(border=True):
        st.markdown(
            f"**[{cve['id']}]({cve['url']})** · :{cor}[**{cve['severidade']}**] · "
            f"CVSS {score} (v{cve['versao_cvss']})"
        )
        st.caption(f"Publicado em {cve['publicado']} · Status: {cve['status']}")
        descricao = cve["descricao"]
        st.write(descricao if len(descricao) <= 400 else descricao[:400] + "…")


# ----------------------------------------------------------------------
# Barra lateral
# ----------------------------------------------------------------------
nvd = get_nvd()
motores = get_motores()

with st.sidebar:
    st.header("Configurações")
    modo = st.radio("Modo do bot", list(motores.keys()))
    if st.button("Limpar conversa"):
        st.session_state.historico = []
        st.rerun()

    st.divider()
    st.caption("Exemplos")
    for exemplo in EXEMPLOS:
        st.code(exemplo, language=None)

    st.divider()
    st.caption(
        f"Chave da NVD: {'configurada' if nvd.api_key else 'não configurada (limite menor)'}"
    )
    st.caption(
        f"Requisições à NVD: {nvd.stats['requisicoes']} · Cache: {nvd.stats['cache_hits']}"
    )

# ----------------------------------------------------------------------
# Chat
# ----------------------------------------------------------------------
st.title("🛡️ Consulta de CVE")
st.caption("Dados da NVD (NIST). Descrições em inglês, como publicadas na fonte.")

if "historico" not in st.session_state:
    st.session_state.historico = []

for msg in st.session_state.historico:
    with st.chat_message(msg["papel"]):
        st.write(msg["texto"])
        for cve in msg.get("cves", []):
            render_cve(cve)

if pergunta := st.chat_input("Ex.: CVE-2021-44228 é crítico?"):
    st.session_state.historico.append({"papel": "user", "texto": pergunta})

    inicio = time.perf_counter()
    with st.spinner("Consultando a NVD..."):
        resp = motores[modo].responder(pergunta)
    tempo_ms = (time.perf_counter() - inicio) * 1000

    registrar(modo, pergunta, tempo_ms, resp)
    st.session_state.historico.append(
        {"papel": "assistant", "texto": resp.texto, "cves": resp.cves}
    )
    st.rerun()

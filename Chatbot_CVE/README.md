# TCC: Chatbot de consulta de vulnerabilidades (CVE)

Comparação entre um chatbot baseado em regras e outro com IA generativa, usando a base NVD (NIST).

## Como rodar

```bash
python -m venv .venv
.venv\Scripts\activate          # Windows
# source .venv/bin/activate     # Linux/macOS
pip install -r requirements.txt
cp .env.example .env            # preencha NVD_API_KEY (opcional, mas recomendado)
streamlit run app.py
```

## Estrutura

- `app.py`: interface (Streamlit). Só tela.
- `core/nvd_client.py`: consulta à NVD, cache e limite de requisições.
- `core/rules_engine.py`: versão A (regras).
- `core/llm_engine.py`: versão B (IA generativa, ainda por implementar).
- `core/logger.py`: grava `logs/consultas.csv` (modo, tempo, erro).
- `data/perguntas_teste.csv`: perguntas de teste. Preencha `resposta_esperada` consultando a NVD diretamente.

## Observações

- As descrições dos CVEs vêm em inglês, como na fonte.
- Em buscas por termo, a NVD retorna até 100 resultados por página e a ordenação por pontuação é feita localmente apenas sobre eles.

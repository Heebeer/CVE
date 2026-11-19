# Roteiro do vídeo (até 5 minutos)

**Meta:** ~4 min 30 s, para sobrar folga. Fale com calma; é melhor cortar uma pergunta do que passar de 5 minutos.

## Antes de gravar

- [ ] Rode o chatbot uma vez para confirmar que tudo funciona.
- [ ] Defina a chave **antes** de começar a gravar e limpe a tela com `cls` (Windows) ou `clear` (Mac/Linux), para a chave não aparecer no vídeo.
- [ ] Deixe o VS Code aberto com `server.py` e `chatbot_visual.py` em abas, e o terminal na pasta do projeto.
- [ ] Aumente a fonte do terminal e do editor, para ficar legível no vídeo.
- [ ] Combine quem fala cada parte, se gravarem em grupo.

---

## 0:00 – 0:30 · Abertura

**Mostrar:** o terminal limpo ou o README.

**Falar:**
> "Somos o grupo X e fizemos um chatbot sobre terremotos. Ele usa o Model Context Protocol, o MCP, para consultar dados reais da API pública do USGS, o serviço geológico dos Estados Unidos. Ela é gratuita e não exige chave."

## 0:30 – 1:30 · Como funciona (arquitetura)

**Mostrar:** o diagrama do README (ou desenhar rapidamente) e depois o `server.py`.

**Falar:**
> "A arquitetura tem três partes: o chatbot, o servidor MCP e a API. O servidor MCP expõe duas ferramentas: `terremotos_recentes`, que lista terremotos por período e magnitude, e `terremotos_por_regiao`, que busca terremotos perto de um ponto. O chatbot descobre essas ferramentas sozinho, envia a lista ao modelo de linguagem, e é o modelo que decide quando chamar cada uma."

**Dica:** no `server.py`, aponte para o decorador `@mcp.tool()` e para a descrição (docstring) das ferramentas. É a descrição que o modelo lê para decidir quando usar cada uma.

## 1:30 – 2:15 · O código do cliente

**Mostrar:** `chatbot_visual.py`, rolando até o trecho do `list_tools`, da chamada ao modelo e do `call_tool`.

**Falar:**
> "No cliente, primeiro pedimos a lista de ferramentas ao servidor com `list_tools`. Depois enviamos a pergunta ao modelo junto com essas ferramentas. Quando o modelo pede uma ferramenta, executamos com `call_tool` no servidor MCP, devolvemos o resultado, e o modelo escreve a resposta final com dados reais."

## 2:15 – 4:15 · Demonstração

**Mostrar:** rodar `python chatbot_visual.py --debug`. O modo `--debug` exibe as chamadas MCP, o que prova que a ferramenta está sendo usada.

Faça estas perguntas, nesta ordem:

1. **"Quais foram os 5 maiores terremotos dos últimos 7 dias?"**
   Aponte na tela a linha `↳ terremotos_recentes(...)` e o `ordenar_por: magnitude`.
2. **"Houve algum terremoto perto de Santiago, no Chile, no último mês?"**
   Mostre que o modelo converteu "Santiago" em coordenadas e chamou `terremotos_por_regiao`.
3. **"E o maior deles, onde fica exatamente?"**
   Mostre que o chatbot **mantém o contexto** da conversa.

**Falar enquanto espera as respostas:**
> "Repare que o modelo não responde de memória: ele chama a ferramenta e usa os dados em tempo real do USGS."

> **Se der erro de limite (429):** espere uns segundos e repita. Isso é do plano gratuito do Groq. Se acontecer na gravação, corte e regrave só esse trecho.

## 4:15 – 4:45 · Encerramento

**Mostrar:** digitar `sair` e voltar ao README ou à lista de arquivos.

**Falar:**
> "Resumindo: um servidor MCP conecta o modelo a uma API pública, e o chatbot usa as ferramentas para responder com dados reais. Poderíamos acrescentar mais ferramentas ou outras APIs ao mesmo servidor. Obrigado!"

---

## Se sobrar tempo (opcional)

- Mostrar o tratamento de erro: o programa não fecha se a API falhar, e mostra um painel vermelho.
- Citar uma limitação: o plano gratuito do LLM tem limite de requisições, e o USGS retorna no máximo 20 resultados por consulta, por escolha nossa.

## Se estiver passando de 5 minutos

Corte, nesta ordem: (1) a parte do código do cliente, (2) a segunda pergunta da demonstração. Mantenha a arquitetura e pelo menos duas perguntas.

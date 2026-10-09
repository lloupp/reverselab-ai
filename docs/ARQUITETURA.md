# ReverseLab AI — arquitetura técnica

## Propósito

Automatizar o **primeiro reconhecimento de um programa compilado** a partir de evidências estáticas, explicando incertezas e preparando os dados para uma análise aprofundada. O produto não busca substituir o Ghidra/IDA/Radare2 e não é um emulador ou um antivírus.

## Componentes do MVP

| Componente | Arquivo | Contrato |
|---|---|---|
| Parsing e métricas | `reverselab/core.py` | `analyze_bytes(bytes, filename) -> dict` |
| Leitura de cabeçalhos | `core.detect` | Formato, arquitetura, entrada, seções, símbolos e importações, quando suportados |
| Desassemblagem | `core._disassemble` | Até 140 instruções em uma janela de até 8 KiB |
| Observações | `core._observations` | Hipóteses com evidências e ressalvas |
| IA local | `reverselab/ai.py` | `explain_with_local_llm(report, question) -> str` |
| Web/API | `reverselab/server.py` | `GET /api/status`, `POST /api/analyze`, `POST /api/explain` |
| CLI | `reverselab/__main__.py` | Subcomandos `serve`, `analyze` |
| Interface | `reverselab/static/` | Arquivo local, abas, tabelas, exportação e pergunta à IA |

## Fluxo completo

1. O usuário seleciona um arquivo próprio, livre ou autorizado no navegador.
2. O navegador envia bytes ao servidor, que só escuta na interface loopback.
3. O servidor valida tamanho e tipo de conteúdo, depois chama o parser.
4. O parser coleta seções/símbolos/importações, extrai strings, calcula SHA-256 e entropia.
5. O desassemblador processa apenas o início de um segmento de código conhecido; procura Capstone (opcional), utiliza decodificador MIPS embutido para N64 ou objdump para x86. Nenhum binário-alvo é executado.
6. O servidor retorna um relatório estruturado em JSON, e o navegador permite exportar Markdown/JSON.
7. Se o usuário solicitar uma explicação, o adaptador envia evidências selecionadas a um modelo **local**. Esse envio não acontece no passo 6.

## Extensão prevista

```
                           UI local
                             |
                           API
                             |
                 Orquestrador de análise
          _______________|___________________
         |               |                   |
   Format parsers  Function analysis    Evidence store
   ELF/PE/Mach-O   Ghidra headless      JSON + SQLite
         |               |                   |
         |     CFG/call graph/cross-refs     |
         \_______________|___________________/
                         |
               LLM local (opcional)
                         |
         Observações fundamentadas + testes
```

### Próximo incremento: Ghidra Headless

A documentação oficial do Ghidra confirma a existência de um analisador de linha de comando (`analyzeHeadless`), permitindo automações em lote e scripts de pós-processamento. A integração deve criar projetos temporários, impor limites de CPU/memória/tempo, exportar funções, blocos básicos, chamadas e strings com referências a offsets. Não incorporar código-fonte de plugins de terceiros sem conferir a licença. Nenhuma integração Ghidra está implementada no MVP.

### Próximo incremento: motor de reconstrução controlada

Para programas pequenos e livres, permitir que a IA proponha uma implementação equivalente (C/Rust), anexe casos de teste determinísticos e compare resultados conhecidos. Rótulo explícito de hipóteses e **nenhuma reescrita automática de executáveis proprietários**. Um port nativo exige engenharia adicional para APIs, memória, gráficos e comportamento.

## Segurança e limites

- Não publicar `0.0.0.0` por padrão; usar apenas `127.0.0.1`.
- Bloquear uploads maiores que 16 MiB e payloads de perguntas maiores que 128 KiB.
- Restrição do servidor LLM a loopback HTTP; nada é enviado para serviços remotos.
- Tratar dados de binários como potencialmente hostis (incluindo strings com instruções fraudulentas para a IA).
- Limite de tempo para `objdump` (6 s). **Isso não é uma sandbox**; produção com binários hostis deve usar isolamento de processo/container ou VM e perfis de segurança de sistema operacional.
- Saídas de IA e desassembladores são hipóteses e extrações técnicas, nunca prova do comportamento dinâmico.
- O modelo local pode inventar explicações; análises importantes precisam de validação por humanos e testes.

## Matriz de validação da v0.1

- Teste real: compilação de `examples/hello.c` com GCC, análise do ELF gerado, descoberta de símbolos e amostra desassemblada.
- Testes de cabeçalho: PE 64 bits e Mach-O.
- Testes de ROM: versões sintéticas z64/n64/v64 e decodificação MIPS.
- Testes HTTP: endpoints, upload válido, tipo de conteúdo rejeitado e limite de tamanho.
- Teste de IA: simulação de servidor HTTP OpenAI-compatible local, sem dependência de provedor externo.
- UI: validação da renderização em desktop/mobile usando respostas simuladas que representam dados reais do núcleo; acesso HTTP local pelo navegador automatizado foi bloqueado pelo ambiente de testes.

## Referências de engenharia

- Capstone: https://www.capstone-engine.org/
- LIEF: https://lief.re/doc/latest/
- Ghidra headless: https://github.com/NationalSecurityAgency/ghidra/blob/master/Ghidra/RuntimeScripts/support/analyzeHeadlessREADME.md


## Provedores de IA (v0.2)

Adaptador `reverselab/ai.py`: provedor `local` restringe URL a loopback; `openrouter` usa origem HTTPS fixa e token por solicitação ou `OPENROUTER_API_KEY`; `chatgpt` integra o Codex CLI oficial instalado/autenticado pelo usuário via `codex login`. O app nunca lê credenciais de conta ChatGPT. Os três provedores usam apenas evidências estáticas limitadas. A interface é local e não persiste chaves. Testes simulam provedores HTTP e binários.


## Incremento v0.3 — análise por função

- `reverselab/ghidra.py`: identifica instalação, valida cabeçalhos ELF/PE, cria diretório temporário, executa Ghidra Headless de forma opt-in e valida JSON exportado.
- `reverselab/ghidra_scripts/ReverseLabExport.py`: script Jython para Ghidra que exporta funções, endereços, chamadas e pseudocódigo do DecompInterface.
- `POST /api/ghidra/analyze`: recebe os mesmos bytes da análise estática e retorna `deep_analysis`; requer clique explícito. `GET /api/status` informa `ghidra.available`.
- `GET /api/status`: continua exibindo conexões dos provedores locais, Codex e Ghidra sem solicitar autenticação externa.
- IA: envia apenas pseudocódigo de uma função selecionada, além de evidência estática limitada.
- Não houve integração do grafo de fluxo de controle intrafunção (CFG): o grafo implementado é de **chamadas entre funções**.

**Evidência de teste:** 31 testes locais, incluindo dois programas ELF reais de formatos válidos e integração com processo Ghidra simulado. Ghidra real indisponível neste ambiente, portanto a exportação Jython não foi verificada em runtime.

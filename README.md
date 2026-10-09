# ReverseLab AI · MVP v0.2

Ferramenta **local** para investigar executáveis e ROMs por **análise estática**, com assistência opcional de IA local, OpenRouter ou ChatGPT via Codex CLI.

> Estado: **MVP funcional**, não um descompilador completo. Não executa, emula ou converte os arquivos analisados. Não detecta malware de forma conclusiva.

## Instalação rápida

**Requisito:** Python 3.10 ou superior. O núcleo e a interface não exigem bibliotecas externas.

Na pasta extraída, execute:

```bash
python -m reverselab serve
```

Abra **http://127.0.0.1:8765** em um navegador da mesma máquina. Arraste um arquivo ELF, EXE, DLL, Mach-O ou ROM N64 de até 16 MiB. Você também pode selecionar o arquivo no celular **se o servidor estiver rodando no próprio celular**, porque o aplicativo não publica serviço na rede.

### Windows

Duplo clique em `iniciar_windows.bat` (com Python instalado). A interface utiliza a porta 8765. Para encerrar, feche o terminal ou pressione `Ctrl+C`.

### Terminal / sem interface

```bash
python -m reverselab analyze examples/hello    # após compilar o exemplo
python -m reverselab analyze examples/hello --format json --output analise.json
python -m reverselab analyze arquivo.z64 --format md --output analise.md
```

Compilando o exemplo no Linux/macOS ou Windows com GCC:

```bash
gcc -O0 -g examples/hello.c -o examples/hello
python -m reverselab analyze examples/hello --output exemplo-relatorio.md
```

## Funcionalidades disponíveis

| Recurso | Estado |
|---|---|
| Identificação de ELF 32/64, PE (EXE/DLL), cabeçalho Mach-O e ROM N64 | Implementado (metadados básicos) |
| Seções e arquitetura | ELF/PE; Mach-O básico sem seções |
| Símbolos e importações | ELF; PE imports/dlls quando válidos |
| Strings ASCII e UTF-16LE | Implementado (amostra de até 110) |
| SHA-256, tamanho, entropia | Implementado |
| Desassemblagem parcial x86/x64 | Via `objdump` do sistema, quando disponível |
| Desassemblagem MIPS de ROM N64 | Decodificador básico próprio |
| Desassemblagem multi-arquitetura | Opcional via `pip install capstone` |
| IA para explicar evidências | Local, OpenRouter ou ChatGPT via Codex CLI |
| Interface, JSON, Markdown | Implementado |
| Pseudocódigo, fluxo de controle completo, reconstrução de fonte | Não implementado |
| Execução, emulação, bypass de proteções | Fora do escopo deste MVP |

O [Capstone](https://www.capstone-engine.org/) é uma dependência **opcional** para instruções adicionais (`pip install capstone`). O [LIEF](https://lief.re/doc/latest/) e o [Ghidra Headless](https://github.com/NationalSecurityAgency/ghidra) são candidatos para futuras versões; não são necessários ou integrados neste MVP.

## IA local (opcional)

A interface não precisa de internet ou IA para a análise estática. Somente quando você clicar em **Consultar IA local**, o navegador pedirá uma explicação ao servidor HTTP do ReverseLab, que enviará um **resumo limitado das evidências** a uma API OpenAI-compatible **em loopback**. O arquivo completo não é enviado a essa API.

Padrões:

- URL: `http://127.0.0.1:8002/v1`
- Modelo: `qwen3-coder-30b`

Essas configurações são úteis se você já utiliza um servidor OpenAI-compatible local nessa porta. O nome precisa corresponder ao modelo realmente oferecido pelo seu servidor. Você pode alterar antes de iniciar o ReverseLab:

**Linux/macOS:**

```bash
export REVERSELAB_LLM_BASE_URL=http://127.0.0.1:8002/v1
export REVERSELAB_MODEL=qwen3-coder-30b
python -m reverselab serve
```

**Windows (PowerShell):**

```powershell
$env:REVERSELAB_LLM_BASE_URL="http://127.0.0.1:8002/v1"
$env:REVERSELAB_MODEL="qwen3-coder-30b"
python -m reverselab serve
```

O endpoint **local** só aceita `localhost`, `127.0.0.1` ou `::1`. OpenRouter e ChatGPT/Codex são exceções explicitamente selecionadas pelo usuário; eles podem processar as evidências remotamente. Sem IA a análise estática continua funcionando.

## Arquitetura

```text
Browser (HTML/CSS/JS, 127.0.0.1)
     | POST bytes do arquivo (até 16 MiB)
     v
Servidor HTTP local [reverselab/server.py]
     |                         |
     v                         | POST resumo, somente sob clique
Núcleo de análise             v
  |-- formatos ELF/PE/N64    Adaptador LLM [ai.py]
  |-- seções/imports           -> endpoint OpenAI-compatible local
  |-- strings, SHA/entropia
  |-- objdump/Capstone* / MIPS próprio
  `-- observações com evidências
     |
     v
JSON / Markdown / UI

* Capstone opcional. objdump é ferramenta externa invocada para analisar
  bytes (NUNCA executa o programa-alvo).
```

## Segurança e privacidade

- O executável analisado **jamais é iniciado**.
- O servidor só escuta em `127.0.0.1` e não permite acesso de outras máquinas.
- Nenhum upload é persistido pelo servidor; bytes existem apenas durante o processamento da solicitação (o navegador mantém o arquivo selecionado enquanto necessário).
- O desassemblador `objdump`, quando usado, roda em processo separado sobre uma amostra extraída do código, **não em sandbox resistente a exploits**. Para examinar arquivos hostis, use uma VM/container isolado atualizado. O parser Python também não é formalmente auditado.
- A interface escapa strings do binário, limita o tamanho dos arquivos e não carrega scripts de terceiros.
- Evidências contidas no arquivo são dados não confiáveis, não instruções para o LLM.
- Ao usar IA, strings e nomes extraídos podem conter informações privadas; nenhuma chamada é feita automaticamente.
- Não use isso como scanner antimalware; indicadores como entropia elevada são ambíguos.

## Testes

```bash
python -m unittest discover -s tests -v
```

Os testes abrangem formatos, decodificação MIPS, geração de relatórios, parsing de casos inválidos, limites, rotas HTTP e um modelo de IA HTTP simulado (sem internet).

## Próximas versões sugeridas

1. **0.2**: integração com Ghidra Headless para funções reais, decompilação e fluxo de controle; execução isolada em VM/container.
2. **0.3**: base de evidências por função com referências a endereços, busca semântica local e comparação de versões.
3. **0.4**: sugerir equivalentes em C/Rust com testes de equivalência sobre pequenos programas livres; sem prometer conversão universal.

Projeto independente. Use executáveis próprios, livres ou com autorização de análise. Respeite licenças e direitos sobre programas e ROMs.

### Exemplo pronto para análise

O arquivo `examples/demo_n64_sintetica.z64` contém **instruções MIPS fictícias escritas para testes**. Não é uma ROM comercial nem um jogo jogável. Basta selecioná-lo na interface para experimentar o fluxo completo. O arquivo `examples/relatorio-demo-n64.md` é o resultado estático gerado pelo próprio ReverseLab.

Capturas de referência (`preview-desktop.png` e `preview-mobile.png`) mostram os componentes visuais com um resultado real do motor, mas a API de análise foi simulada no navegador de testes por restrição de acesso loopback do ambiente automatizado.

## IA com ChatGPT, OpenRouter e modelo local (v0.2)

Na aba **Assistente IA**, escolha um dos três provedores. O ReverseLab não envia o binário original a nenhum provedor. Envia apenas a amostra de metadados, strings e instruções exibida no relatório, depois do seu clique. Essas evidências ainda podem ser privadas e a consulta a provedores externos pode ter custos.

### Minha conta ChatGPT — autenticação oficial via Codex CLI

Uma assinatura ChatGPT **não é uma API key genérica** para aplicações externas. Para usar sua conta, o ReverseLab usa o **Codex CLI oficial**, executando uma consulta de análise de texto com sessão autenticada, em uma pasta temporária vazia e modo de sandbox de leitura (`read-only`). O Codex é instalado e autenticado **por você** no terminal, não na interface do ReverseLab:

```bash
npm install -g @openai/codex
codex login
codex login status
```

Depois, abra a aba **Assistente IA**, escolha **Minha conta ChatGPT (via Codex CLI)** e clique em **Verificar conexão**. Você pode deixar o campo modelo vazio para manter o modelo autorizado padrão do Codex. A disponibilidade e os limites dependem da conta. Sem Codex instalado, a análise estática e os outros provedores funcionam normalmente. O ReverseLab não acessa arquivos de autenticação, não recebe senha e não exporta tokens.

Documentação: https://help.openai.com/en/articles/11369540-using-codex-with-your-chatgpt-plan

### OpenRouter — escolha qualquer modelo

Em https://openrouter.ai/settings/keys crie sua chave. Escolha **OpenRouter** e informe-a no campo do tipo senha, sem colocá-la em código nem no GitHub. Escreva o slug do modelo, por exemplo `openai/gpt-4o`, `anthropic/claude-sonnet-4`, `google/gemini-2.5-flash` ou outro modelo atualmente disponível na sua conta. Também é possível clicar em **Carregar modelos disponíveis** para obter sugestões da API pública (a lista é limitada; slugs digitados manualmente são aceitos). Para roteamento automático, deixe vazio ou use `openrouter/auto`.

Alternativamente configure a chave no ambiente do processo, antes de iniciar o servidor:

Linux:

```bash
export OPENROUTER_API_KEY='SUA_CHAVE_AQUI'
python -m reverselab serve
```

Windows PowerShell:

```powershell
$env:OPENROUTER_API_KEY='SUA_CHAVE_AQUI'
python -m reverselab serve
```

A chave digitada **não é armazenada em disco, localStorage, cookies ou no código**. Ela permanece no campo da página até você apagá-la ou fechar a aba e é transmitida somente ao servidor local e deste para `https://openrouter.ai/api/v1`. Não cole chaves em mensagens ou issues. O provedor pode cobrar por tokens dependendo do modelo.

Documentação: https://openrouter.ai/docs/api/api-reference/chat/send-chat-completion-request

### Modelo local

O funcionamento de análise offline não mudou. O campo de modelo permite selecionar outro nome compatível com seu servidor; o endpoint é configurável somente para `127.0.0.1`, `localhost` ou `::1` via `REVERSELAB_LLM_BASE_URL`, impedindo que a interface vire um proxy HTTP aberto.

### Escopo e segurança

O servidor continua acessível **somente na própria máquina**. Se acessar pela rede usando túneis, proxies ou encaminhamento de portas, acrescente autenticação e TLS antes de expor a interface. O uso de Codex pode envolver inferência remota, mesmo em modo `read-only`. A sandbox do Codex e a do `objdump` não substituem uma VM de segurança para análise de binários hostis. Jamais publique chaves ou tokens no GitHub.

# Comando tunnel no Windows restrito

O wrapper gerencia somente a parte do Windows restrito: o agente Python. Nao sobe
servicos corporativos, o gateway AWS ou o cliente WSL. Nao depende de Docker nem
instala servico/tarefa de inicializacao. Usa o launcher existente, sem administrador.

## Atualizar na raiz do clone

```powershell
Set-Location C:\CAMINHO\secure-gateway
git pull --ff-only origin main
```

Precisa do pacote privado existente em `bundles-https\agent`, Python aprovado e as
dependencias de requirements-https.txt na venv da raiz (ou no Python aprovado do PATH).
Nao gere certificados novos. O agente nao recebe o token do cliente.

## Executar da raiz ou adicionar ao PATH

Da raiz: `.\tunnel.cmd up` ou `.\Tunnel.ps1 up`.
Para chamar de qualquer pasta, adicione a PASTA do clone ao Path do usuario Windows,
na tela de variaveis de ambiente, e abra um novo terminal. Nao adicione o nome do
arquivo ao Path. Exemplo desta estacao de desenvolvimento:
`C:\Users\david.oliveira2\projects\windows\secure-gateway`.
No Windows restrito, use o caminho do clone daquele usuario/computador.

```powershell
Get-Command tunnel -All
where.exe tunnel
```

Confirme que o comando selecionado aponta ao `tunnel.cmd` deste clone. Se existir
outro comando com o mesmo nome, use o caminho completo ao nosso tunnel.cmd.
O shim resolve Tunnel.ps1 pela propria pasta; a pasta atual do terminal pode ser
qualquer projeto. Nao modifica a execution policy; use a politica corporativa
aprovada caso a execucao de scripts esteja restrita.

## Comandos

```powershell
tunnel up
tunnel status
tunnel check
tunnel logs
tunnel logs -Tail 50
tunnel logs -Tail 50 -Follow
tunnel down
tunnel logs
tunnel restart
tunnel rotate-client-token -PolicyJsonBase64 COLE_O_VALOR_GERADO_NA_AWS
```

- `up`: valida arquivos/dependencias, politica e conectividade pelo preflight. So
  inicia apos sucesso, em segundo plano, e libera o terminal. No perfil homologacao,
  atende GitLab/Artifactory com os workers existentes. Se ja gerenciado, retorna o
  mesmo processo sem duplicar. Operacoes de ciclo de vida simultaneas sao recusadas.
- `status`: informa o processo gerenciado e caminhos dos logs. Processo ativo nao
  comprova login nas aplicacoes nem saude do canal; use `check` para os acessos.
- `check`: executa as verificacoes sem iniciar outro agente.
- `down`: solicita parada e, se necessario, encerra somente o PID cujo executavel e
  horario de criacao correspondem ao registro. Pode ser repetido se ja estiver parado.
- `logs`: mostra as ultimas 100 linhas de CADA stream (stdout e stderr), com prefixo
  identificador. `-Tail` muda a quantidade; `-Follow` ou `-f` acompanha ambos ate Ctrl+C.
  Funciona tambem apos down e em falhas de inicio que ja criaram os arquivos de log.
- `restart`: executa down seguido de up, repetindo o preflight.

Os logs e metadados ficam em `%LOCALAPPDATA%\secure-gateway\agent`. O processo segue
visivel no Gerenciador de Tarefas. Acompanhar logs prende apenas aquele terminal;
Ctrl+C em `logs -Follow` nao encerra o agente. O acompanhamento permanece na execucao
selecionada; depois de restart execute logs novamente. Nao ha exclusao/rotacao
recursiva automatica de logs; defina retencao conforme o procedimento local.

## Configuracao alternativa

```powershell
tunnel up -Config C:\CAMINHO\agent\config.json
tunnel status -RuntimeDirectory C:\CAMINHO\runtime-agente
tunnel logs -RuntimeDirectory C:\CAMINHO\runtime-agente -Tail 30
```

Use o MESMO RuntimeDirectory em up/down/status/logs para uma instancia alternativa.
Caminhos relativos de Config/RuntimeDirectory sao resolvidos a partir da pasta de
onde o comando foi chamado; os padroes apontam ao clone e ao perfil do usuario.
O wrapper nao inicia automaticamente fixtures de laboratorio. Para um fixture
ja executando, use `-Service lab-status`; o laboratorio sintetico anterior continua
no Start-RestrictedLab.ps1 em modo Test.

## Aplicar uma politica de ate 720 horas

Gere o perfil no aws-frp conforme [HOMOLOGATION.md](HOMOLOGATION.md), nunca no agente.
Atualize primeiro o clone no Windows restrito: helpers antigos recusam mais de 24h.
Receba somente agent-policy.json em bundles-renovacao e execute:

```powershell
tunnel down
git pull --ff-only origin main
.\.venv\Scripts\python.exe homologation.py apply `
  --config bundles-https/agent/config.json `
  --policy bundles-renovacao/agent-policy.json
tunnel up
tunnel check
```

Token e autorizacao dos servicos precisam estar validos. Up/restart nao renovam
nenhum deles e nao ignoram expiracao. Default: 24 horas; maximo: 720 horas.

## Receber a rotacao do aws-frp e restabelecer o agente

Na AWS use [AWS-TUNNEL.md](AWS-TUNNEL.md). Copie somente a linha pronta depois de
WINDOWS_COMMAND e execute de qualquer pasta no Windows restrito:

```powershell
tunnel rotate-client-token -PolicyJsonBase64 COLE_O_VALOR_GERADO_NA_AWS
```

O wrapper valida formato, papel agent, identidade, escopo, prazo e ausencia de
segredos ANTES de parar o agente. Depois aplica a politica com backup e executa up,
com preflight completo. Input invalido nao interrompe um agente existente. Se a
politica e valida mas um destino esta inacessivel, a configuracao e aplicada e o
inicio e recusado; use check/logs e o backup indicado para diagnostico.

Tambem aceita uma string JSON pura no PowerShell, usando Tunnel.ps1 diretamente
(esse arquivo tambem e encontrado pelo PATH). Substitua o placeholder pelo JSON
completo de WINDOWS_AGENT_POLICY_JSON:

```powershell
$policyJson = 'COLE_SOMENTE_O_JSON_COMPLETO_DE_WINDOWS_AGENT_POLICY_JSON'
Tunnel.ps1 rotate-client-token -PolicyJson $policyJson
```

Ou passe o JSON pela entrada padrao do shim CMD:

```powershell
$policyJson | tunnel rotate-client-token -PolicyStdin
```

Evite JSON cheio de aspas diretamente nos argumentos de tunnel.cmd: CMD/PowerShell
podem remover aspas. Prefira o comando Base64 gerado automaticamente ou o pipe.
Nenhuma forma recebe o token do cliente; campos de token/senha/chave privada sao
recusados. O usuario intermediario precisa atualizar separadamente a credencial do
proxy e a variavel do Maven. O agente continua com suas chaves de assinatura e TLS.

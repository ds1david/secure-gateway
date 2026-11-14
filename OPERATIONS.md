# Operacao diaria por ambiente

Todos os comandos de codigo partem da raiz do clone `secure-gateway`.
Repositorio oficial: https://github.com/ds1david/secure-gateway.
Para atualizar a estrutura antiga, siga primeiro [MIGRATION.md](MIGRATION.md).

| Ambiente | Responsabilidade |
| --- | --- |
| aws-frp / Linux | Gateway, proxy externo TLS, emissao e revogacao de tokens |
| Windows restrito / PowerShell + Python | Agente, preflight e acesso aos destinos |
| Intermediario / WSL Linux | Git/Maven, autenticacao do cliente e proxy local opcional |

## 1. aws-frp

Atualizar codigo (quando houver nova versao):

```bash
git -C ~/secure-gateway pull --ff-only origin main
sudo install -o root -g root -m 0644 ~/secure-gateway/{https_poc.py,poc.py,stream.py,homologation.py} /opt/gateway-poc-https/
sudo systemctl restart gateway-poc-https
```

Somente iniciar/verificar, sem atualizar:

```bash
sudo systemctl start gateway-poc-https
sudo systemctl status gateway-poc-https --no-pager
sudo journalctl -u gateway-poc-https -n 20 --no-pager
```

Tokens/perfis nao sao renovados por restart. Emissao, rotacao e distribuicao seguem
[HOMOLOGATION.md](HOMOLOGATION.md). O cliente recebe `client.token`; o Windows restrito
recebe somente `agent-policy.json`. Para entrada externa HTTPS use
[EXTERNAL-PROXY.md](EXTERNAL-PROXY.md), inclusive regra de acesso da porta 8443.

## 2. Windows restrito

No PowerShell, entre no clone local desse computador (ajuste o caminho do usuario):

```powershell
Set-Location C:\CAMINHO\secure-gateway
.\Start-RestrictedLab.ps1 -Mode Stop
git pull --ff-only origin main
```

Na primeira execucao apos migrar, prepare a venv na raiz:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements-https.txt
```

Quando receber uma nova politica, aplique-a ANTES do Check:

```powershell
.\.venv\Scripts\python.exe homologation.py apply `
  --config bundles-https/agent/config.json `
  --policy bundles-renovacao/agent-policy.json
```

Se a politica atual continua valida, pule o apply. Depois:

```powershell
.\Start-RestrictedLab.ps1 -Mode Check
.\Start-RestrictedLab.ps1
.\Start-RestrictedLab.ps1 -Mode Status
```

O launcher repete o preflight e inicia em segundo plano somente em caso de sucesso.
Status informa o PID e os logs em `%LOCALAPPDATA%\secure-gateway\agent`.
Pare com `.\Start-RestrictedLab.ps1 -Mode Stop`. O agente nao recebe token do cliente.

## 3. Cliente no intermediario / WSL

Com o proxy HTTPS externo habilitado, nao inicie nenhum processo Python local:

```bash
git -c http.proxy=https://intermediario-01@secure-gateway.sicredi.space:8443 \
    -c http.proxyAuthMethod=basic \
    ls-remote https://gitlab.sicredi.net/SEU_GRUPO/SEU_PROJETO.git
```

No desafio do proxy, usuario e o ID e senha e o token atual. O login do GitLab e
separado. Nao coloque o segredo na URL, linha de comando ou repositorio. Na rotacao,
atualize somente a credencial do proxy no gerenciador aprovado. O Edge do Windows
pode ser aberto com `tools/Start-ExternalEdge.ps1` pelo PowerShell do intermediario;
o desenvolvimento permanece no WSL. Para Maven sem processo local, configure o
mirror HTTPS conforme [MAVEN.md](MAVEN.md). LDAP permanece independente do gateway.

Se optar pelo proxy local (por exemplo, para o Maven ja configurado):

```bash
cd ~/secure-gateway
.venv/bin/python homologation.py apply \
  --config bundles-https/client/config.json \
  --policy bundles-renovacao/client-policy.json
.venv/bin/python https_poc.py proxy --config bundles-https/client/config.json
```

O apply exige `client.token` ao lado da politica e so e necessario ao renovar.
Mantenha o terminal do proxy aberto; em outro terminal use Git/Maven. Nao execute
simultaneamente dois proxies locais na mesma porta. O token nunca vai ao agente.

## Clone oficial de desenvolvimento

No Windows desta estacao:

```powershell
Set-Location C:\Users\david.oliveira2\projects\windows\secure-gateway
git remote -v
git status --short
```

Os testes rodam da raiz: `.\.venv\Scripts\python.exe -m unittest discover -s tests -v`.
Somente este clone e usado para alteracoes futuras; os clones antigos ficam como
referencia, sem receber novas alteracoes.

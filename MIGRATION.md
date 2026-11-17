# Atualizar para codigo na raiz

Repositorio oficial: https://github.com/ds1david/secure-gateway.
Workspace Windows: `C:\Users\david.oliveira2\projects\windows\secure-gateway`.
Os arquivos Python e PowerShell agora ficam na raiz do clone, junto de `tests/`,
`deploy/` e `tools/`. Execute os comandos abaixo na raiz, nao na subpasta antiga.

Se ainda usa o repositorio pessoal `ds1david`, faca um clone novo do repositorio
oficial. Os historicos sao independentes: nao basta trocar o remote e fazer pull.
Transfira somente o pacote privado da funcao de cada ambiente por canal aprovado.
Nao apague o clone anterior antes de validar. Tokens/chaves publicados no historico
antigo precisam de revogacao/rotacao; o novo repo nao distribui segredos.

## Windows restrito: PowerShell e Python

Antes do pull, pare o agente pelo launcher que estiver gerenciando o processo:

```powershell
Set-Location C:\CAMINHO\secure-gateway
if (Test-Path .\gateway-poc\Start-RestrictedLab.ps1) {
    .\gateway-poc\Start-RestrictedLab.ps1 -Mode Stop
} else {
    .\Start-RestrictedLab.ps1 -Mode Stop
}
git pull --ff-only origin main
```

Pacotes privados ignorados pelo Git podem continuar na pasta antiga depois do pull.
Se o pacote do agente ainda estiver la e o destino nao existir, copie-o:

```powershell
if ((Test-Path .\gateway-poc\bundles-https\agent) -and
    -not (Test-Path .\bundles-https\agent)) {
    New-Item -ItemType Directory -Force .\bundles-https | Out-Null
    Copy-Item -Recurse -LiteralPath .\gateway-poc\bundles-https\agent -Destination .\bundles-https\
}
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements-https.txt
.\Start-RestrictedLab.ps1 -Mode Check
.\Start-RestrictedLab.ps1
.\Start-RestrictedLab.ps1 -Mode Status
```

Copie somente o pacote de agente, nunca o token do cliente. Se o config contiver
caminhos absolutos, confira se ainda apontam para arquivos existentes. Se a politica
expirou, aplique a nova politica sem segredos antes do Check. Nao gere chaves novas
independentes nem sobrescreva um pacote que ja exista na raiz.

## aws-frp: Linux

```bash
git -C ~/secure-gateway pull --ff-only origin main
sudo install -o root -g root -m 0644 ~/secure-gateway/{https_poc.py,poc.py,stream.py,web_policy.py,homologation.py,requirements-https.txt} /opt/gateway-poc-https/
sudo /opt/gateway-poc-https/.venv/bin/python -m pip install -r /opt/gateway-poc-https/requirements-https.txt
sudo install -o root -g root -m 0644 ~/secure-gateway/deploy/gateway-poc-https.service /etc/systemd/system/gateway-poc-https.service
sudo systemctl daemon-reload
sudo systemctl restart gateway-poc-https
sudo systemctl status gateway-poc-https --no-pager
```

As pastas `/opt/gateway-poc-https`, `/etc/gateway-poc-https` e
`/var/lib/gateway-poc-https`, o usuario de servico e o nome da unidade systemd sao
mantidos por compatibilidade com a instalacao existente. Nao sao subpastas do clone
nem dependencias da estrutura antiga. Nao mova certificados, config ou replay DB.
HAProxy, Certbot, identidades e tokens nao sao alterados por esta reorganizacao.

## Windows intermediario: WSL Linux

O proxy externo nao requer Python no cliente; Git/Maven rodam no WSL conforme
[EXTERNAL-PROXY.md](EXTERNAL-PROXY.md). Para atualizar as ferramentas do clone:

```bash
cd ~/secure-gateway
git pull --ff-only origin main
```

Se usa a alternativa de proxy local, pare o processo com Ctrl+C antes do pull e
copie somente o pacote privado do cliente, se necessario:

```bash
if [ -d gateway-poc/bundles-https/client ] && [ ! -e bundles-https/client ]; then
    mkdir -p bundles-https
    cp -a gateway-poc/bundles-https/client bundles-https/
fi
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements-https.txt
.venv/bin/python https_poc.py proxy --config bundles-https/client/config.json
```

Nao copie o ambiente `.venv` do Windows para o Linux. Crie um ambiente por sistema.
A pasta antiga pode conter arquivos privados; nao faca exclusao recursiva automatica.
Depois de validar, arquive esses arquivos pelo procedimento local aprovado.

## Desenvolvimento e publicacao

Todas as alteracoes passam pelo clone local oficial. Revise os arquivos antes de
adicionar explicitamente codigo/documentacao ao commit. Nao use `git add .` para
incluir pacotes operacionais. Depois de testes e commit, publique com
`git push origin main`. EC2 e Windows restrito apenas recebem codigo por pull.

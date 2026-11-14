# Migracao para ds1david/secure-gateway

Repositorio oficial: https://github.com/ds1david/secure-gateway.
Foi migrado somente o codigo/documentacao, com historico novo. O repositorio anterior
contem arquivos operacionais publicados; revogue/rotacione os tokens que passaram por
ele. Nao reutilize ZIPs publicados contendo chaves; substitua essas chaves pelo
procedimento aprovado de provisionamento. Nenhum segredo foi copiado para este repo.

Nao basta mudar o remote e fazer pull: os historicos sao diferentes. Faca um clone
novo, mantendo o antigo como referencia ate validar a migracao. Nao use force/reset.

## EC2 aws-frp

```bash
git clone https://github.com/ds1david/secure-gateway.git ~/secure-gateway
git -C ~/secure-gateway remote -v
sudo install -o root -g root -m 0644 ~/secure-gateway/gateway-poc/{https_poc.py,poc.py,stream.py,homologation.py,requirements-https.txt} /opt/gateway-poc-https/
sudo /opt/gateway-poc-https/.venv/bin/python -m pip install -r /opt/gateway-poc-https/requirements-https.txt
sudo install -o root -g root -m 0644 ~/secure-gateway/gateway-poc/deploy/gateway-poc-https.service /etc/systemd/system/gateway-poc-https.service
sudo systemctl daemon-reload
sudo systemctl restart gateway-poc-https
sudo systemctl status gateway-poc-https --no-pager
```

Se `~/secure-gateway` ja existe, confira o remote antes e use `git -C ~/secure-gateway
pull --ff-only origin main`. Configuracao, certificados e replay DB permanecem em
`/etc/gateway-poc-https` e `/var/lib/gateway-poc-https`. Nao aplique o roteiro de
primeira instalacao sobre um ambiente existente. Nao troque HAProxy/Certbot.

## Windows restrito

Feche o agente antigo antes de iniciar o novo; se gerenciado pelo launcher, use
`Start-RestrictedLab.ps1 -Mode Stop` na pasta antiga. No diretorio pai do clone antigo:

```powershell
git clone https://github.com/ds1david/secure-gateway.git secure-gateway
New-Item -ItemType Directory -Force .\secure-gateway\gateway-poc\bundles-https | Out-Null
Copy-Item -Recurse -LiteralPath .\ds1david\gateway-poc\bundles-https\agent -Destination .\secure-gateway\gateway-poc\bundles-https\
Set-Location .\secure-gateway\gateway-poc
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements-https.txt
.\Start-RestrictedLab.ps1 -Mode Check
.\Start-RestrictedLab.ps1
.\Start-RestrictedLab.ps1 -Mode Status
```

Adapte somente o caminho da pasta antiga se necessario. Copie exclusivamente o
pacote privado de agente ja provisionado; nao o token do cliente. Nao gere novas
chaves independentes. Se houver caminhos absolutos no config, preserve o destino
existente ou ajuste para os arquivos copiados. Se o perfil expirou, aplique a nova
`agent-policy.json` sem segredos antes do Check, conforme HOMOLOGATION.md.

## Cliente WSL

O proxy direto externo nao requer instalar Python nem copiar chaves do agente no
cliente. Configure Git/Edge conforme [EXTERNAL-PROXY.md](gateway-poc/EXTERNAL-PROXY.md).
Se optar por manter o proxy local para ferramentas ainda incompativeis:

```bash
git clone https://github.com/ds1david/secure-gateway.git ~/secure-gateway
cd ~/secure-gateway/gateway-poc
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements-https.txt
mkdir -p bundles-https
# Copie SOMENTE bundles-https/client do seu clone antigo para bundles-https/client.
.venv/bin/python https_poc.py proxy --config bundles-https/client/config.json
```

O token e distribuido diretamente ao cliente por canal aprovado, nunca pelo Git.

## Atualizacoes futuras

Somente a maquina de desenvolvimento faz commit/push para o novo repo:

```bash
git remote get-url origin
git status --short
git diff --check
# Adicione explicitamente os arquivos de codigo/documentacao revisados.
git commit -m "Describe the gateway change"
git push origin main
```

AWS e Windows apenas fazem pull do clone novo antes de instalar/iniciar. Preserve
os pacotes privados fora do controle de versao. O clone antigo nao foi apagado.

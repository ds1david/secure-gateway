# Jira e Confluence pelo proxy HTTPS

URLs: https://sicredi.atlassian.net/jira e https://sicredi.atlassian.net/wiki.
O navegador executa no intermediario. O agente Windows transporta conexoes TCP;
nao ha RBI, automacao de navegador ou interceptacao TLS implementada pelo projeto.

## Escopo

O grupo `atlassian` autoriza apenas TCP 443 para `sicredi.atlassian.net` e os
seguintes dominios de infraestrutura compartilhada, incluindo subdominios:
`atlassian.com`, `atl-paas.net`, `ss-inf.net`, `jira.com`, `atlassian-dev.net`,
`atlassian-3p.com`. Estes ultimos incluem infraestrutura de apps/Forge; a permissao
e de dominio, nao de pagina nem exclusiva ao tenant. Outros tenants atlassian.net
sao recusados. Jira e Confluence compartilham o mesmo host; CONNECT nao permite
separar /jira de /wiki sem interceptar TLS. O grupo concede ambos.

Referencia consultada em 17/11/2026:
https://support.atlassian.com/organization-administration/docs/ip-addresses-and-domains-for-atlassian-cloud-products/

O PAC usa exatamente essas regras e preserva GitLab/Artifactory. Para destinos
encaminhados, nao existe fallback DIRECT. Autorizacao expirada continua passando
pelo proxy e sendo recusada, ate a politica ser renovada.

Parceiros/CDNs terceiros e provedores corporativos de SSO nao sao liberados
indiscriminadamente: permanecem DIRECT no PAC. Se acessiveis no intermediario,
funcionam diretamente. Se precisarem sair pelo agente, e necessario identificar
os hosts exatos e revisar uma extensao da politica; nao habilitar *.cloudfront.net
ou todos os dominios corporativos. Nao ha garantia de todos os plugins/whiteboards
antes de testar seu fluxo real. O contexto de dispositivo Windows, cookies e
certificados pessoais nao sao transferidos para o intermediario. MFA, SSO e regras
de dispositivo continuam sendo exigidos.

O agente resolve os nomes e conecta a enderecos publicos validados, sem resolver
novamente entre validacao e conexao. DNS apontando para loopback, rede privada,
link-local ou metadados EC2 e recusado neste grupo. DNS corporativo que retorne
IPs privados exige analise especifica, nao remocao automatica da protecao.

## 1. AWS: atualizar codigo e servico

Execute no shell Linux da EC2 (nao no WSL intermediario):

```bash
git -C ~/secure-gateway pull --ff-only origin main
sudo install -o root -g root -m 0644 ~/secure-gateway/web_policy.py ~/secure-gateway/https_poc.py ~/secure-gateway/homologation.py ~/secure-gateway/poc.py ~/secure-gateway/stream.py /opt/gateway-poc-https/
sudo install -o root -g root -m 0644 ~/secure-gateway/deploy/gateway-poc-https.service /etc/systemd/system/gateway-poc-https.service
sudo systemctl daemon-reload
```

A unidade mantém CPU/memoria limitadas e aumenta TasksMax para 128 e arquivos
abertos para 512. O perfil de navegador habilita ate 16 sessoes, 64 MiB por sessao,
1800 segundos por sessao e 90 segundos ociosos. Conexoes persistentes sao renovadas
pelo navegador; nao significa acesso ilimitado nem throughput garantido.

## 2. AWS: habilitar o cliente existente sem trocar token

```bash
browser_bundle="/etc/gateway-poc-https/browser-$(date -u +%Y%m%dT%H%M%SZ)"
sudo /opt/gateway-poc-https/.venv/bin/python /opt/gateway-poc-https/homologation.py enable-atlassian --config /etc/gateway-poc-https/config.json --client-id intermediario-01 --out "$browser_bundle"
sudo systemctl restart gateway-poc-https
bash ~/secure-gateway/tunnel.sh check
```

O comando preserva o hash/token e a expiracao do cliente; nao renova autorizacoes
existentes nem altera outros clientes. Cliente expirado/revogado e recusado. Exibe
um comando `tunnel rotate-client-token -PolicyJsonBase64 ...` contendo APENAS a
politica publica do agente. O nome do wrapper e historico: neste fluxo nao ocorre
rotacao. A autorizacao permanece teste solicitado pelo operador, homologacao
corporativa pendente. Nao indica aprovacao de producao.

## 3. Windows restrito: atualizar e aplicar a politica

PowerShell, no clone usado pelo wrapper:

```powershell
Set-Location 'C:\Users\david_rogerio\tools\secure-gateway'
git pull --ff-only origin main
```

Cole o comando completo gerado no passo 2. Ele valida a politica antes de parar o
agente, aplica com backup, faz preflight e reinicia em segundo plano.
Depois execute:

```powershell
tunnel status
tunnel check
tunnel logs -Tail 30
```

O preflight agora inclui TODOS os servicos reais habilitados (tambem Atlassian).
Ele testa transporte/TLS e HEAD, nao login ou todas as funcionalidades.
Nenhum token de cliente e enviado ao Windows restrito.

## 4. Intermediario: abrir Edge

No PowerShell, no clone atualizado:

```powershell
git pull --ff-only origin main
.\tools\Start-ExternalEdge.ps1 -Application Jira
# Ou: -Application Confluence / -Application All
```

Feche antes apenas as janelas do perfil dedicado secure-gateway/edge-external,
para o Edge iniciar com o PAC atualizado. Nao encerre outros perfis de trabalho.
O usuario do proxy e intermediario-01 e a senha e seu token vigente (inalterado).
O login/MFA Atlassian e separado. Nao inserir credenciais nos argumentos.

Se estiver no WSL, execute o launcher pelo PowerShell do Windows usando o caminho
Windows do clone; nao configurar somente o proxy do Git ou variaveis do Bash,
pois isso nao configura o navegador Edge do Windows.

## Validacao e diagnostico

No WSL, teste transporte (302/login ou 200 podem ser esperados):

```bash
curl --connect-timeout 10 --max-time 60 --proxy https://secure-gateway.sicredi.space:8443 --proxy-basic --proxy-user intermediario-01 --head https://sicredi.atlassian.net/jira
curl --connect-timeout 10 --max-time 60 --proxy https://secure-gateway.sicredi.space:8443 --proxy-basic --proxy-user intermediario-01 --head https://sicredi.atlassian.net/wiki
```

No Edge: login/MFA, abrir tarefa e quadro, pesquisar, ler/editar pagina autorizada,
anexar/baixar arquivo de teste e verificar atualizacoes persistentes. Usar dados
de teste autorizados; sucesso de curl nao comprova login nem edicao.
Se falhar: DevTools/Network, anotar apenas hostname e status, sem HAR completo,
cookies, cabecalhos de autenticacao ou parametros de URL. Na AWS usar journalctl
-u gateway-poc-https; no restrito tunnel logs -Tail 100. proxy_destination_denied
registra host/porta sem caminho/query. Nao desligar TLS, EDR ou controles corporativos.

## Retorno

Pare o agente antes de restaurar os backups dos dois configs. Na AWS o comando
informa backup; no Windows o apply cria config.json.before-homologation-*. Use o
backup imediatamente anterior e preserve dono/permissoes originais. Reinicie o
gateway e o agente, reabra o perfil Edge. O token original continua valido conforme
sua data de expiracao. Nunca publique backups/bundles no Git.

## Limites da entrega

Testes automatizados usam servicos ficticios locais. Nenhuma conexao autenticada
com Jira/Confluence corporativos e feita no ambiente de desenvolvimento. Deploy
na EC2 e aceite no navegador dependem de executar os passos acima nos ambientes.

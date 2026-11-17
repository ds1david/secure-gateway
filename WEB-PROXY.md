# Proxy de navegacao: implementacao e homologacao

O navegador/JavaScript/cookies executam no intermediario. HTTP, HTTPS e WebSockets
usam o proxy AWS e o agente Windows resolve/conecta ao destino autorizado.
Nao ha renderizacao remota, reescrita de URLs, copia de cookies ou automacao do Edge.
A identidade/conformidade do dispositivo corporativo nao e transferida.

## Modos e politica

`Start-ExternalEdge.ps1 -Routing Selective` preserva o PAC seletivo existente.
`-Routing All` usa um proxy HTTPS explicito em um perfil separado edge-external-all,
sem fallback DIRECT. O host do proprio proxy e excecao direta para evitar ciclos.
O modo manual permite o teste localhost pelo agente; PAC tem bypass implicito de
loopback no Chromium. O launcher nao altera proxy do sistema ou outros perfis.
`-PrintCommand` mostra o comando sem abrir o navegador e sem credenciais.

Isso cobre requisicoes HTTP/HTTPS e WS/WSS suportadas pelo proxy do navegador,
nao e VPN nem garantia de todo pacote do processo: UDP/WebRTC, protocolos externos,
politicas gerenciadas, extensoes e conexoes de outros programas precisam ser
avaliados separadamente. Nunca desabilite controles corporativos. Para garantia
de saida exclusiva em nivel de rede e necessario controle de rede autorizado.

O grupo `web` e opcional. As permissoes fixas anteriores continuam aditivas: um
cliente autorizado a GitLab pode continuar usando esse destino mesmo que nao esteja
na lista web. Configure um cliente dedicado com somente web se precisar de escopo
exclusivo (issue-client --services web apos habilitar o grupo).

Cada sessao transporta hostname/porta dentro do canal assinado. Gateway E agente
validam a politica. O agente valida todos os IPs retornados pelo DNS e conecta ao
IP aprovado, sem segunda resolucao. Dominios, portas, redes, validade, sessoes,
volume e tempo sao limitados. Nenhum destino e autorizado apenas por existir no PAC.

## Politicas

`examples/web-policy.lab.json` e o padrao: somente localhost:18765/18766 e IPs de
loopback no Windows restrito. Esses ports sao reservados a fixtures ficticias.
Nao exponha dados reais no laboratorio. Nenhum CIDR e aceito no modo lab.

`examples/web-policy.corporate.json` e exemplo OPT-IN, nao aplicado automaticamente.
Lista os destinos ja discutidos e infraestrutura compartilhada Atlassian. Nao
comprova homologacao corporativa. Os dominios auxiliares do SSO precisam ser
identificados e autorizados explicitamente. Nao adiciona todos *.sicredi.net.

Campos exatos:
- hosts: nomes DNS exatos em minusculas, sem esquema, caminho, wildcard ou porta;
- suffixes: dominio raiz e seus subdominios em fronteiras DNS (empresa.exemplo
  inclui api.empresa.exemplo, nao falsaempresa.exemplo);
- ports: 80/443 no modo corporativo, 18765/18766 no laboratorio;
- private_networks: CIDRs privados estritos explicitamente autorizados, de preferencia
  IPs /32 ou /128 dos destinos. Vazio exige IP global. Somente RFC1918 e ULA podem
  ser autorizados. Loopback, link-local, multicast e metadados permanecem negados;
- lab_only: true ou false.

Names/ports/IPs nao previstos sao recusados, incluindo apos redirecionamentos.
Um DNS que misture IPs permitidos e negados e recusado por inteiro. Se o GitLab
resolver para IP privado no Windows, autorize seu IP/rede necessario antes do teste
corporativo; nao libere 0.0.0.0/0. O grupo e compartilhado entre os clientes que
recebem web no mesmo agente: a lista e por grupo/agente, nao uma lista diferente
por cliente. Tokens e habilitacao continuam individuais.

## 1. Atualizar AWS (Linux da EC2)

```bash
git -C ~/secure-gateway pull --ff-only origin main
sudo install -o root -g root -m 0644 ~/secure-gateway/{https_poc.py,poc.py,stream.py,homologation.py,web_policy.py} /opt/gateway-poc-https/
sudo install -o root -g root -m 0644 ~/secure-gateway/deploy/gateway-poc-https.service /etc/systemd/system/gateway-poc-https.service
sudo systemctl daemon-reload
```

Nao use somente o git pull: o systemd executa a copia em /opt. web_policy.py agora
e obrigatorio tambem para os modos antigos. Nao ha novas dependencias pip.
A unidade preserva limites de CPU/memoria, TasksMax=128 e LimitNOFILE=512.

## 2. Preparar fixture no Windows restrito (PowerShell)

```powershell
Set-Location 'C:\Users\david_rogerio\tools\secure-gateway'
git pull --ff-only origin main
python web_lab.py
```

Deixe esse terminal aberto durante o teste. O servidor escuta APENAS 127.0.0.1:18765,
sem administrador. Se a porta ja estiver ocupada por outro laboratorio, encerre
somente o laboratorio anterior; nao mate processos desconhecidos.

## 3. Habilitar politica de laboratorio na AWS

```bash
web_bundle="/etc/gateway-poc-https/web-lab-$(date -u +%Y%m%dT%H%M%SZ)"
sudo /opt/gateway-poc-https/.venv/bin/python /opt/gateway-poc-https/homologation.py configure-web-proxy --config /etc/gateway-poc-https/config.json --client-id intermediario-01 --policy ~/secure-gateway/examples/web-policy.lab.json --out "$web_bundle"
sudo systemctl restart gateway-poc-https
bash ~/secure-gateway/tunnel.sh check
```

O comando exige cliente existente, habilitado e nao expirado. Preserva token e
expiracao, nao muda outros clientes e gera backup. Nunca exibe o token. A lista do
grupo web pode mudar para todos os clientes que ja tinham permissao web.
Copie APENAS a linha `tunnel rotate-client-token -PolicyJsonBase64 ...` gerada.

## 4. Aplicar no Windows restrito

Em outro PowerShell, cole a linha gerada na AWS. O wrapper valida antes de parar,
aplica a politica publica com backup, faz preflight e inicia o agente em segundo
plano. O nome rotate-client-token e historico: este fluxo NAO troca o token.

```powershell
tunnel status
tunnel check
tunnel logs -Tail 30
```

O check web exige ao menos uma porta permitida acessivel por host exato. Nao enumera suffixes
nem testa login; cada conexao real e validada separadamente. As autorizacoes
anteriores GitLab/Artifactory/Atlassian continuam passando pelo seu preflight.

## 5. Testar no intermediario

PowerShell, no clone do projeto:

```powershell
git pull --ff-only origin main
$env:NO_PROXY = ''
curl.exe --proxy https://secure-gateway.sicredi.space:8443 --proxy-basic --proxy-user intermediario-01 http://localhost:18765/status
.\tools\Start-ExternalEdge.ps1 -Routing All -Application Lab
```

Use o token VIGENTE no prompt do proxy; login de aplicacao e separado. Para curl
no WSL use `curl` e a mesma URL, com `--noproxy ''` para neutralizar NO_PROXY=localhost.
NO_PROXY foi esvaziado apenas nesse terminal para impedir bypass do teste local.

O localhost da URL e resolvido/conectado NO WINDOWS RESTRITO. O servidor precisa
continuar rodando la. No intermediario nao deve existir um servidor de laboratorio.
Feche antes as janelas do perfil edge-external-all para aplicar novos argumentos;
nao encerre outros perfis. Em edge://version confira --proxy-server e o caminho
do perfil. Politicas corporativas podem prevalecer; nao contorne essas politicas.

Aceite manual na pagina:
1. GET/API: resposta status ok, source restricted-windows-lab.
2. Upload: bytes e SHA256 retornados, somente fixture-upload.
3. Download: fixture.bin de 65536 bytes.
4. Redirecionamento: volta a pagina inicial.
5. WebSocket: fixture-websocket ecoado.
6. Destino negado: abrir https://example.invalid no MESMO perfil e obter falha;
   na AWS deve haver proxy_destination_denied sem caminho/query.
7. Indisponibilidade: tunnel down no restrito deve interromper novos acessos a
   localhost:18765; nao deve acessar servico local do intermediario. Depois tunnel up.

Se falhar, capture apenas hostname/status, hora e ID da sessao. Nao envie HAR,
JWT, cookies, senhas ou cabecalhos Authorization/Proxy-Authorization.

## 6. Homologacao corporativa especifica (opt-in)

Somente apos validar o laboratorio e ter autorizacao para os destinos:

1. Copie examples/web-policy.corporate.json para um arquivo operacional fora do Git.
2. Revise hosts, suffixes e private_networks com os destinos/rede realmente permitidos.
3. Na AWS repita configure-web-proxy com --policy apontando para esse arquivo e
   --out em NOVA pasta. Reinicie o gateway e aplique a nova linha no Windows.
4. No intermediario abra -Routing All -Application All. O token nao muda.
5. Teste login/MFA, tarefa Jira, pagina Confluence, edicao autorizada e anexos,
   GitLab login e navegacao; confirme se os dominios auxiliares foram autorizados.
6. Compare logs gateway/agente e revise destinos recusados, sem liberar wildcards
   indiscriminadamente. Aumentar a lista nao transfere identidade do dispositivo.

Autorizacoes geradas permanecem requester_authorized_test/corporate_approval=pending;
nao representam homologacao de endpoint nem aprovacao de producao. A renovacao
normal via rotate-client-token preserva integralmente a politica web configurada.

## Diagnostico e retorno

AWS: sudo journalctl -u gateway-poc-https -f -o short-iso-precise.
Windows restrito: tunnel logs -Tail 100 -Follow.
web_target_failed informa web_dns_failed, web_destination_denied,
web_address_denied ou web_connect_failed com ID de sessao e sem URL/conteudo.
https_session_started registra apenas hostname/porta, cliente e ID.
Falhas JWT agora distinguem emissor, destinatario, emissao e mensagem ainda nao
valida; nenhuma tolerancia de horario nem validacao TLS foi alterada.

Para retorno, pare o agente e restaure o backup anterior dos configs AWS/Windows,
preservando dono/permissoes. Reinicie gateway/agente. Reabra o Edge com
-Routing Selective (perfil anterior). Token original e demais aplicacoes permanecem
conforme suas autorizacoes. Ctrl+C encerra apenas a fixture web_lab.py.

## Evidencia de testes

Testes automatizados usam somente localhost e enderecos DNS simulados. Verificam
politica, DNS/IPs, token/rotacao, HTTP, upload, binario, redirect, upgrade WebSocket
e recusa independente no agente. Login real, politicas Edge e comportamento
JavaScript no ambiente corporativo exigem aceite manual acima.

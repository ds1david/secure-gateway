# Proxy HTTPS direto no aws-frp

O cliente nao precisa executar Python para Git/curl/Edge compativeis com proxy HTTPS.
O agente continua no Windows restrito. A entrada opcional usa o MESMO certificado
publico do gateway e a porta TLS 8443; o canal de agente/cliente anterior em 443 e
preservado. Nao e proxy aberto: cada conexao exige ID/token valido, escopo por servico,
autorizacao do agente, prazo e limites. Sem configuracao explicita nao ha listener novo.

## 1. Atualizar o aws-frp

Se esta migrando do repo antigo, siga primeiro [MIGRATION.md](../MIGRATION.md).
Caso ja tenha o clone novo:

```bash
git -C ~/secure-gateway pull --ff-only origin main
sudo install -o root -g root -m 0644 ~/secure-gateway/gateway-poc/{https_poc.py,poc.py,stream.py,homologation.py} /opt/gateway-poc-https/
sudo install -o root -g root -m 0644 ~/secure-gateway/gateway-poc/deploy/gateway-poc-https.service /etc/systemd/system/gateway-poc-https.service
sudo systemctl daemon-reload
```

O gateway deve estar no modo `client_auth: token` e ter politicas de homologacao
validas, conforme [HOMOLOGATION.md](HOMOLOGATION.md). Tokens que passaram pelo Git
antigo devem ser revogados/rotacionados. Nenhum token e obtido do repositorio novo.

## 2. Habilitar a entrada TLS

```bash
sudo python3 /opt/gateway-poc-https/homologation.py configure-proxy \
  --config /etc/gateway-poc-https/config.json \
  --host secure-gateway.sicredi.space --port 8443 --bind 0.0.0.0
sudo systemctl restart gateway-poc-https
sudo systemctl status gateway-poc-https --no-pager
sudo ss -ltnp 'sport = :8443'
```

O helper cria backup e preserva o modo/permissoes do config, certificados, clientes
e chaves existentes. O certificado `tls_cert` precisa cobrir
`secure-gateway.sicredi.space`, com cadeia publica completa. Nao gere outra CA.

No Security Group da EC2, libere entrada TCP 8443 SOMENTE dos IPs publicos de saida
dos clientes autorizados (/32, ou faixa corporativa aprovada). Se houver firewall
local, aplique o mesmo escopo. Nao e necessario abrir 9443/9444 ou alterar HAProxy.
O DNS existente precisa apontar diretamente para a EC2, como na configuracao atual.
Se usar Cloudflare como terminador TLS, valide explicitamente o suporte a forward
proxy/CONNECT: esta entrega nao depende desse modo. O enlace do cliente deve permitir
TLS/8443; se estiver bloqueado, solicite a liberacao, sem contornar o controle.

Teste no WSL, SEM token primeiro:

```bash
curl --proxy https://secure-gateway.sicredi.space:8443 \
  --head https://gitlab.sicredi.net/
```

O esperado e `407 Proxy Authentication Required`, comprovando TLS e desafio de
autenticacao. Nao use `-k`, `--proxy-insecure` nem desligue verificacao SSL.
Uma conexao HTTP simples nessa porta nao e aceita.

## 3. Testar com token sem coloca-lo na linha de comando

No WSL, copie o token do arquivo privado ao prompt quando o curl pedir a senha:

```bash
curl --proxy https://secure-gateway.sicredi.space:8443 \
  --proxy-basic --proxy-user intermediario-01 \
  --head https://gitlab.sicredi.net/
```

Usuario do PROXY: `intermediario-01`. Senha do PROXY: conteudo de `client.token`.
O GitLab recebe suas proprias credenciais corporativas depois; nao recebe o token
do proxy. Nao use a senha corporativa como senha do proxy. O servidor guarda apenas
o hash do token. Basic e aceito SOMENTE dentro do TLS do proxy, nunca por HTTP aberto.
Uma inspecao TLS autorizada nesse enlace pode observar o token bearer.

## 4. Git no WSL sem cliente Python

Git/libcurl devem suportar proxy HTTPS. O username no endereco faz o Git consultar
o mecanismo de credenciais para a senha do proxy, em vez de gravar o token na URL.

```bash
git -c http.proxy=https://intermediario-01@secure-gateway.sicredi.space:8443 \
    -c http.proxyAuthMethod=basic \
    ls-remote https://gitlab.sicredi.net/SEU_GRUPO/SEU_PROJETO.git
```

Forneca o token quando o prompt for do host do PROXY; quando for do GitLab, forneca
o metodo de credenciais permitido pela organizacao (senha/SSO web nao equivale
necessariamente a senha aceita por Git HTTPS). Nao registre o token no shell/config.

Para configurar somente esse GitLab:

```bash
git config --global 'http.https://gitlab.sicredi.net/.proxy' https://intermediario-01@secure-gateway.sicredi.space:8443
git config --global 'http.https://gitlab.sicredi.net/.proxyAuthMethod' basic
git clone https://gitlab.sicredi.net/SEU_GRUPO/SEU_PROJETO.git
```

Em projetos existentes, confira configuracoes antigas de `http.proxy` e
`remote.origin.proxy` com `git config --show-origin --get-regexp '^(http\..*proxy|remote\..*\.proxy)$'`.
Remova SOMENTE os overrides locais do proxy antigo que voce tiver configurado.
Se o gerenciador de credenciais guardar o token anterior, atualize a entrada do
host do proxy na rotacao; nao apague as credenciais corporativas do GitLab.

## 5. Edge no Windows intermediario

Nao abra a porta do proxy como se fosse uma pagina. Execute do clone novo:

```powershell
.\tools\Start-ExternalEdge.ps1
```

O launcher abre um perfil separado e usa
`https://secure-gateway.sicredi.space:8443/proxy.pac`. O PAC e publico, sem segredos:
somente GitLab/Artifactory usam a AWS; outros dominios usam a conexao normal do
cliente. Nao ha fallback direto para os dois destinos privados. Feche as janelas
desse perfil antes de alterar parametros e abrir novamente. Politicas corporativas
do Edge podem impedir overrides; nao sao alteradas pelo script.

No desafio do proxy informe o ID do cliente e o token. Depois autentique no GitLab
com sua conta corporativa. Para copiar o token a area de transferencia a partir do
WSL, se essa integracao ja estiver habilitada, use `clip.exe < CAMINHO/client.token`.
Nao copie o token para o Windows restrito. Evite historico/sincronizacao de clipboard.

### LDAP/SSO indisponivel

Um erro LDAP mostrado pelo GitLab pode ser do backend de autenticacao GitLab->LDAP;
o proxy nao faz essas consultas e nao substitui esse backend. Nao e possivel afirmar
a causa sem o erro exato. Se houver redirecionamento para outro dominio, o PAC usa
o acesso normal da estacao; dominios corporativos adicionais privados nao sao
automaticamente autorizados. Registre apenas dominio, horario UTC e request ID,
sem cookies, tokens, HAR com credenciais ou query string de SSO. Compare o mesmo
login no Windows restrito onde o acesso ja e autorizado para localizar a falha.

## 6. Artifactory e Maven

curl pode acessar o Artifactory HTTP pelo proxy HTTPS: cliente->AWS e criptografado,
mas agente->Artifactory:80 continua sem TLS. Configure HTTPS no servico antes de
transmitir credenciais/dados sensiveis.

Nao substitua apenas o host/porta no proxy HTTP do Maven: suporte a proxy TLS depende
da versao e transporte do Maven. A configuracao anterior com proxy local continua
valida; acesso Maven direto sem processo local requer validar esse suporte na sua
versao. Nao oferecemos listener HTTP sem TLS para acomodar transportes incompativeis.

## 7. Rotacao, limites e rollback

A emissao/revogacao continua no aws-frp com `homologation.py`; novos clientes usam
`issue-client`, renovacao do mesmo ID segue HOMOLOGATION.md. Nao ha token no agente.
No proxy direto o cliente so atualiza a credencial do proxy, sem executar Python.
Renovar a janela de homologacao ainda exige a politica sem segredos no agente.

Limites de escopo, expiracao, bytes, tempo, sessoes e taxa do gateway sao compartilhados
com os clientes anteriores. Sao quatro sessoes globais na POC, nao uma configuracao
dimensionada para uso intenso de navegador ou clones grandes. Falhas de login de
aplicacao sao independentes de `407` (credencial do proxy), `403` (destino/escopo)
e `502` (agente/sessao indisponivel). Limites podem encerrar sessoes durante operacoes.

```bash
sudo journalctl -u gateway-poc-https -f
sudo python3 /opt/gateway-poc-https/homologation.py configure-proxy \
  --config /etc/gateway-poc-https/config.json --disable
sudo systemctl restart gateway-poc-https
```

Feche a regra 8443 do Security Group ao desativar. O proxy local e os canais 443
anteriores continuam disponiveis. Nenhum teste local comprova o login LDAP real.

Referencias: [Edge e proxy HTTPS/PAC](https://learn.microsoft.com/en-us/deployedge/configure-microsoft-edge-proxy-support),
[Git: proxy e credenciais](https://git-scm.com/docs/git-config#Documentation/git-config.txt-httpproxy),
[curl](https://curl.se/docs/manpage.html).

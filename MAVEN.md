# Maven direto no secure-gateway AWS

A porta HTTPS externa agora oferece tambem uma entrada de repositorio em
`https://secure-gateway.sicredi.space:8443/maven/repo`. Esta rota nao e um proxy
HTTP do Maven: ela atende GET/HEAD e encaminha o caminho ao repositorio fixo
`/artifactory/repo` pelo agente, preservando a identidade e os limites existentes.
Nao e necessario cliente Python local no WSL para esse modelo.

## 1. Atualizar o gateway no aws-frp / Linux

```bash
git -C ~/secure-gateway pull --ff-only origin main
sudo install -o root -g root -m 0644 ~/secure-gateway/{https_poc.py,poc.py,stream.py,homologation.py} /opt/gateway-poc-https/
sudo systemctl restart gateway-poc-https
sudo systemctl status gateway-poc-https --no-pager
```

O listener externo 8443 deve estar habilitado com certificado valido, conforme
[EXTERNAL-PROXY.md](EXTERNAL-PROXY.md). Nao ha mudanca de certificados, tokens ou
protocolo do agente. O agente existente precisa estar rodando e sua politica ainda
valida. Se a homologacao expirou, renove pelo procedimento de HOMOLOGATION.md.
Esta atualizacao interrompe sessoes em andamento pelo reinicio do gateway.

## 2. Conferir a rota no WSL

Sem credenciais, o esperado e 401 com `WWW-Authenticate: Basic` e o cabecalho
`X-SecureGateway-Request-Id`. Nao use `--proxy`: esta e uma URL HTTPS de repositorio.

```bash
curl --connect-timeout 10 --max-time 20 --head \
  https://secure-gateway.sicredi.space:8443/maven/repo/
```

Com ID/token, teste um POM conhecido e existente no Artifactory:

```bash
curl --connect-timeout 10 --max-time 60 --user intermediario-01 --head \
  https://secure-gateway.sicredi.space:8443/maven/repo/org/springframework/boot/spring-boot-starter-parent/4.1.2/spring-boot-starter-parent-4.1.2.pom
```

O curl solicita o token como senha, sem expo-lo na linha de comando. Um 200 confirma
acesso a ESSE arquivo; 404 significa que ele nao foi encontrado no repositorio.
Um 407 indica entrada de forward proxy ou gateway antigo, nao a rota nova.
Um 403 sem o cabecalho de request ID nao identifica esta implementacao: confira
versao implantada e possivel bloqueio de outro intermediario antes de atribuir ao token.

## 3. Instalar settings.xml no WSL

O exemplo [examples/maven-settings.xml](examples/maven-settings.xml) nao tem segredos.
Antes de substituir seu arquivo, preserve eventuais servers/mirrors/perfis extras:

```bash
mkdir -p ~/.m2
if [ -f ~/.m2/settings.xml ]; then
  cp -p ~/.m2/settings.xml ~/.m2/settings.xml.backup-$(date -u +%Y%m%dT%H%M%SZ)
fi
cp ~/secure-gateway/examples/maven-settings.xml ~/.m2/settings.xml
chmod 600 ~/.m2/settings.xml
```

Os IDs de `<server>` e `<mirror>` precisam ser iguais. O token pertence ao gateway,
nao ao Artifactory. Nao adicione o token em `<proxies>`, na URL ou no POM do projeto.
Nao e necessario bloco `<proxies>` para esse mirror. Se tiver configuracoes globais
extras de proxy, confira que a URL do gateway nao esta sendo encaminhada ao proxy
local antigo. Nao desative validacao TLS para resolver erros de certificado Java.

## 4. Carregar token e executar o build

A partir do arquivo privado ja recebido no WSL (adapte o caminho):

```bash
export SECURE_GATEWAY_TOKEN="$(cat ~/secure-gateway/bundles-renovacao/client.token)"
```

Ou cole sem eco na tela e sem gravar o segredo no historico:

```bash
read -r -s -p "Token do secure-gateway: " SECURE_GATEWAY_TOKEN
printf '\n'
export SECURE_GATEWAY_TOKEN
```

Verifique somente se a variavel esta preenchida, sem imprimir o valor:

```bash
test -n "$SECURE_GATEWAY_TOKEN" && echo "Token carregado" || echo "Token ausente"
```

No diretorio do projeto:

```bash
mvn -s "$HOME/.m2/settings.xml" -U \
  -Daether.connector.basic.threads=2 \
  -Daether.dependencyCollector.bf.threads=2 clean test
```

Os dois limites de threads reduzem a concorrencia para caber nas quatro sessoes
globais da POC; evite outros downloads simultaneos pelo gateway durante o teste.
`-U` permite nova tentativa de resolucao apos falhas cacheadas; nao e preciso apagar
`~/.m2/repository` nem alterar `parent.relativePath` para corrigir um erro de rede.
Ao rotacionar o token, recarregue a variavel em cada terminal ou IDE que executa Maven.
Ao terminar, `unset SECURE_GATEWAY_TOKEN` remove a variavel desse terminal.

## Autenticacao, erros e limites

- 401: token ausente, errado, revogado ou expirado; nao e login do GitLab/LDAP.
- 403: token valido mas escopo Artifactory ou politica do agente negado/expirado.
- 404/410: artefato indisponivel no repositorio fixo.
- 405: operacao de escrita; somente GET/HEAD sao permitidos.
- 413: artefato excede o limite da sessao, descontada margem para cabecalhos.
- 429: limite de requisicoes. 502: agente/upstream indisponivel ou resposta rejeitada.

O log `maven_request_rejected` diferencia `maven_upstream_auth_required`,
`maven_upstream_redirect_denied`, `maven_upstream_framing_invalid` e outras falhas,
sem caminhos de artefatos, tokens, cookies ou corpos. O request ID permite correlacao.
Respostas upstream 401/403 viram 502: o token do gateway NUNCA e enviado ao Artifactory.
Caso o repositorio exija credencial nativa, ela precisa de uma configuracao separada,
nao implementada nesta rota. Nao substitua o token pela senha corporativa.

Downloads POM/JAR/checksums, HEAD, range e validacao condicional sao suportados.
Uploads/deploy, caminhos com percent-encoding/traversal, queries e redirecionamentos
sao rejeitados. Cookies e cabecalhos de autenticacao do upstream nao sao repassados.
A resposta binaria e transmitida em blocos; nao ha cache de artefatos no gateway.

Permanecem quatro sessoes globais, limites de bytes/tempo/taxa e a validade do perfil.
A POC nao e um repositorio Maven de producao nem garante downloads grandes ou builds
muito paralelos. Cliente->AWS usa TLS; agente->Artifactory:80 continua HTTP.
Os testes usam somente um repositorio ficticio e nao provam a existencia de versoes
ou permissoes nos repositorios corporativos.

Referencia de concorrencia: [Maven Resolver](https://maven.apache.org/resolver-1.x/configuration.html).

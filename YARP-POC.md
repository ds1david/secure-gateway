# POC YARP isolada: HTTPS no Windows restrito

## Escopo desta entrega

Componente .NET/YARP que executa no Windows restrito, escuta somente
127.0.0.1:18766 e encaminha a UM destino de laboratorio fixo. O agente Python,
o gateway e o proxy atual nao foram alterados. Destinos corporativos sao recusados
explicitamente nesta primeira etapa; nao ha configuracao GitLab habilitada.

Fluxo da prova:
Edge intermediario (http://localhost:18766/) -> proxy HTTPS AWS -> agente Python
-> YARP no restrito -> HTTPS da fixture no restrito.

O Edge nao recebe o certificado HTTPS da fixture. Quem valida a cadeia e o
hostname desse destino e o YARP no Windows. O canal cliente-AWS continua HTTPS,
o canal AWS-agente continua assinado/TLS; HTTP local e restrito ao loopback.

Isto comprova terminacao de HTTPS no restrito. NAO comprova compatibilidade de
GitLab/Jira/Confluence, nao reescreve HTML/JavaScript e nao herda perfil ou cookies
do Edge corporativo. YARP e um componente de encaminhamento, nao um Glype pronto.

## Preparacao no intermediario (build)

Precisa do SDK .NET 10 apenas na maquina de build. O Windows restrito nao precisa
do SDK. Build/publish sao instalacoes explicitas, sem ofuscacao ou compactacao de
executavel. A execucao deve ser permitida pelos controles corporativos existentes.

PowerShell na raiz do clone:

```powershell
git pull --ff-only origin main
.\tools\Build-YarpPoc.ps1
```

Saida: yarp-poc/publish-win-x64. Transfira a PASTA COMPLETA para o clone no
Windows restrito usando mecanismo autorizado. Nao versione binarios, certificados,
chaves ou arquivos operacionais no Git. Sem administrador, IIS ou servico Windows.
O default self-contained inclui o runtime .NET e ocupa mais espaco. Se o restrito
ja possui Microsoft.AspNetCore.App 10, -FrameworkDependent reduz os artefatos.
No WSL com SDK .NET 10, equivalente:

```bash
dotnet publish yarp-poc/SecureGateway.Yarp.csproj -c Release -r win-x64 --self-contained true -o yarp-poc/publish-win-x64
```

Nao instalar o SDK no restrito como requisito da POC.

## Windows restrito: preparar fixture HTTPS sintetica

Atualize o clone, encerre apenas o web_lab.py anterior que usa 18765 e qualquer
fixture echo anterior em 18766. Se uma porta estiver ocupada, identifique o dono;
nao mate processos desconhecidos.

```powershell
Set-Location 'C:\Users\david_rogerio\tools\secure-gateway'
git pull --ff-only origin main
python make_lab_certs.py --out certs-yarp --hostname localhost --openssl 'C:\Program Files\Git\usr\bin\openssl.exe'
python yarp_lab.py prepare --cert-dir certs-yarp
python yarp_lab.py serve --cert-dir certs-yarp
```

Os certificados/chaves gerados sao apenas ficticios e ficam ignorados pelo Git.
O helper prepara yarp-poc/lab.user.json com caminho da CA publica e SHA256 do
certificado DER. Nenhuma CA e instalada no repositorio de certificados do Windows.
Se a pasta certs-yarp ja existir, reutilize a fixture anterior valida ou gere outra
pasta com novo nome; nao sobrescreva certificados operacionais.

O ultimo comando deixa a origem HTTPS rodando somente no loopback:18765.
Em outro PowerShell do restrito inicie o YARP:

```powershell
Set-Location 'C:\Users\david_rogerio\tools\secure-gateway'
.\yarp-poc\publish-win-x64\SecureGateway.Yarp.exe --config .\yarp-poc\lab.user.json
```

Mantenha os dois terminais abertos nesta POC. Ctrl+C encerra cada componente.
O YARP valida cadeia, validade e hostname. A CA explicita precisa corresponder
a impressao digital configurada e ser uma raiz CA. Somente para a CA sintetica
local, nao se consulta CRL (a fixture nao tem servico de revogacao). Isso nao e
uma configuracao de TLS de producao. Sem TrustedRootFile, usa a confianca normal
da plataforma. Nunca aceita qualquer certificado por callback.

## AWS e agente: reutilizar politica de laboratorio

Se o grupo web ainda esta na politica corporativa, aplique novamente a politica
de laboratorio ja homologada (afeta todos os clientes autorizados ao grupo web).
GitLab/Artifactory fixos e tokens nao sao alterados, mas o escopo web muda.

No shell Linux da AWS:

```bash
lab_bundle="/etc/gateway-poc-https/yarp-lab-$(date -u +%Y%m%dT%H%M%SZ)"
sudo /opt/gateway-poc-https/.venv/bin/python /opt/gateway-poc-https/homologation.py configure-web-proxy --config /etc/gateway-poc-https/config.json --client-id intermediario-01 --policy ~/secure-gateway/examples/web-policy.lab.json --out "$lab_bundle"
sudo systemctl restart gateway-poc-https
```

Cole no restrito a linha publica `tunnel rotate-client-token -PolicyJsonBase64 ...`
gerada pelo comando. O token nao muda. Fixture e YARP precisam estar rodando antes
do preflight. Depois tunnel check. As portas 18765/18766 ja estao no escopo lab;
nenhuma porta de entrada precisa ser aberta no Windows.

## Intermediario: aceite manual

Abra o perfil integral existente:

```powershell
.\tools\Start-ExternalEdge.ps1 -Routing All -Application Lab
```

IMPORTANTE: troque a URL para http://localhost:18766/ (18765 agora serve HTTPS da
origem e nao e o endereco que o Edge deve usar para esta prova). Usuario/token do
proxy continuam iguais. Neste teste o browser fala HTTP com YARP pelo tunel; ele
nao termina o TLS da origem e nao precisa confiar na CA sintetica.

1. Pagina e JavaScript: GET/API, upload, download, redirecionamento, WebSocket.
2. Encerrar YARP: novas chamadas a 18766 devem falhar. Reiniciar: voltam a funcionar.
3. tunnel down: novas chamadas devem falhar. tunnel up: devem voltar.
4. Encerrar a fixture HTTPS: YARP deve retornar erro de encaminhamento.
5. Alterar CA/fingerprint da fixture deve impedir startup ou conexao. Nao ignorar TLS.
6. Logs yarp_request_finished devem mostrar status e outcome sem URL, senha ou cookie.

O arquivo lab.json versionado aponta para a fixture HTTP anterior e serve como
smoke test opcional. Para comprovar o HTTPS no restrito use lab.user.json gerado.

## Build e testes locais

```powershell
dotnet build .\yarp-poc\SecureGateway.Yarp.csproj -c Release
python -m unittest discover -s tests -p test_yarp.py -v
```

Os testes precisam .NET 10 e OpenSSL, usam apenas portas locais temporarias e CAs
ficticias. Validam HTTP, upload, binarios, cookies, redirect interno/externo,
WebSocket, TLS sem CA (recusado), CA explicita (aceita), hostname errado (recusado),
Host indevido e startup com destino fora do laboratorio (recusado).

## Proxima etapa: GitLab por aplicacao

Antes de habilitar GitLab real, definir um hostname HTTPS publico proprio e
certificado valido no frontend AWS; manter autenticacao/autorizacao por cliente;
integrar esse frontend com o servico YARP pelo canal autorizado; adaptar com
testes Host/Origin, cookies e redirecionamentos; preservar CSRF/CSP e validar login.
Nao publicar credenciais reais pelo endereco HTTP localhost desta fixture.

Corpo HTML/JavaScript nao e reescrito automaticamente. URL absoluta a dominio de
SSO ou recurso externo exige arquitetura e autorizacao especificas. Nao remover
CSP/CSRF ou desativar certificados para fazer o login passar. O perfil do Edge
corporativo nao e reutilizado automaticamente pelo HttpClient do YARP.

Referencias:
https://learn.microsoft.com/en-us/aspnet/core/fundamentals/servers/yarp/direct-forwarding
https://learn.microsoft.com/en-us/aspnet/core/fundamentals/servers/yarp/transforms

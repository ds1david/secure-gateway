# Comando tunnel no aws-frp / Linux

O wrapper gerencia gateway-poc-https e verifica HAProxy, entradas TLS e expiracao.
Nao requer Docker. Os controles de servico usam sudo quando necessario. Nao sao
alterados certificados, chaves ou regras de firewall por esse wrapper.

## Instalar/atualizar

```bash
git -C ~/secure-gateway pull --ff-only origin main
sudo install -o root -g root -m 0644 ~/secure-gateway/{https_poc.py,poc.py,stream.py,homologation.py} /opt/gateway-poc-https/
sudo systemctl restart gateway-poc-https
mkdir -p ~/.local/bin
ln -s ~/secure-gateway/tunnel.sh ~/.local/bin/tunnel
export PATH="$HOME/.local/bin:$PATH"
```

Crie o link apenas na primeira vez, se ~/.local/bin/tunnel ainda nao existe. Nao
sobrescreva outro comando sem conferir. Para persistencia, inclua ~/.local/bin no
PATH do seu usuario conforme a configuracao do shell. `readlink -f ~/.local/bin/tunnel`
confirma o destino. O arquivo do Git e executavel e usa LF; tambem pode chamar
`bash ~/secure-gateway/tunnel.sh COMANDO` sem link ou PATH.

## Comandos

```bash
tunnel up
tunnel status
tunnel check
tunnel logs --tail 50
tunnel logs --tail 50 --follow
tunnel down
tunnel restart
```

- up garante HAProxy e gateway iniciados e roda check, com tentativas curtas para
  aguardar a abertura dos listeners. Nao instala dependencias nem renova politicas.
- down para somente gateway-poc-https. HAProxy e preservado por poder ser compartilhado.
- status mostra as duas unidades; se alguma estiver parada, systemctl pode retornar
  codigo diferente de zero. check retorna falha para servico/entrada TLS/validade ruins.
- logs mostra o journal do gateway; --follow/-f acompanha ate Ctrl+C.
- restart reinicia o gateway e verifica; sessoes em andamento sao interrompidas.

check usa HTTPS validado na entrada do agente via HAProxy:443 (403 esperado sem
assinatura), na entrada Maven (401 sem token) e no PAC (200). Mostra validade das
politicas e metadados dos clientes, sem tokens ou hashes. Nao testa GitLab/Artifactory
atraves do agente: para isso use tunnel check no Windows restrito e os testes do cliente.
--config permite indicar o MESMO arquivo usado pela unidade; default:
/etc/gateway-poc-https/config.json. --agent-host ajusta o SNI do agente, se necessario.

## Rotacionar um cliente e renovar o perfil por 720 horas

```bash
tunnel rotate-client-token --client-id intermediario-01 --hours 720
```

Default se omitir --hours: 24. Maximo: 720. O cliente precisa existir e estar enabled;
clientes revogados nao sao reativados. --out permite escolher uma pasta NOVA; default
privado em /etc/gateway-poc-https/rotations. A mesma pasta nao e sobrescrita.

A operacao renova as politicas dos servicos fixos JA habilitados, preserva os limites
de trafego, troca somente o token do cliente escolhido e preserva seu escopo. Tokens
e revogacoes dos outros clientes nao mudam. A aprovacao corporativa continua pending.
Reinicia o gateway e roda check antes de mostrar:

- CLIENT_ID e EXPIRES_UTC;
- CLIENT_TOKEN: novo segredo, somente para o intermediario cliente;
- BUNDLE: diretorio privado com os arquivos de politica;
- WINDOWS_AGENT_POLICY_JSON: politica publica, sem token, para o Windows restrito;
- WINDOWS_COMMAND: na linha seguinte, comando pronto para colar no Windows.

Copie a linha que comeca com `tunnel rotate-client-token -PolicyJsonBase64 ...` para
o Windows restrito. Base64 so protege a integridade das aspas no CMD, nao criptografa;
o conteudo e a politica sem segredos. Nunca encaminhe CLIENT_TOKEN ao agente.

O token e mostrado porque esta e uma acao administrativa explicitamente solicitada;
nao e escrito no journal pelo wrapper. Nao compartilhe a saida completa, screenshot
ou gravacao do terminal. O gateway continua armazenando somente o hash no config;
o segredo existe no pacote privado para distribuicao ao cliente.

ROTATION_BUNDLE informa a pasta planejada antes da alteracao, para localizar os
arquivos se uma etapa posterior falhar. Se o reinicio/check falhar, o comando retorna
erro antes de mostrar o segredo.
Confira status/logs e o backup config.json.before-homologation-*; nao repita a
rotacao automaticamente. O token antigo deixa de valer ao carregar a nova configuracao.

No cliente intermediario, atualize a credencial do proxy Git/Edge e a variavel
SECURE_GATEWAY_TOKEN do Maven. Para proxy local, transfira client-policy.json e
client.token e aplique normalmente. Nao e necessario instalar esse wrapper AWS no WSL.

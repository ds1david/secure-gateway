# Correcoes do transporte Git e sincronizacao de mensagens

O registro global de sessoes mantinha seu lock durante recv/sendall. Com varias
sessoes, leituras lentas serializavam poll, check e outras trocas, podendo causar
timeouts do canal HTTPS. A troca agora usa um lock por sessao; sequencia e limites
continuam validados e o registro global permanece protegido.

Teste de regressao: tests/test_exchange_concurrency.py bloqueia uma leitura e
verifica que outra consulta de trabalho continua disponivel e que a resposta final
nao e perdida. A reproducao usa apenas sockets ficticios, sem servicos corporativos.

## Atualizacao na AWS (Linux)

```bash
git -C ~/secure-gateway pull --ff-only
sudo install -o root -g root -m 0644 ~/secure-gateway/{https_poc.py,stream.py} /opt/gateway-poc-https/
sudo systemctl restart gateway-poc-https
sudo systemctl status gateway-poc-https --no-pager
sudo journalctl -u gateway-poc-https -f -o short-iso
```

O restart encerra sessoes em andamento. Nao e necessario renovar tokens ou
certificados, alterar HAProxy, nem atualizar o agente para a correcao de concorrencia isoladamente.
Para a correcao temporal abaixo, atualize tambem o agente.

## Homologacao no cliente (WSL)

```bash
for n in 1 2 3 4 5; do
  date -u
  time git ls-remote origin HEAD || break
done
git push -u origin doc/CA02-2294
```

Confira o hash com git ls-remote --heads origin refs/heads/doc/CA02-2294 antes
de excluir qualquer branch antiga. Se persistir a falha, correlacione o horario
UTC com os logs AWS e tunnel logs -Tail 100 -Follow no Windows restrito.
A correcao remove um defeito comprovado em laboratorio; o funcionamento no
ambiente corporativo depende da homologacao acima.

## Tolerancia temporal do canal assinado

O agente e o gateway usam a mesma funcao decode. iat e nbf podem estar ate cinco
segundos no futuro em relacao ao receptor. Esses campos continuam obrigatorios
e inteiros. A verificacao desses dois campos e feita explicitamente depois da
assinatura, em vez da comparacao estrita padrao da biblioteca JWT. exp continua
validado sem tolerancia pela biblioteca. A duracao declarada maxima permanece
30 segundos, com emissor, audiencia, binding da resposta e replay preservados.
A validade do token do cliente e das autorizacoes de servico nao foi alterada.

Testes em tests/test_message_clock.py cobrem a margem inclusiva de cinco segundos,
rejeicao em seis segundos, expiracao sem grace period, tipos, duracao, identidade,
audiencia, campo obrigatorio, replay e diagnosticos distintos de sessao.

Atualize primeiro a AWS com os comandos acima. No Windows restrito (PowerShell):

```powershell
Set-Location C:\Users\david_rogerio\tools\secure-gateway
git pull --ff-only
if ($LASTEXITCODE -ne 0) { throw 'Falha ao atualizar o repositorio' }
tunnel restart
tunnel status
tunnel check
tunnel logs -Tail 40
```

Nao e necessario instalar dependencias novas nem trocar certificados/tokens.
Use o restart para carregar o codigo novo no processo em segundo plano. Os dois
restarts interrompem sessoes ativas. O cliente WSL nao precisa atualizar codigo.
Somente as novas entradas de log devem ser consideradas na verificacao.

Novos codigos na AWS: session_not_found, session_closed,
exchange_sequence_invalid, exchange_invalid e agent_rate_limited. Esses codigos
nao registram o conteudo da mensagem nem segredos. Fora da margem temporal, o
agente continua registrando application_message_not_yet_valid; nesse caso,
investigue a sincronizacao dos relogios em vez de aumentar a tolerancia.

## Upload Git: propriedade exclusiva dos sockets

O relay anterior usava duas threads que podiam fazer recv e sendall no mesmo
SSLSocket ao mesmo tempo. EOF em uma thread tambem sinalizava parada global,
antes de garantir o termino da resposta no sentido oposto. O relay agora usa
um unico fluxo com select e verificacao de pending TLS; mantem limites de tempo,
bytes e inatividade, e suporta half-close TCP para receber a resposta final.
A escrita tem prazo proprio limitado, separado da consulta curta de leitura.

A atualizacao AWS precisa copiar AMBOS https_poc.py e stream.py (comando acima).
Se a correcao temporal anterior ja esta nos dois ambientes, apenas a AWS precisa
de restart para o proxy externo; o cliente WSL nao executa relay local neste modo.
Nao e necessario trocar token, CA ou certificado. Atualize tambem qualquer cliente
que execute o proxy Python local, se esse modo estiver em uso.

tests/test_stream_relay.py cobre acesso exclusivo, resposta depois de half-close
e diagnosticos sem dados sensiveis. O teste de exclusividade falha com a versao
anterior e passa com a correcao. O teste Git smart HTTP em tests/test_https.py
cria um repositorio bare descartavel e envia 80 KB aleatorios atraves do agente,
proxy TLS e origem TLS, verificando o hash publicado. Ele tambem passou antes da
correcao com capacidade suficiente: nao reproduziu exatamente a falha corporativa.
O teste usa somente endpoints locais e credenciais ficticias.

Em caso de nova falha, proxy_transport_error registra stage (relay_read,
relay_write ou relay_wait), direction, errno e tls_reason quando disponiveis.
Nao registra texto da excecao, payload, senha ou token. Correlacione os horarios
com external_proxy_finished e https_session_finished. A causa especifica no
ambiente corporativo ainda depende da homologacao depois do deploy.

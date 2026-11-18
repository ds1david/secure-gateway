# Correcao de concorrencia do transporte Git

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
sudo install -o root -g root -m 0644 ~/secure-gateway/https_poc.py /opt/gateway-poc-https/https_poc.py
sudo systemctl restart gateway-poc-https
sudo systemctl status gateway-poc-https --no-pager
sudo journalctl -u gateway-poc-https -f -o short-iso
```

O restart encerra sessoes em andamento. Nao e necessario renovar tokens ou
certificados, alterar HAProxy, nem atualizar o agente para esta correcao.

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

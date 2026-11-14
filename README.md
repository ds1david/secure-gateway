# Secure Gateway

Repositorio oficial: [ds1david/secure-gateway](https://github.com/ds1david/secure-gateway).
Gateway e agente Python para uma POC controlada, com identidade por agente, tokens
por cliente, TLS, destinos fixos, auditoria sem segredos e limites de trafego.

- [Migrar EC2, Windows restrito e WSL do repositorio antigo](MIGRATION.md).
- [Proxy HTTPS direto na AWS para Git e Edge](gateway-poc/EXTERNAL-PROXY.md).
- [Homologacao temporaria, renovacao e tokens](gateway-poc/HOMOLOGATION.md).
- [Instalacao inicial na EC2](gateway-poc/deploy/INSTALL-HTTPS-EC2.md).
- [Laboratorio sintetico e arquitetura anterior](gateway-poc/README.md).

O projeto continua em `gateway-poc/`. Ferramentas auxiliares ficam em `tools/`.
Nao ha certificados, tokens, arquivos privados nem historico do repositorio anterior
nesta migracao. Credenciais operacionais devem ser transferidas por canal aprovado.

O proxy externo e opcional e vem desativado. O agente continua necessario no Windows
restrito. TLS do GitLab e autenticacao corporativa permanecem independentes do token
do gateway; indisponibilidade de LDAP/SSO nao e corrigida pelo proxy.

O perfil de homologacao dura ate 24 horas e registra aprovacao corporativa pendente.
Os testes usam apenas servicos ficticios locais; nao comprovam homologacao corporativa.

## Testar

```bash
cd gateway-poc
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements-https.txt
.venv/bin/python -m unittest discover -s tests -v
```

Os testes de certificados precisam de OpenSSL; no Windows tambem procuram o OpenSSL
do Git. O teste de TLS dentro de CONNECT valida o certificado da origem por uma
segunda sessao TLS, encapsulada no TLS do proxy, usando a biblioteca padrao.

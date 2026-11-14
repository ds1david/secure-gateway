# Secure Gateway

Repositorio oficial: [ds1david/secure-gateway](https://github.com/ds1david/secure-gateway).
Workspace de desenvolvimento: `C:\Users\david.oliveira2\projects\windows\secure-gateway`.

Codigo, launchers e dependencias ficam diretamente na raiz do repositorio.
Ferramentas auxiliares ficam em `tools/`, testes em `tests/` e unidades em `deploy/`.

| Ambiente | Execucao |
| --- | --- |
| Windows restrito | PowerShell + Python: agente com preflight e inicio em segundo plano |
| Windows intermediario | WSL Linux: Git/Maven e cliente/proxy local opcional |
| aws-frp | Linux: gateway, proxy HTTPS externo e administracao de tokens |

- [Operacao nos tres ambientes](OPERATIONS.md).
- [Atualizar instalacoes com a estrutura anterior](MIGRATION.md).
- [Proxy HTTPS externo para Git e Edge](EXTERNAL-PROXY.md).
- [Homologacao, tokens e renovacao](HOMOLOGATION.md).
- [Primeira instalacao na EC2](deploy/INSTALL-HTTPS-EC2.md).
- [Laboratorio sintetico e transporte anterior](LAB.md).

O proxy externo e opcional e vem desativado. O agente continua necessario no Windows
restrito. Autenticacao GitLab/LDAP/SSO permanece independente do token do gateway.
O perfil de homologacao dura ate 24 horas e registra aprovacao corporativa pendente.
Nao publique certificados, tokens, bundles, backups, logs ou configuracoes privadas.

## Testar na raiz do clone

Linux/WSL:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements-https.txt
.venv/bin/python -m unittest discover -s tests -v
```

PowerShell:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements-https.txt
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
```

Os testes de certificados precisam de OpenSSL; no Windows tambem procuram o OpenSSL
do Git. Todos os destinos usados nos testes sao ficticios e locais.

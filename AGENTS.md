# Workspace e convencoes

- Repositorio oficial: https://github.com/ds1david/secure-gateway.
- Workspace Windows oficial: C:\Users\david.oliveira2\projects\windows\secure-gateway.
- Trabalhe neste clone. Nao altere os clones anteriores em ds1david ou Documents/ChatGPT.
- Codigo Python e launchers ficam na raiz; deploy/, tests/ e tools/ sao pastas auxiliares.
- Windows restrito usa PowerShell e Python; intermediario usa WSL Linux; aws-frp usa Linux.
- Execute testes da raiz: python -m unittest discover -s tests -v, com as dependencias
  de requirements-https.txt. Testes de TLS usam OpenSSL e servicos ficticios locais.
- Preserve os caminhos operacionais e nomes de servico existentes na EC2:
  /opt/gateway-poc-https, /etc/gateway-poc-https, /var/lib/gateway-poc-https,
  gateway-poc-https.service e usuario gateway-poc. Eles nao sao pastas do repositorio.
- Administracao de tokens e feita no aws-frp. O agente nao recebe o token do cliente.
- Nunca versionar tokens, certificados, chaves, bundles, arquivos de transferencia,
  logs, bancos de replay ou configuracoes operacionais. Nao desligue validacao TLS.
- Nao implemente ocultacao do agente ou contorno de controles corporativos.

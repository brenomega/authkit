# Instalação do golden path

[English](INSTALL.md) | [Português (Brasil)](INSTALL-ptBR.md)

O inglês é autoritativo quando houver divergência de tradução.

Este procedimento instala a topologia v0.1 suportada de instância única: AuthKit, PostgreSQL 17, Redis 7.4 autenticado e Caddy terminando TLS. Use um host Linux limpo com Docker Engine e Compose v2, DNS para o host público, certificado TLS válido, conta SMTP que exija TLS e templates de e-mail escritos pelo operador. Não exponha PostgreSQL, Redis nem a porta 8080 do AuthKit.

## 1. Preparar a configuração

Copie `deploy/golden/.env.example` para `deploy/golden/.env` e substitua todos os exemplos. Origins são origins HTTPS exatas, sem wildcards. O issuer deriva de `AUTHKIT_PUBLIC_HOST` e deve permanecer estável. Mantenha o registro como `restricted` até que signup público seja uma decisão intencional do operador.

A rede interna golden reserva `172.30.0.10` para o Caddy e `172.30.0.20` para o worker/load runner autenticado separadamente. Mantenha `AUTHKIT_WORKER_TRUSTED_ORIGINS=172.30.0.20/32`; nunca confie no Caddy nem em `172.30.0.0/24`. O worker deve entrar na rede Compose `internal` com endereço `.20` e enviar `X-Worker-Token`. O Caddy deliberadamente não roteia `/api/v1/internal/**` nem `/actuator/prometheus`, portanto nem cliente público nem proxy satisfazem o fator de rede.

Crie o diretório definido por `AUTHKIT_SECRETS_DIRECTORY`. Siga `deploy/golden/secrets/README.md`; no Compose local use modo `0700` no diretório e `0444` nos secrets read-only, valores aleatórios independentes, par RSA de pelo menos 2048 bits e certificado que cubra o host público. Nunca reutilize a senha do owner Flyway no runtime ou na retenção. `email_provider_credential` é a senha SMTP por padrão; com `AUTHKIT_EMAIL_PROVIDER_TYPE=resend`, ele contém a API key Resend e host/usuário SMTP podem ficar vazios. SMTP só é suportado quando o relay escolhido passou pelo drill documentado de crash/reclaim e deduplica reenvios pelo `Message-ID` RFC 5322 estável do AuthKit; após preservar essa evidência do provider, configure `AUTHKIT_SMTP_DEDUPLICATION_GUARANTEED=true`. O startup de produção falha enquanto o valor estiver falso ou omitido.

Crie os 14 arquivos exigidos pelo [contrato de templates](EMAIL_TEMPLATES-ptBR.md) no diretório absoluto definido por `AUTHKIT_EMAIL_TEMPLATES_DIRECTORY`. O AuthKit deliberadamente não fornece texto, localização, HTML ou branding de produção.

Valide antes de iniciar:

Execute o preflight público e depois a validação do Compose. O Compose seleciona um arquivo versionado de modo de cadastro; valor omitido ou diferente de `public`/`restricted` falha na configuração em vez de escolher default silencioso.

```sh
deploy/scripts/preflight-config.sh deploy/golden/.env
docker compose --env-file deploy/golden/.env -f deploy/golden/compose.yml config -q
```

## 2. Construir e iniciar

Até existir um digest de imagem auditado de forma independente, faça o build local da árvore revisada:

```sh
docker compose --env-file deploy/golden/.env -f deploy/golden/compose.yml build authkit
docker compose --env-file deploy/golden/.env -f deploy/golden/compose.yml up -d
docker compose --env-file deploy/golden/.env -f deploy/golden/compose.yml ps
```

A primeira inicialização cria logins separados de owner, runtime e retenção. O Flyway aplica migrations como owner; requests normais usam `authkit_app`; a retenção apaga auditoria somente por funções restritas e auditadas.

Valide através de TLS, nunca contornando o Caddy:

```sh
curl --fail --silent --show-error https://AUTHKIT_PUBLIC_HOST/actuator/health
curl --fail --silent --show-error https://AUTHKIT_PUBLIC_HOST/.well-known/openid-configuration
```

## 3. Criar o primeiro administrador

Crie um JSON local temporário com modo `0600`; ao contrário dos secrets montados no container, ele permanece no host e é lido por stdin. Ele é secreto porque contém a senha inicial:

```json
{
  "email": "admin@example.com",
  "password": "substitua-por-uma-senha-forte-e-unica",
  "name": "Administrador Inicial",
  "termsAccepted": true,
  "privacyPolicyAccepted": true
}
```

Forneça por stdin, não como argumento:

```sh
docker compose --env-file deploy/golden/.env -f deploy/golden/compose.yml run --rm -T authkit bootstrap-admin < /caminho/local/seguro/bootstrap-admin.json
```

O comando é não HTTP, trava um guard singleton no banco, cria um `PLATFORM_ADMIN` verificado, registra auditoria crítica síncrona e rejeita repetições. Elimine o arquivo local pelo processo recuperável de descarte de segredos do host. Faça login e cadastre TOTP ou passkey imediatamente; mutações administrativas ficam bloqueadas até existir segundo fator local e cada mutação apresentar senha recente mais TOTP ou autenticação recente por passkey.

## 4. Checklist de aceite

- Certificado e hostname TLS são válidos; portas do backend não são acessíveis externamente.
- O TLS público retorna `404` para paths internos/Prometheus mesmo com token worker válido; na rede interna, somente rede e somente token falham, enquanto `.20` mais token passa.
- Modo de registro, versões legais, origins CORS exatas, RP de passkey, issuer, audience e UI de autorização foram aprovados pelo operador.
- STARTTLS SMTP está habilitado e obrigatório; registre aceitação real do provider e observação separada da inbox. `ACCEPTED` nunca significa entrega na inbox.
- Registro/confirmação/login/refresh/logout funciona; replays de confirmação e refresh antigo falham.
- Backups PostgreSQL/Redis são criptografados e off-host; restauração em host limpo ocorre antes do lançamento.
- Routing de alertas, retenção, worker token, rotação de assinatura, falha de provider, Redis fail-closed e rollback foram exercitados com o [guia operacional](OPERATIONS-ptBR.md).

`docker compose down` preserva os volumes nomeados. `down -v` destrói dados e não faz parte da operação rotineira.

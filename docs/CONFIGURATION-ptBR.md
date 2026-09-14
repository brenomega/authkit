# Referência de configuração

[English](CONFIGURATION.md) | [Português (Brasil)](CONFIGURATION-ptBR.md)

O inglês é autoritativo quando houver divergência de tradução.

A referência canônica por variável (propósito, default/condição obrigatória, validação, exemplo e fonte) está em [Environment variables](reference/ENVIRONMENT_VARIABLES.md).

`deploy/golden/compose.yml`, `deploy/golden/.env.example`, `src/main/resources/application.yml` e `application-prod.yml` são as fontes legíveis por máquina. Esta página define o significado operacional; segredos usam variáveis `*_FILE` montadas e suportadas por `docker/entrypoint.sh`.

| Área | Configuração golden obrigatória | Contrato |
| --- | --- | --- |
| Identidade pública | host, issuer, audience e key ID | Issuer HTTPS estável; audience/key ID explícitos; chaves RSA read-only. |
| Banco | `DB_*`, `SPRING_FLYWAY_*`, `AUTH_RETENTION_DB_*` | PostgreSQL 17 e credenciais distintas de owner/runtime/retenção. |
| Redis | `REDIS_*`, backend `redis` | Redis 7 autenticado; obrigatório no golden path e em high-risk fail-closed. |
| Browser | URLs frontend, origins CORS exatas, cookie seguro e CSRF | Somente origins HTTPS em produção; sem wildcard com credenciais. |
| Tokens | access TTL de 300 s | Máximo recomendado de cinco minutos; refresh opaco, rotativo e familiar. |
| Registro/legal | modo, versões legais e base legal | `public` ou `restricted` explícito; decisões jurídicas pertencem ao operador. |
| E-mail | outbox direto, provider, remetente, credenciais e diretório de templates | SMTP TLS é o padrão neutro; templates externos são obrigatórios. |
| Senha | HIBP habilitado e concorrência Argon2 | HIBP e Argon2 limitado são obrigatórios no golden path. |
| Passkeys | RP ID/nome e origins exatas | RP ID deve corresponder ao domínio; portas em origin não são aceitas em produção. |
| OAuth/social | UI de autorização; social opt-in e providers administrativos | Issuers Google/OIDC são allowlist exata; segredos ficam criptografados. |
| Proxy | `NETWORK_SECURITY_TRUSTED_ORIGINS` para CIDRs de proxy confiável, XFF depth 1 e forwarding Spring desabilitado | Headers forwarded só são aceitos do peer Caddy fixo. O Compose golden fixa `172.30.0.10/32`. |
| Auditoria/retenção | pepper HMAC, job e login restrito | Falha crítica aborta a mutação; retenção é limitada e separada. |
| Introspecção interna | worker token e `NETWORK_SECURITY_WORKER_TRUSTED_ORIGINS` independente (`AUTHKIT_WORKER_TRUSTED_ORIGINS=172.30.0.20/32` no Compose golden) | Credencial network-bound e rotativa. `.10` é o Caddy e nunca deve ser confiado; não reutilize a faixa do proxy, toda a subnet interna, nem exponha paths internos. |

A validação de produção falha o startup diante de placeholders, segredos ausentes/fracos, URLs públicas HTTP, modo de registro ausente, CORS/proxy inseguro, SMTP sem TLS, templates ausentes, TTL acima de 300 segundos, HIBP desabilitado, Redis ausente ou retenção sem separação. Nunca forneça segredos como argumentos CLI ou em `.env` commitado.

Resend usa `AUTH_EMAIL_PROVIDER_TYPE=resend` e `RESEND_API_KEY_FILE`; SMTP usa `smtp`. RabbitMQ e token storage JDBC são previews sem suporte, excluídos das instruções de produção.

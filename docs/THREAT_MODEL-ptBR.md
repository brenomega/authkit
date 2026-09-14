# Modelo de ameaças

[English](THREAT_MODEL.md) | [Português (Brasil)](THREAT_MODEL-ptBR.md)

O inglês é autoritativo quando houver divergência de tradução.

## Escopo e fronteiras de confiança

Os ativos protegidos são identidades, autenticadores, linhagens de tokens first-party e OAuth, evidência de consentimento/auditoria, chaves de assinatura e criptografia, estado de cerimônias de email e disponibilidade operacional. As fronteiras são proxy TLS público, browser/cookie/CSRF, clientes OAuth e resource servers, provedores OIDC sociais, SMTP/Resend, rede interna mais worker token, PostgreSQL, Redis e supply chain de release.

## Adversários, controles e risco residual

| Ameaça / adversário | Hipótese ou caso de abuso | Controles preventivos e detectivos | Risco residual / ação operacional |
|---|---|---|---|
| Credential stuffing e DoS de senha | Atacante remoto tem corpus de email/senha ou envia inputs caros | Corpo limitado, semáforo Argon2, limites por IP/device/email, lockout, HIBP, métricas | Limites distribuídos dependem de Redis; paths high-risk falham fechados e aplica-se o runbook de dependência. |
| Roubo de sessão ou refresh | Bearer/cookie é copiado ou repetido | Cookie HttpOnly Secure Strict, CSRF, rotação/family revocation, estado live JTI, access TTL curto | Access token permanece válido até TTL salvo rejeição por estado de conta/sessão; investigar reuse imediatamente. |
| Substituição entre classes de token | JWT OAuth, ID ou first-party é apresentado na fronteira errada | `token_use` exato, uma audiência exata, claims obrigatórios, decoder por endpoint, estado live de sessão/family | Downstream precisa validar a mesma classe e atualizar JWKS diante de `kid` desconhecido. |
| Ataque a redirect/code OAuth | Cliente malicioso altera redirect, PKCE, state ou nonce | Redirect registrado exato sem fragmento, PKCE S256, code/transação one-time, state obrigatório e nonce OIDC | Origem de cliente comprometida pode abusar da própria autorização; revogar o cliente. |
| Acesso a dados de outro tenant | Tenant autenticado tenta identificadores cross-tenant | Filtro Hibernate tipado UUID, checagens explícitas, not-found opaco, separação de platform admin | Platform admins são globais por design e exigem step-up local mais segundo fator. |
| Criação/link social indevido | Subject federado colide com email local ou contorna cadastro restricted | Issuer+subject imutáveis, sem auto-link por email, link com step-up explícito, policy de cadastro em toda identidade nova | Segurança depende da integridade do issuer e da allowlist configurada. |
| Corrida/replay de cerimônia one-time | Confirmação, recovery, TOTP, passkey, OAuth ou email-change concorrentes | Row locks/transições condicionais, estado hasheado, expiração e testes concorrentes em stores reais | Falha de disponibilidade pode negar tentativa válida; nunca pode produzir dois vencedores. |
| Supressão de audit ou rollback cross-store | Falha DB/Redis entre mutação, audit e revogação | Audit crítico participa da transação SQL; revogação externa após commit; recovery só ativa token após outbox durável | Falha de cleanup pós-commit exige reconciliação e alerta; estado live no DB permanece autoritativo. |
| Email duplicado ou token vazado | Crash após aceite do provider; URL vaza por query/referrer | Identidade de outbox, idempotência provider ou Message-ID SMTP estável/dedupe, token em fragmento, sem segredo em log | Relay SMTP precisa demonstrar dedupe na janela de reclaim; fora disso email é at-least-once. |
| Comprometimento de worker interno | Caller da internet obtém token ou forja headers de proxy | Proxy público não roteia interno/Prometheus; rede confiável e token são independentes; forwarded headers reconstruídos | Comprometer rede interna e token atual concede acesso; rotacionar e investigar. |
| Comprometimento de chave/supply chain | Chave antiga segue ativa, artefato é substituído ou segredo entra no source | Conjuntos current/retiring/revoked, rejeição de unknown kid, SBOM, checksum, assinatura, provenance e scans | Operador protege chaves e conclui rotações; seguir runbook de rotação. |
| Exaustão de recursos | Corpos oversized/chunked, hostile bursts, esgotamento de pool | Limite streaming inclusive DELETE, timeouts, rate limits, métricas pool/Argon2, gate em 2 vCPU/4 GiB | Saturação sustentada causa perda fail-closed; planejar capacidade pelo baseline medido. |

Consulte [modelo de segurança](SECURITY_MODEL-ptBR.md), [rastreabilidade](TRACEABILITY-ptBR.md) e os [runbooks](runbooks/health-readiness.md).

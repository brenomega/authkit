# Rastreabilidade dos requisitos da v0.1

[English — normativo](TRACEABILITY.md)

Esta matriz pública relaciona cada achado da auditoria independente ao contrato implementado e à evidência. O histórico detalhado de comandos/arquivos fica em `docs/release/IMPLEMENTATION_MATRIX.md`; a disposição operacional obrigatória fica em `docs/release/RELEASE_GATES-ptBR.md`. `IMPLEMENTADO` não substitui prova externa nem auditoria final.

| ID | Disposição normativa | Implementação/migration principal | Teste ou prova | Estado |
| --- | --- | --- | --- | --- |
| AK-001 | RP Google/OIDC genérico permitido; state/nonce/PKCE; `(issuer, subject)`; sem auto-link por e-mail; link/unlink explícito; descarte de tokens | Controllers/services/clients sociais; V20 | Testes social-only, linking, issuer e concorrência one-time; providers reais pendentes | IMPLEMENTADO; PROVA EXTERNA PENDENTE |
| AK-002 | Mudança segura de e-mail com request/confirm/cancel, aviso ao antigo e revogação | `EmailChangeService`; V17 | Testes positivos, replay, colisão e vencedor concorrente | VERIFICADO LOCALMENTE |
| AK-003 | ACTIVE/SUSPENDED/DELETION_PENDING e anonimização irreversível; suspender/reativar completos | Lifecycle/admin; V15–V16 | Testes de estado, autoridade, auditoria e migration | VERIFICADO LOCALMENTE |
| AK-004 | Carência 0–30 dias (padrão 7), cancelamento, anonymize/purge idempotentes | Lifecycle/anonymization; V15–V18 | Limites, retry, cancelamento e permissão de purge | VERIFICADO LOCALMENTE |
| AK-005 | USER/PLATFORM_ADMIN; migração segura; último admin; `tenant_id` pessoal; clients globais | Segurança/admin/tenant; V15 | Migrations fresh/upgrade, trigger DB e regressão do filtro admin | VERIFICADO LOCALMENTE |
| AK-006 | Senha nullable para conta social-only | User/auth; V15 | Testes de entidade/login/social e PostgreSQL | VERIFICADO LOCALMENTE |
| AK-007 | Registro public/restricted explícito | Registration/validator | Dois modos e fail-fast prod | VERIFICADO LOCALMENTE |
| AK-008 | GET authorize convencional, redirect exato, erros padrão, Code+PKCE S256/state/nonce | OAuth; V21 | Transação browser, redirect e PKCE | VERIFICADO LOCALMENTE; CONFORMANCE PENDENTE |
| AK-009 | Refresh OAuth opaco/rotativo por família; replay revoga família | OAuth; V21 | Rotação serial/concorrente e replay | VERIFICADO LOCALMENTE |
| AK-010 | Userinfo/introspection/revocation padrão; chains/classes corretas; discovery/JWKS/ID token | OAuth/security | Wire, audience, autenticação, revogação e classes | VERIFICADO LOCALMENTE; CLIENTE EXTERNO PENDENTE |
| AK-011 | Transação login/consent assinada, expirável, retomável e one-time | Codec/service OAuth; V21 | Inspect/approve/deny/replay/rollback de audit | VERIFICADO LOCALMENTE |
| AK-012 | Bootstrap admin offline one-shot e plano PLATFORM_ADMIN completo com step-up | Bootstrap/admin; V25 | Singleton, rejeição, rollback, cursor/sessão/admin e drill CLI golden limpo | VERIFICADO LOCALMENTE |
| AK-013 | Metadados seguros, lastSeen limitado, introspecção autenticada e revogação imediata | Session/storage/introspection; V19 | Redis 7/JDBC, paginação, throttle e HTTP | VERIFICADO LOCALMENTE |
| AK-014 | Recovery/storage one-time atômico com commit/retry/compensação | Redis Lua/JDBC/services; V17 | Fault injection e lifecycle real Redis/PG | VERIFICADO LOCALMENTE |
| AK-015 | Confirmação/estados one-time seguros em concorrência | Locks registration/email-change | Barriers com um vencedor exato | VERIFICADO LOCALMENTE |
| AK-016 | Templates externos obrigatórios, renderer restrito, fragmento seguro e aceitação/retry honesto | Email/outbox; V22 | Traversal/variáveis/timing e SMTP local | VERIFICADO LOCALMENTE; SMTP/RESEND REAL PENDENTE |
| AK-017 | Audit crítico síncrono/transacional aborta mutação | Eventos/audit | Fault injection com rollback | VERIFICADO LOCALMENTE |
| AK-018 | Role/processo de retention separado com purge auditado | Retention gateway; V18/V23 | Permissões reais PostgreSQL e purge log | VERIFICADO LOCALMENTE |
| AK-019 | Rejeitar `token_use` ausente/ambíguo e separar classes | Política JWT | Fixtures/decoder negativos | VERIFICADO LOCALMENTE |
| AK-020 | Sem perfil/chave de teste em artefatos/contexto | Maven/Docker/harness | Inspeção JAR/contexto/imagem local final | VERIFICADO LOCALMENTE |
| AK-021 | Counter passkey monotônico concorrente; step-up/último autenticador | Passkey/social/MFA; V16/V20 | CAS/replay/concorrência/remoção | VERIFICADO LOCALMENTE; CERIMÔNIA REAL PENDENTE |
| AK-022 | Export versionado completo sem secrets | Profile/export | Fixture completa/redaction, step-up e audit | VERIFICADO LOCALMENTE |
| AK-023 | Prod canônico e Compose AuthKit+PG17+Redis7+TLS hardened com secrets | Prod/golden; V23 | Instalação V1→V25, TLS, bootstrap e fluxo manual | VERIFICADO LOCALMENTE; OPERADOR INDEPENDENTE PENDENTE |
| AK-024 | Retry-After, duplicatas, JSON estrito, CORS HTTPS, peers confiáveis e Redis fail-closed | Filtros/config edge | HTTP negativo, spoof/depth e falhas | VERIFICADO LOCALMENTE |
| AK-025 | OpenAPI semântico, schemas/validação/headers/exemplos/erros/paginação e requestId | OpenAPI/respostas | Contrato semântico e correlação manual | VERIFICADO LOCALMENTE |
| AK-026 | Matriz negativa/concorrente/one-time completa | Suítes transversais | Suíte final 289/289, PG17/Redis7 reais e negativos manuais | VERIFICADO LOCALMENTE |
| AK-027 | Provas reais TLS/providers/client/JWKS | Instruções/harnesses reproduzíveis | TLS/sample local passou; faltam providers/topologias públicas/conformance/rotação | PARCIAL LOCAL; PROVA EXTERNA PENDENTE |
| AK-028 | Backup/restore, falhas, alertas/runbook e carga/burst/soak 4h | Operação/harnesses | Restores em containers limpos e falhas locais passaram; faltam off-host/host limpo, alertas e soak 4h | PARCIAL LOCAL; PROVA EXTERNA PENDENTE |
| AK-029 | Scans, OCI amd64/arm64, SBOM, checksums, assinatura e provenance | CI/automação local | Faltam ferramentas/identidade do mantenedor | PARCIAL; NÃO COMPROVADO |
| AK-030 | Docs EN normativo/pt-BR integral e exemplos same/cross-site | Docs e `samples/` | Testes sample, sintaxe JS e scan de links/pares passam | VERIFICADO LOCALMENTE |
| AK-031 | Apache-2.0, políticas OSS, DCO/sem CLA, POM | Raiz/POM | Model/build Maven | VERIFICADO LOCALMENTE |
| AK-032 | Sem claims exagerados nem textos obsoletos de prompts/audits | Docs canônicas e limpeza absorvida | Scan passa; comentários V11/V12 retidos por checksum Flyway | VERIFICADO LOCALMENTE |
| AK-033 | Support matrix experimental/não suportado, honesto e opt-in | Matriz bilíngue/isolação | Defaults/regressão | IMPLEMENTADO |
| AK-034 | Prod Redis/direct/SMTP TLS/HIBP/fail-closed/TTL≤300; alternativa Resend | Config prod/golden | Validator/provider/Compose | VERIFICADO LOCALMENTE |
| AK-035 | Remover phone de modelo/DB/DTO/export/OpenAPI/docs | User/contracts; V15 | Compile/search/migração | VERIFICADO LOCALMENTE |
| AK-036 | Candidato coerente e evidência ligada a árvore/digest | `0.1.0-rc.1`, changelog/automação | Evidência local liga HEAD baseline, manifests da árvore e ID imutável; registry pendente | VERIFICADO LOCALMENTE; PROVA EXTERNA PENDENTE |
| AK-037 | `ACCEPTED` é aceitação do provider, nunca inbox | Outbox/provider; V22 | Migration/provider/linha SMTP local | VERIFICADO LOCALMENTE; PROVIDERS REAIS PENDENTES |

A release permanece `NO-GO` enquanto qualquer gate estiver `NÃO COMPROVADO` ou pendente e até uma nova auditoria independente não encontrar P0/P1 GA em aberto.

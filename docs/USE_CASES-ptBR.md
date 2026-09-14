# Catálogo de casos de uso AuthKit v0.1

[English](USE_CASES.md) | [Português (Brasil)](USE_CASES-ptBR.md)

O inglês é autoritativo quando houver divergência. Cada caso usa o template normativo: objetivo, atores, trigger, precondições, fluxo principal, fluxos de falha, pós-condições, propriedades de segurança, componentes, endpoints, estado e testes. O OpenAPI permanece o contrato exaustivo por operação; este catálogo agrupa operações em resultados ponta a ponta.

## UC-003 — Cadastrar uma conta local

- Objetivo: criar uma identidade local pertencente a um tenant sem enumeração de conta.
- Atores/trigger: browser anônimo envia o cadastro.
- Precondições: `registration.mode=public`, versões atuais das políticas aceitas, policy de senha e controles de abuso disponíveis.
- Fluxo principal: normalizar email; arbitrar unicidade; gerar hash da senha; registrar snapshot de consentimento; criar confirmação hasheada e mensagem durável no outbox; retornar o resultado público configurado.
- Fluxos de falha: modo restricted nega; duplicidade segue a policy stealth; falha de audit/outbox faz rollback; losers concorrentes nunca retornam 500.
- Pós-condições/segurança: um User, uma confirmação atual e um consent event; nenhum token bruto em SQL/logs.
- Componentes/endpoints/estado/testes: `RegistrationService`; `/api/v1/auth/register`, confirmação/resend; `users`, `consent_events`, `email_outbox`; operações Register do OpenAPI; provas de concorrência de cadastro e confirmação com um vencedor.

## UC-016 — Alterar o email principal com segurança

- Objetivo: transferir o identificador principal somente após step-up local e prova da nova mailbox.
- Atores/trigger: usuário autenticado solicita, confirma, substitui ou cancela uma cerimônia de mudança de email.
- Precondições: conta ativa confirmada, consentimento atual, senha e MFA quando habilitado.
- Fluxo principal: serializar no User, armazenar somente hash e expiração, enfileirar notificação, travar e consumir na confirmação, atualizar email normalizado único, revogar linhagens renováveis first-party e OAuth após commit.
- Fluxos de falha: email duplicado, token expirado/incorreto e corridas cancel-vs-confirm/request-vs-confirm têm um resultado terminal; falha de audit crítico faz rollback.
- Pós-condições/segurança: refresh families antigas falham; tokens de recovery anteriores/novos são revogados; endereço anterior recebe notificação.
- Componentes/endpoints/estado/testes: `EmailChangeService`, `OAuthLifecycleRevocationService`; `/api/v1/users/me/email-change`, `/api/v1/auth/email-change/confirm`; `users`, tabelas OAuth refresh, outbox/audit; testes de concorrência e lifecycle de email.

## UC-019 — Solicitar deleção de conta

- Objetivo: entrar no grace period de privacidade ou anonimizar imediatamente.
- Atores/trigger: usuário autenticado conclui step-up local e solicita deleção.
- Precondições: conta ativa confirmada, consentimento atual, controle distribuído de abuso high-risk e usuário não é o último platform admin ativo.
- Fluxo principal: travar o invariante global de admin e o User, persistir timestamp/estado e audit crítico, revogar estado OAuth em SQL, revogar sessões externas após commit.
- Fluxos de falha: falha de audit/SQL faz rollback; tentativa do último admin é negada; remoções administrativas concorrentes serializam.
- Pós-condições/segurança: deletion pending ou anonymized; escrita/autenticação negadas; identidade nunca é restaurada silenciosamente.
- Componentes/endpoints/estado/testes: `AccountLifecycleService`; `DELETE /api/v1/users/me`; `users`, social/OAuth/outbox/audit; matriz PostgreSQL de último admin e testes de lifecycle.

## UC-020 — Cancelar deleção antes do cutoff

- Objetivo: restaurar conta pendente somente enquanto o grace interval está aberto.
- Atores/trigger: platform admin com step-up local solicita cancelamento.
- Precondições: alvo travado em `DELETION_PENDING`; tempo atual estritamente anterior a requested-at mais grace.
- Fluxo principal/falhas: validar deadline sob o mesmo row lock da anonimização; cancelar e auditar antes do cutoff; negar no/depois do cutoff ou após anonimização.
- Pós-condições/segurança: exatamente um entre cancelamento e anonimização vence, e deleção expirada nunca termina ACTIVE.
- Componentes/endpoints/estado/testes: `AdminService`, `AccountAnonymizationService`; `DELETE /api/v1/admin/users/{userId}/deletion`; `users`, security events; prova de boundary e corrida.

## UC-028 — Detectar consentimento desatualizado

- Objetivo: expor versões aceitas/requeridas e uma decisão estável `consentRequired`.
- Atores/trigger: usuário autenticado lê consentimento após o operador elevar uma versão.
- Precondições: sessão first-party válida e viva.
- Fluxo/propriedades: comparar as duas versões exatas no servidor; permitir leitura enquanto a conta está limitada; nunca inferir atualidade apenas pelos booleanos.
- Componentes/endpoints/estado/testes: `AccountLifecycleService`, `UserAuthoritiesFilter`; `GET /api/v1/users/me/consent`; `users`, ledger de consentimento; prova full-context.

## UC-029 — Impor credencial limitada por consentimento

- Objetivo: impedir uma sessão com consentimento desatualizado de escrever, fazer refresh ou autorizar OAuth.
- Atores/trigger: conta desatualizada chama operação protegida.
- Fluxo/falhas: permitir somente leitura/aceite de consentimento e logout; retornar `consent_required` estável; perda de dependência falha indisponível; OAuth usa sua superfície protocolar.
- Pós-condições/segurança: nenhuma linhagem renovável ou authorization code é emitida antes do aceite.
- Componentes/endpoints/estado/testes: `UserAuthoritiesFilter`, `AuthService`, `OAuthProviderService`; APIs protegidas, refresh e authorize; integração HTTP/filter/service.

## UC-030 — Aceitar o consentimento atual

- Objetivo: aceitar atomicamente as versões exatas apresentadas pelo servidor.
- Atores/trigger: usuário autenticado limitado envia ambos reconhecimentos true e as versões exatas.
- Precondições: conta ativa confirmada e versões iguais à configuração atual.
- Fluxo principal/falhas: travar User; atualizar timestamp/versões/base legal; anexar consent e audit crítico; commitar e então invalidar cache de autoridade. Versões antigas retornam conflict; falha de audit faz rollback; chamadas concorrentes são idempotentes.
- Pós-condições/segurança: autorização normal retorna somente após commit durável.
- Componentes/endpoints/estado/testes: `POST /api/v1/users/me/consent`; `users`, `consent_events`, `security_events`; prova de rollback e aceite concorrente.

## UC-067 — Autenticar ou criar identidade social

- Objetivo: autenticar identidades imutáveis `(issuer, subject)` sem auto-link por email.
- Atores/trigger: browser anônimo conclui authorization-code/PKCE com Google ou OIDC genérico.
- Precondições: provider permitido/ativo, state/nonce/verifier one-time, issuer/assinatura/audience/email verificados.
- Fluxo principal: link existente autentica em todos os modos; subject novo cria User/consent/link somente no modo public.
- Fluxos de falha: nova identidade em restricted, colisão de email, replay de state, erro de provider ou falha ao persistir consentimento não criam identidade parcial.
- Componentes/endpoints/estado/testes: `SocialIdentityService`, `SocialOidcClient`; start/callback social; tabelas provider/transaction/identity/User/consent; integração PostgreSQL e prova com providers externos.

## UC-109 — Preservar o último platform admin

- Objetivo: garantir ao menos um platform admin ativo sob todas as corridas de remoção.
- Atores/trigger: admins rebaixam, suspendem ou removem admins distintos concorrentemente.
- Precondições: step-up de senha local mais TOTP ou passkey recente.
- Fluxo principal/falhas: cada remoção trava o mesmo conjunto ordenado de linhas de admins ativos, depois o alvo, e reconta; no máximo uma transação vence.
- Pós-condições/segurança: `active_admin_count >= 1` após demote/demote, suspend/suspend, delete/delete e todos os pares mistos.
- Componentes/endpoints/estado/testes: `AdminService`, `AccountLifecycleService`, `UserRepository`; operações de role/suspensão e deleção; matriz PostgreSQL 17 com barreira e seis pares.

## UC-137 — Autorizar worker interno

- Objetivo: exigir dois fatores independentes: rede interna confiável e worker token rotativo.
- Atores/trigger: worker de retenção/introspecção ou Prometheus acessa path interno.
- Fluxo principal/falhas: proxy TLS público retorna 404 independentemente do token; requisição interna direta falha com apenas rede ou apenas token e passa com ambos; uso do token anterior é medido na rotação limitada.
- Componentes/endpoints/estado/testes: Caddy, `WorkerAuthFilter`; `/api/v1/internal/**`, `/actuator/prometheus`; matriz de topologias pública/interna.

## UC-138 — Falhar controles de abuso high-risk de forma fechada

- Objetivo: impedir bypass de limite distribuído quando Redis está ausente.
- Atores/trigger: qualquer policy high-risk é avaliada durante perda do Redis no startup/runtime.
- Fluxo principal/falhas: todo membro `highRisk` do enum retorna dependency-unavailable e incrementa métricas fail-closed com tag de policy; somente operações explicitamente não high-risk usam fallback local.
- Componentes/endpoints/estado/testes: `AbuseThrottleService`, `AbuseRateLimitPolicy`; endpoints de autenticação, recovery, OAuth, admin e lifecycle; teste exaustivo do enum e parada/recuperação Redis.

## Matriz de rastreabilidade

| Caso de uso | Endpoint / contrato | Serviço | Persistência | Controle de segurança | Prova |
|---|---|---|---|---|---|
| UC-003 | Operações OpenAPI de cadastro/confirmação | RegistrationService | users, consent_events, email_outbox | unicidade, Argon2, token hasheado, stealth | concorrência de cadastro/confirmação |
| UC-016 | operações de email-change | EmailChangeService | users, OAuth refresh, outbox/audit | row lock, step-up local, revogação pós-commit | corrida de email + rejeição de family antiga |
| UC-019/020 | deleção/admin deletion | AccountLifecycleService/AdminService | users, social/OAuth/audit | locks agregado+row, step-up, cutoff estrito | corrida mista PostgreSQL + boundary temporal |
| UC-028/029/030 | consent GET/POST, refresh, authorize | AccountLifecycle/Auth/OAuth | users, consent/audit | versões exatas, credencial limitada, audit crítico | full-context, rollback, aceite concorrente |
| UC-067 | social start/callback | SocialIdentityService | tabelas social, users, consent | OIDC, subject imutável, policy de cadastro | PostgreSQL + Google/OIDC externo |
| UC-109 | admin role/suspensão, deleção | Admin/AccountLifecycle | users, security_events | lock global, step-up, segundo fator | matriz de seis pares PostgreSQL 17 |
| UC-137 | interno/Prometheus | WorkerAuthFilter + Caddy | metrics/audit | rede+token independentes | matriz de topologia pública/interna |
| UC-138 | endpoints high-risk | AbuseThrottleService | Redis + métricas | fail closed | enum exaustivo + parada/recuperação Redis |

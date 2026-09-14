# Gates de release do AuthKit v0.1

[English](RELEASE_GATES.md) | [Português (Brasil)](RELEASE_GATES-ptBR.md)

O inglês é autoritativo quando houver divergência de tradução.

Este documento define os gates obrigatórios de uma release AuthKit v0.1. Ele deliberadamente não incorpora contagem mutável de testes, commit, tree, digest de imagem ou resultado de gate: esses valores pertencem ao manifest externo de evidências produzido depois que o candidate de source é congelado. Isso evita evidência stale e a autorreferência impossível de armazenar um hash do tree dentro do próprio tree identificado.

Cada resultado deve identificar um único candidate por commit base, candidate tree, SHA-256 do source archive, digest OCI imutável e manifest de artefatos. `PASS` exige evidência objetiva atual para exatamente esse candidate. Evidência ausente, histórica, parcial, substituída por mock ou contraditória permanece `NOT PROVEN`. Nenhum gate é opcional no golden path.

| # | Gate obrigatório | Condição objetiva de PASS | Evidência a preservar |
| --- | --- | --- | --- |
| 1 | Clean build e suíte completa com PostgreSQL e Redis reais | Build limpo Java 21 termina com zero; todos os testes obrigatórios rodam sem falha, erro ou skip; PostgreSQL 17 e Redis 7 são containers reais. | Log completo, XML Surefire/Failsafe e versões de ferramentas/containers. |
| 2 | Instalação nova do golden path | Ambiente vazio fica healthy usando somente instruções públicas; smoke positivo passa e configuração ausente/insegura falha rápido. | Compose redigido, IDs de imagem, estado Flyway, health e smoke. |
| 3 | TLS/reverse proxy same-site e cross-site | As duas topologias passam TLS, cookie, CSRF, CORS e forwarded headers; ingress público/backend direto não satisfazem a boundary de worker. | Cadeia do certificado, HAR/curl, logs de proxy e prova de rede/firewall. |
| 4 | SMTP e Resend reais | Ambos aceitam registration/recovery; retry, crash/reclaim, deduplicação e DEAD cumprem o contrato de email. | IDs de aceite, message IDs/idempotency keys, outbox e logs de retry. |
| 5 | Google e OIDC genérico independente reais | Fluxos de identidade nova/existente passam nos dois; negativas de restricted, state/nonce/issuer e colisão falham com segurança. | Traces redigidos, IDs de provider/auditoria e estado de conta/vínculo. |
| 6 | Interoperabilidade externa OAuth/OIDC e conformidade aplicável | Cliente independente e perfil aplicável passam discovery, code + PKCE, token, userinfo, introspection, revocation e negativas sem suppressions enfraquecedoras. | Relatório da suíte, protocolo raw e configuração do cliente. |
| 7 | Lifecycle downstream JWT/JWKS | Verificador independente aplica issuer/audience/token class exatos e demonstra unknown `kid`, rotação planejada, revogação emergencial e invalidação de lifecycle. | Snapshots/hashes JWKS, logs do verificador e metadados sem token raw. |
| 8 | Backup PostgreSQL/Redis e restore limpo | Backups cifrados restauram em host independente limpo com estado consistente e RPO/RTO medidos; input corrupto/parcial falha closed. | Hashes, logs de cifra/checksum, contagens restauradas e smoke. |
| 9 | Falhas controladas de dependências | Falhas Redis, PostgreSQL e email preservam fail-closed/atomicidade/outbox, recuperam no tempo registrado e roteiam os alertas exigidos. | Chaos logs, métricas, notificações e snapshots de estado. |
| 10 | Carga mista, hostile burst e soak | Pelo menos quatro horas na classe 2 vCPU/4 GiB atendem thresholds publicados; replay, abuso e bodies oversized/chunked são rejeitados sem colapso. | Dados k6 e métricas de host/JVM/PostgreSQL/Redis/outbox. |
| 11 | Smoke, tokens negativos, concorrência e one-time state | Fluxos e corpus passam; cada race tem um winner ou outcome fail-safe documentado nos stores reais. | Smoke, manifest de fixtures, relatórios de race e estado final. |
| 12 | Zero indicadores de integridade não resolvidos | A janela termina sem DEAD não resolvido, perda crítica de auditoria, erro de integridade, pool wait sustentado ou backlog fora do limite. | Snapshots Prometheus/SQL/Redis e janela temporal exata. |
| 13 | Scans bloqueantes de segurança e supply chain | Scans de dependency, filesystem, container, static, secret e IaC terminam sem blocker não resolvido ou suppression injustificada. | Relatórios machine-readable, versões/configuração e justificativas. |
| 14 | SBOM, checksums, assinaturas e provenance | Artefatos multiarch imutáveis, SBOMs, checksums, assinaturas autorizadas e provenance verificável vinculam o mesmo source/digest OCI. | Descritores OCI, SBOMs, manifest de checksum, assinaturas, attestations e autorização. |
| 15 | Clean room por operador novo | Operador isolado conclui setup/operação usando só docs/artefatos públicos, sem passo oculto ou edição normativa ad hoc. | Transcript, inputs públicos, hashes e observações do operador. |
| 16 | Zero P0/P1 não resolvido em GA | Todo P0/P1 está fechado no candidate congelado com acceptance criteria evidenciados; uma auditoria independente adicional não é exigida apenas para fechar este gate. | Matriz de findings, índice de evidências e identidades do candidate. |

Somente o bundle de evidências gerado e a auditoria consolidada final podem declarar resultados atuais. Eles usam `PASS`, `FAIL` ou `NOT PROVEN` e só emitem `GO` quando Gates 1–16 estão `PASS`. Promoção, publicação e tag continuam ações exclusivas do maintainer.

# Operação e resposta a incidentes

[English](OPERATIONS.md) | [Português (Brasil)](OPERATIONS-ptBR.md)

O inglês é autoritativo quando houver divergência de tradução.

O operador é responsável por hardening do host, DNS/TLS, segredos, texto jurídico, conteúdo/entregabilidade de e-mail, contas de providers, backups/criptografia off-host, routing de alertas, capacidade, upgrades e decisões de incidente. O AuthKit fornece health/métricas, primitivas de auditoria, jobs limitados, APIs de revogação e harnesses; não é SIEM externo, mailbox, serviço de backup nem certificação de compliance.

## Verificações rotineiras

- Consulte `/actuator/health` por TLS e faça scrape de `/actuator/prometheus` apenas em rede confiável com `X-Worker-Token`.
- Monitore erros/latência, saturação Argon2, pool PostgreSQL, falhas Redis, falhas de autenticação, lockouts, replay de refresh, falha de auditoria, backlog/idade/dead do outbox e retenção.
- Trate `security_effects_outstanding > 0` por cinco minutos como crítico e siga [reconciliação de efeitos de segurança](runbooks/security-effect-reconciliation.md). O estado vivo no PostgreSQL mantém credenciais stale negadas enquanto a limpeza Redis tenta novamente.
- Use `GET /api/v1/admin/operations` para contagens não secretas de aceite e postura. Use eventos paginados por cursor para investigação e exporte para o SIEM do operador quando necessário.
- Trate `ACCEPTED` como aceite do provider. Observação da inbox é separada e nunca deve ser inferida do aceite.

## Política de falhas

| Falha | Comportamento esperado | Ação do operador |
| --- | --- | --- |
| Redis indisponível | Operações high-risk falham fechadas; consumidores JWT offline ficam limitados pela expiração. | Restaurar Redis, verificar saturação/rede/auth e testar login/refresh/logout. |
| Redis indisponível após mutação de credencial committed | O `security_version` committed no PostgreSQL nega JWT/sessão/refresh stale; um registro durável tenta novamente a limpeza física no Redis. | Seguir o runbook de reconciliação; nunca contornar a validação viva nem marcar a tarefa manualmente como completa. |
| PostgreSQL indisponível | Mutações e checks vivos falham com 5xx opaco. | Interromper tráfego arriscado, restaurar banco/pool e verificar Flyway/auditoria. |
| Auditoria indisponível | Mutações críticas abortam. | Restaurar persistência e confirmar rollback antes do retry. |
| SMTP/Resend indisponível | Outbox faz retry/backoff limitado e termina em `DEAD`. | Corrigir provider, reconciliar IDs e reprocessar por procedimento aprovado. |
| Falha após aceite SMTP | SMTP não oferece idempotência portátil no protocolo. O relay suportado deve comprovar deduplicação pelo Message-ID estável do AuthKit, inclusive em retry após crash/reclaim. | Verificar a janela de dedupe e reconciliar logs/Message-ID; aceite não comprova entrega na inbox. Relay sem essa prova não é configuração suportada para release. |
| JWT com `kid` desconhecido | Validator atualiza JWKS e rejeita se continuar desconhecido. | Conferir propagação/issuer; nunca contornar assinatura ou classe. |
| Família refresh comprometida | Replay revoga a família inteira imediatamente no AuthKit. | Investigar auditoria e exigir nova autenticação. |

## Backup e restore

Faça backup consistente do PostgreSQL e AOF/RDB do Redis conforme o RPO. Criptografe antes de transferir off-host, restrinja credenciais e registre checksums. A prova exige restore em host limpo, validação Flyway, fluxos de login/sessão, reconciliação de auditoria/outbox, comportamento Redis e RPO/RTO reais; copiar arquivos no host original não é prova.

Os checks fornecidos restauram deliberadamente em containers limpos e isolados. Os papéis PostgreSQL são recriados pelo script versionado de inicialização do golden path e pelos secrets montados atuais; assim, o dump do banco não exporta hashes de senha reutilizáveis. Exemplo após identificar o container Compose exato e um diretório protegido:

```sh
AUTHKIT_BACKUP_DIR=/secure/authkit-backups \
AUTHKIT_POSTGRES_CONTAINER=authkit-golden-postgres-1 \
deploy/scripts/backup-postgres.sh

AUTHKIT_BACKUP_DIR=/secure/authkit-backups \
AUTHKIT_SECRETS_DIRECTORY=/secure/authkit-secrets \
deploy/scripts/restore-postgres-check.sh

AUTHKIT_BACKUP_DIR=/secure/authkit-backups \
AUTHKIT_REDIS_CONTAINER=authkit-golden-redis-1 \
deploy/scripts/backup-redis.sh

AUTHKIT_BACKUP_DIR=/secure/authkit-backups \
deploy/scripts/restore-redis-check.sh
```

O modo Compose executa `redis-cli --rdb` autenticado dentro do container Redis não exposto, copia somente o RDB ao diretório protegido e remove o arquivo temporário do container. O modo remoto aceita `REDIS_HOST`, `REDIS_PORT` e `REDIS_PASSWORD`. Criptografe e copie ambos os backups off-host após a verificação local. O check em container limpo é evidência útil, mas não prova por si só armazenamento off-host, RPO/RTO de produção nem o exercício de recuperação em host limpo.

## Rotação de chaves e segredos

Nota de upgrade: a migration V27 invalida transações de redirect social em andamento
criadas antes da vinculação das versões de consentimento. Usuários devem reiniciar
esses redirects curtos após o upgrade; nenhuma conta ou ledger de consentimento
aceito é removido. V28 adiciona ativação durável de recovery e recibos de retry JDBC.

Introduza nova chave RSA e `kid`, mantenha a pública anterior pelo maior lifetime emitido, valide refresh de JWKS downstream e então revogue/remova a antiga. Rotacione worker, Redis, banco, providers e chave MFA usando janelas anteriores quando suportadas. Pepper usa invalidação coordenada sem overlap online: siga [rotação de chaves](runbooks/key-rotation.md), incluindo manutenção, invalidação dos estados dependentes e verificação histórica de audit.

Email de recovery permanece `WAITING_ACTIVATION` até a ativação durável do token.
Falhas Redis têm retry automático sem estender expiry nem recriar token consumido.
Ativação expirada ou superada cancela o email não enviado como `CANCELLED`; o usuário
pode pedir novo link. Monitore `security_effects_outstanding` e o alerta de
reconciliação. Effects concluídos usam `AUTH_SECURITY_EVENT_RETENTION_DAYS` e
`AUTH_RETENTION_BATCH_SIZE` no job de retention limitado e protegido por lock;
effects pending, failed e processing nunca são purgados.

## Capacidade e prova de release

Execute carga mista, burst hostil e soak de pelo menos quatro horas na classe declarada de 2 vCPU/4 GiB. Registre commit, digest, configuração sem segredos, dados, p50/p95/p99, throughput, erros, CPU, memória, GC, saturação PostgreSQL/Redis, fila Argon2 e backlog. Estimativas e mocks não são evidência. Google/OIDC, SMTP/Resend, topologias TLS, cliente/conformance OAuth externo, JWKS downstream, routing de alertas, restore limpo e backup off-host ficam `NÃO COMPROVADOS` até execução real.

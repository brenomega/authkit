# Design de sistema do AuthKit v0.1

[English](SYSTEM_DESIGN.md) | [Português (Brasil)](SYSTEM_DESIGN-ptBR.md)

O inglês é autoritativo quando houver divergência de tradução.

## Fronteiras de confiança e dados

```mermaid
flowchart LR
  Browser[Aplicação browser] -->|TLS, cookies + CSRF ou OAuth PKCE| Proxy[Caddy peer confiável]
  Client[Cliente OAuth/OIDC] -->|TLS, formatos padrão| Proxy
  Proxy -->|peer fixo, headers sobrescritos| AK[AuthKit]
  AK -->|DML runtime| PG[(PostgreSQL 17)]
  AK -->|sessões, one-time e abuso| Redis[(Redis 7)]
  AK -->|outbox direto durável| Mail[SMTP TLS ou Resend]
  Retention[Worker de retenção restrito] -->|somente funções SECURITY DEFINER| PG
  Resource[Resource server] -->|JWKS + introspecção interna opcional| AK
```

O browser não recebe tokens do provider após federação. Refresh first-party fica em cookie HttpOnly same-site com CSRF double-submit; access token é curto e somente em memória. Clientes OAuth cross-site usam Authorization Code, state, nonce, redirect exato e PKCE S256. Refresh OAuth é opaco, rotativo e ligado a família travada. `tenant_id` particiona os registros de uma pessoa e não carrega autoridade organizacional.

## Direção das dependências internas

```mermaid
flowchart LR
  HTTP[Controllers e filtros de segurança] --> APP[Serviços de lifecycle/aplicação]
  JOBS[Schedulers e comandos offline] --> APP
  APP --> DOMAIN[Entidades, invariantes e value objects]
  APP --> PORTS[Ports de repository, token store, email e audit]
  PORTS --> SQL[Adapters JPA/JDBC]
  PORTS --> CACHE[Adapters Redis/JDBC de token]
  PORTS --> PROVIDERS[Adapters SMTP, Resend e OIDC]
  SQL --> PG[(PostgreSQL)]
  CACHE --> REDIS[(Redis)]
```

Código de transporte não chama adapters de persistência diretamente. Serviços controlam transações; audit crítico e estado SQL usam a mesma transação, enquanto revogação/cache não transacional é registrado somente após commit. O domínio não depende de Spring MVC, Redis, SMTP nem formatos wire de providers.

## Propriedade dos dados

```mermaid
erDiagram
  USER ||--o{ CONSENT_EVENT : registra
  USER ||--o{ SECURITY_EVENT : sujeito
  USER ||--o{ PASSKEY_CREDENTIAL : possui
  USER ||--o{ MFA_CREDENTIAL : possui
  USER ||--o{ SOCIAL_IDENTITY : vincula
  USER ||--o{ OAUTH_CONSENT : concede
  USER ||--o{ OAUTH_REFRESH_FAMILY : possui
  USER ||--o{ ONE_TIME_STATE : vincula
  EMAIL_OUTBOX }o--|| USER : notifica
```

PostgreSQL é autoritativo para usuários, lifecycle, consentimentos, famílias OAuth, counters WebAuthn, email durável e audit. Redis possui sessões first-party expirantes, estado distribuído de abuso/lockout e alguns claims one-time; chaves carregam vínculo user/tenant e TTL. Tokens de provider são validados e descartados, não persistidos.

## Variantes de deployment

```mermaid
flowchart TB
  subgraph Golden[Deployment golden GA]
    C[Caddy TLS/reverse proxy] --> A1[AuthKit]
    A1 --> P1[(PostgreSQL 17)]
    A1 --> R1[(Redis 7)]
    A1 --> E1[SMTP TLS ou Resend]
  end
  subgraph Scale[Planejamento scale-out não suportado]
    LB[Proxy/load balancer confiável] --> A2[AuthKit réplica A]
    LB --> A3[AuthKit réplica B]
    A2 & A3 --> P2[(PostgreSQL 17)]
    A2 & A3 --> R2[(Redis 7 obrigatório)]
  end
  subgraph Experimental[Explicitamente experimental]
    A4[Instância AuthKit única] --> P3[(PostgreSQL 17)]
    A4 --> J[Token store JDBC]
  end
```

A topologia Compose golden é a referência de fresh install. Layouts browser same-site e OAuth cross-site diferem em cookie/CORS, não na confiança de forwarded headers. Token store JDBC é restrito a uma instância e nunca substitui Redis quando o gate exige Redis real.

## Lifecycle de identidade

```mermaid
stateDiagram-v2
  [*] --> ACTIVE: identidade local/social verificada
  ACTIVE --> SUSPENDED: admin + step-up local
  SUSPENDED --> ACTIVE: reativação administrativa
  ACTIVE --> DELETION_PENDING: solicitação e revogação de sessões
  DELETION_PENDING --> ACTIVE: cancelamento fortemente autenticado
  DELETION_PENDING --> ANONYMIZED: carência 0..30 dias
  ANONYMIZED --> ANONYMIZED: purge repetível
```

Anonimização é irreversível. Retenção de segurança/consentimento é limitada e append-only para o runtime; deleção só ocorre pelo papel separado através de procedimentos auditados. O último administrador ativo é protegido no serviço e por trigger serializado PostgreSQL.

## Fronteiras one-time e transacionais

Confirmação e mudança de e-mail travam a linha do usuário. Recovery usa Lua Redis atômico ou JDBC travado com compensação finalize/release. Transações/codes OAuth, state social, nonce, PKCE, refresh e counters de passkey são consumidos condicionalmente ou atualizados monotonicamente. Auditoria crítica é síncrona na transação; sua falha aborta a mutação.

Criação do e-mail e estado de negócio commitam com o outbox. Dispatch ocorre fora: SMTP faz uma tentativa por claim e o outbox controla retries; Resend adiciona retry limitado e idempotente. Aceite do provider e entrega na inbox são fatos distintos.

```mermaid
sequenceDiagram
  participant S as Serviço de lifecycle
  participant PG as PostgreSQL
  participant W as Worker do outbox
  participant M as SMTP/Resend
  S->>PG: Commita mutação + email PENDING
  W->>PG: Claim de row com lease
  W->>M: Envia com identidade idempotente estável
  alt Provider aceita
    W->>PG: Registra ACCEPTED + message ID
  else Falha temporária
    W->>PG: Libera com backoff limitado
  else Budget esgotado
    W->>PG: Marca DEAD e dispara alerta crítico
  end
```

## Classes de token e revogação

| Classe | `token_use` | Audience | Revogação |
| --- | --- | --- | --- |
| Access first-party | `first_party_access` | API configurada | sessão/JTI vivo e `session_version` PostgreSQL sem cache; consumers offline limitados a ≤300 s |
| Access OAuth | `oauth_access` | cliente OAuth | cliente/família/JTI e introspecção autenticada |
| ID token OIDC | `id_token` | cliente OAuth | declaração de autenticação; nunca bearer de API |

Ausência ou divergência de classe, issuer, audience, assinatura, expiração, `kid` ou claims é rejeitada. JWKS publica apenas chaves públicas atuais/retiring. O contrato está no [OpenAPI](../openapi.yaml) e deveres do operador em [Operações](../OPERATIONS-ptBR.md).

## Casos de uso principais

### Conta e sessão first-party

```mermaid
sequenceDiagram
  actor Pessoa
  participant App as Aplicação same-site
  participant AK as AuthKit
  participant PG as PostgreSQL
  participant R as Redis
  Pessoa->>App: Registro com versões legais aceitas
  App->>AK: POST /api/v1/auth/register
  AK->>PG: User + consent + outbox em uma transação
  Pessoa->>App: Abre action_url do operador em fragmento
  App->>AK: Envia token de confirmação no JSON
  AK->>PG: Trava user, consome uma vez e audita
  App->>AK: Login
  AK->>R: Cria sessão rotativa e revogável
  AK-->>App: Access no corpo; cookies refresh/CSRF
  App->>AK: Refresh com cookies + header CSRF
  AK->>R: Rotação atômica; replay revoga sessão
```

### Federação sem auto-link por e-mail

```mermaid
sequenceDiagram
  actor Pessoa
  participant UI as UI do operador
  participant AK as AuthKit
  participant IdP as Provider OIDC permitido
  UI->>AK: Inicia com providerKey
  AK-->>UI: URL do provider; state/nonce/PKCE no servidor
  UI->>IdP: Autentica
  IdP->>AK: Callback exato com state + code
  AK->>IdP: Troca code e valida ID token assinado
  AK->>AK: Resolve somente por (issuer, subject) exato
  alt Identidade existente
    AK-->>UI: Sessão first-party
  else Apenas e-mail coincide
    AK-->>UI: Link explícito necessário; sem auto-link
  end
  AK->>AK: Descarta tokens access/refresh/ID do provider
```

### Autorização OAuth/OIDC

```mermaid
sequenceDiagram
  actor Pessoa
  participant Client as Cliente externo
  participant AK as AuthKit
  participant UI as UI login/consent do operador
  Client->>AK: GET /oauth2/authorize + state + nonce + S256
  AK-->>UI: Handle de transação opaco e assinado
  Pessoa->>UI: Login e aprova/recusa
  UI->>AK: Retoma transação one-time
  AK-->>Client: Redirect exato com code/erro + state
  Client->>AK: POST /oauth2/token + code_verifier
  AK-->>Client: oauth_access + id_token opcional + refresh opaco
  Client->>AK: Rotaciona refresh
  AK->>AK: Replay revoga a família inteira
```

### Lifecycle administrativo e retenção

```mermaid
sequenceDiagram
  actor Admin as PLATFORM_ADMIN
  participant AK as AuthKit
  participant PG as PostgreSQL
  participant RW as Worker de retenção
  Admin->>AK: Mutação + step-up local recente
  AK->>PG: Lock do alvo e proteção do último admin
  AK->>PG: Estado + audit crítico em uma transação
  Note over AK,PG: Falha de audit faz rollback da mutação
  RW->>PG: Função SECURITY DEFINER limitada
  PG->>PG: Registra retention; DELETE direto negado
```

Pesquisas administrativas usam cursors assinados, curtos e vinculados à query. O primeiro administrador é criado por comando offline one-shot, nunca por HTTP.

## Backup, restore e rotação de chaves de assinatura

```mermaid
flowchart LR
  Freeze[Registra candidate e cutoff UTC] --> Dump[pg_dump + RDB Redis]
  Dump --> Hash[SHA-256, cifra e copia off-host]
  Hash --> Clean[Host PostgreSQL/Redis limpo]
  Clean --> Restore[Restaura PostgreSQL e depois Redis]
  Restore --> Verify[Flyway, contagens, sessões, cadeia audit e smoke]

  Current[Chave de assinatura atual] --> Add[Configura nova current + pública anterior]
  Add --> Publish[Publica ambos kids no JWKS]
  Publish --> Issue[Emite somente com novo kid]
  Issue --> Retire[Aguarda lifetime máximo]
  Retire --> Remove[Remove material privado/público antigo]
```

Backup/restore é exercício em host limpo, não apenas comando de dump; checksums, criptografia, expirações Redis, estado Flyway, integridade de audit e smoke são verificados. Rotação planejada publica overlap antes de mudar emissão. Revogação emergencial remove o `kid` comprometido, invalida estado vivo afetado e aceita o impacto limitado de disponibilidade; `kid` desconhecido ou revogado sempre falha fechado. Procedimentos e campos de evidência estão em [Operações](../OPERATIONS-ptBR.md) e no [playbook de provas](../proof/README-ptBR.md).

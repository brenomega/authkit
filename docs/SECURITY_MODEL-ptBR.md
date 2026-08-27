# Modelo de segurança do AuthKit

[English — normativo](SECURITY_MODEL.md)

## Papéis

O AuthKit possui exatamente `USER` e `PLATFORM_ADMIN`. Toda escrita administrativa requer step-up recente e segundo fator. O último administrador ativo não pode ser rebaixado, suspenso, anonimizado ou excluído; PostgreSQL também serializa e impõe essa invariante. Não existem papéis de organização, owner ou tenant-admin. Clients OAuth são globais da instância.

## Identificador de partição pessoal

Cada conta recebe `tenant_id` opaco e único, usado apenas como partição pessoal de defesa em profundidade e correlação. Não representa empresa, equipe, assinatura, tenant compartilhado ou fronteira de membros. O integrador modela organizações e autorização no próprio domínio. O filtro Hibernate é defesa adicional; services ainda impõem ownership e falhas não enumeráveis.

## Lifecycle

Os estados duráveis são `ACTIVE`, `SUSPENDED`, `DELETION_PENDING` e `ANONYMIZED`. Apenas contas ativas e com e-mail confirmado recebem authorities runtime. Suspensão revoga sessões imediatamente e reativação não as restaura. Anonimização é irreversível e remove identificadores diretos e senha local.

## Credenciais e autenticadores

Senha local pode ser nula em conta social-only; ausência nunca equivale a senha vazia. Operações de senha, passkey, TOTP, recovery, linking e unlinking preservam o último autenticador e exigem o step-up adequado ao autenticador presente.

## Tokens e borda

Todo JWT aceito contém `token_use` explícito. `first_party_access`, `oauth_access` e `id_token` têm audiences e consumidores distintos. APIs first-party exigem `jti` de sessão viva; OAuth/ID token nunca é aceito nessas rotas. Endpoints de alto risco possuem throttles específicos; produção exige origins HTTPS e peers proxy/CDN explícitos, sem confiar em headers enviados fora desses peers.

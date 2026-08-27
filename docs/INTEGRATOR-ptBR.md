# Guia do integrador do AuthKit

[English — normativo](INTEGRATOR.md)

## Escolha uma topologia de browser

Uma aplicação first-party same-site usa o login AuthKit, access token apenas em memória e o cookie de refresh `HttpOnly; Secure; SameSite=Strict`, espelhando o cookie CSRF legível no header configurado. Siga `samples/first-party-same-site`.

Uma aplicação cross-site é cliente OAuth/OIDC. Use Authorization Code, state, nonce para `openid`, redirect URI exata e PKCE S256. Mantenha o estado da cerimônia brevemente em `sessionStorage`, remova os parâmetros do callback imediatamente e mantenha tokens emitidos em memória; um cliente browser de produção deve usar backend-for-frontend para custodiar refresh durável. Siga `samples/oauth-cross-site`.

Nunca armazene credenciais access, refresh, MFA, authorization-code, confirmação, recovery ou mudança de e-mail em `localStorage`. URLs de ação do operador carregam credenciais one-time no fragmento; remova-o com `history.replaceState` antes de submeter a credencial em JSON. Fragmentos não podem chegar a analytics ou logs.

## Classes de token

Todo JWT precisa ter exatamente um `token_use` explícito; valores ausentes ou legados são rejeitados.

| `token_use` | Audience exata | Consumidor | Fronteira obrigatória |
| --- | --- | --- | --- |
| `first_party_access` | Audience AuthKit/API configurada | APIs first-party de user/admin | `sub`, `jti`, `tenant_id` pessoal, `amr`; sessão AuthKit viva |
| `oauth_access` | ID do cliente OAuth | API do cliente, userinfo e introspection/revocation autenticadas | `sub`, `jti`, `client_id`, `scope`, `tenant_id` pessoal; client/família vivos |
| `id_token` | ID do cliente OAuth | Somente resultado de autenticação OIDC | Nunca bearer de API; valide nonce quando emitido para authorize |

Consumers validam algoritmo configurado, `iss` exato, `aud` esperado, assinatura, expiração/not-before, `kid` e classe exata antes dos claims. `tenant_id` correlaciona a partição de uma pessoa e nunca é autoridade de organização. Papéis, organizações, assinaturas e permissões do produto pertencem ao integrador.

## JWKS e revogação

Cacheie `/.well-known/jwks.json` por período curto e limitado. Com `kid` desconhecido, atualize uma vez e rejeite se continuar ausente. Fixe algoritmos permitidos independentemente do header do token. Em rotação planejada, mantenha chaves públicas retiring até todos os tokens expirarem; exercite remoção emergencial separadamente.

O AuthKit revoga imediatamente sessões first-party e famílias OAuth em seus checks/introspection vivos. Resource server downstream que valida JWT offline observa revogação no máximo na expiração do access (recomendação golden de até 300 segundos). Use introspecção first-party autenticada somente entre peers confiáveis; use introspecção OAuth padrão autenticada para tokens OAuth.

O sample Spring demonstra issuer, audience, `token_use=oauth_access` e scope. Ele não converte `PLATFORM_ADMIN` em autoridade do produto nem usa `tenant_id` como organização.

## Federação

Somente providers permitidos por administrador podem ser usados. O AuthKit vincula identidade apenas por `(issuer, subject)` exato. E-mail igual nunca auto-linka; a pessoa autenticada inicia cerimônia explícita com step-up local. Unlink não pode remover o último autenticador. Tokens access, refresh e ID do provider são descartados após a cerimônia.

## Fixtures negativas

Gere fixtures de teste em `target/` ignorado e execute fronteiras:

```sh
testing/proof/fixtures/generate-test-tokens.sh
AUTHKIT_BASE_URL=https://auth.example.test testing/proof/smoke/negative-contracts.sh
```

As fixtures usam chaves de teste do repositório e nunca são credenciais de produção. O wire contract completo está em `docs/openapi.yaml`; configuração e responsabilidades ficam em `docs/CONFIGURATION-ptBR.md` e `docs/OPERATIONS-ptBR.md`.

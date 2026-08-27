# AuthKit

[English — normativo](README.md)

O AuthKit é um serviço headless e independente de autenticação e identidade para aplicações SaaS greenfield. Ele oferece sessões first-party, MFA e passkeys, federação Google e OIDC genérico permitido pelo operador e um servidor de autorização OAuth 2.0/OIDC.

O AuthKit v0.1 tem como alvo lançamentos iniciais de SaaS greenfield por meio do golden path documentado. Ele não é um produto de migração de autenticação em uso e não faz alegações não medidas de escala ou disponibilidade. A working tree atual é um candidato não publicado sob auditoria de implementação; a prontidão para produção não foi estabelecida e nenhuma implantação ou publicação está autorizada antes da aprovação de todos os gates obrigatórios.

## Golden path da v0.1

A topologia suportada é um container OCI do AuthKit em Linux com Java 21, PostgreSQL 17, Redis 7 autenticado, envio direto pelo outbox durável, SMTP com TLS obrigatório ou Resend e um proxy reverso TLS. É uma topologia de instância única; alta disponibilidade, migração sem interrupção de outro sistema de identidade, tenancy organizacional e capacidade não medida estão fora do contrato v0.1.

Comece pela [instalação do golden path](docs/INSTALL-ptBR.md) e consulte a [referência de configuração](docs/CONFIGURATION-ptBR.md), o [contrato de templates de e-mail](docs/EMAIL_TEMPLATES-ptBR.md), o [modelo de segurança](docs/SECURITY_MODEL.md), o [guia operacional](docs/OPERATIONS-ptBR.md) e o [contrato OpenAPI](docs/openapi.yaml). A [matriz de suporte](docs/reference/SUPPORT_MATRIX-ptBR.md) identifica os caminhos preview sem suporte; a [rastreabilidade](docs/TRACEABILITY-ptBR.md) e os [16 gates](docs/release/RELEASE_GATES-ptBR.md) declaram o que foi implementado e o que continua sem prova.

## Fronteiras de segurança

- `tenant_id` é uma partição opaca de uma pessoa, nunca uma organização ou modelo de autorização do produto integrador.
- Os únicos papéis são `USER` e `PLATFORM_ADMIN`.
- Tokens de acesso first-party, acesso OAuth e ID token são classes separadas e exigem `token_use` explícito.
- Credenciais de refresh e estados de cerimônia permanecem no servidor, são rotativos ou one-time e têm revogação imediata dentro do AuthKit.
- HTML, localização e branding de e-mail pertencem ao operador integrador. O AuthKit apenas valida, renderiza com segurança, enfileira e registra a aceitação do provider.
- OAuth/OIDC implementa Authorization Code com PKCE S256. Implicit, password, client credentials, device, PAR, JAR, CIBA e registro dinâmico não são implementados.

## Desenvolvimento

Java 21 e Docker são necessários para a suíte completa:

```sh
./mvnw clean verify
```

Os testes que comprovam semântica PostgreSQL e Redis usam Testcontainers. Artefatos de produção também precisam passar por `testing/release/inspect-release-artifacts.sh`; perfis e chaves privadas de teste nunca podem estar no JAR, imagem ou contexto de build.

Consulte [CONTRIBUTING.md](CONTRIBUTING.md), [SECURITY.md](SECURITY.md), [SUPPORT.md](SUPPORT.md) e [LICENSE](LICENSE). Contribuições usam DCO e Apache-2.0; não há CLA neste momento.

1. Resumo executivo
O candidato não pode avançar para release nem para a rodada final de provas externas. A auditoria encontrou:
- 0 P0;
- 5 P1;
- 4 P2;
- 1 P3.
Os bloqueadores principais são:
1. O clean verify falha com PostgreSQL e Redis reais por uma regressão introduzida na sanitização.
2. A introspecção OAuth pode declarar ativos tokens pertencentes a contas suspensas ou em exclusão.
3. O RP OIDC aceita ID tokens com audiências adicionais não confiáveis e não valida adequadamente azp.
4. Contas criadas por login social não registram a evidência imutável de consentimento nem usam as versões configuradas.
5. O OpenAPI canônico não descreve semanticamente numerosas respostas GA.
A árvore rastreada estava limpa antes e depois da auditoria, mas as evidências existentes em RELEASE_GATES.md e IMPLEMENTATION_MATRIX.md não representam o commit atual: elas alegam 289 testes verdes, enquanto o candidato possui 290 testes e falha com 1 erro quando Docker está disponível.
A implementação tem bases sólidas: fronteiras de token, TOTP, backup codes, passkeys, bootstrap, outbox, retenção, migrations e fail-closed Redis foram verificadas localmente. Isso não compensa os P1 nem os gates externos ausentes.
2. Identidade exata auditada
Campo	Valor
Branch	release/authkit-v0.1.0-rc1-final-audit
Commit	23a6ad66bec32ce247ce8505dd4035a4f9865014
Tree	7a895d2fe552e032f4bfc05293b939f94480cbfa
Commit date	2026-08-28T01:40:19-03:00
Upstream	branch local 4 commits à frente de origin/release/authkit-v0.1.0-rc1-final-audit
Estado inicial	git status --porcelain vazio
Estado final	git status --porcelain vazio
Congelamento rastreado	Sim
Artefatos ignorados	target/, targets dos samples e artefatos de teste
Autorização humana de publicação	Não concedida


Portanto, o candidato estava congelado quanto a arquivos rastreados. Entretanto, ele ainda não é um artefato remoto imutável, assinado e publicado.
3. Comandos e resultados reais
Verificação	Resultado
./mvnw clean verify -B sem acesso Docker	BUILD SUCCESS; 290 testes, 9 ignorados: 5 PostgreSQL e 4 Redis. Não vale como prova real.
./mvnw clean verify -B ... com Docker	BUILD FAILURE; 290 testes, 0 failures, 1 error, 0 skipped.
PostgreSQL Testcontainers	PostgreSQL 17; 4 de 5 testes passaram. Fresh V1–V25, upgrade V15, ShedLock e retention role passaram; purge relacionado falhou por SQL mal formatado no teste.
Redis Testcontainers	Redis 7; 4 de 4 testes reais passaram.
Resource-server sample	2 testes, 0 falhas/erros/ignorados.
./mvnw -DskipTests package	Sucesso; usado somente para inspeção, não como Gate 1.
JAR	674 entradas, aproximadamente 91 MiB; sem perfil de teste, chaves ou marcador privado.
SHA-256 JAR	aa69539378be5ee6a224671981a3d283c52accb55a8e4b54203a2e9f680fee11
CycloneDX JSON	3f37f87d00e53bc38400b4aaea139059136aa990b87aeb8fcaf759b9133e3a58
CycloneDX XML	6a13a3f9883d591868cfadad835419f5036c5a1768ba1c32d6478dd75ea47d3d
jarsigner -verify	JAR tratado como não assinado; META-INF/BOOT.SF não é assinatura verificável.
Build de imagem	Sucesso local, sem publicação.
Imagem local	sha256:256030034ed16082ddad38c3163b101c7572b329a59e58e6a70a8de2d38a4e42
Metadados OCI	versão 0.1.0-rc.1, revision igual ao commit auditado, usuário appuser, 158.604.047 bytes.
Inspeção do contexto/imagem	PASSOU; testes, .env, chaves e perfis de teste excluídos.
Documentação	PASSOU o checker: 47 Markdown, 12 pares bilíngues, 37 AK. O checker é estrutural, não semântico.
JS samples	Ambos passaram em node --check.
Scripts shell	Todos passaram em bash -n.
Compose	docker compose ... config --quiet passou.
OpenAPI	Parser passou e encontrou 65 operações; 22 respostas 2xx não têm content/schema. Apenas /oauth2/revoke é justificadamente sem corpo; restam 21 omissões materiais.
Golden local	PostgreSQL 17.9, Redis 7.4, AuthKit, Caddy e Mailpit ficaram saudáveis; TLS health, discovery e JWKS passaram.
Bootstrap offline	Primeira execução passou; segunda foi rejeitada com “already complete”.
SMTP local	Recuperação foi aceita por Mailpit STARTTLS; 1 mensagem ACCEPTED. Não prova provedor ou inbox real.
Redis fault injection	Redis parado → login retornou 503 opaco com requestId; após reinício, health voltou a UP.
PostgreSQL backup/restore	Dump 4c8af8…b78c; restauração limpa passou em Flyway 25, users=1, bootstrap_guard=1, accepted_email=1.
Redis backup/restore	RDB 290698…9b9c; restauração limpa passou com 7 chaves.
Scanners	trivy, gitleaks, semgrep, checkov, hadolint, syft, grype e cosign indisponíveis. Gate não comprovado.
Busca de secrets	Nenhum secret real encontrado. Há somente o placeholder deliberado em [k8s/05-secrets.example.yaml (line 36)](/home/breno/Workspaces/ws-antigravity/authkit/k8s/05-secrets.example.yaml:36). O .env ignorado não foi lido.


A stack temporária foi parada e seus containers/redes removidos; volumes temporários, imagem local e backups em /tmp não foram publicados.
4. Arquitetura e fronteiras verificadas
Foram confirmadas na implementação:
- papéis efetivos limitados a USER e PLATFORM_ADMIN;
- tenant_id como partição pessoal opaca, não como organização;
- estados ACTIVE, SUSPENDED, DELETION_PENDING e ANONYMIZED;
- separação entre first_party_access, oauth_access e id_token;
- sessões first-party revogáveis com refresh rotativo;
- OAuth Code + PKCE S256, state, nonce, redirects exatos e famílias de refresh opacas;
- TOTP criptografado, replay de timestep, backup codes com consumo condicional;
- passkeys com challenge one-time, user verification, RP/origin e contador monotônico;
- bootstrap não HTTP e singleton;
- outbox transacional com semântica ACCEPTED distinta de inbox;
- auditoria crítica síncrona e rollback;
- retention role separado;
- deny-by-default HTTP, CSRF, CORS explícito, proxy peer fixo, parsing estrito e limites;
- migrations V1–V25, fresh install e upgrade V15 representativo;
- isolamento dos caminhos preview JDBC/RabbitMQ/Kubernetes/systemd por opt-in ou classificação unsupported.
As exceções materiais são os achados abaixo.
5. Reavaliação independente AK-001–AK-037
“Confirmada localmente” significa implementação e teste local, não prova externa.
AK	Disposição independente
AK-001	REFUTADA — RP OIDC não rejeita audiências adicionais não confiáveis nem valida azp adequadamente.
AK-002	CONFIRMADA LOCALMENTE — request/confirm/cancel, colisão, replay e revogação estão cobertos.
AK-003	REFUTADA — introspecção OAuth não observa suspensão atual da conta.
AK-004	REFUTADA — exclusão revoga sessões first-party, mas não impede introspecção OAuth ativa imediatamente.
AK-005	CONFIRMADA LOCALMENTE — dois papéis, partição pessoal e last-admin guard; há Javadoc contraditório.
AK-006	CONFIRMADA LOCALMENTE — senha nullable e social-only funcionam.
AK-007	CONFIRMADA LOCALMENTE — modos public/restricted e fail-fast.
AK-008	PARCIAL — implementação local presente; cliente/conformance externos pendentes.
AK-009	CONFIRMADA LOCALMENTE — refresh opaco, rotação e replay familiar.
AK-010	REFUTADA — introspecção não verifica conta atual; revogação de JTI pode degradar fail-open.
AK-011	CONFIRMADA LOCALMENTE — transação assinada, expiração e one-time.
AK-012	CONFIRMADA LOCALMENTE — bootstrap real e rejeição da repetição verificados.
AK-013	CONFIRMADA LOCALMENTE — introspecção first-party, metadata e revogação de sessão.
AK-014	CONFIRMADA LOCALMENTE — claims Redis/JDBC e compensação.
AK-015	CONFIRMADA LOCALMENTE — one-time e concorrência.
AK-016	PARCIAL — renderer/outbox/SMTP local presentes; SMTP e Resend reais pendentes.
AK-017	CONFIRMADA LOCALMENTE — auditoria crítica aborta mutação.
AK-018	CONFIRMADA LOCALMENTE — retention role real passou.
AK-019	CONFIRMADA LOCALMENTE para token_use; o tratamento de kid tem defeito separado.
AK-020	CONFIRMADA LOCALMENTE — JAR, contexto e imagem limpos.
AK-021	PARCIAL — contador/invariantes locais presentes; cerimônia real pendente.
AK-022	REFUTADA — social signup gera exportação sem histórico imutável de consentimento.
AK-023	PARCIAL — golden local saudável; operador independente pendente.
AK-024	CONFIRMADA LOCALMENTE — edge e Redis fail-closed observados.
AK-025	REFUTADA — OpenAPI não é semanticamente completo.
AK-026	REFUTADA — suíte completa real está vermelha e faltam negativos para os novos P1.
AK-027	REFUTADA/PENDENTE — provas externas ausentes e há defeito na validação OIDC.
AK-028	PARCIAL — restore e Redis failure locais passaram; off-host, alertas e soak faltam.
AK-029	NÃO COMPROVADA — scans, assinatura e proveniência verificável ausentes.
AK-030	PARCIAL — pares e samples passam, mas há drift semântico/Javadoc.
AK-031	CONFIRMADA LOCALMENTE — Apache-2.0, DCO/no CLA, políticas e metadados.
AK-032	REFUTADA — ledger sobrestima Gate 1; prompt de agente e Javadocs obsoletos permanecem.
AK-033	CONFIRMADA LOCALMENTE — preview/unsupported é explícito e opt-in.
AK-034	CONFIRMADA LOCALMENTE — defaults golden e alternativa Resend existem; prova Resend real falta no Gate 4.
AK-035	CONFIRMADA LOCALMENTE — telefone removido do modelo e contratos atuais.
AK-036	REFUTADA — evidência publicada nos docs não corresponde à suíte/tree atual.
AK-037	PARCIAL — semântica de aceitação local correta; provedores reais pendentes.


6. Novos achados
AUD-001 — clean verify real falha
- Prioridade/natureza: P1; regressão de sanitização e gap de teste.
- Requisito: Gate 1, Gate 11, AK-026 e congelamento reproduzível.
- Local: [PostgresMigrationTest.java (line 405)](/home/breno/Workspaces/ws-antigravity/authkit/src/test/java/io/github/brenomega/authkit/infrastructure/persistence/PostgresMigrationTest.java:405).
- Cenário: .formatted() é aplicado somente ao segundo literal da concatenação. O primeiro %s chega ao PostgreSQL e causa invalid input syntax for type uuid: "%s".
- Impacto: clean verify vermelho; prova de purge com relações ausente; evidência documental 289/289 inválida.
- Correção: aplicar a formatação à string concatenada inteira ou usar parâmetros SQL.
- Aceite: ./mvnw clean verify -B com Docker deve resultar em 290 ou mais testes, zero failures/errors/skips.
- Provas: preservar log, versões reais de PostgreSQL/Redis, relatórios Surefire e hashes do JAR/SBOM gerados pela mesma execução.
AUD-002 — Introspecção OAuth ignora suspensão/exclusão
- Prioridade/natureza: P1; defeito de código e gap de teste.
- Requisito: AK-003, AK-004, AK-010 e contrato de revogação/liveness.
- Local: introspecção em [OAuthProviderService.java (line 536)](/home/breno/Workspaces/ws-antigravity/authkit/src/main/java/io/github/brenomega/authkit/service/OAuthProviderService.java:536); retorno ativo em [OAuthProviderService.java (line 563)](/home/breno/Workspaces/ws-antigravity/authkit/src/main/java/io/github/brenomega/authkit/service/OAuthProviderService.java:563); suspensão revoga somente first-party em [AdminService.java (line 257)](/home/breno/Workspaces/ws-antigravity/authkit/src/main/java/io/github/brenomega/authkit/service/AdminService.java:257); exclusão idem em [AccountLifecycleService.java (line 279)](/home/breno/Workspaces/ws-antigravity/authkit/src/main/java/io/github/brenomega/authkit/service/AccountLifecycleService.java:279).
- Cenário: emitir token OAuth, suspender ou solicitar exclusão da conta e introspectar com cliente confidencial. Access e refresh podem continuar active=true.
- Impacto: resource server que confia na introspecção pode autorizar conta suspensa/excluída. A RFC 7662 define introspecção como consulta ao estado atual e reserva active=true a tokens ainda válidos para uso no recurso protegido. RFC 7662
- Correção: verificar usuário ativo/confirmado na introspecção e revogar famílias/JTIs OAuth nas transições de lifecycle.
- Aceite: suspensão, exclusão pendente, anonimização e remoção do usuário devem produzir active=false imediatamente; reativação não deve ressuscitar tokens antigos.
- Provas: testes reais com PostgreSQL, cliente confidencial, access/refresh, concorrência e restart; resource-server externo.
AUD-003 — RP OIDC aceita audiência adicional não confiável
- Prioridade/natureza: P1; defeito de código e gap de teste.
- Requisito: AK-001, AK-027 e OIDC Core.
- Local: [NimbusSocialOidcClient.java (line 109)](/home/breno/Workspaces/ws-antigravity/authkit/src/main/java/io/github/brenomega/authkit/infrastructure/social/NimbusSocialOidcClient.java:109), especialmente a verificação por simples contains em [linha 115 (line 115)](/home/breno/Workspaces/ws-antigravity/authkit/src/main/java/io/github/brenomega/authkit/infrastructure/social/NimbusSocialOidcClient.java:115).
- Cenário: ID token assinado pelo issuer permitido com aud=[authkit-client,outro-client] e azp=outro-client é aceito.
- Impacto: substituição cross-client de ID token em provedores/extensões que emitem múltiplas audiências.
- Correção: rejeitar audiências extras não explicitamente confiáveis; validar azp quando presente e exigir semântica adequada para múltiplas audiências.
- Aceite: fixtures com audiência única correta passam; multi-audience não confiável, azp ausente/incompatível e client diferente falham. OIDC Core requer rejeição quando há audiências adicionais não confiáveis. OIDC Core §3.1.3.7
- Provas: suíte negativa local, provedor genérico real e conformance aplicável.
AUD-004 — Social signup não registra consentimento imutável/configurado
- Prioridade/natureza: P1; funcionalidade ausente, defeito de código e gap de teste.
- Requisito: consentimento versionado e exportação completa, AK-022.
- Local: dependências de [SocialIdentityService.java (line 64)](/home/breno/Workspaces/ws-antigravity/authkit/src/main/java/io/github/brenomega/authkit/service/SocialIdentityService.java:64); criação social em [linha 190 (line 190)](/home/breno/Workspaces/ws-antigravity/authkit/src/main/java/io/github/brenomega/authkit/service/SocialIdentityService.java:190); constructor usa defaults em [User.java (line 133)](/home/breno/Workspaces/ws-antigravity/authkit/src/main/java/io/github/brenomega/authkit/domain/user/entity/User.java:133). O caminho normal usa configuração e ledger em [RegistrationService.java (line 111)](/home/breno/Workspaces/ws-antigravity/authkit/src/main/java/io/github/brenomega/authkit/service/RegistrationService.java:111).
- Cenário: operador configura novas versões de termos/política; usuário cria conta somente via OIDC. O snapshot fica com defaults e nenhum consent_event é criado.
- Impacto: exportação traz consentHistory vazio e versão incorreta; ausência de evidência imutável da aceitação.
- Correção: injetar configuração e ConsentEventService, chamar recordConsent() e recordCurrentConsent() na mesma transação social.
- Aceite: social signup deve gravar exatamente um evento com versões configuradas; falha do evento deve reverter usuário e identidade.
- Provas: integração social+PostgreSQL, export completo, rollback e concorrência.
AUD-005 — OpenAPI GA semanticamente incompleto
- Prioridade/natureza: P1; drift de documentação e gap de teste.
- Requisito: AK-025 e contrato canônico de integração.
- Local: omissões começam em [openapi.yaml (line 11)](/home/breno/Workspaces/ws-antigravity/authkit/docs/openapi.yaml:11); respostas genéricas em [linha 412 (line 412)](/home/breno/Workspaces/ws-antigravity/authkit/docs/openapi.yaml:412); ApiResponse.data irrestrito em [linha 685 (line 685)](/home/breno/Workspaces/ws-antigravity/authkit/docs/openapi.yaml:685). O teste exige somente alguma resposta em [OpenApiContractTest.java (line 65)](/home/breno/Workspaces/ws-antigravity/authkit/src/test/java/io/github/brenomega/authkit/OpenApiContractTest.java:65).
- Cenário: gerar cliente para login, discovery, JWKS, perfil, MFA, passkeys, social, userinfo ou admin lists. O gerador obtém void ou object sem semântica.
- Impacto: clientes não podem ser gerados/validados com segurança; headers, envelopes e modelos podem divergir sem falhar CI.
- Correção: schemas concretos por operação e resposta, incluindo headers e erros; documentar explicitamente respostas sem corpo.
- Aceite: toda resposta 2xx com corpo resolve para schema concreto; revocation é explicitamente no-body; fixtures reais validam contra o OpenAPI.
- Provas: contract test reforçado, geração de cliente e validação de respostas representativas.
AUD-006 — Sanitização não foi somente remoção segura
- Prioridade/natureza: P2; regressão de sanitização e higiene de release/OSS.
- Requisito: AK-032 e AK-036.
- Local: prompt de agente em [.agents/skills/grilling/SKILL.md (line 1)](/home/breno/Workspaces/ws-antigravity/authkit/.agents/skills/grilling/SKILL.md:1), origem externa em [skills-lock.json (line 1)](/home/breno/Workspaces/ws-antigravity/authkit/skills-lock.json:1), Javadoc obsoleto em [AdminService.java (line 61)](/home/breno/Workspaces/ws-antigravity/authkit/src/main/java/io/github/brenomega/authkit/service/AdminService.java:61).
- Cenário: comparação contextual de 108cd95 com HEAD: 327 arquivos, +3.686/-2.872; 324 modificados e 3 adicionados. A alteração de formatação gerou AUD-001 e material de agente foi adicionado.
- Impacto: escopo de revisão ampliado, source distribution contaminada por material não pertencente ao produto e evidência anterior invalidada.
- Correção: separar tooling de agente da distribuição; revisar o lote com allowlist explícita; corrigir Javadocs de papéis.
- Aceite: diff final contém somente mudanças justificadas; nenhuma .agents/skills-lock; suíte e evidence ledger regenerados.
AUD-007 — Fronteira de kid é inconsistente
- Prioridade/natureza: P2; defeito de código, risco operacional e drift.
- Requisito: AK-019, AK-027 e rotação segura.
- Local: validator aceita kid ausente em [JwtConfig.java (line 137)](/home/breno/Workspaces/ws-antigravity/authkit/src/main/java/io/github/brenomega/authkit/infrastructure/security/JwtConfig.java:137); JWKS remove o kid ativo quando revogado em [JwtKeyService.java (line 68)](/home/breno/Workspaces/ws-antigravity/authkit/src/main/java/io/github/brenomega/authkit/infrastructure/security/JwtKeyService.java:68), mas o encoder continua usando-o em [linha 58 (line 58)](/home/breno/Workspaces/ws-antigravity/authkit/src/main/java/io/github/brenomega/authkit/infrastructure/security/JwtKeyService.java:58).
- Cenário: configurar o key-id ativo também na lista revogada ou apresentar token válido sem kid.
- Impacto: auto-DoS na rotação/revogação e divergência com [SYSTEM_DESIGN.md (line 50)](/home/breno/Workspaces/ws-antigravity/authkit/docs/architecture/SYSTEM_DESIGN.md:50).
- Correção: exigir kid string presente/publicado; impedir startup se o kid ativo estiver revogado ou duplicado.
- Aceite: negativos para ausente, desconhecido, duplicado e ativo-revogado; drill planejado/emergencial downstream.
AUD-008 — Revogação OAuth degrada fail-open
- Prioridade/natureza: P2; risco operacional e drift de documentação.
- Requisito: AK-010 e promessa de revogação viva.
- Local: comportamento admitido em [OAuthTokenRevocationService.java (line 15)](/home/breno/Workspaces/ws-antigravity/authkit/src/main/java/io/github/brenomega/authkit/infrastructure/security/OAuthTokenRevocationService.java:15) e implementação em [linha 82 (line 82)](/home/breno/Workspaces/ws-antigravity/authkit/src/main/java/io/github/brenomega/authkit/infrastructure/security/OAuthTokenRevocationService.java:82); docs prometem imediatismo em [INTEGRATOR.md (line 25)](/home/breno/Workspaces/ws-antigravity/authkit/docs/INTEGRATOR.md:25).
- Cenário: indisponibilidade Redis combinada com restart/evicção do cache local após revogação.
- Impacto: userinfo ou validação local pode aceitar JTI revogado até expirar, no golden limitado a 300 segundos.
- Correção: persistência durável ou fail-closed para checks de revogação em endpoints vivos; documentar claramente a política offline.
- Aceite: restart e falha Redis não ressuscitam JTI revogado; métricas e alertas comprovados.
AUD-009 — Build não é reproduzível por identidade imutável
- Prioridade/natureza: P2; higiene de supply chain.
- Requisito: AK-029 e AK-036.
- Local: imagens-base mutáveis em [Dockerfile (line 13)](/home/breno/Workspaces/ws-antigravity/authkit/Dockerfile:13) e [Dockerfile (line 45)](/home/breno/Workspaces/ws-antigravity/authkit/Dockerfile:45); Compose em [compose.yml (line 5)](/home/breno/Workspaces/ws-antigravity/authkit/deploy/golden/compose.yml:5), [linha 31 (line 31)](/home/breno/Workspaces/ws-antigravity/authkit/deploy/golden/compose.yml:31) e [linha 174 (line 174)](/home/breno/Workspaces/ws-antigravity/authkit/deploy/golden/compose.yml:174). O próprio Dockerfile reconhece ranges transitivos Maven.
- Cenário: rebuild do mesmo commit em outra data resolve novas bases ou dependências release.
- Impacto: artefato e SBOM podem mudar sem mudança de tree.
- Correção: pin por digest, lock/resolução controlada de dependências e atualização automatizada revisada.
- Aceite: dois clean builds isolados produzem composição equivalente e todos os inputs aparecem na proveniência.
AUD-010 — Overlay SMTP local não documenta SAN mailpit
- Prioridade/natureza: P3; gap de comprovação e drift documental.
- Requisito: reprodutibilidade da prova local AK-016/Gate 2.
- Local: [testing/golden/README.md (line 1)](/home/breno/Workspaces/ws-antigravity/authkit/testing/golden/README.md:1) e reutilização do certificado TLS em [compose.local-proof.yml (line 15)](/home/breno/Workspaces/ws-antigravity/authkit/testing/golden/compose.local-proof.yml:15).
- Cenário: certificado cobrindo somente o host público provoca No subject alternative DNS name matching mailpit found.
- Impacto: operador não reproduz a alegada aceitação SMTP local.
- Correção: usar secrets separados para SMTP ou documentar certificado local com SAN do host público e mailpit.
- Aceite: execução do zero seguindo somente o README deve entregar uma mensagem ACCEPTED.
7. Análise da sanitização
A conclusão “removeu apenas material seguro” foi refutada.
Aspectos seguros confirmados:
- migrations V1–V25 do candidato aplicam no banco vazio;
- .dockerignore exclui .agents, skills-lock.json, testes, .env e chaves do contexto;
- JAR e imagem não incorporam os prompts de agente;
- remoção dos package-info.java no commit final não produziu regressão de runtime observável.
Aspectos problemáticos:
- o lote após o upstream alterou 324 arquivos e adicionou 3;
- material de agente foi adicionado ao source distribution;
- a alteração de formatação em PostgresMigrationTest mudou a precedência de .formatted() e quebrou a suíte real;
- Javadocs introduzidos/revisados preservam papéis inexistentes;
- evidências documentadas não foram regeneradas depois dessas mudanças.
Logo, a sanitização ampliou o candidato e alterou comportamento de teste; não foi uma remoção puramente mecânica e segura.
8. Contradições encontradas
1. [RELEASE_GATES.md (line 9)](/home/breno/Workspaces/ws-antigravity/authkit/docs/release/RELEASE_GATES.md:9) diz 289/289 verdes; o commit auditado executa 290 e falha com 1 erro real.
2. AK-025 aparece como verificado, mas 21 respostas materiais não têm schema e ApiResponse.data é irrestrito.
3. Docs prometem liveness/revogação OAuth imediata; introspecção não verifica conta e o store de JTI degrada fail-open.
4. SYSTEM_DESIGN.md diz que kid ausente/desconhecido/revogado é rejeitado; o validator permite ausência.
5. SECURITY_MODEL.md diz que não existem tenant/system admins; AdminService afirma o contrário em Javadoc.
6. Registro local grava versões configuradas e consent_event; registro social usa defaults e não grava ledger.
7. O ledger cita digest multiarch e evidência anterior, mas o artefato local desta auditoria possui digest diferente e a suíte desta tree está vermelha.
8. O checker documental passa porque verifica estrutura, pares e links; não detecta essas contradições semânticas.
9. Matriz dos 16 gates
Gate	Estado	Fundamentação/ação restante
1	FALHOU	clean verify real: 1 erro.
2	NÃO COMPROVADO	Smoke local parcial passou; falta operador independente, host limpo e fluxo público integral.
3	NÃO COMPROVADO	Executar DNS/certificado válidos nas topologias same-site e cross-site, com navegador e negação do backend direto.
4	NÃO COMPROVADO	Executar SMTP e Resend reais; preservar IDs do provedor e observação separada de inbox/spam.
5	NÃO COMPROVADO	Corrigir AUD-003/AUD-004 e executar Google + OIDC genérico reais.
6	NÃO COMPROVADO	Cliente externo e suíte de conformance após correção OIDC/OpenAPI.
7	NÃO COMPROVADO	Downstream independente com unknown kid, rotação planejada/emergencial e revogação.
8	NÃO COMPROVADO	Restore local passou; faltam backup criptografado off-host, clean host, RPO/RTO e reconciliação funcional.
9	NÃO COMPROVADO	Redis/email locais exercitados; faltam PostgreSQL controlado no ambiente de referência e alert routing real.
10	NÃO COMPROVADO	Rodar mixed/burst e soak ≥4h em 2 vCPU/4 GiB com métricas completas.
11	FALHOU	Suíte real vermelha e negativos ausentes para lifecycle OAuth, multi-audience e consentimento social.
12	NÃO COMPROVADO	Requer Gate 10 e consulta pós-prova de DEAD, perdas, integridade e pool wait.
13	NÃO COMPROVADO	Rodar scanners bloqueantes na tree e digest imutável; arquivar resultados e suppressions.
14	NÃO COMPROVADO	SBOM local existe; faltam multiarch ligado à tree corrigida, assinatura e proveniência verificável.
15	NÃO COMPROVADO	Entregar somente docs públicos a operador/ambiente independente.
16	FALHOU	Existem cinco P1 GA conhecidos.


Nenhum gate é não aplicável ao golden path.
10. Riscos residuais
Mesmo após os P1, permanecerão:
- ausência de Google, OIDC genérico, SMTP e Resend reais;
- ausência de browser topologies e cliente OAuth/conformance externo;
- ausência de rotação JWKS downstream;
- ausência de soak de quatro horas e capacidade medida;
- ausência de scans de dependências, imagem, código, secrets e IaC;
- ausência de alert routing e exercício completo de PostgreSQL failure;
- ausência de restore off-host/clean-host e RPO/RTO;
- bases/dependências mutáveis;
- assinatura e proveniência ausentes;
- paths JDBC/RabbitMQ/Kubernetes/systemd ainda unsupported e não promovíveis;
- nenhuma autorização humana de publicação.
11. Plano de remediação
1. Manter o candidato congelado e não reutilizar as evidências atuais.
2. Corrigir AUD-001 a AUD-005 e adicionar negativos objetivos.
3. Remover material de agente, corrigir Javadocs e revisar todo o lote de sanitização.
4. Corrigir kid, política de revogação e reprodutibilidade de build.
5. Executar novamente clean verify com PostgreSQL/Redis reais, fresh/upgrade V1–V25, sample, OpenAPI e golden local.
6. Gerar novo JAR, SBOM, imagem e digest a partir da mesma tree limpa.
7. Executar Gates 3–15, vinculando cada prova ao mesmo commit/tree/digest.
8. Realizar nova auditoria independente para o Gate 16.
9. Somente depois, obter autorização humana explícita para assinatura/publicação. Nenhum risco deve ser aceito implicitamente.
12. Veredito final
O candidato não está tecnicamente pronto para a execução final das provas externas: primeiro é necessário resolver os cinco P1, obter uma suíte real verde e regenerar as evidências. Nenhuma tag, publicação, merge ou promoção foi realizada.
NO-GO
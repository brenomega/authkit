# Procedimento do candidato à release

[English — normativo](RELEASING.md)

O repositório identifica o candidato não publicado `0.1.0-rc.1`. Build candidato é evidência para auditoria; não autoriza tag, publicação, promoção, implantação nem aceitação de risco.

1. Registre branch, HEAD, status completo e checksum do patch. Se a árvore estiver dirty, identifique-a como candidato de árvore e não atribua as mudanças apenas ao HEAD.
2. Mantenha revision/changelist, changelog, OpenAPI, docs, labels OCI e manifesto de evidência coerentes.
3. Execute `testing/release/build-candidate-evidence.sh` para build/testes, sample, inspeção JAR/contexto/imagem, SBOM/checksums e inventário honesto de scanners.
4. Execute dependências reais PostgreSQL 17/Redis 7, fresh install/bootstrap/fluxos manuais, restore, falhas e soak de quatro horas.
5. Rode scans bloqueantes de dependência, código estático, secrets, IaC, container e supply chain na árvore/digest exatos.
6. Gere manifesto OCI `linux/amd64` e `linux/arm64`, SBOM/checksums e provenance. Assinatura do digest usa identidade controlada pelo mantenedor; automação local não publica.
7. Reavalie os 16 gates em `docs/release/RELEASE_GATES-ptBR.md`; indisponibilidade permanece `NÃO COMPROVADO`.
8. Solicite nova auditoria independente. Somente o mantenedor autoriza versão final, tag, publicação, promoção ou release.

CI só é evidência quando executado no mesmo commit/árvore congelado. Runs históricos, mocks e tags locais mutáveis não satisfazem gates.

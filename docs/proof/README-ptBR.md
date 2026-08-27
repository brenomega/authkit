# Harnesses de prova do candidato

[English — normativo](README.md)

Os harnesses exercitam o golden path v0.1, mas nunca autoaprovam release. Ligue cada relatório ao HEAD, checksum do patch rastreado, manifesto dos não rastreados, versão candidata e digest OCI imutável. Não registre senhas, tokens, URLs de reset/ação, secrets de provider, chaves privadas nem arquivos de ambiente completos.

Use `testing/release/build-candidate-evidence.sh` para clean build, sample, inspeção de artefatos, imagem local, SBOM/checksums e inventário de scanners. Use `testing/proof/run-proof.sh` para smoke/negativos/chaos e `testing/proof/run-reference-load.sh` para as quatro horas obrigatórias no host de referência. A prova golden de produção usa somente `docs/INSTALL.md`, nunca os Composes de desenvolvimento.

Cada relatório registra comandos/resultados reais, hardware, configuração sem secrets, aceitação do provider separada de observação em inbox, p50/p95/p99/erros/saturação/backlog, invariantes de falha, RPO/RTO e roteamento de alertas. Ferramenta, credencial, ambiente DNS/TLS, conta externa, identidade de assinatura ou operador independente ausente permanece `NÃO COMPROVADO`, com dependência exata em `docs/release/RELEASE_GATES-ptBR.md`.

O template fica em `templates/proof-report-template.md`. Relatórios locais históricos não provam o candidato atual e não permanecem na árvore pública.

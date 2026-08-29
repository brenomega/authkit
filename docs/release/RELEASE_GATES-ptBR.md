# Gates de release do AuthKit v0.1

[English — normativo](RELEASE_GATES.md)

Este é o espelho em português do ledger normativo de validação interna final. O candidato é o commit base `23a6ad66bec32ce247ce8505dd4035a4f9865014`, tree `7a895d2fe552e032f4bfc05293b939f94480cbfa`, mais o patch de remediação não commitado. `PASSOU` exige evidência executada; ausência de prova permanece `NÃO COMPROVADO`.

| # | Gate | Estado | Disposição |
| --- | --- | --- | --- |
| 1 | Clean build e suíte real PostgreSQL/Redis | PASSOU | 303 testes, zero falhas/erros/skips. |
| 2 | Golden path novo | PASSOU | Stack Docker vazia, Flyway V25 e fluxos API/SMTP/bootstrap/failure reais passaram. |
| 3 | TLS/proxy browser same-site/cross-site | NÃO COMPROVADO | DNS, certificado público e browsers externos pendentes. |
| 4 | SMTP e Resend reais | NÃO COMPROVADO | Mailpit prova só SMTP local. |
| 5 | Google e OIDC genérico reais | NÃO COMPROVADO | Credenciais/providers externos pendentes. |
| 6 | Cliente OAuth/OIDC e conformidade externos | NÃO COMPROVADO | Execução externa pendente. |
| 7 | Downstream JWKS/rotação/revogação | NÃO COMPROVADO | Drill downstream externo pendente. |
| 8 | Backup e restore em host limpo | NÃO COMPROVADO | Restore em containers limpos passou; host/off-host independente pendente. |
| 9 | Falhas e alert routing completos | NÃO COMPROVADO | Redis real passou; matriz completa/alertas pendentes. |
| 10 | Burst e soak de quatro horas | NÃO COMPROVADO | Soak atual não executado. |
| 11 | Smoke, negativos, concorrência e one-time | PASSOU | Suíte real e casos HTTP selecionados passaram. |
| 12 | Zero perdas/DEAD/integridade/pool wait sob carga | NÃO COMPROVADO | Depende das provas de carga/falha. |
| 13 | Scanners bloqueantes | NÃO COMPROVADO | Ferramentas indisponíveis localmente. |
| 14 | Assinatura e provenance verificável | NÃO COMPROVADO | SBOM/checksums locais existem; assinatura/digest publicado pendentes. |
| 15 | Operador novo usando apenas docs públicas | NÃO COMPROVADO | Operador independente não executado. |
| 16 | Zero P0/P1 conhecido após validação final | PASSOU | AUD-001–AUD-010 foram revalidados; os cinco P1 e os P2/P3 requeridos estão resolvidos, sem novo P0/P1 GA conhecido. |

Hashes locais: JAR `9869de06d5a0724993f0d27f93009e704065ee6df4b190a237c60b44e3de1882`, CycloneDX JSON `3f37f87d00e53bc38400b4aaea139059136aa990b87aeb8fcaf759b9133e3a58`, XML `6a13a3f9883d591868cfadad835419f5036c5a1768ba1c32d6478dd75ea47d3d` e imagem `sha256:97e7c8d6e999e5fedafaad87b75474e0fd4bd9fa518ba9aa6406b7f090877e3c`.

O Gate 16 está fechado por validação interna. Gates externos sem execução permanecem `NÃO COMPROVADO`; nenhuma tag, publicação ou promoção foi realizada.

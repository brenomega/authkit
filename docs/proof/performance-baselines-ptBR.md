# Baseline de performance do AuthKit v0.1

[English](performance-baselines.md) | [Português (Brasil)](performance-baselines-ptBR.md)

O inglês é autoritativo quando houver divergência de tradução. Este baseline é vinculado à linha `v0.1.0-rc.1` e à identidade imutável do candidate registrada na auditoria consolidada final; não é promessa de capacidade para outro hardware ou workload.

## Tier de referência e limites imutáveis de aceitação

| Dimensão | Referência v0.1 |
| --- | --- |
| Host | Linux, 2 vCPU, 4 GiB de RAM |
| Colocação | AuthKit, PostgreSQL 17 e Redis 7 no mesmo host |
| JVM | Java 21; heap máximo de 1 GiB |
| Workload | Tráfego misto de lifecycle mais hostile burst controlado |
| Soak | Pelo menos 4 horas contínuas |
| Latência de login | p95 <= 1.200 ms |
| Latência de refresh | p95 <= 300 ms |
| Latência de introspecção OAuth | p95 <= 300 ms |
| Latência de listagem de sessões | p95 <= 400 ms |
| Integridade | Zero replay aceito, erro de integridade ou perda de audit crítico |
| Pool | Sem espera Hikari sustentada |
| Email | Sem backlog não resolvido mais antigo que cinco minutos |

Os valores vêm da seção 23 da Release Specification e não podem ser enfraquecidos para tornar verde uma execução falha. O relatório registra intervalo UTC, SHA-256 do source e digest OCI do candidate, limites do host/cgroup, configuração completa, mistura do workload, duração, contagens, p50/p95/p99, classes de erro, saturação de CPU/memória/JVM/DB/Redis/Hikari, consultas de integridade de audit/email e limitações. Exemplos de usuários registrados ou DAU são apenas entradas de planejamento.

## Reprodução

Use `testing/proof/k6/mixed-auth-workload.js` para a mistura estável e os perfis k6 focados para isolar lifecycles. Execute o hostile burst sem desabilitar os controles de abuso em Redis nem alterar o hashing de senha. Rode os probes SQL em `testing/proof/perf/sql/` no PostgreSQL populado e anexe a saída de `EXPLAIN (ANALYZE, BUFFERS)`. Compare os stores Redis e JDBC somente em execuções separadas e explicitamente rotuladas. A topologia golden release-gated do AuthKit v0.1 usa uma única instância; layouts multi-instância permanecem planejamento não suportado.

A execução estável de referência usa por padrão quatro VUs cadenciados para `K6_TARGET_RPS=0.8` agregado, abaixo do budget normativo de 60 requests/minuto para seu único endereço cliente não falsificado. Os logins iniciais com senha são escalonados em quatro segundos para respeitar o pool limitado de admissão Argon2 antes do tráfego estável. Registre qualquer override. Carga agregada maior exige endereços clientes reais independentes; não é válido enfraquecer o limiter nem falsificar headers de forwarding. O hostile burst separado cruza deliberadamente a fronteira e deve permanecer fail-closed.

A auditoria consolidada final é o índice de evidências. Até que seu registro do Gate 10 contenha uma execução completa que satisfaça cada linha acima contra um único candidate congelado, este arquivo define um baseline-alvo, não uma medição aprovada.

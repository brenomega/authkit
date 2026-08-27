# Matriz de suporte

[English](SUPPORT_MATRIX.md) | [Português (Brasil)](SUPPORT_MATRIX-ptBR.md)

O inglês é normativo. Esta matriz está vinculada ao candidato à release v0.1.0.

## Golden path candidato

O único alvo submetido aos gates da v0.1 é um container OCI do AuthKit em Linux com Java 21, PostgreSQL 17, Redis 7 autenticado, envio direto por outbox durável, SMTP sobre TLS ou Resend e reverse proxy TLS. É uma implantação greenfield de instância única e não promete alta disponibilidade nem migração ao vivo. Essa classificação define o escopo do candidato; ela não declara prontidão para produção enquanto as provas de release e a auditoria final estiverem incompletas.

## Caminhos experimentais e não suportados

| Capacidade | Classificação na v0.1 | Padrão | Instruções de release | Motivo |
| --- | --- | --- | --- | --- |
| Token storage PostgreSQL/JDBC sem Redis | Preview não suportado | Desligado | Excluído | Existem código e cobertura unitária, mas faltam smoke dedicado com dependência real e prova operacional. |
| Envio por RabbitMQ | Preview não suportado | Desligado | Excluído | O adapter existe, mas faltam smoke dedicado do broker, prova de falhas e orientação reproduzível ao operador. |
| Manifests Kubernetes | Exemplo não suportado | Desligado | Excluído | Os manifests não são um caminho de produção comprovado na v0.1. |
| Implantação systemd | Exemplo não suportado | Desligado | Excluído | As units são material de referência sem prova completa de host na v0.1. |
| Tiers diferentes do golden path | Material de planejamento não suportado | Desligado | Excluído | Alegações de capacidade e operação não foram medidas. |
| Federação Gov.br | Não suportado | Desligado | Excluído | Não há implementação nem prova com provedor real. |
| Outras versões de banco, Redis, sistema operacional ou plataforma | Não suportado | Desligado | Excluído | Somente as versões do golden path passam pelos gates de release. |

Código de preview não suportado permanece isolado atrás de opt-in explícito e não pode enfraquecer os padrões do golden path. Presença no repositório não é alegação de suporte. Um caminho só pode ser promovido a experimental depois de ter testes unitários e de integração verdes, smoke dedicado com dependência real, configuração reproduzível, limitações documentadas e prova de que seu estado desabilitado não afeta os padrões GA.

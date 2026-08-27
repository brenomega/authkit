# Contrato de templates de e-mail do operador

[English — normativo](EMAIL_TEMPLATES.md)

A aplicação integradora é responsável por todo texto, HTML, localização, texto jurídico e branding de produção. O AuthKit não gera esses assets. Ele carrega um diretório read-only do operador no startup, rejeita template ausente ou inválido e realiza apenas substituição escapada e não executável.

Forneça `<stem>.subject.txt` e `<stem>.body.html` para cada stem:

| Stem | Finalidade | Placeholder obrigatório |
| --- | --- | --- |
| `email-confirmation` | Verificar nova conta | `{{action_url}}` |
| `password-recovery` | Redefinir senha | `{{action_url}}` |
| `password-changed` | Notificar alteração de senha | nenhum |
| `email-change-confirmation` | Verificar novo endereço | `{{action_url}}` |
| `email-change-requested` | Notificar endereço antigo | nenhum |
| `email-changed` | Notificar conclusão | nenhum |
| `email-change-cancelled` | Notificar cancelamento | nenhum |

Subjects devem ter uma linha não vazia de até 255 caracteres. Bodies devem ser arquivos UTF-8 não vazios, dentro do limite configurado (64 KiB por padrão). O renderer rejeita scripts, URLs JavaScript, handlers inline, iframe/object/embed, traversal, escape por symlink, placeholders desconhecidos/malformados e action URLs ausentes. Valores substituídos recebem escape HTML.

`action_url` transporta o segredo one-time no fragmento da URL, não na query. O frontend deve ler o fragmento em memória, removê-lo imediatamente com `history.replaceState`, enviá-lo no corpo JSON sobre TLS e nunca colocá-lo em logs, analytics, referrers, persistência ou relatórios de erro de terceiros.

SMTP recebe uma tentativa de transporte por claim durável porque não existe idempotência SMTP portável. O outbox faz retry/backoff limitado e pode produzir duplicata se a conexão falhar depois do aceite remoto; o operador reconcilia logs do provider e chamados. Resend usa idempotência do provider com retries internos limitados. `ACCEPTED` e `accepted_at` significam apenas aceite do provider, nunca entrega, leitura ou localização na inbox/spam.

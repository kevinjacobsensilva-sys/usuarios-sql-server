# Usuários SQL Server

Tela de portal interno para administrar os **logins de um SQL Server sem abrir o SSMS**:
quem tem acesso a quê, há quanto tempo não entra, criação do acesso com bancos, papel e
servidores vinculados, desativação, reset de senha, exclusão, inatividade e histórico.

Extraída de um portal corporativo em 06/11/2026 e **higienizada**: nomes de empresa,
servidores, bancos, logins de serviço, domínio, IPs e pessoas foram trocados por nomes
genéricos (`Empresa`, `SRV-SQL`, `SRV_RM`, `svc_portal_iam`, `10.0.0.10`...). Não há
dados, senhas nem segredos aqui. É uma referência para reaproveitar em outro lugar, não
um projeto que roda sozinho: ela depende do portal hospedeiro (ver os `INTEGRACAO.md`).

## O que tem

| Pasta | Conteúdo |
|---|---|
| `backend/app/services/acessos_sql.py` | Regras e acesso ao SQL Server (pymssql): visão dos logins, criação, bancos/papéis, servidores vinculados, desativar/resetar/excluir, inatividade, pessoa do RH, Excel |
| `backend/app/routers/acessos_sql.py` | Rotas FastAPI (`/usuarios-sql/*`), só para quem tem a tela; escrita exige o nível `/usuarios-sql/editar` |
| `backend/app/services/email_graph.py` | E-mail de usuário e senha pelo Microsoft Graph (app registration, `Mail.Send` de aplicação) |
| `backend/tests/test_acessos_sql.py` | Testes das funções puras (validar login, gerar senha, papel, plano de bancos e de servidores vinculados...) |
| `web/src/app/(bi)/usuarios-sql/` | Tela Next.js: tabela de logins, gaveta com bancos/servidores/pessoa, criação, visão por banco e por servidor vinculado, Excel |
| `deploy/sqlserver/acessos_sql_setup.sql` | Setup do servidor (rodar uma vez como `sa`): login de serviço, tabelas `DBA_Monitor.acesso_sql_*`, Server Audit de logins, jobs do Agent (coleta a cada 15 min, manutenção 02:30) |
| `*/INTEGRACAO.md` | Trechos que entram no portal hospedeiro (settings, rotas, catálogo de telas, menu, ícone, workflow de deploy) |

## Como funciona

- A API conecta com um **login de serviço próprio** (`svc_portal_iam`, sysadmin), nunca com a
  credencial de leitura das telas. Variáveis: `PORTAL_SQL_IAM_USER` / `PORTAL_SQL_IAM_PASSWORD`.
- **Último acesso** vem de um Server Audit (`SUCCESSFUL_LOGIN_GROUP`) lido por um job a cada 15 min
  e gravado em `DBA_Monitor.dbo.acesso_sql_login_acesso`.
- **Senha nova** nasce com `MUST_CHANGE` + expiração ligada (exigência do SQL); o job de manutenção
  desliga a expiração depois da primeira troca.
- **Servidores vinculados** têm dois modelos, deduzidos pela linha padrão de `sys.linked_logins`:
  - *lista de bloqueio*: a linha padrão tem credencial; quem **não** entra ganha linha sem credencial.
    Liberar/bloquear não exige senha nenhuma.
  - *lista de permissão*: a linha padrão é "não serão feitas"; quem entra tem linha **com** credencial
    remota. Liberar exige a credencial em `PORTAL_SQL_IAM_LINKED_CREDS`
    (JSON `{"SRV_RM": {"usuario": "...", "senha": "..."}}`); sem ela a tela avisa e não faz.
- **Pessoa do RH**: o login é vinculado à chapa; a ficha vem do banco do RH (TOTVS RM, `RGI_PFUNC`).
  Desligado no RH = aviso na tela (desativar automático é opcional, por configuração).
- Logins protegidos (`sa`, sysadmin, `svc_*`, Windows) só aparecem para leitura.

## Para usar em outro lugar

1. Rode `deploy/sqlserver/acessos_sql_setup.sql` no servidor (troque `<<SENHA_SVC_IAM>>`).
2. Crie os secrets/env: `PORTAL_SQL_IAM_USER`, `PORTAL_SQL_IAM_PASSWORD`, opcionalmente
   `PORTAL_SQL_IAM_LINKED_CREDS` e os do e-mail (`PORTAL_MAIL_*`, `PORTAL_PORTAL_URL`).
3. Encaixe os trechos dos `INTEGRACAO.md` no backend, no front e no deploy.
4. Adapte o que é específico do portal de origem: módulo de permissões por tela, ícones e
   tokens de CSS, nome do banco de RH e dos servidores vinculados.

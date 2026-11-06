# Trechos de integração no backend (FastAPI)

Esta tela não é um app sozinho: ela vive dentro de um portal FastAPI que já tem
`app.core.config` (settings via env), `app.core.permissions` (telas e níveis por
usuário) e `app.core.security` (`CurrentUser`). O que entra em cada um:

## `app/core/config.py` — campos de settings

```python
    # --- E-mail por aplicativo (Microsoft Graph) -------------------------
    # Primeiro uso: Auditoria Interna (28/10/2026). Client credentials do
    # mesmo aplicativo das automacoes do RH; o remetente (MAIL_FROM) e a caixa
    # do Kevin no QAS ate a TI liberar a caixa generica da Auditoria Interna.
    # Vazio = e-mail desligado (a tela avisa e nada mais falha).
    mail_tenant_id: str = Field(default="")
    mail_client_id: str = Field(default="")
    mail_client_secret: str = Field(default="")
    mail_from: str = Field(default="")
    mail_from_name: str = Field(default="Portal · Auditoria Interna")
    # Usuarios SQL Server (04/11/2026): usuario e senha vao pela caixa do SUPORTE TI,
    # nao pela da Auditoria. Mesmo app do Graph (Mail.Send e de aplicacao); so muda a
    # caixa. Vazio = cai na PORTAL_MAIL_FROM.
    mail_from_ti: str = Field(default="")
    mail_from_ti_name: str = Field(default="Portal · Suporte TI")
    # Endereco publico do portal (https://qas-portal.empresa.com.br), para os
    # links dos e-mails. Vazio = e-mail sem botao de abrir.
    portal_url: str = Field(default="")

    @property
    def sql_comercial_configurado(self) -> bool:
        return bool(self.sql_comercial_host and self.sql_comercial_user)

    # --- Configuracoes > Usuarios SQL Server (Kevin, 04/11/2026) ---
    #
    # A tela cria e controla os LOGINS do SQL Server (bancos, papeis, servidores
    # vinculados, desativacao). Isso exige privilegio de servidor, que a credencial de
    # leitura das telas (PORTAL_SQL_COMERCIAL_*) nao tem e nao deve ter. Entra aqui
    # um login de servico proprio, `svc_portal_iam`, criado por
    # deploy/sqlserver/acessos_sql_setup.sql e usado SO por services/acessos_sql.
    # Mesmo host/porta do PORTAL_SQL_COMERCIAL_*. Vazio = a tela diz o que falta.
    sql_iam_user: str = Field(default="")
    sql_iam_password: str = Field(default="")
    # Servidor vinculado no modelo de LISTA DE PERMISSAO (hoje so o SRV_RM/RM):
    # liberar alguem la exige a credencial remota, que fica aqui como JSON
    # {"SRV_RM": {"usuario": "sa", "senha": "..."}}. Sem a entrada, a tela
    # mostra o servidor como "manual" e nao tenta liberar.
    sql_iam_linked_creds: str = Field(default="")

    @property
    def sql_iam_configurado(self) -> bool:
        return bool(self.sql_comercial_host and self.sql_iam_user and self.sql_iam_password)
```

## `app/main.py`

```python
from app.routers import acessos_sql
app.include_router(acessos_sql.router)
```

## `app/core/permissions.py` — catálogo de telas (duas chaves)

```python
    # T.I. -- Usuarios SQL Server (Kevin, 2026-11-04). Os logins do SQL Server pela
    # tela: quem tem acesso a que, ultimo acesso, criacao com bancos/papeis/servidores
    # vinculados e e-mail. Duas chaves: a tela (somente visualizacao) e /editar (cria,
    # altera, desativa, reseta, exclui, configura a inatividade).
    "/usuarios-sql",
    "/usuarios-sql/editar",
```

## `app/core/permissions_rules.py` — nível "editar" ligado à tela-mãe

```python
NIVEIS_DE_TELA: dict[str, str] = {
    "/auditoria-interna/auditor": "/auditoria-interna",
    "/usuarios-sql/editar": "/usuarios-sql",
}
```

O router usa `require_page("/usuarios-sql")` para ver e `require_page("/usuarios-sql/editar")`
para criar/alterar/excluir; `is_page_allowed`/`resolve_access` vêm do mesmo módulo.

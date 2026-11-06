/* ============================================================================
   Portal · Configuracoes > Acessos SQL — setup do SERVIDOR (SQL Server)
   04/11/2026 · rodar UMA vez, conectado como sa no 10.0.0.10 (SRV-SQL)
   Idempotente: rodar de novo nao duplica nada.

   O que cria:
     1. login de servico svc_portal_iam (sysadmin) — o unico que a API usa para
        criar/alterar logins. Senha: troque <<SENHA_SVC_IAM>> e guarde nos secrets
        PORTAL_SQL_IAM_USER / PORTAL_SQL_IAM_PASSWORD do repo Empresa/Portal.
     2. em DBA_Monitor: acesso_sql_cadastro (e-mail/nome/chapa/setor por login),
        acesso_sql_login_acesso (ultimo acesso), acesso_sql_config, acesso_sql_evento.
     3. Server Audit Portal_Logins (login com sucesso) em arquivo, limitado a
        8 x 64 MB em C:\db\Audit — o servidor so registrava FALHA de login.
     4. procedures acesso_sql_coletar (audit -> tabela) e acesso_sql_manutencao
        (desliga a expiracao depois da 1a troca; desativa por inatividade se a
        tela configurar dias > 0) + 2 jobs do Agent (15 min e 02:30).

   Por que sysadmin e nao securityadmin: colocar usuario nos papeis FIXOS de banco
   (db_datareader etc.) exige db_owner em cada banco, e securityadmin pode se
   conceder CONTROL SERVER de qualquer jeito — seria a mesma forca com mais
   pecas. A senha vive so nos secrets; o login nao e usado por pessoa nenhuma.
   ============================================================================ */
SET NOCOUNT ON;
IF IS_SRVROLEMEMBER('sysadmin') <> 1
BEGIN
    DECLARE @quem sysname = SUSER_SNAME();
    RAISERROR('Conectado como %s, que nao e sysadmin. Reconecte como sa. Nada foi alterado.', 16, 1, @quem);
    RETURN;
END

DECLARE @senha nvarchar(128) = N'<<SENHA_SVC_IAM>>';
IF @senha = N'<<SENHA_SVC_IAM>>' AND NOT EXISTS (SELECT 1 FROM sys.server_principals WHERE name = N'svc_portal_iam')
BEGIN
    RAISERROR('Troque <<SENHA_SVC_IAM>> pela senha do login de servico (24+ caracteres). Nada foi alterado.', 16, 1);
    RETURN;
END

/* ---------------------------------------------------------------- 1. login de servico */
IF NOT EXISTS (SELECT 1 FROM sys.server_principals WHERE name = N'svc_portal_iam')
BEGIN
    DECLARE @ddl nvarchar(max) = N'CREATE LOGIN [svc_portal_iam] WITH PASSWORD = N''' + REPLACE(@senha, '''', '''''')
        + N''', CHECK_POLICY = ON, CHECK_EXPIRATION = OFF, DEFAULT_DATABASE = master';
    EXEC (@ddl);
    PRINT 'login svc_portal_iam criado';
END
ELSE PRINT 'login svc_portal_iam ja existia (senha mantida)';
IF IS_SRVROLEMEMBER('sysadmin', 'svc_portal_iam') <> 1
    ALTER SERVER ROLE sysadmin ADD MEMBER [svc_portal_iam];
GO

/* ---------------------------------------------------------------- 2. tabelas em DBA_Monitor */
IF DB_ID('DBA_Monitor') IS NULL
BEGIN RAISERROR('Banco DBA_Monitor nao existe neste servidor.', 16, 1); RETURN; END
GO
USE DBA_Monitor;
GO
IF OBJECT_ID('dbo.acesso_sql_cadastro') IS NULL
CREATE TABLE dbo.acesso_sql_cadastro (
    login_name     sysname        NOT NULL PRIMARY KEY,
    nome           nvarchar(200)  NULL,
    email          nvarchar(254)  NULL,
    chapa          varchar(16)    NULL,
    setor          nvarchar(200)  NULL,
    criado_por     nvarchar(254)  NULL,
    criado_em      datetime2(0)   NOT NULL CONSTRAINT DF_asc_criado DEFAULT SYSDATETIME(),
    atualizado_em  datetime2(0)   NULL
);
/* Excecao por login (04/11/2026, caso do um colaborador que vira PJ): ficha demitida no RM, mas o
   login fica. O job de desligados pula quem tem 1 aqui; a tela marca na gaveta. */
IF COL_LENGTH('dbo.acesso_sql_cadastro', 'excecao_desligado') IS NULL
    ALTER TABLE dbo.acesso_sql_cadastro ADD excecao_desligado bit NOT NULL CONSTRAINT DF_asc_excecao DEFAULT 0;
/* Login GENERICO (04/11/2026, Kevin: baseacesso, Carteira, Painellogistica...): nao e uma
   pessoa; guarda a finalidade e quem responde por ele. Fica fora da busca do RM e da
   regra de desligado. */
IF COL_LENGTH('dbo.acesso_sql_cadastro', 'generico') IS NULL
    ALTER TABLE dbo.acesso_sql_cadastro ADD generico bit NOT NULL CONSTRAINT DF_asc_generico DEFAULT 0;
IF COL_LENGTH('dbo.acesso_sql_cadastro', 'finalidade') IS NULL
    ALTER TABLE dbo.acesso_sql_cadastro ADD finalidade nvarchar(200) NULL;
IF OBJECT_ID('dbo.acesso_sql_login_acesso') IS NULL
CREATE TABLE dbo.acesso_sql_login_acesso (
    login_name      sysname        NOT NULL PRIMARY KEY,
    primeiro_em     datetime2(0)   NULL,
    ultimo_em       datetime2(0)   NULL,
    total           bigint         NOT NULL CONSTRAINT DF_asla_total DEFAULT 0,
    ultimo_host     nvarchar(128)  NULL,
    ultimo_programa nvarchar(128)  NULL,
    atualizado_em   datetime2(0)   NOT NULL CONSTRAINT DF_asla_atu DEFAULT SYSDATETIME()
);
IF OBJECT_ID('dbo.acesso_sql_config') IS NULL
CREATE TABLE dbo.acesso_sql_config (
    chave  varchar(64)    NOT NULL PRIMARY KEY,
    valor  nvarchar(400)  NULL
);
IF OBJECT_ID('dbo.acesso_sql_evento') IS NULL
CREATE TABLE dbo.acesso_sql_evento (
    id          bigint IDENTITY(1,1) NOT NULL PRIMARY KEY,
    em          datetime2(0)   NOT NULL CONSTRAINT DF_ase_em DEFAULT SYSDATETIME(),
    por         nvarchar(254)  NULL,
    acao        varchar(40)    NOT NULL,
    login_alvo  sysname        NULL,
    detalhe     nvarchar(max)  NULL
);
IF NOT EXISTS (SELECT 1 FROM dbo.acesso_sql_config WHERE chave = 'dias_inatividade')
    INSERT INTO dbo.acesso_sql_config (chave, valor) VALUES ('dias_inatividade', '0');
IF NOT EXISTS (SELECT 1 FROM dbo.acesso_sql_config WHERE chave = 'audit_inicio')
    INSERT INTO dbo.acesso_sql_config (chave, valor) VALUES ('audit_inicio', CONVERT(varchar(19), SYSDATETIME(), 120));
IF NOT EXISTS (SELECT 1 FROM dbo.acesso_sql_config WHERE chave = 'audit_marca')
    INSERT INTO dbo.acesso_sql_config (chave, valor) VALUES ('audit_marca', '2000-01-01 00:00:00');
/* Desligado no RM (chapa vinculada com CODSITUACAO = 'D' em todas as coligadas): a tela
   AVISA e o Kevin decide (04/11/2026). '1' liga a desativacao automatica pelo job de
   15 min; '0' (padrao) so avisa. Muda pela tela, em "Desativacao automatica". */
IF NOT EXISTS (SELECT 1 FROM dbo.acesso_sql_config WHERE chave = 'desativar_desligados')
    INSERT INTO dbo.acesso_sql_config (chave, valor) VALUES ('desativar_desligados', '0');
PRINT 'tabelas acesso_sql_* ok';
GO

/* ---------------------------------------------------------------- 3. Server Audit: login com sucesso */
USE master;
GO
EXEC master.dbo.xp_create_subdir N'C:\db\Audit';
GO
IF NOT EXISTS (SELECT 1 FROM sys.server_audits WHERE name = N'Portal_Logins')
    CREATE SERVER AUDIT [Portal_Logins]
    TO FILE (FILEPATH = N'C:\db\Audit\', MAXSIZE = 64 MB, MAX_ROLLOVER_FILES = 8, RESERVE_DISK_SPACE = OFF)
    WITH (QUEUE_DELAY = 5000, ON_FAILURE = CONTINUE);
IF EXISTS (SELECT 1 FROM sys.server_audits WHERE name = N'Portal_Logins' AND is_state_enabled = 0)
    ALTER SERVER AUDIT [Portal_Logins] WITH (STATE = ON);
IF NOT EXISTS (SELECT 1 FROM sys.server_audit_specifications WHERE name = N'Portal_Logins_Spec')
    CREATE SERVER AUDIT SPECIFICATION [Portal_Logins_Spec]
    FOR SERVER AUDIT [Portal_Logins]
    ADD (SUCCESSFUL_LOGIN_GROUP)
    WITH (STATE = ON);
PRINT 'audit Portal_Logins ligado';
GO

/* ---------------------------------------------------------------- 4. procedures */
USE DBA_Monitor;
GO
CREATE OR ALTER PROCEDURE dbo.acesso_sql_coletar
AS
/* Audit (login com sucesso) -> acesso_sql_login_acesso, so o que chegou desde a marca.
   O audit grava em UTC; aqui vira hora local. Sessoes abertas agora tambem contam
   (cobre o periodo antes do audit e quem ficou conectado). */
BEGIN
    SET NOCOUNT ON;
    DECLARE @marca datetime2(0) = ISNULL(TRY_CONVERT(datetime2(0), (SELECT valor FROM dbo.acesso_sql_config WHERE chave = 'audit_marca'), 120), '2000-01-01');
    DECLARE @desloc int = DATEDIFF(minute, SYSUTCDATETIME(), SYSDATETIME());

    SELECT server_principal_name AS login_name,
           DATEADD(minute, @desloc, CONVERT(datetime2(0), event_time)) AS em,
           event_time AS em_utc,
           LEFT(ISNULL(CONVERT(nvarchar(128), client_ip), ''), 128) AS host_name,
           LEFT(ISNULL(application_name, ''), 128) AS programa
    INTO #ev
    FROM sys.fn_get_audit_file(N'C:\db\Audit\Portal_Logins*.sqlaudit', DEFAULT, DEFAULT)
    WHERE action_id = 'LGIS' AND succeeded = 1 AND event_time > @marca
      AND server_principal_name NOT LIKE 'NT %' AND server_principal_name NOT LIKE '##%';

    ;WITH agg AS (
        SELECT login_name, MIN(em) AS primeiro, MAX(em) AS ultimo, COUNT(*) AS n
        FROM #ev GROUP BY login_name
    ), ult AS (
        SELECT login_name, host_name, programa,
               ROW_NUMBER() OVER (PARTITION BY login_name ORDER BY em DESC) AS rn
        FROM #ev
    )
    MERGE dbo.acesso_sql_login_acesso AS d
    USING (SELECT a.login_name, a.primeiro, a.ultimo, a.n, u.host_name, u.programa
           FROM agg a JOIN ult u ON u.login_name = a.login_name AND u.rn = 1) AS s
    ON d.login_name = s.login_name
    WHEN MATCHED THEN UPDATE SET
        primeiro_em = CASE WHEN d.primeiro_em IS NULL OR s.primeiro < d.primeiro_em THEN s.primeiro ELSE d.primeiro_em END,
        ultimo_em = CASE WHEN d.ultimo_em IS NULL OR s.ultimo > d.ultimo_em THEN s.ultimo ELSE d.ultimo_em END,
        total = d.total + s.n,
        ultimo_host = CASE WHEN d.ultimo_em IS NULL OR s.ultimo > d.ultimo_em THEN s.host_name ELSE d.ultimo_host END,
        ultimo_programa = CASE WHEN d.ultimo_em IS NULL OR s.ultimo > d.ultimo_em THEN s.programa ELSE d.ultimo_programa END,
        atualizado_em = SYSDATETIME()
    WHEN NOT MATCHED THEN INSERT (login_name, primeiro_em, ultimo_em, total, ultimo_host, ultimo_programa)
        VALUES (s.login_name, s.primeiro, s.ultimo, s.n, s.host_name, s.programa);

    /* sessoes abertas agora (login_time ja e hora local) */
    MERGE dbo.acesso_sql_login_acesso AS d
    USING (SELECT login_name, MAX(login_time) AS lt, MAX(host_name) AS host_name, MAX(program_name) AS programa
           FROM sys.dm_exec_sessions WHERE is_user_process = 1 AND login_name NOT LIKE 'NT %'
           GROUP BY login_name) AS s
    ON d.login_name = s.login_name
    WHEN MATCHED AND (d.ultimo_em IS NULL OR s.lt > d.ultimo_em) THEN UPDATE SET
        ultimo_em = s.lt, ultimo_host = LEFT(s.host_name, 128), ultimo_programa = LEFT(s.programa, 128), atualizado_em = SYSDATETIME(),
        primeiro_em = ISNULL(d.primeiro_em, s.lt)
    WHEN NOT MATCHED THEN INSERT (login_name, primeiro_em, ultimo_em, total, ultimo_host, ultimo_programa)
        VALUES (s.login_name, s.lt, s.lt, 0, LEFT(s.host_name, 128), LEFT(s.programa, 128));

    DECLARE @nova datetime2(0) = (SELECT MAX(em_utc) FROM #ev);
    IF @nova IS NOT NULL
        UPDATE dbo.acesso_sql_config SET valor = CONVERT(varchar(19), @nova, 120) WHERE chave = 'audit_marca';
    DROP TABLE #ev;
END
GO

CREATE OR ALTER PROCEDURE dbo.acesso_sql_manutencao
AS
/* 1) Senha SEM vencimento depois da primeira troca: o login nasce com expiracao
      ligada so para obrigar a troca (MUST_CHANGE exige isso). Trocou -> desliga.
   2) Inatividade: se dias_inatividade > 0, desativa login SQL de pessoa que nao
      entra ha mais de N dias (contando so a partir do inicio do audit, para nao
      desativar todo mundo no primeiro dia). Nunca mexe em sa, sysadmin, svc_*, portal_*. */
BEGIN
    SET NOCOUNT ON;
    DECLARE @nome sysname, @sql nvarchar(400);

    DECLARE c1 CURSOR LOCAL FAST_FORWARD FOR
        SELECT name FROM sys.sql_logins
        WHERE is_expiration_checked = 1
          AND CONVERT(int, LOGINPROPERTY(name, 'IsMustChange')) = 0
          AND CONVERT(datetime, LOGINPROPERTY(name, 'PasswordLastSetTime')) > DATEADD(minute, 1, create_date)
          AND name <> 'sa' AND name NOT LIKE 'svc[_]%' AND name NOT LIKE 'portal[_]%' AND name NOT LIKE '##%';
    OPEN c1; FETCH NEXT FROM c1 INTO @nome;
    WHILE @@FETCH_STATUS = 0
    BEGIN
        SET @sql = N'ALTER LOGIN ' + QUOTENAME(@nome) + N' WITH CHECK_EXPIRATION = OFF';
        BEGIN TRY
            EXEC (@sql);
            INSERT INTO dbo.acesso_sql_evento (por, acao, login_alvo, detalhe) VALUES ('job', 'expiracao_off', @nome, 'senha trocada pelo usuario: expiracao desligada');
        END TRY BEGIN CATCH
            INSERT INTO dbo.acesso_sql_evento (por, acao, login_alvo, detalhe) VALUES ('job', 'erro', @nome, ERROR_MESSAGE());
        END CATCH
        FETCH NEXT FROM c1 INTO @nome;
    END
    CLOSE c1; DEALLOCATE c1;

    DECLARE @dias int = TRY_CONVERT(int, (SELECT valor FROM dbo.acesso_sql_config WHERE chave = 'dias_inatividade'));
    DECLARE @inicio datetime2(0) = TRY_CONVERT(datetime2(0), (SELECT valor FROM dbo.acesso_sql_config WHERE chave = 'audit_inicio'), 120);
    IF ISNULL(@dias, 0) > 0 AND @inicio IS NOT NULL
    BEGIN
        DECLARE @limite datetime2(0) = DATEADD(day, -@dias, SYSDATETIME());
        DECLARE c2 CURSOR LOCAL FAST_FORWARD FOR
            SELECT l.name FROM sys.sql_logins l
            LEFT JOIN dbo.acesso_sql_login_acesso a ON a.login_name = l.name
            WHERE l.is_disabled = 0
              AND ISNULL(IS_SRVROLEMEMBER('sysadmin', l.name), 0) = 0
              AND l.name <> 'sa' AND l.name NOT LIKE 'svc[_]%' AND l.name NOT LIKE 'portal[_]%' AND l.name NOT LIKE '##%'
              AND @inicio < @limite
              AND l.create_date < @limite
              AND ISNULL(a.ultimo_em, @inicio) < @limite;
        OPEN c2; FETCH NEXT FROM c2 INTO @nome;
        WHILE @@FETCH_STATUS = 0
        BEGIN
            SET @sql = N'ALTER LOGIN ' + QUOTENAME(@nome) + N' DISABLE';
            BEGIN TRY
                EXEC (@sql);
                INSERT INTO dbo.acesso_sql_evento (por, acao, login_alvo, detalhe) VALUES ('job', 'desativar_inatividade', @nome, CONVERT(varchar(10), @dias) + ' dias sem acesso');
            END TRY BEGIN CATCH
                INSERT INTO dbo.acesso_sql_evento (por, acao, login_alvo, detalhe) VALUES ('job', 'erro', @nome, ERROR_MESSAGE());
            END CATCH
            FETCH NEXT FROM c2 INTO @nome;
        END
        CLOSE c2; DEALLOCATE c2;
    END
END
GO
CREATE OR ALTER PROCEDURE dbo.acesso_sql_desligados
AS
/* Pessoa desligada no RM nao pode continuar entrando (Kevin, 04/11/2026). Vale para o
   login de pessoa com chapa vinculada no cadastro da tela cuja ficha em
   BancoRH.dbo.RGI_PFUNC (copia diaria do RM) esta com CODSITUACAO = 'D' em TODAS as
   coligadas -- quem foi transferido tem uma ficha demitida e outra ativa, e fica.
   Desativa (nao exclui): o historico e os acessos ficam para a auditoria; excluir e
   decisao de gente, pela tela. Nunca mexe em sa, sysadmin, svc_*, portal_*. */
BEGIN
    SET NOCOUNT ON;
    IF ISNULL((SELECT valor FROM dbo.acesso_sql_config WHERE chave = 'desativar_desligados'), '0') <> '1' RETURN;
    DECLARE @nome sysname, @chapa varchar(16), @sql nvarchar(400);
    DECLARE c CURSOR LOCAL FAST_FORWARD FOR
        SELECT c.login_name, c.chapa
        FROM dbo.acesso_sql_cadastro c
        JOIN sys.sql_logins l ON l.name = c.login_name
        WHERE c.chapa IS NOT NULL AND c.chapa <> '' AND l.is_disabled = 0
          AND ISNULL(c.excecao_desligado, 0) = 0
          AND ISNULL(IS_SRVROLEMEMBER('sysadmin', l.name), 0) = 0
          AND l.name <> 'sa' AND l.name NOT LIKE 'svc[_]%' AND l.name NOT LIKE 'portal[_]%'
          /* COLLATE: DBA_Monitor e CI_AS, BancoRH e CI_AI */
          AND EXISTS (SELECT 1 FROM BancoRH.dbo.RGI_PFUNC f
                      WHERE f.CHAPA COLLATE Latin1_General_CI_AS = c.chapa COLLATE Latin1_General_CI_AS AND f.CODSITUACAO = 'D')
          AND NOT EXISTS (SELECT 1 FROM BancoRH.dbo.RGI_PFUNC f
                          WHERE f.CHAPA COLLATE Latin1_General_CI_AS = c.chapa COLLATE Latin1_General_CI_AS AND f.CODSITUACAO <> 'D');
    OPEN c; FETCH NEXT FROM c INTO @nome, @chapa;
    WHILE @@FETCH_STATUS = 0
    BEGIN
        SET @sql = N'ALTER LOGIN ' + QUOTENAME(@nome) + N' DISABLE';
        BEGIN TRY
            EXEC (@sql);
            INSERT INTO dbo.acesso_sql_evento (por, acao, login_alvo, detalhe) VALUES ('job', 'desativar_desligado', @nome, 'chapa ' + @chapa + ' desligada no RM');
        END TRY BEGIN CATCH
            INSERT INTO dbo.acesso_sql_evento (por, acao, login_alvo, detalhe) VALUES ('job', 'erro', @nome, ERROR_MESSAGE());
        END CATCH
        FETCH NEXT FROM c INTO @nome, @chapa;
    END
    CLOSE c; DEALLOCATE c;
END
GO
PRINT 'procedures ok';
GO

/* ---------------------------------------------------------------- 5. jobs do Agent */
USE msdb;
GO
IF NOT EXISTS (SELECT 1 FROM msdb.dbo.sysjobs WHERE name = N'Portal - Acessos SQL - coleta')
BEGIN
    EXEC sp_add_job @job_name = N'Portal - Acessos SQL - coleta', @owner_login_name = N'sa',
         @description = N'Audit de login com sucesso -> DBA_Monitor.dbo.acesso_sql_login_acesso (tela Acessos SQL do Portal)';
    EXEC sp_add_jobstep @job_name = N'Portal - Acessos SQL - coleta', @step_name = N'coletar',
         @subsystem = N'TSQL', @database_name = N'DBA_Monitor', @command = N'EXEC dbo.acesso_sql_coletar; EXEC dbo.acesso_sql_desligados;';
    EXEC sp_add_jobschedule @job_name = N'Portal - Acessos SQL - coleta', @name = N'a cada 15 min',
         @freq_type = 4, @freq_interval = 1, @freq_subday_type = 4, @freq_subday_interval = 15, @active_start_time = 0;
    EXEC sp_add_jobserver @job_name = N'Portal - Acessos SQL - coleta';
    PRINT 'job coleta criado';
END
IF NOT EXISTS (SELECT 1 FROM msdb.dbo.sysjobs WHERE name = N'Portal - Acessos SQL - manutencao')
BEGIN
    EXEC sp_add_job @job_name = N'Portal - Acessos SQL - manutencao', @owner_login_name = N'sa',
         @description = N'Desliga expiracao de senha apos a 1a troca; desativa por inatividade (tela Acessos SQL do Portal)';
    EXEC sp_add_jobstep @job_name = N'Portal - Acessos SQL - manutencao', @step_name = N'manutencao',
         @subsystem = N'TSQL', @database_name = N'DBA_Monitor', @command = N'EXEC dbo.acesso_sql_manutencao';
    EXEC sp_add_jobschedule @job_name = N'Portal - Acessos SQL - manutencao', @name = N'diario 02:30',
         @freq_type = 4, @freq_interval = 1, @freq_subday_type = 1, @active_start_time = 23000;
    EXEC sp_add_jobserver @job_name = N'Portal - Acessos SQL - manutencao';
    PRINT 'job manutencao criado';
END
/* job ja existia (setup rodado antes de 04/11 a tarde): garante o passo dos desligados */
EXEC sp_update_jobstep @job_name = N'Portal - Acessos SQL - coleta', @step_id = 1,
     @command = N'EXEC dbo.acesso_sql_coletar; EXEC dbo.acesso_sql_desligados;';
GO
/* primeira coleta na hora */
EXEC DBA_Monitor.dbo.acesso_sql_coletar;
EXEC DBA_Monitor.dbo.acesso_sql_desligados;
GO
SELECT 'svc_portal_iam' AS login, IS_SRVROLEMEMBER('sysadmin', 'svc_portal_iam') AS sysadmin,
       (SELECT is_state_enabled FROM sys.server_audits WHERE name = 'Portal_Logins') AS audit_on,
       (SELECT COUNT(*) FROM DBA_Monitor.dbo.acesso_sql_login_acesso) AS logins_com_acesso_registrado,
       (SELECT COUNT(*) FROM msdb.dbo.sysjobs WHERE name LIKE 'Portal - Acessos SQL%') AS jobs;

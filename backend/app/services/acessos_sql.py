"""Configuracoes > Acessos SQL (Kevin, 04/11/2026).

A tela que cria e controla os logins do SQL Server (SRV-SQL) sem abrir o
SSMS: usuario, e-mail e setor (do RM), bancos e papel em cada um, servidores
vinculados, senha inicial com troca obrigatoria e SEM vencimento depois, e-mail com
as credenciais, e o controle de quem tem o que e ha quanto tempo nao entra -- a
mesma regra de 30/60/90/120 dias da Auditoria de acessos do portal.

Como se le o servidor
---------------------
Tudo vem das catalogo-views do proprio SQL Server (sys.server_principals,
sys.sql_logins, sys.database_role_members de cada banco, sys.linked_logins) mais
quatro tabelas em DBA_Monitor que o setup cria (deploy/sqlserver/acessos_sql_setup.sql):

  acesso_sql_cadastro        e-mail / nome / chapa / setor por login (o SQL Server
                             nao guarda isso)
  acesso_sql_login_acesso    ultimo acesso por login, alimentado por um Server Audit
                             de login com sucesso + job de 15 min (o servidor so
                             registrava FALHA de login ate aqui)
  acesso_sql_config          dias_inatividade (0 = nao desativa sozinho), marcas do audit
  acesso_sql_evento          o que a tela e os jobs fizeram, por quem, quando

Servidores vinculados: dois modelos, e a tela le qual e qual
-----------------------------------------------------------
Em 04/11/2026 o SRV_RM (RM) ficou no modelo de LISTA DE PERMISSAO (regra de
baixo "nao serao feitas"; quem entra tem linha com credencial remota) e os outros
oito no modelo de LISTA DE BLOQUEIO (regra de baixo com a credencial salva; quem nao
entra tem linha SEM credencial). A API deduz o modelo pela existencia da linha
padrao e age de acordo: bloquear/liberar no modelo de bloqueio nao exige senha
nenhuma; liberar no modelo de permissao exige a credencial remota em
PORTAL_SQL_IAM_LINKED_CREDS. ERP/ERP_QAS/QAS ficaram de fora por decisao do Kevin: a
tela mostra "aberto" e nao mexe.

Privilegio
----------
Conecta como `svc_portal_iam` (PORTAL_SQL_IAM_*), um login de servico sysadmin
usado SO por este modulo. Nao reaproveita core/sqlserver de proposito: aquele e
"somente leitura" por contrato, e este cria login -- a diferenca tem de ser
visivel no import.

Sincrono em thread, conexao por operacao, autocommit (CREATE/ALTER LOGIN nao
aceitam parametro nem transacao; o nome e a senha entram no DDL ja validados e
com aspas dobradas).
"""
from __future__ import annotations

import asyncio
import json
import re
import secrets
import string
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Optional, Sequence

from fastapi import HTTPException, status
from loguru import logger

from app.core.config import get_settings
from app.services import email_graph as mail

SERVIDOR = "SRV-SQL"
SERVIDOR_ENDERECO = "10.0.0.10"
AUDIT_NOME = "Portal_Logins"

# Nome de login: letra, depois letras/digitos/_ . - ; 3 a 64. Sem espaco, sem
# barra (login Windows e DOMINIO\nome e a tela nao cria desses).
LOGIN_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_.\-]{2,63}$")

# O que a tela oferece por banco. "outro" e so leitura: papel que a tela nao
# conhece (db_ddladmin, papel customizado...) aparece e nao e tocado.
PAPEIS: dict[str, list[str]] = {
    "leitura": ["db_datareader"],
    "escrita": ["db_datareader", "db_datawriter"],
    "dono": ["db_owner"],
}
ROTULO_PAPEL = {"leitura": "Leitura", "escrita": "Leitura e escrita", "dono": "Dono do banco", "outro": "Outro", "sem": "Sem papel"}

BANCOS_SISTEMA = {"master", "model", "msdb", "tempdb", "distribution"}
# Familia ERP: fora do controle por decisao do Kevin (04/11/2026).
LS_ABERTOS = {"ERP", "ERP_QAS", "QAS", "QAS TESTE"}
# Logins que a tela lista mas nao desativa, nao reseta e nao exclui.
PROTEGIDOS_EXATOS = {"sa"}
PROTEGIDOS_PREFIXO = ("svc_", "portal_", "##", "NT ")

FAIXAS = ("ate30", "31a60", "61a90", "91a120", "mais120", "nunca")


# ---------------------------------------------------------------- erros
class FonteNaoConfigurada(HTTPException):
    def __init__(self) -> None:
        super().__init__(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"ok": False, "reason": "fonte_nao_configurada",
                    "message": "Acessos SQL nao configurado neste ambiente (PORTAL_SQL_IAM_USER/PASSWORD)."},
        )


class FonteIndisponivel(HTTPException):
    def __init__(self, detalhe: str = "") -> None:
        super().__init__(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"ok": False, "reason": "fonte_indisponivel",
                    "message": "SQL Server indisponivel — tente novamente", "detail": detalhe[:600]},
        )


class SetupPendente(HTTPException):
    def __init__(self, detalhe: str = "") -> None:
        super().__init__(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"ok": False, "reason": "setup_pendente",
                    "message": "O setup do servidor ainda nao foi rodado (deploy/sqlserver/acessos_sql_setup.sql).",
                    "detail": detalhe[:600]},
        )


class Invalido(HTTPException):
    def __init__(self, msg: str, reason: str = "invalido") -> None:
        super().__init__(status_code=status.HTTP_400_BAD_REQUEST,
                         detail={"ok": False, "reason": reason, "message": msg})


# ---------------------------------------------------------------- regras puras (testadas sem banco)
def validar_login(nome: str) -> str:
    n = (nome or "").strip()
    if not LOGIN_RE.match(n):
        raise Invalido("Nome de login invalido: comece com letra e use so letras, numeros, _ . - (3 a 64).")
    if n.lower() in PROTEGIDOS_EXATOS or n.lower().startswith(tuple(p.lower() for p in PROTEGIDOS_PREFIXO)):
        raise Invalido("Esse nome e reservado para contas de servico.")
    return n


def protegido(nome: str, sysadmin: bool = False) -> bool:
    n = (nome or "").lower()
    return sysadmin or n in PROTEGIDOS_EXATOS or n.startswith(tuple(p.lower() for p in PROTEGIDOS_PREFIXO))


def gerar_senha(tamanho: int = 14) -> str:
    """Senha temporaria que passa na politica do Windows (3 das 4 classes) e e
    legivel num e-mail: sem 0/O/l/1/I. Sempre tem maiuscula, minuscula, digito e
    um simbolo de teclado comum."""
    mai = "ABCDEFGHJKLMNPQRSTUVWXYZ"
    minu = "abcdefghijkmnpqrstuvwxyz"
    dig = "23456789"
    sim = "#@!$%&*?"
    todos = mai + minu + dig + sim
    base = [secrets.choice(mai), secrets.choice(minu), secrets.choice(dig), secrets.choice(sim)]
    base += [secrets.choice(todos) for _ in range(max(tamanho, 10) - 4)]
    secrets.SystemRandom().shuffle(base)
    return "".join(base)


def papel_de(roles: Sequence[str]) -> str:
    """O papel que a tela mostra para o conjunto de papeis que o usuario tem no banco."""
    s = {r.lower() for r in roles if r}
    if "db_owner" in s:
        return "dono"
    if "db_datawriter" in s and "db_datareader" in s and s <= {"db_datareader", "db_datawriter"}:
        return "escrita"
    if s == {"db_datareader"}:
        return "leitura"
    if not s:
        return "sem"
    return "outro"


def plano_bancos(atual: dict[str, list[str]], desejado: dict[str, str]) -> list[tuple[str, str, Optional[str]]]:
    """Diferenca entre o que o login tem e o que a tela pediu -> operacoes.

    `atual`: {banco: [papeis]} (banco presente = usuario existe la, mesmo sem papel).
    `desejado`: {banco: papel} com papel em leitura/escrita/dono/sem/remover.
    Devolve [(op, banco, papel_sql)] com op em criar_usuario / add / drop / remover_usuario.
    Banco com papel "outro" (que a tela nao conhece) nunca e tocado.
    """
    ops: list[tuple[str, str, Optional[str]]] = []
    for banco, papel in desejado.items():
        if papel not in ("leitura", "escrita", "dono", "sem", "remover"):
            raise Invalido(f"Papel desconhecido para {banco}: {papel}")
        tem = banco in atual
        roles_atuais = {r.lower() for r in atual.get(banco, [])}
        if papel == "remover":
            if tem:
                ops.append(("remover_usuario", banco, None))
            continue
        if papel_de(sorted(roles_atuais)) == "outro":
            continue  # nao mexe no que nao conhece
        if not tem:
            ops.append(("criar_usuario", banco, None))
        alvo = set(PAPEIS.get(papel, []))
        for r in sorted(roles_atuais - alvo):
            ops.append(("drop", banco, r))
        for r in sorted(alvo - roles_atuais):
            ops.append(("add", banco, r))
    return ops


def modelo_do_ls(nome: str, tem_padrao: bool) -> str:
    """aberto (familia ERP, nao controlado) / bloqueio (padrao existe; linha sem
    credencial = bloqueado) / permissao (sem padrao; linha com credencial = liberado)."""
    if nome in LS_ABERTOS:
        return "aberto"
    return "bloqueio" if tem_padrao else "permissao"


def situacao_no_ls(modelo: str, linha: Optional[dict]) -> str:
    """permitido / bloqueado para um login num servidor vinculado, dada a linha dele
    em sys.linked_logins (None = sem linha)."""
    if modelo == "aberto":
        return "permitido"
    com_credencial = bool(linha) and (bool(linha.get("remote_name")) or bool(linha.get("uses_self")))
    if modelo == "bloqueio":
        return "bloqueado" if (linha is not None and not com_credencial) else "permitido"
    return "permitido" if com_credencial else "bloqueado"


def plano_linked(modelos: dict[str, str], atual: dict[str, Optional[dict]], permitidos: set[str],
                 creds: dict[str, dict]) -> list[tuple[str, str, str]]:
    """-> [(op, ls, motivo)] com op em liberar_drop / bloquear_sem_cred / liberar_com_cred / manual.
    `manual` = modelo de permissao sem credencial configurada: a tela avisa, nao faz."""
    ops: list[tuple[str, str, str]] = []
    for ls, modelo in modelos.items():
        if modelo == "aberto":
            continue
        quer = ls in permitidos
        tem = situacao_no_ls(modelo, atual.get(ls)) == "permitido"
        if quer == tem:
            continue
        if modelo == "bloqueio":
            ops.append(("liberar_drop" if quer else "bloquear_sem_cred", ls, ""))
        else:
            if quer:
                ops.append(("liberar_com_cred", ls, "") if ls in creds else ("manual", ls, "sem credencial remota configurada"))
            else:
                ops.append(("bloquear_drop", ls, ""))
    return ops


def situacao_rm(chapa: Optional[str], ficha: Optional[dict]) -> Optional[str]:
    """ativo / desligado / nao_encontrado para quem tem chapa; None sem chapa.
    Desligado = nenhuma ficha fora de 'D' (transferido entre coligadas segue ativo)."""
    if not chapa:
        return None
    if not ficha or not ficha.get("fichas"):
        return "nao_encontrado"
    return "ativo" if ficha.get("tem_ativa") else "desligado"


def faixa_de(ultimo: Optional[datetime], agora: datetime) -> str:
    if ultimo is None:
        return "nunca"
    if ultimo.tzinfo is None:
        ultimo = ultimo.replace(tzinfo=agora.tzinfo)
    dias = (agora - ultimo).total_seconds() / 86400
    if dias <= 30:
        return "ate30"
    if dias <= 60:
        return "31a60"
    if dias <= 90:
        return "61a90"
    if dias <= 120:
        return "91a120"
    return "mais120"


def ident(nome: str) -> str:
    """[identificador] com ] dobrado."""
    return "[" + nome.replace("]", "]]") + "]"


def lit(valor: str) -> str:
    """N'literal' com ' dobrada."""
    return "N'" + valor.replace("'", "''") + "'"


def credenciais_linked() -> dict[str, dict]:
    raw = (get_settings().sql_iam_linked_creds or "").strip()
    if not raw:
        return {}
    try:
        d = json.loads(raw)
        return {k: v for k, v in d.items() if isinstance(v, dict) and v.get("usuario") and v.get("senha") is not None}
    except Exception:  # noqa: BLE001
        logger.warning("PORTAL_SQL_IAM_LINKED_CREDS nao e JSON valido; ignorado")
        return {}


# ---------------------------------------------------------------- conexao
def _conectar(database: str = "master"):
    import pymssql  # import local: sem credencial o modulo nem e usado

    s = get_settings()
    if not s.sql_iam_configurado:
        raise FonteNaoConfigurada()
    return pymssql.connect(
        server=s.sql_comercial_host, port=str(s.sql_comercial_port),
        user=s.sql_iam_user, password=s.sql_iam_password, database=database,
        login_timeout=8, timeout=90, charset="UTF-8", autocommit=True,
    )


def _linhas(cur) -> list[dict]:
    if not cur.description:
        return []
    nomes = [(d[0] or f"col_{i}") for i, d in enumerate(cur.description)]
    return [dict(zip(nomes, r)) for r in cur.fetchall() or []]


def _rodar(fn: Callable[[Any], Any]) -> Any:
    """Abre a conexao, entrega ao `fn(cursor)` e fecha. Erros de rede/login viram 503."""
    conn = None
    try:
        conn = _conectar()
        return fn(conn.cursor())
    except HTTPException:
        raise
    except Exception as exc:  # noqa: BLE001
        msg = str(exc)
        logger.error("Acessos SQL: {}", msg[:300])
        if "acesso_sql_" in msg and ("Invalid object name" in msg or "Nome de objeto" in msg or "inválido" in msg or "invalido" in msg):
            raise SetupPendente(msg) from exc
        raise FonteIndisponivel(msg) from exc
    finally:
        if conn is not None:
            try:
                conn.close()
            except Exception:  # noqa: BLE001
                pass


async def em_thread(fn: Callable[[Any], Any]) -> Any:
    return await asyncio.to_thread(_rodar, fn)


# ---------------------------------------------------------------- leitura: a visao geral
_SQL_LOGINS = """
SELECT p.name, p.type, p.is_disabled, p.create_date, p.modify_date,
       l.is_policy_checked, l.is_expiration_checked,
       CONVERT(datetime, LOGINPROPERTY(p.name, 'PasswordLastSetTime')) AS senha_em,
       CONVERT(int, LOGINPROPERTY(p.name, 'IsMustChange')) AS must_change,
       CONVERT(int, LOGINPROPERTY(p.name, 'IsLocked')) AS travado,
       ISNULL(IS_SRVROLEMEMBER('sysadmin', p.name), 0) AS sysadmin
FROM sys.server_principals p
LEFT JOIN sys.sql_logins l ON l.principal_id = p.principal_id
WHERE p.type IN ('S', 'U', 'G') AND p.name NOT LIKE '##%' AND p.name NOT LIKE 'NT %'
ORDER BY p.name
"""
_SQL_ROLES_SERVIDOR = """
SELECT m.name AS login, r.name AS papel
FROM sys.server_role_members rm
JOIN sys.server_principals r ON r.principal_id = rm.role_principal_id
JOIN sys.server_principals m ON m.principal_id = rm.member_principal_id
"""
_SQL_BANCOS = """
SELECT name FROM sys.databases
WHERE database_id > 4 AND state = 0 AND is_read_only = 0 AND name NOT IN ('distribution')
ORDER BY name
"""
_SQL_LINKED = """
SELECT s.name AS ls, s.provider, s.data_source,
       ll.local_principal_id, p.name AS login, ll.uses_self_credential AS uses_self, ll.remote_name
FROM sys.servers s
LEFT JOIN sys.linked_logins ll ON ll.server_id = s.server_id
LEFT JOIN sys.server_principals p ON p.principal_id = ll.local_principal_id
WHERE s.is_linked = 1
ORDER BY s.name
"""
_SQL_RM_SITUACAO = """
SELECT c.login_name,
       MAX(CASE WHEN f.CODSITUACAO <> 'D' THEN 1 ELSE 0 END) AS tem_ativa,
       COUNT(*) AS fichas,
       MAX(f.DATADEMISSAO) AS demissao
FROM DBA_Monitor.dbo.acesso_sql_cadastro c
JOIN BancoRH.dbo.RGI_PFUNC f
  ON f.CHAPA COLLATE Latin1_General_CI_AS = c.chapa COLLATE Latin1_General_CI_AS
WHERE c.chapa IS NOT NULL AND c.chapa <> ''
GROUP BY c.login_name
"""
# (COLLATE dos dois lados: DBA_Monitor e CI_AS e o BancoRH e CI_AI -- sem isso o
#  JOIN cai em "collation conflict" e a visao inteira perde o cadastro.)
_SQL_SESSOES = """
SELECT login_name, MAX(login_time) AS login_time, COUNT(*) AS sessoes
FROM sys.dm_exec_sessions WHERE is_user_process = 1 GROUP BY login_name
"""
_SQL_AUDIT = f"""
SELECT a.is_state_enabled AS audit_on,
       (SELECT TOP 1 sp.is_state_enabled FROM sys.server_audit_specifications sp WHERE sp.audit_guid = a.audit_guid) AS spec_on
FROM sys.server_audits a WHERE a.name = '{AUDIT_NOME}'
"""


def _sql_membros(bancos: Sequence[str]) -> str:
    """Um INSERT por banco, cada um protegido: banco em single-user ou em
    restauracao nao pode derrubar a tela inteira."""
    partes = ["CREATE TABLE #m (banco sysname, login sysname, papel sysname NULL);"]
    for b in bancos:
        db = ident(b)
        partes.append(
            f"BEGIN TRY INSERT INTO #m SELECT {lit(b)}, sp.name, r.name "
            f"FROM {db}.sys.database_principals u JOIN sys.server_principals sp ON sp.sid = u.sid "
            f"LEFT JOIN {db}.sys.database_role_members rm ON rm.member_principal_id = u.principal_id "
            f"LEFT JOIN {db}.sys.database_principals r ON r.principal_id = rm.role_principal_id "
            f"WHERE u.type IN ('S','U','G') AND sp.name NOT LIKE '##%' AND sp.name NOT LIKE 'NT %'; "
            f"END TRY BEGIN CATCH END CATCH;"
        )
    partes.append("SELECT banco, login, papel FROM #m; DROP TABLE #m;")
    return "\n".join(partes)


def _coletar_acessos(cur) -> None:
    """Puxa o audit para a tabela de ultimo acesso antes de ler. Barato (so o que
    chegou desde a marca). Setup ausente = ignora: a tela mostra o aviso."""
    try:
        cur.execute("EXEC DBA_Monitor.dbo.acesso_sql_coletar")
        try:
            cur.fetchall()
        except Exception:  # noqa: BLE001
            pass
    except Exception as exc:  # noqa: BLE001
        logger.warning("acesso_sql_coletar: {}", str(exc)[:200])


_COLUNAS_NOVAS = {"excecao_desligado": "CONVERT(bit, 0) AS excecao_desligado",
                  "generico": "CONVERT(bit, 0) AS generico",
                  "finalidade": "CONVERT(nvarchar(200), NULL) AS finalidade"}


def _colunas_cadastro(cur) -> list[str]:
    """As colunas do cadastro, com as que ainda nao existem no servidor viradas em
    constante (o setup v2/v3 pode nao ter rodado)."""
    cur.execute("SELECT name FROM DBA_Monitor.sys.columns WHERE object_id = OBJECT_ID('DBA_Monitor.dbo.acesso_sql_cadastro')")
    existentes = {r["name"] for r in _linhas(cur)}
    base = ["login_name", "nome", "email", "chapa", "setor", "criado_por", "criado_em"]
    return base + [c if c in existentes else alt for c, alt in _COLUNAS_NOVAS.items()]


def _ler_visao(cur) -> dict:
    _coletar_acessos(cur)
    cur.execute(_SQL_LOGINS)
    logins = _linhas(cur)
    cur.execute(_SQL_ROLES_SERVIDOR)
    roles_srv: dict[str, list[str]] = {}
    for r in _linhas(cur):
        roles_srv.setdefault(r["login"], []).append(r["papel"])
    cur.execute(_SQL_BANCOS)
    bancos = [r["name"] for r in _linhas(cur)]
    cur.execute(_sql_membros(bancos))
    membros: dict[str, dict[str, list[str]]] = {}
    for r in _linhas(cur):
        d = membros.setdefault(r["login"], {}).setdefault(r["banco"], [])
        if r["papel"]:
            d.append(r["papel"])
    cur.execute(_SQL_LINKED)
    linked_rows = _linhas(cur)
    cur.execute(_SQL_SESSOES)
    sessoes = {r["login_name"]: r for r in _linhas(cur)}
    cur.execute(_SQL_AUDIT)
    audit = _linhas(cur)

    setup_ok = True
    cadastro: dict[str, dict] = {}
    acessos: dict[str, dict] = {}
    config: dict[str, str] = {}
    eventos: list[dict] = []
    rm: dict[str, dict] = {}
    try:
        # Colunas que chegaram depois do primeiro setup (excecao_desligado no v2,
        # generico/finalidade no v3): antes delas a tela nao pode cair, entao o
        # SELECT se adapta ao que existe.
        cur.execute(f"SELECT {', '.join(_colunas_cadastro(cur))} FROM DBA_Monitor.dbo.acesso_sql_cadastro")
        cadastro = {r["login_name"]: r for r in _linhas(cur)}
        # situacao no RM de quem tem chapa: desligado = CODSITUACAO 'D' em TODAS as fichas
        # (transferido tem uma demitida e outra ativa, e conta como ativo).
        cur.execute(_SQL_RM_SITUACAO)
        rm = {r["login_name"]: r for r in _linhas(cur)}
        cur.execute("SELECT login_name, primeiro_em, ultimo_em, total, ultimo_host, ultimo_programa FROM DBA_Monitor.dbo.acesso_sql_login_acesso")
        acessos = {r["login_name"]: r for r in _linhas(cur)}
        cur.execute("SELECT chave, valor FROM DBA_Monitor.dbo.acesso_sql_config")
        config = {r["chave"]: r["valor"] for r in _linhas(cur)}
        cur.execute("SELECT TOP 300 id, em, por, acao, login_alvo, detalhe FROM DBA_Monitor.dbo.acesso_sql_evento ORDER BY id DESC")
        eventos = _linhas(cur)
    except Exception as exc:  # noqa: BLE001
        setup_ok = False
        logger.warning("Acessos SQL: setup pendente ({})", str(exc)[:160])

    # servidores vinculados: modelo e a linha de cada login
    ls_info: dict[str, dict] = {}
    linha_por_login: dict[str, dict[str, dict]] = {}
    for r in linked_rows:
        info = ls_info.setdefault(r["ls"], {"nome": r["ls"], "provider": r["provider"], "data_source": r["data_source"],
                                            "tem_padrao": False, "remoto_padrao": None})
        if r["local_principal_id"] is None:
            continue
        if r["local_principal_id"] == 0:
            info["tem_padrao"] = True
            info["remoto_padrao"] = r["remote_name"]
        elif r["login"]:
            linha_por_login.setdefault(r["login"], {})[r["ls"]] = {"remote_name": r["remote_name"], "uses_self": r["uses_self"]}
    creds = credenciais_linked()
    linked_servers = []
    modelos: dict[str, str] = {}
    for nome in sorted(ls_info):
        info = ls_info[nome]
        modelo = modelo_do_ls(nome, info["tem_padrao"])
        modelos[nome] = modelo
        linked_servers.append({"nome": nome, "modelo": modelo, "remoto_padrao": info["remoto_padrao"],
                               "data_source": info["data_source"], "controlado": modelo != "aberto",
                               "libera_pela_tela": modelo == "bloqueio" or (modelo == "permissao" and nome in creds)})

    agora = datetime.now(timezone.utc)
    saida = []
    for l in logins:
        nome = l["name"]
        tipo = {"S": "sql", "U": "windows", "G": "grupo"}.get(l["type"], "outro")
        acc = acessos.get(nome) or {}
        ultimo = acc.get("ultimo_em")
        ses = sessoes.get(nome)
        if ses and ses.get("login_time") and (ultimo is None or ses["login_time"] > ultimo):
            ultimo = ses["login_time"]
        ult_utc = ultimo.replace(tzinfo=timezone.utc) if isinstance(ultimo, datetime) and ultimo.tzinfo is None else ultimo
        faixa = faixa_de(ult_utc, agora)
        dias = int((agora - ult_utc).total_seconds() // 86400) if ult_utc else None
        banco_lista = []
        for b in bancos:
            if b in membros.get(nome, {}):
                roles = membros[nome][b]
                banco_lista.append({"banco": b, "papel": papel_de(roles), "roles": roles})
        linked = {ls: situacao_no_ls(modelos[ls], linha_por_login.get(nome, {}).get(ls)) for ls in modelos}
        pes = cadastro.get(nome) or {}
        sit = rm.get(nome)
        pessoa = None
        if pes:
            pessoa = {"nome": pes.get("nome"), "email": pes.get("email"), "chapa": pes.get("chapa"), "setor": pes.get("setor"),
                      "rm_situacao": None if pes.get("generico") else situacao_rm(pes.get("chapa"), sit),
                      "rm_demissao": None if pes.get("generico") else (sit.get("demissao") if sit else None),
                      "excecao_desligado": bool(pes.get("excecao_desligado")),
                      "generico": bool(pes.get("generico")), "finalidade": pes.get("finalidade")}
        sysadmin = bool(l["sysadmin"])
        saida.append({
            "login": nome, "tipo": tipo, "desativado": bool(l["is_disabled"]), "travado": bool(l["travado"]),
            "sysadmin": sysadmin, "roles_servidor": roles_srv.get(nome, []),
            "protegido": protegido(nome, sysadmin) or tipo != "sql",
            "criado_em": l["create_date"], "senha_em": l["senha_em"], "must_change": bool(l["must_change"]),
            "expiracao": bool(l["is_expiration_checked"]), "politica": bool(l["is_policy_checked"]),
            "bancos": banco_lista,
            "linked": linked,
            "linked_permitidos": sum(1 for ls, s in linked.items() if s == "permitido" and modelos[ls] != "aberto"),
            "pessoa": pessoa,
            "ultimo_acesso": ultimo, "dias_sem_acesso": dias, "faixa": faixa,
            "conectado_agora": bool(ses), "total_acessos": acc.get("total"), "ultimo_host": acc.get("ultimo_host"),
            "ultimo_programa": acc.get("ultimo_programa"),
        })

    try:
        dias_inat = int(config.get("dias_inatividade") or 0)
    except ValueError:
        dias_inat = 0
    audit_on = bool(audit and audit[0].get("audit_on") and audit[0].get("spec_on"))
    return {
        "ok": True, "gerado_em": agora, "servidor": SERVIDOR, "endereco": SERVIDOR_ENDERECO,
        "setup_ok": setup_ok, "audit_ligado": audit_on, "audit_desde": config.get("audit_inicio"),
        "email_configurado": mail.configurado(),
        "bancos": [b for b in bancos if b not in BANCOS_SISTEMA],
        "linked_servers": linked_servers,
        # desativar_desligados: '0' por padrao -- a tela avisa e o Kevin decide (04/11/2026).
        "config": {"dias_inatividade": dias_inat, "desativar_desligados": (config.get("desativar_desligados") or "0") == "1"},
        "papeis": [{"id": k, "rotulo": ROTULO_PAPEL[k]} for k in ("leitura", "escrita", "dono")],
        "logins": saida, "eventos": eventos,
    }


async def visao() -> dict:
    return await em_thread(_ler_visao)


# ---------------------------------------------------------------- pessoas do RM (setor automatico)
_SQL_RM = """
SELECT TOP 15 f.CHAPA AS chapa, f.NOME AS nome, f.CODSECAO AS codsecao, s.DESCRICAO AS setor, f.CODSITUACAO AS situacao
FROM BancoRH.dbo.RGI_PFUNC f
LEFT JOIN BancoRH.dbo.RGI_PSECAO s ON s.CODCOLIGADA = f.CODCOLIGADA AND s.CODIGO = f.CODSECAO
WHERE f.CODSITUACAO <> 'D' AND f.NOME LIKE %s
ORDER BY f.NOME
"""


async def pessoas(q: str) -> list[dict]:
    termo = "%" + "%".join(p for p in (q or "").strip().upper().split() if p) + "%"
    if len(termo) < 4:
        return []

    def fn(cur):
        cur.execute(_SQL_RM, (termo,))
        return [{"chapa": r["chapa"], "nome": r["nome"], "setor": r["setor"], "codsecao": r["codsecao"]} for r in _linhas(cur)]

    return await em_thread(fn)


# ---------------------------------------------------------------- escrita
@dataclass
class Quem:
    email: str
    nome: str = ""


def _evento(cur, q: Quem, acao: str, login: str, detalhe: str = "") -> None:
    try:
        cur.execute("INSERT INTO DBA_Monitor.dbo.acesso_sql_evento (por, acao, login_alvo, detalhe) VALUES (%s, %s, %s, %s)",
                    (q.email[:254], acao[:40], login[:128], detalhe[:4000]))
    except Exception as exc:  # noqa: BLE001
        logger.warning("evento nao gravado ({}): {}", acao, str(exc)[:120])


def _login_existe(cur, nome: str) -> Optional[dict]:
    cur.execute("SELECT name, type, is_disabled, ISNULL(IS_SRVROLEMEMBER('sysadmin', name), 0) AS sysadmin FROM sys.server_principals WHERE name = %s", (nome,))
    rows = _linhas(cur)
    return rows[0] if rows else None


def _exigir_login_sql(cur, nome: str, para: str) -> dict:
    l = _login_existe(cur, nome)
    if not l:
        raise Invalido(f"Login {nome} nao existe.", "nao_existe")
    if l["type"] != "S":
        raise Invalido(f"{nome} e login do Windows: a tela so {para} logins SQL.", "windows")
    if protegido(nome, bool(l["sysadmin"])):
        raise Invalido(f"{nome} e conta de servico ou sysadmin: nao se {para} pela tela.", "protegido")
    return l


def _membros_de(cur, login: str, bancos: Sequence[str]) -> dict[str, list[str]]:
    cur.execute(_sql_membros(bancos))
    out: dict[str, list[str]] = {}
    for r in _linhas(cur):
        if r["login"] == login:
            out.setdefault(r["banco"], [])
            if r["papel"]:
                out[r["banco"]].append(r["papel"])
    return out


def _bancos_validos(cur) -> list[str]:
    cur.execute(_SQL_BANCOS)
    return [r["name"] for r in _linhas(cur) if r["name"] not in BANCOS_SISTEMA]


def _aplicar_bancos(cur, login: str, ops: Sequence[tuple[str, str, Optional[str]]]) -> list[str]:
    feitos = []
    for op, banco, papel in ops:
        db, u = ident(banco), ident(login)
        if op == "criar_usuario":
            cur.execute(f"USE {db}; IF NOT EXISTS (SELECT 1 FROM sys.database_principals WHERE name = {lit(login)}) CREATE USER {u} FOR LOGIN {u}; USE master;")
            feitos.append(f"{banco}: usuario criado")
        elif op == "add":
            cur.execute(f"USE {db}; ALTER ROLE {ident(papel or '')} ADD MEMBER {u}; USE master;")
            feitos.append(f"{banco}: +{papel}")
        elif op == "drop":
            cur.execute(f"USE {db}; ALTER ROLE {ident(papel or '')} DROP MEMBER {u}; USE master;")
            feitos.append(f"{banco}: -{papel}")
        elif op == "remover_usuario":
            cur.execute(f"USE {db}; IF EXISTS (SELECT 1 FROM sys.database_principals WHERE name = {lit(login)}) DROP USER {u}; USE master;")
            feitos.append(f"{banco}: usuario removido")
    return feitos


def _derrubar_sessoes(cur, login: str) -> int:
    """KILL em cada sessao aberta do login. Desativar sem isso deixa quem ja esta
    conectado trabalhando ate sair; excluir sem isso e o erro 15434 ("the user is
    currently logged in"), que apareceu no primeiro teste do Kevin (04/11/2026)."""
    cur.execute("SELECT session_id FROM sys.dm_exec_sessions WHERE login_name = %s AND session_id <> @@SPID", (login,))
    ids = [r["session_id"] for r in _linhas(cur)]
    for sid in ids:
        try:
            cur.execute(f"KILL {int(sid)}")
        except Exception as exc:  # noqa: BLE001 -- sessao ja fechou entre o SELECT e o KILL
            logger.warning("KILL {} ({}): {}", sid, login, str(exc)[:120])
    return len(ids)


def _modelos_e_linhas(cur) -> tuple[dict[str, str], dict[str, dict[str, dict]]]:
    cur.execute(_SQL_LINKED)
    tem_padrao: dict[str, bool] = {}
    linhas: dict[str, dict[str, dict]] = {}
    for r in _linhas(cur):
        tem_padrao.setdefault(r["ls"], False)
        if r["local_principal_id"] == 0:
            tem_padrao[r["ls"]] = True
        elif r["login"]:
            linhas.setdefault(r["login"], {})[r["ls"]] = {"remote_name": r["remote_name"], "uses_self": r["uses_self"]}
    return {ls: modelo_do_ls(ls, p) for ls, p in tem_padrao.items()}, linhas


def _aplicar_linked(cur, login: str, permitidos: set[str]) -> tuple[list[str], list[str]]:
    modelos, linhas = _modelos_e_linhas(cur)
    creds = credenciais_linked()
    ops = plano_linked(modelos, linhas.get(login, {}), permitidos, creds)
    feitos, manuais = [], []
    for op, ls, motivo in ops:
        if op == "manual":
            manuais.append(f"{ls}: {motivo}")
            continue
        if op in ("liberar_drop", "bloquear_drop", "liberar_com_cred", "bloquear_sem_cred") and linhas.get(login, {}).get(ls) is not None:
            cur.execute(f"EXEC sp_droplinkedsrvlogin @rmtsrvname = {lit(ls)}, @locallogin = {lit(login)}")
        if op == "bloquear_sem_cred":
            cur.execute(f"EXEC sp_addlinkedsrvlogin @rmtsrvname = {lit(ls)}, @useself = 'FALSE', @locallogin = {lit(login)}, @rmtuser = NULL, @rmtpassword = NULL")
            feitos.append(f"{ls}: bloqueado")
        elif op == "liberar_com_cred":
            c = creds[ls]
            cur.execute(f"EXEC sp_addlinkedsrvlogin @rmtsrvname = {lit(ls)}, @useself = 'FALSE', @locallogin = {lit(login)}, "
                        f"@rmtuser = {lit(str(c['usuario']))}, @rmtpassword = {lit(str(c['senha']))}")
            feitos.append(f"{ls}: liberado")
        elif op == "liberar_drop":
            feitos.append(f"{ls}: liberado")
        elif op == "bloquear_drop":
            feitos.append(f"{ls}: bloqueado")
    return feitos, manuais


def _bloquear_tudo_de_novo_login(cur, login: str, permitidos: set[str]) -> tuple[list[str], list[str]]:
    """Login recem-criado nao tem linha em nenhum servidor vinculado: no modelo de
    bloqueio isso significa LIBERADO. A criacao fecha tudo que a tela nao marcou."""
    return _aplicar_linked(cur, login, permitidos)


def _upsert_cadastro(cur, q: Quem, login: str, nome: Optional[str], email: Optional[str],
                     chapa: Optional[str], setor: Optional[str]) -> None:
    cur.execute(
        "MERGE DBA_Monitor.dbo.acesso_sql_cadastro AS d USING (SELECT %s AS login_name) AS s ON d.login_name = s.login_name "
        "WHEN MATCHED THEN UPDATE SET nome = %s, email = %s, chapa = %s, setor = %s, atualizado_em = SYSDATETIME() "
        "WHEN NOT MATCHED THEN INSERT (login_name, nome, email, chapa, setor, criado_por) VALUES (s.login_name, %s, %s, %s, %s, %s);",
        (login, nome, email, chapa, setor, nome, email, chapa, setor, q.email[:254]),
    )


def _email_credenciais(login: str, senha: str, email: str, nome: Optional[str], bancos: Sequence[str],
                       reset: bool) -> dict:
    s = get_settings()
    titulo = "Seu acesso ao SQL Server foi " + ("redefinido" if reset else "criado")
    como = (
        "Abra o SQL Server Management Studio, conecte em <b>" + mail.esc(SERVIDOR) + "</b> "
        "(autenticacao do SQL Server) com o login e a senha temporaria abaixo. "
        "Na primeira conexao o SQL Server pede a sua nova senha. "
        "Depois da troca a senha <b>nao expira</b>."
    )
    blocos = [
        ("Servidor", f"{mail.esc(SERVIDOR)} ({mail.esc(SERVIDOR_ENDERECO)})"),
        ("Login", f"<code style='font-size:14px'>{mail.esc(login)}</code>"),
        ("Senha temporaria", f"<code style='font-size:14px'>{mail.esc(senha)}</code>"),
        ("Bancos liberados", mail.esc(", ".join(bancos)) if bancos else "nenhum ainda"),
        ("Como trocar a senha", como),
    ]
    html = mail.corpo(titulo, blocos, link=(s.portal_url or None), rotulo_link="Abrir o Portal",
                      rodape="Mensagem automatica do Portal · Suporte TI. Em duvida, responda este e-mail.")
    return html, titulo


async def _enviar(para: str, assunto: str, html: str):
    """Pela caixa do Suporte TI (PORTAL_MAIL_FROM_TI); sem ela, pela caixa padrao."""
    s = get_settings()
    return await mail.enviar([para], assunto, html, de=s.mail_from_ti or None, de_nome=s.mail_from_ti_name)


async def criar(q: Quem, login: str, email: Optional[str], nome: Optional[str], chapa: Optional[str],
                setor: Optional[str], bancos: dict[str, str], linked_permitidos: Sequence[str],
                enviar_email: bool) -> dict:
    login = validar_login(login)
    email = (email or "").strip().lower() or None
    senha = gerar_senha()

    def fn(cur):
        if _login_existe(cur, login):
            raise Invalido(f"Ja existe um login chamado {login}.", "duplicado")
        validos = set(_bancos_validos(cur))
        for b in bancos:
            if b not in validos:
                raise Invalido(f"Banco desconhecido: {b}")
        cur.execute(f"CREATE LOGIN {ident(login)} WITH PASSWORD = {lit(senha)} MUST_CHANGE, CHECK_POLICY = ON, CHECK_EXPIRATION = ON, DEFAULT_DATABASE = master")
        feitos = _aplicar_bancos(cur, login, plano_bancos({}, {b: p for b, p in bancos.items() if p != "remover"}))
        ls_feitos, manuais = _bloquear_tudo_de_novo_login(cur, login, set(linked_permitidos))
        _upsert_cadastro(cur, q, login, nome, email, chapa, setor)
        _evento(cur, q, "criar", login, "; ".join(feitos + ls_feitos) or "sem banco")
        return feitos, ls_feitos, manuais

    feitos, ls_feitos, manuais = await em_thread(fn)
    resultado_email = None
    if enviar_email and email:
        html, titulo = _email_credenciais(login, senha, email, nome, [b for b, p in bancos.items() if p != "remover"], reset=False)
        r = await _enviar(email, titulo, html)
        resultado_email = {"enviado": r.enviado, "erro": r.erro}
        await em_thread(lambda cur: _evento(cur, q, "email", login, "enviado" if r.enviado else f"falhou: {r.erro}"))
    return {"ok": True, "login": login, "senha_temporaria": senha, "feitos": feitos + ls_feitos,
            "manuais": manuais, "email": resultado_email}


async def atualizar_bancos(q: Quem, login: str, bancos: dict[str, str]) -> dict:
    def fn(cur):
        _exigir_login_sql(cur, login, "altera")
        validos = _bancos_validos(cur)
        for b in bancos:
            if b not in validos:
                raise Invalido(f"Banco desconhecido: {b}")
        atual = _membros_de(cur, login, validos)
        ops = plano_bancos(atual, bancos)
        feitos = _aplicar_bancos(cur, login, ops)
        if feitos:
            _evento(cur, q, "bancos", login, "; ".join(feitos))
        return feitos

    return {"ok": True, "feitos": await em_thread(fn)}


async def atualizar_linked(q: Quem, login: str, permitidos: Sequence[str]) -> dict:
    def fn(cur):
        _exigir_login_sql(cur, login, "altera")
        feitos, manuais = _aplicar_linked(cur, login, set(permitidos))
        if feitos:
            _evento(cur, q, "linked", login, "; ".join(feitos))
        return feitos, manuais

    feitos, manuais = await em_thread(fn)
    return {"ok": True, "feitos": feitos, "manuais": manuais}


async def vincular_pessoa(q: Quem, login: str, nome: Optional[str], email: Optional[str],
                          chapa: Optional[str], setor: Optional[str],
                          excecao_desligado: Optional[bool] = None,
                          generico: Optional[bool] = None, finalidade: Optional[str] = None) -> dict:
    def fn(cur):
        if not _login_existe(cur, login):
            raise Invalido(f"Login {login} nao existe.", "nao_existe")
        if generico:
            chapa_f = None  # generico nao tem ficha no RM
        else:
            chapa_f = chapa
        _upsert_cadastro(cur, q, login, nome, (email or "").strip().lower() or None, chapa_f, setor)
        extras = []
        if excecao_desligado is not None:
            extras.append(("excecao_desligado", 1 if excecao_desligado else 0, "v2"))
        if generico is not None:
            extras.append(("generico", 1 if generico else 0, "v3"))
            extras.append(("finalidade", (finalidade or "").strip()[:200] or None, "v3"))
        if extras:
            cur.execute("SELECT name FROM DBA_Monitor.sys.columns WHERE object_id = OBJECT_ID('DBA_Monitor.dbo.acesso_sql_cadastro')")
            existentes = {r["name"] for r in _linhas(cur)}
            for col, valor, versao in extras:
                if col not in existentes:
                    raise Invalido(f"Esse campo exige o setup {versao} do servidor (acesso_sql_setup.sql).", "setup_pendente")
                cur.execute(f"UPDATE DBA_Monitor.dbo.acesso_sql_cadastro SET {col} = %s, atualizado_em = SYSDATETIME() WHERE login_name = %s",
                            (valor, login))
        _evento(cur, q, "pessoa", login, f"{nome or ''} <{email or ''}> {setor or ''}".strip()
                + "".join(f" | {c}={v}" for c, v, _ in extras))

    await em_thread(fn)
    return {"ok": True}


async def situacao(q: Quem, login: str, desativar: bool) -> dict:
    def fn(cur):
        _exigir_login_sql(cur, login, "desativa" if desativar else "ativa")
        cur.execute(f"ALTER LOGIN {ident(login)} {'DISABLE' if desativar else 'ENABLE'}")
        n = _derrubar_sessoes(cur, login) if desativar else 0
        _evento(cur, q, "desativar" if desativar else "ativar", login, f"{n} sessao(oes) derrubada(s)" if n else "")

    await em_thread(fn)
    return {"ok": True}


async def resetar_senha(q: Quem, login: str, enviar_email: bool) -> dict:
    senha = gerar_senha()

    def fn(cur):
        _exigir_login_sql(cur, login, "reseta")
        cur.execute(f"ALTER LOGIN {ident(login)} WITH PASSWORD = {lit(senha)} MUST_CHANGE, CHECK_POLICY = ON, CHECK_EXPIRATION = ON")
        cur.execute(f"ALTER LOGIN {ident(login)} ENABLE")
        _evento(cur, q, "resetar_senha", login)
        cur.execute("SELECT email, nome FROM DBA_Monitor.dbo.acesso_sql_cadastro WHERE login_name = %s", (login,))
        rows = _linhas(cur)
        return (rows[0]["email"], rows[0]["nome"]) if rows else (None, None)

    email, nome = await em_thread(fn)
    resultado_email = None
    if enviar_email and email:
        html, titulo = _email_credenciais(login, senha, email, nome, [], reset=True)
        r = await _enviar(email, titulo, html)
        resultado_email = {"enviado": r.enviado, "erro": r.erro}
        await em_thread(lambda cur: _evento(cur, q, "email", login, "enviado" if r.enviado else f"falhou: {r.erro}"))
    return {"ok": True, "senha_temporaria": senha, "email": resultado_email, "email_destino": email}


async def excluir(q: Quem, login: str) -> dict:
    def fn(cur):
        _exigir_login_sql(cur, login, "exclui")
        validos = _bancos_validos(cur)
        atual = _membros_de(cur, login, validos)
        feitos = _aplicar_bancos(cur, login, [("remover_usuario", b, None) for b in atual])
        _, linhas = _modelos_e_linhas(cur)
        for ls in linhas.get(login, {}):
            cur.execute(f"EXEC sp_droplinkedsrvlogin @rmtsrvname = {lit(ls)}, @locallogin = {lit(login)}")
        n = _derrubar_sessoes(cur, login)
        if n:
            feitos.append(f"{n} sessao(oes) derrubada(s)")
        cur.execute(f"DROP LOGIN {ident(login)}")
        cur.execute("DELETE FROM DBA_Monitor.dbo.acesso_sql_cadastro WHERE login_name = %s", (login,))
        _evento(cur, q, "excluir", login, "; ".join(feitos))
        return feitos

    return {"ok": True, "feitos": await em_thread(fn)}


async def gravar_config(q: Quem, dias_inatividade: Optional[int], desativar_desligados: Optional[bool]) -> dict:
    if dias_inatividade is not None and (dias_inatividade < 0 or dias_inatividade > 3650):
        raise Invalido("Dias de inatividade: entre 0 (desligado) e 3650.")
    pares = []
    if dias_inatividade is not None:
        pares.append(("dias_inatividade", str(dias_inatividade)))
    if desativar_desligados is not None:
        pares.append(("desativar_desligados", "1" if desativar_desligados else "0"))
    if not pares:
        raise Invalido("Nada a gravar.")

    def fn(cur):
        for chave, valor in pares:
            cur.execute(
                "MERGE DBA_Monitor.dbo.acesso_sql_config AS d USING (SELECT %s AS chave) AS s ON d.chave = s.chave "
                "WHEN MATCHED THEN UPDATE SET valor = %s WHEN NOT MATCHED THEN INSERT (chave, valor) VALUES (s.chave, %s);",
                (chave, valor, valor),
            )
        _evento(cur, q, "config", "-", "; ".join(f"{k}={v}" for k, v in pares))

    await em_thread(fn)
    return {"ok": True, **dict(pares)}


# ---------------------------------------------------------------- Excel (Kevin, 04/11/2026: "exportar um relatorio desse controle")
_AZUL = "FF203BA4"
Coluna = tuple[str, int, str]  # (rotulo, largura, tipo: txt | int | data)
ROTULO_FAIXA = {"ate30": "Ativo (30 dias)", "31a60": "31 a 60 dias", "61a90": "61 a 90 dias",
                "91a120": "91 a 120 dias", "mais120": "Mais de 120 dias", "nunca": "Sem registro"}
ROTULO_RM = {"ativo": "Ativo no RM", "desligado": "Desligado no RM", "nao_encontrado": "Chapa nao achada", None: ""}


def _brasilia(dt: Optional[datetime]) -> Optional[datetime]:
    """UTC com tz -> Brasilia sem tz (o Excel nao tem fuso). Datetime sem tz ja e
    hora local do servidor e passa como esta."""
    if dt is None or not isinstance(dt, datetime):
        return None
    if dt.tzinfo is None:
        return dt
    return (dt - timedelta(hours=3)).replace(tzinfo=None)


def _aba(wb, titulo: str, subtitulo: str, colunas: list[Coluna], linhas: list[list]):
    """Uma aba no desenho das outras exportacoes do Portal: titulo, subtitulo,
    cabecalho azul na linha 4, dados a partir da 5, painel congelado e filtro."""
    from openpyxl.styles import Alignment, Font, PatternFill
    from openpyxl.utils import get_column_letter

    ws = wb.create_sheet(title=titulo[:31])
    ultima = get_column_letter(len(colunas))
    ws["A1"] = titulo
    ws.merge_cells(f"A1:{ultima}1")
    ws["A1"].font = Font(bold=True, size=13)
    ws["A2"] = subtitulo
    ws.merge_cells(f"A2:{ultima}2")
    ws["A2"].font = Font(size=9, color="FF64748B")
    cab = 4
    fundo = PatternFill(fill_type="solid", start_color=_AZUL)
    for i, (rotulo, largura, _t) in enumerate(colunas, start=1):
        c = ws.cell(row=cab, column=i, value=rotulo)
        c.font = Font(bold=True, color="FFFFFFFF")
        c.fill = fundo
        c.alignment = Alignment(horizontal="center", vertical="center", wrap_text=True)
        ws.column_dimensions[get_column_letter(i)].width = largura
    ws.row_dimensions[cab].height = 30
    lin = cab + 1
    for linha in linhas:
        for i, (_r, _l, tipo) in enumerate(colunas, start=1):
            v = linha[i - 1] if i - 1 < len(linha) else None
            c = ws.cell(row=lin, column=i)
            if tipo == "data":
                d = _brasilia(v)
                if d is not None:
                    c.value = d
                    c.number_format = "dd/mm/yyyy hh:mm"
                else:
                    c.value = "" if v is None else str(v)
            elif tipo == "int":
                c.value = int(v) if v not in (None, "") else None
                c.number_format = "#,##0"
            else:
                c.value = "" if v is None else str(v)
                c.data_type = "s"
        lin += 1
    fim = max(lin - 1, cab)
    ws.freeze_panes = f"A{cab + 1}"
    ws.auto_filter.ref = f"A{cab}:{ultima}{fim}"
    return ws


def montar_xlsx(dados: dict) -> bytes:
    """Quatro abas a partir da visao: Logins (uma linha por login, com tudo que a
    tela mostra), Bancos (login x banco x papel), Servidores vinculados (login x
    servidor x situacao) e Historico (o que a tela e os jobs fizeram)."""
    import io as _io
    from openpyxl import Workbook

    gerado = _brasilia(dados["gerado_em"])
    gerado_txt = gerado.strftime("%d/%m/%Y %H:%M") if gerado else ""
    sub = f"{dados.get('servidor', SERVIDOR)} ({dados.get('endereco', SERVIDOR_ENDERECO)}) · gerado em {gerado_txt}"
    ls_controlados = [l["nome"] for l in dados.get("linked_servers", []) if l.get("controlado")]
    ls_todos = [l["nome"] for l in dados.get("linked_servers", [])]

    wb = Workbook()
    wb.remove(wb.active)

    cols_l: list[Coluna] = [
        ("Login", 24, "txt"), ("Tipo", 12, "txt"), ("Situação", 12, "txt"), ("Protegido", 10, "txt"),
        ("Pessoa", 32, "txt"), ("E-mail", 32, "txt"), ("Setor", 28, "txt"), ("Chapa", 10, "txt"),
        ("Genérico", 9, "txt"), ("Finalidade", 36, "txt"),
        ("Situação no RM", 16, "txt"), ("Desligado em", 14, "data"), ("Exceção", 9, "txt"),
        ("Último acesso", 18, "data"), ("Dias sem acesso", 11, "int"), ("Faixa", 16, "txt"),
        ("Acessos registrados", 12, "int"), ("De onde", 18, "txt"), ("Programa", 22, "txt"),
        ("Bancos", 8, "int"), ("Bancos (papel)", 48, "txt"),
        ("Serv. vinculados liberados", 11, "int"), ("Servidores liberados", 40, "txt"),
        ("Senha", 18, "txt"), ("Senha definida em", 18, "data"), ("Papéis de servidor", 22, "txt"), ("Criado em", 18, "data"),
    ]
    linhas_l, linhas_b, linhas_s = [], [], []
    for x in dados.get("logins", []):
        p = x.get("pessoa") or {}
        if x.get("tipo") != "sql":
            senha = "Windows"
        elif x.get("must_change"):
            senha = "troca pendente"
        elif x.get("expiracao"):
            senha = "expira"
        else:
            senha = "não expira"
        liberados = [ls for ls, s in (x.get("linked") or {}).items() if s == "permitido" and ls in ls_controlados]
        linhas_l.append([
            x["login"], x.get("tipo"), "desativado" if x.get("desativado") else "ativo", "sim" if x.get("protegido") else "",
            p.get("nome"), p.get("email"), p.get("setor"), p.get("chapa"),
            "sim" if p.get("generico") else "", p.get("finalidade"),
            ROTULO_RM.get(p.get("rm_situacao"), ""), p.get("rm_demissao"), "sim" if p.get("excecao_desligado") else "",
            x.get("ultimo_acesso"), x.get("dias_sem_acesso"), ROTULO_FAIXA.get(x.get("faixa"), x.get("faixa")),
            x.get("total_acessos"), x.get("ultimo_host"), x.get("ultimo_programa"),
            len(x.get("bancos") or []), "; ".join(f"{b['banco']} ({ROTULO_PAPEL.get(b['papel'], b['papel'])})" for b in x.get("bancos") or []),
            len(liberados), "; ".join(liberados),
            senha, x.get("senha_em"), ", ".join(x.get("roles_servidor") or []), x.get("criado_em"),
        ])
        for b in x.get("bancos") or []:
            linhas_b.append([x["login"], p.get("nome"), b["banco"], ROTULO_PAPEL.get(b["papel"], b["papel"]), ", ".join(b.get("roles") or [])])
        for ls in ls_todos:
            s = (x.get("linked") or {}).get(ls)
            linhas_s.append([x["login"], p.get("nome"), ls, "aberto a todos" if ls not in ls_controlados else (s or "")])

    _aba(wb, "Logins", sub, cols_l, linhas_l)
    _aba(wb, "Bancos", "Uma linha por login e banco", [
        ("Login", 24, "txt"), ("Pessoa", 32, "txt"), ("Banco", 24, "txt"), ("Acesso", 20, "txt"), ("Papéis no banco", 36, "txt"),
    ], linhas_b)
    _aba(wb, "Servidores vinculados", "Uma linha por login e servidor vinculado", [
        ("Login", 24, "txt"), ("Pessoa", 32, "txt"), ("Servidor vinculado", 28, "txt"), ("Situação", 16, "txt"),
    ], linhas_s)
    _aba(wb, "Histórico", "O que a tela e os jobs fizeram, por quem e quando", [
        ("Quando", 18, "data"), ("Quem", 32, "txt"), ("Ação", 22, "txt"), ("Login", 24, "txt"), ("Detalhe", 80, "txt"),
    ], [[e.get("em"), e.get("por"), e.get("acao"), e.get("login_alvo"), e.get("detalhe")] for e in dados.get("eventos", [])])

    buf = _io.BytesIO()
    wb.save(buf)
    return buf.getvalue()


def nome_arquivo(agora: Optional[datetime] = None) -> str:
    d = _brasilia(agora or datetime.now(timezone.utc))
    return f"usuarios-sql-server-{d:%Y-%m-%d}.xlsx"

"""Configuracoes > Usuarios SQL Server (Kevin, 04/11/2026).

Logins do SQL Server pela tela: criar com bancos, papel, servidores vinculados e
e-mail; desativar, resetar senha, excluir; vincular a pessoa do RM; e o controle de
quem tem o que e ha quanto tempo nao entra.

Tela do catalogo, no workspace T.I. (Kevin, 04/11/2026 a tarde: "nao faz sentido
estar em Configuracoes, nao se trata de Portal"). Duas chaves de permissao, no
padrao de nivel da Auditoria Interna:

  /usuarios-sql          somente visualizacao: a lista, os acessos, o historico
  /usuarios-sql/editar   cria, altera bancos e servidores vinculados, vincula pessoa,
                         desativa, ativa, reseta senha, exclui, configura a inatividade

Toda rota exige a tela; as de escrita exigem o nivel. A visao devolve `pode_editar`
para a tela esconder o que a pessoa nao pode. Cada escrita grava um evento em
DBA_Monitor.dbo.acesso_sql_evento com o e-mail de quem fez.
"""
from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Body, Depends, HTTPException, Query, Response, status
from pydantic import BaseModel, Field

from app.core.permissions import is_page_allowed, require_page, resolve_access
from app.core.security import CurrentUser, UserContext
from app.services import acessos_sql as svc

PAGINA = "/usuarios-sql"
PERM_EDITAR = f"{PAGINA}/editar"

router = APIRouter(prefix=PAGINA, tags=["usuarios-sql"], dependencies=[Depends(require_page(PAGINA))])

XLSX = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"


class BancoPapel(BaseModel):
    banco: str = Field(..., min_length=1, max_length=128)
    papel: str = Field(..., pattern=r"^(leitura|escrita|dono|sem|remover)$")


class NovoLogin(BaseModel):
    login: str = Field(..., min_length=3, max_length=64)
    email: Optional[str] = Field(default=None, max_length=254)
    nome: Optional[str] = Field(default=None, max_length=200)
    chapa: Optional[str] = Field(default=None, max_length=16)
    setor: Optional[str] = Field(default=None, max_length=200)
    bancos: list[BancoPapel] = Field(default_factory=list)
    linked_permitidos: list[str] = Field(default_factory=list)
    enviar_email: bool = True


class BancosIn(BaseModel):
    bancos: list[BancoPapel] = Field(default_factory=list)


class LinkedIn(BaseModel):
    permitidos: list[str] = Field(default_factory=list)


class PessoaIn(BaseModel):
    nome: Optional[str] = Field(default=None, max_length=200)
    email: Optional[str] = Field(default=None, max_length=254)
    chapa: Optional[str] = Field(default=None, max_length=16)
    setor: Optional[str] = Field(default=None, max_length=200)
    # Ficha demitida no RM, mas o login fica (ex.: virou PJ). O job de desligados pula.
    excecao_desligado: Optional[bool] = None
    # Login generico (nao e uma pessoa): finalidade e quem responde por ele.
    generico: Optional[bool] = None
    finalidade: Optional[str] = Field(default=None, max_length=200)


class ResetIn(BaseModel):
    enviar_email: bool = True


class ConfigIn(BaseModel):
    dias_inatividade: Optional[int] = Field(default=None, ge=0, le=3650)
    desativar_desligados: Optional[bool] = None


async def _pode_editar(user: UserContext) -> bool:
    access = await resolve_access(user.user_id, user.email)
    return bool(access.is_sa or is_page_allowed(access.keys, PERM_EDITAR))


async def _quem(user: UserContext) -> svc.Quem:
    """Escrita: exige o nivel /editar e nunca roda na visao espelhada (o "Ver como"
    e para olhar a tela como a pessoa, nao para agir em nome dela)."""
    if user.ver_como:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"ok": False, "message": "Usuarios SQL Server nao grava na visao espelhada", "reason": "ver_como"},
        )
    if not await _pode_editar(user):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"ok": False, "message": "Voce so pode visualizar esta tela (falta o nivel Edicao)", "reason": "sem_edicao"},
        )
    return svc.Quem(email=(user.email or "").strip().lower())


def _mapa(bancos: list[BancoPapel]) -> dict[str, str]:
    out: dict[str, str] = {}
    for b in bancos:
        out[b.banco] = b.papel
    return out


@router.get("/visao")
async def visao(user: UserContext = CurrentUser) -> dict:
    out = await svc.visao()
    out["pode_editar"] = (not user.ver_como) and await _pode_editar(user)
    return out


@router.get("/excel")
async def excel(user: UserContext = CurrentUser) -> Response:
    """A planilha do controle (Logins, Bancos, Servidores vinculados, Historico). Ver basta."""
    dados = await svc.visao()
    nome = svc.nome_arquivo(dados["gerado_em"])
    return Response(content=svc.montar_xlsx(dados), media_type=XLSX,
                    headers={"Content-Disposition": f'attachment; filename="{nome}"'})


@router.get("/pessoas")
async def pessoas(q: str = Query("", max_length=120), user: UserContext = CurrentUser) -> dict:
    await _quem(user)
    return {"ok": True, "pessoas": await svc.pessoas(q)}


@router.post("/logins")
async def criar(corpo: NovoLogin = Body(...), user: UserContext = CurrentUser) -> dict:
    q = await _quem(user)
    return await svc.criar(q, corpo.login, corpo.email, corpo.nome, corpo.chapa, corpo.setor,
                           _mapa(corpo.bancos), corpo.linked_permitidos, corpo.enviar_email)


@router.put("/logins/{login}/bancos")
async def bancos(login: str, corpo: BancosIn = Body(...), user: UserContext = CurrentUser) -> dict:
    q = await _quem(user)
    return await svc.atualizar_bancos(q, login, _mapa(corpo.bancos))


@router.put("/logins/{login}/linked")
async def linked(login: str, corpo: LinkedIn = Body(...), user: UserContext = CurrentUser) -> dict:
    q = await _quem(user)
    return await svc.atualizar_linked(q, login, corpo.permitidos)


@router.put("/logins/{login}/pessoa")
async def pessoa(login: str, corpo: PessoaIn = Body(...), user: UserContext = CurrentUser) -> dict:
    q = await _quem(user)
    return await svc.vincular_pessoa(q, login, corpo.nome, corpo.email, corpo.chapa, corpo.setor, corpo.excecao_desligado,
                                     corpo.generico, corpo.finalidade)


@router.post("/logins/{login}/desativar")
async def desativar(login: str, user: UserContext = CurrentUser) -> dict:
    q = await _quem(user)
    return await svc.situacao(q, login, desativar=True)


@router.post("/logins/{login}/ativar")
async def ativar(login: str, user: UserContext = CurrentUser) -> dict:
    q = await _quem(user)
    return await svc.situacao(q, login, desativar=False)


@router.post("/logins/{login}/resetar-senha")
async def resetar(login: str, corpo: ResetIn = Body(default=ResetIn()), user: UserContext = CurrentUser) -> dict:
    q = await _quem(user)
    return await svc.resetar_senha(q, login, corpo.enviar_email)


@router.delete("/logins/{login}")
async def excluir(login: str, user: UserContext = CurrentUser) -> dict:
    q = await _quem(user)
    return await svc.excluir(q, login)


@router.put("/config")
async def config(corpo: ConfigIn = Body(...), user: UserContext = CurrentUser) -> dict:
    q = await _quem(user)
    return await svc.gravar_config(q, corpo.dias_inatividade, corpo.desativar_desligados)

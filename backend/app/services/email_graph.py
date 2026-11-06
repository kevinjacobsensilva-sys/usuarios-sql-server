"""Envio de e-mail pela API da Microsoft (Graph) com credencial de aplicativo.

Primeiro uso: Auditoria Interna (28/10/2026) -- o plano de acao vai por e-mail
ao responsavel, e a resposta dele avisa o auditor. Mesmo mecanismo do IAM
(portal_iam/app/email.py) e das automacoes do RH no SRV-SQL: token por
client credentials em login.microsoftonline.com e POST /users/{remetente}/sendMail.

Remetente: PORTAL_MAIL_FROM. No QAS e a caixa do Kevin (as chaves ja
existem); quando a TI liberar a caixa generica da Auditoria Interna, troca-se
so a variavel -- o aplicativo registrado e o mesmo.

Nunca levanta: sem credencial, ou com o Graph fora, devolve (False, motivo) e
quem chamou decide o que dizer na tela. Um e-mail que nao sai nao pode impedir
o responsavel de salvar a resposta.
"""
from __future__ import annotations

import html as _html
from dataclasses import dataclass
from typing import Optional, Sequence

import httpx
from loguru import logger

from app.core.config import get_settings


@dataclass(frozen=True)
class Resultado:
    enviado: bool
    erro: Optional[str] = None


def configurado() -> bool:
    s = get_settings()
    return bool(s.mail_tenant_id and s.mail_client_id and s.mail_client_secret and s.mail_from)


async def _token() -> str:
    s = get_settings()
    url = f"https://login.microsoftonline.com/{s.mail_tenant_id}/oauth2/v2.0/token"
    data = {
        "client_id": s.mail_client_id,
        "client_secret": s.mail_client_secret,
        "grant_type": "client_credentials",
        "scope": "https://graph.microsoft.com/.default",
    }
    async with httpx.AsyncClient(timeout=20) as c:
        r = await c.post(url, data=data)
        r.raise_for_status()
        tok = r.json().get("access_token")
        if not tok:
            raise RuntimeError("token vazio")
        return str(tok)


async def enviar(para: Sequence[str], assunto: str, html: str,
                 copia: Sequence[str] = (), de: Optional[str] = None,
                 de_nome: Optional[str] = None) -> Resultado:
    """Manda um e-mail HTML. `para`/`copia` sao e-mails; vazios sao ignorados.
    `de`/`de_nome` trocam a caixa remetente (outra caixa do mesmo tenant, que o
    app do Graph pode usar); vazios = PORTAL_MAIL_FROM."""
    s = get_settings()
    remetente = (de or "").strip() or s.mail_from
    remetente_nome = (de_nome or "").strip() or s.mail_from_name
    destinos = [e.strip() for e in para if e and e.strip()]
    if not destinos:
        return Resultado(False, "sem destinatario")
    if not configurado():
        return Resultado(False, "e-mail nao configurado neste ambiente (PORTAL_MAIL_*)")
    payload = {
        "message": {
            "subject": assunto[:250],
            "body": {"contentType": "HTML", "content": html},
            "toRecipients": [{"emailAddress": {"address": e}} for e in destinos],
            "ccRecipients": [{"emailAddress": {"address": e.strip()}} for e in copia if e and e.strip()],
            "from": {"emailAddress": {"address": remetente, "name": remetente_nome}},
        },
        "saveToSentItems": True,
    }
    try:
        token = await _token()
        url = f"https://graph.microsoft.com/v1.0/users/{remetente}/sendMail"
        async with httpx.AsyncClient(timeout=25) as c:
            r = await c.post(url, headers={"Authorization": f"Bearer {token}"}, json=payload)
        if r.status_code not in (200, 202):
            erro = f"Graph {r.status_code}: {r.text[:300]}"
            logger.warning("sendMail falhou: {}", erro)
            return Resultado(False, erro)
        return Resultado(True)
    except Exception as ex:  # noqa: BLE001 -- rede, token, DNS: tudo vira motivo na tela
        logger.warning("erro enviando e-mail: {}", ex)
        return Resultado(False, str(ex)[:400])


# ---------------------------------------------------------------- modelo visual
def esc(v: object) -> str:
    return _html.escape("" if v is None else str(v))


def corpo(titulo: str, blocos: Sequence[tuple[str, str]], link: Optional[str] = None,
          rotulo_link: str = "Abrir no Portal", rodape: str = "") -> str:
    """HTML simples e legivel no Outlook: titulo, pares rotulo/valor e um botao.
    `blocos` ja vem escapado por quem monta (use `esc`)."""
    linhas = "".join(
        f'<tr><td style="padding:6px 10px;color:#5b6472;font-size:12px;white-space:nowrap;vertical-align:top">{esc(r)}</td>'
        f'<td style="padding:6px 10px;font-size:13px;color:#111827;vertical-align:top">{v}</td></tr>'
        for r, v in blocos
    )
    botao = (
        f'<p style="margin:18px 0 0"><a href="{esc(link)}" style="display:inline-block;background:#203BA4;color:#fff;'
        f'text-decoration:none;font-weight:600;padding:9px 16px;border-radius:8px;font-size:13px">{esc(rotulo_link)}</a></p>'
        if link else ""
    )
    return (
        '<div style="font-family:Segoe UI,Arial,sans-serif;max-width:640px;margin:0 auto;color:#111827">'
        f'<h2 style="font-size:17px;margin:0 0 12px;color:#0f3d8c">{esc(titulo)}</h2>'
        f'<table style="border-collapse:collapse;border:1px solid #e5e7eb;border-radius:8px;width:100%">{linhas}</table>'
        f"{botao}"
        f'<p style="margin:18px 0 0;color:#6b7280;font-size:11.5px">{esc(rodape) if rodape else "Mensagem automática do Portal · Auditoria Interna."}</p>'
        "</div>"
    )

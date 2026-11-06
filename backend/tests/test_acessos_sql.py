"""Acessos SQL (Configuracoes > Acessos SQL, 04/11/2026).

As regras que nao dependem do servidor: nome de login valido, senha temporaria
dentro da politica, o papel que a tela mostra para os papeis do banco, o plano de
alteracoes (bancos e servidores vinculados), o modelo de cada servidor vinculado e
a faixa de recencia.
"""
from datetime import datetime, timedelta, timezone

import pytest
from fastapi import HTTPException

from app.services import acessos_sql as svc

AGORA = datetime(2026, 11, 4, 12, 0, tzinfo=timezone.utc)


# -- nome do login --------------------------------------------------------------

def test_validar_login_aceita_o_padrao_da_casa():
    assert svc.validar_login("usuario_a") == "usuario_a"
    assert svc.validar_login("  usuario_b ") == "usuario_b"
    assert svc.validar_login("joao.silva-2") == "joao.silva-2"


@pytest.mark.parametrize("ruim", ["", "ab", "1abc", "joao silva", "DOMINIO\\usuario_c", "a" * 65, "sa", "svc_novo", "portal_x"])
def test_validar_login_recusa(ruim):
    with pytest.raises(HTTPException) as e:
        svc.validar_login(ruim)
    assert e.value.status_code == 400


def test_protegido():
    assert svc.protegido("sa")
    assert svc.protegido("svc_portal_api_prd")
    assert svc.protegido("portal_etl")
    assert svc.protegido("fulano", sysadmin=True)
    assert not svc.protegido("usuario_a")


# -- senha temporaria -------------------------------------------------------------

def test_gerar_senha_passa_na_politica_e_e_legivel():
    for _ in range(50):
        s = svc.gerar_senha()
        assert len(s) == 14
        assert any(c.isupper() for c in s) and any(c.islower() for c in s) and any(c.isdigit() for c in s)
        assert any(c in "#@!$%&*?" for c in s)
        assert not set("0O1lI") & set(s)


# -- papel por banco ---------------------------------------------------------------

def test_papel_de():
    assert svc.papel_de([]) == "sem"
    assert svc.papel_de(["db_datareader"]) == "leitura"
    assert svc.papel_de(["db_datareader", "db_datawriter"]) == "escrita"
    assert svc.papel_de(["db_owner"]) == "dono"
    assert svc.papel_de(["db_owner", "db_datareader"]) == "dono"
    assert svc.papel_de(["db_datawriter"]) == "outro"
    assert svc.papel_de(["db_ddladmin", "db_datareader"]) == "outro"


def test_plano_bancos_cria_troca_e_remove():
    atual = {"DW": ["db_datareader"], "ZSAP": ["db_datareader", "db_datawriter"], "PowerBi": []}
    desejado = {"DW": "escrita", "ZSAP": "leitura", "PowerBi": "remover", "COMERCIAL": "leitura"}
    ops = svc.plano_bancos(atual, desejado)
    assert ("add", "DW", "db_datawriter") in ops
    assert ("drop", "ZSAP", "db_datawriter") in ops
    assert ("remover_usuario", "PowerBi", None) in ops
    assert ("criar_usuario", "COMERCIAL", None) in ops
    assert ("add", "COMERCIAL", "db_datareader") in ops
    assert not [o for o in ops if o[1] == "DW" and o[0] == "criar_usuario"]


def test_plano_bancos_nao_mexe_no_que_nao_conhece():
    ops = svc.plano_bancos({"DW": ["db_ddladmin"]}, {"DW": "leitura"})
    assert ops == []


def test_plano_bancos_dono_troca_para_leitura():
    ops = svc.plano_bancos({"DW": ["db_owner"]}, {"DW": "leitura"})
    assert ("drop", "DW", "db_owner") in ops and ("add", "DW", "db_datareader") in ops


def test_plano_bancos_sem_papel_so_cria_usuario():
    assert svc.plano_bancos({}, {"DW": "sem"}) == [("criar_usuario", "DW", None)]


def test_plano_bancos_papel_desconhecido():
    with pytest.raises(HTTPException):
        svc.plano_bancos({}, {"DW": "admin"})


# -- servidores vinculados -----------------------------------------------------------

def test_modelo_do_ls():
    assert svc.modelo_do_ls("ERP", True) == "aberto"
    assert svc.modelo_do_ls("SRV_WEB", True) == "bloqueio"
    assert svc.modelo_do_ls("SRV_RM", False) == "permissao"


def test_situacao_no_ls_modelo_bloqueio():
    assert svc.situacao_no_ls("bloqueio", None) == "permitido"
    assert svc.situacao_no_ls("bloqueio", {"remote_name": None, "uses_self": False}) == "bloqueado"
    assert svc.situacao_no_ls("bloqueio", {"remote_name": "sa", "uses_self": False}) == "permitido"


def test_situacao_no_ls_modelo_permissao():
    assert svc.situacao_no_ls("permissao", None) == "bloqueado"
    assert svc.situacao_no_ls("permissao", {"remote_name": None, "uses_self": False}) == "bloqueado"
    assert svc.situacao_no_ls("permissao", {"remote_name": "sa", "uses_self": False}) == "permitido"
    assert svc.situacao_no_ls("permissao", {"remote_name": None, "uses_self": True}) == "permitido"


def test_plano_linked_bloqueio_nao_precisa_de_senha():
    modelos = {"SRV_WEB": "bloqueio", "SRV_CHAMADOS": "bloqueio", "ERP": "aberto"}
    atual = {"SRV_WEB": {"remote_name": None, "uses_self": False}}  # bloqueado no SRV_WEB; livre no SRV_CHAMADOS
    ops = svc.plano_linked(modelos, atual, {"SRV_WEB"}, {})
    assert ("liberar_drop", "SRV_WEB", "") in ops
    assert ("bloquear_sem_cred", "SRV_CHAMADOS", "") in ops
    assert not [o for o in ops if o[1] == "ERP"]


def test_plano_linked_permissao_exige_credencial():
    modelos = {"SRV_RM": "permissao"}
    assert svc.plano_linked(modelos, {}, {"SRV_RM"}, {}) == [("manual", "SRV_RM", "sem credencial remota configurada")]
    assert svc.plano_linked(modelos, {}, {"SRV_RM"}, {"SRV_RM": {"usuario": "sa", "senha": "x"}}) == [("liberar_com_cred", "SRV_RM", "")]
    atual = {"SRV_RM": {"remote_name": "sa", "uses_self": False}}
    assert svc.plano_linked(modelos, atual, set(), {}) == [("bloquear_drop", "SRV_RM", "")]


def test_plano_linked_sem_mudanca():
    modelos = {"SRV_WEB": "bloqueio"}
    assert svc.plano_linked(modelos, {}, {"SRV_WEB"}, {}) == []


# -- recencia --------------------------------------------------------------------------

def test_faixa_de():
    assert svc.faixa_de(None, AGORA) == "nunca"
    assert svc.faixa_de(AGORA - timedelta(days=3), AGORA) == "ate30"
    assert svc.faixa_de(AGORA - timedelta(days=45), AGORA) == "31a60"
    assert svc.faixa_de(AGORA - timedelta(days=75), AGORA) == "61a90"
    assert svc.faixa_de(AGORA - timedelta(days=100), AGORA) == "91a120"
    assert svc.faixa_de(AGORA - timedelta(days=200), AGORA) == "mais120"
    assert svc.faixa_de(datetime(2026, 11, 1, 12, 0), AGORA) == "ate30"  # naive = UTC


# -- identificadores e literais ---------------------------------------------------------

def test_ident_e_lit_dobram_o_caractere_de_fechamento():
    assert svc.ident("a]b") == "[a]]b]"
    assert svc.lit("x'y") == "N'x''y'"


def test_sql_membros_protege_cada_banco():
    sql = svc._sql_membros(["DW", "Z'ERP"])
    assert sql.count("BEGIN TRY") == 2
    assert "N'Z''ERP'" in sql and "[Z'ERP].sys.database_principals" in sql


# -- desligado no RM ---------------------------------------------------------------------

def test_situacao_rm():
    assert svc.situacao_rm(None, None) is None
    assert svc.situacao_rm("00001", None) == "nao_encontrado"
    assert svc.situacao_rm("00001", {"fichas": 1, "tem_ativa": 0}) == "desligado"
    assert svc.situacao_rm("00001", {"fichas": 2, "tem_ativa": 1}) == "ativo"  # transferido: uma ficha D, outra ativa



# -- Excel ------------------------------------------------------------------------------

def test_montar_xlsx_quatro_abas():
    import io
    from openpyxl import load_workbook
    dados = {
        "gerado_em": AGORA, "servidor": "SRV-SQL", "endereco": "10.0.0.10",
        "linked_servers": [{"nome": "SRV_WEB", "controlado": True}, {"nome": "ERP", "controlado": False}],
        "logins": [{
            "login": "fulano", "tipo": "sql", "desativado": False, "protegido": False, "must_change": True, "expiracao": True,
            "pessoa": {"nome": "FULANO", "email": "f@x", "setor": "T.I.", "chapa": "1", "rm_situacao": "desligado",
                       "rm_demissao": datetime(2026, 10, 1), "excecao_desligado": False},
            "ultimo_acesso": datetime(2026, 11, 3, 10, 0), "dias_sem_acesso": 1, "faixa": "ate30", "total_acessos": 7,
            "ultimo_host": "10.0.0.1", "ultimo_programa": "SSMS", "bancos": [{"banco": "DW", "papel": "leitura", "roles": ["db_datareader"]}],
            "linked": {"SRV_WEB": "permitido", "ERP": "permitido"}, "senha_em": None, "roles_servidor": [], "criado_em": None,
        }],
        "eventos": [{"em": datetime(2026, 11, 4, 9, 0), "por": "kevin", "acao": "criar", "login_alvo": "fulano", "detalhe": "x"}],
    }
    wb = load_workbook(io.BytesIO(svc.montar_xlsx(dados)))
    assert wb.sheetnames == ["Logins", "Bancos", "Servidores vinculados", "Histórico"]
    ws = wb["Logins"]
    cab = [c.value for c in ws[4]]
    linha = [c.value for c in ws[5]]
    assert linha[cab.index("Login")] == "fulano"
    assert linha[cab.index("Situação no RM")] == "Desligado no RM"
    assert linha[cab.index("Senha")] == "troca pendente"
    assert linha[cab.index("Serv. vinculados liberados")] == 1  # ERP e aberto, nao conta
    assert wb["Bancos"]["C5"].value == "DW"
    assert svc.nome_arquivo(AGORA) == "usuarios-sql-server-2026-11-04.xlsx"

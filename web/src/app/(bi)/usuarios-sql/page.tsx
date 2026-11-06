import UsuariosSql from "./UsuariosSql.client";

/**
 * Usuários SQL Server — os logins do SQL Server pela tela (Kevin, 04/11/2026).
 *
 * Tela do catálogo, no workspace T.I.: quem abre é quem tem a chave `/usuarios-sql`
 * (o gate do layout de (bi) cuida disso). Quem também tem o nível
 * `/usuarios-sql/editar` cria, altera e exclui; o resto só visualiza — a API
 * devolve `pode_editar` e a tela esconde o que não pode.
 */
export default function UsuariosSqlPage() {
  return <UsuariosSql />;
}

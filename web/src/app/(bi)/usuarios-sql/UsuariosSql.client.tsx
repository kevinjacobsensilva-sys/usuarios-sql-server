"use client";

// Configurações > Usuários SQL Server — os logins do SQL Server pela tela.
//
// Pedido do Kevin em 04/11/2026, depois de fechar os servidores vinculados na mão:
// "o trabalho que vou ter quando for criar um usuário novo". Aqui: criar o login
// com e-mail, setor (do RM), bancos e papel em cada um, servidores vinculados e
// a senha temporária por e-mail; e o controle — quem tem o quê, há quanto tempo
// não entra (regra de 30/60/90/120 dias, como a Auditoria de acessos), desativar,
// resetar senha, excluir e a desativação automática por inatividade.
//
// Como a tela se lê, de cima para baixo:
//   1. barra de comando: busca, recorte (todos / ativos / sem acesso / desativados /
//      serviço), "Novo usuário", Atualizar;
//   2. indicadores: logins de pessoas, ativos nos 30 dias, +90 dias, nunca, desativados;
//   3. à esquerda a tabela dos logins (rola dentro do quadro); à direita o painel do
//      login escolhido (pessoa, bancos, servidores vinculados, ações) ou o
//      formulário de novo usuário;
//   4. a configuração da inatividade e o histórico do que a tela e os jobs fizeram.
//
// O que vem do servidor é a visão inteira (GET /api/bi/usuarios-sql/visao); cada
// ação grava e a tela recarrega a visão — o SQL Server é a fonte, não um estado local.
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { IconClose, IconExcel, IconInfo, IconRefresh, IconSearch, IconUser } from "@/components/icons";
import "./usuarios-sql.css";

// ---------------------------------------------------------------------------
// Tipos do contrato com a API
// ---------------------------------------------------------------------------

type Faixa = "ate30" | "31a60" | "61a90" | "91a120" | "mais120" | "nunca";
type Papel = "leitura" | "escrita" | "dono" | "sem" | "outro";
type PapelEscolha = "leitura" | "escrita" | "dono" | "sem" | "remover";

type BancoDoLogin = { banco: string; papel: Papel; roles: string[] };
type SituacaoRm = "ativo" | "desligado" | "nao_encontrado" | null;
type Pessoa = {
  nome: string | null; email: string | null; chapa: string | null; setor: string | null;
  /** Situação da chapa na cópia do RM (BancoRH): só quem tem chapa. */
  rm_situacao?: SituacaoRm; rm_demissao?: string | null;
  /** Ficha demitida no RM, mas o login fica (ex.: virou PJ): o job não desativa. */
  excecao_desligado?: boolean;
  /** Login genérico (não é uma pessoa): finalidade e quem responde por ele. */
  generico?: boolean; finalidade?: string | null;
};
type LoginApi = {
  login: string;
  tipo: "sql" | "windows" | "grupo" | "outro";
  desativado: boolean;
  travado: boolean;
  sysadmin: boolean;
  roles_servidor: string[];
  protegido: boolean;
  criado_em: string | null;
  senha_em: string | null;
  must_change: boolean;
  expiracao: boolean;
  politica: boolean;
  bancos: BancoDoLogin[];
  linked: Record<string, "permitido" | "bloqueado">;
  linked_permitidos: number;
  pessoa: Pessoa | null;
  ultimo_acesso: string | null;
  dias_sem_acesso: number | null;
  faixa: Faixa;
  conectado_agora: boolean;
  total_acessos: number | null;
  ultimo_host: string | null;
  ultimo_programa: string | null;
};
type LinkedServer = {
  nome: string;
  modelo: "aberto" | "bloqueio" | "permissao";
  remoto_padrao: string | null;
  data_source: string | null;
  controlado: boolean;
  libera_pela_tela: boolean;
};
type Evento = { id: number; em: string; por: string | null; acao: string; login_alvo: string | null; detalhe: string | null };
type Visao = {
  ok: boolean;
  gerado_em: string;
  servidor: string;
  endereco: string;
  setup_ok: boolean;
  audit_ligado: boolean;
  audit_desde: string | null;
  email_configurado: boolean;
  bancos: string[];
  linked_servers: LinkedServer[];
  config: { dias_inatividade: number; desativar_desligados: boolean };
  papeis: { id: Papel; rotulo: string }[];
  logins: LoginApi[];
  eventos: Evento[];
  /** Tem o nível /usuarios-sql/editar (ou é SA) e não está na visão espelhada. */
  pode_editar: boolean;
};
type PessoaRm = { chapa: string; nome: string; setor: string | null; codsecao: string | null };

type Recorte = "todos" | "ativos" | "sem_acesso" | "desligados" | "desativados" | "servico";
type Ordem = { chave: keyof LoginApi | "pessoa"; desc: boolean };
/** O que a gaveta mostra: o login escolhido, o formulário de novo usuário, ou quem está num banco / servidor vinculado. */
type Aberto =
  | { tipo: "detalhe"; login: string }
  | { tipo: "novo" }
  | { tipo: "banco"; banco: string }
  | { tipo: "servidor"; nome: string }
  | null;
/** O ângulo da tabela principal (Kevin, 04/11/2026: "a visão por bancos e servidores vinculados, quem são os usuários neles"). */
type VisaoTipo = "logins" | "bancos" | "servidores";
const VISOES: { id: VisaoTipo; rotulo: string }[] = [
  { id: "logins", rotulo: "Logins" },
  { id: "bancos", rotulo: "Bancos" },
  { id: "servidores", rotulo: "Servidores vinculados" },
];

// Duração do deslize de saída da gaveta: a mesma do `usql-gav-sai` no CSS.
const SAIDA_MS = 260;

// ---------------------------------------------------------------------------
// Vocabulário
// ---------------------------------------------------------------------------

const FAIXA_ROTULO: Record<Faixa, string> = {
  ate30: "Ativo",
  "31a60": "31 a 60 dias",
  "61a90": "61 a 90 dias",
  "91a120": "91 a 120 dias",
  mais120: "+120 dias",
  nunca: "Sem registro",
};
const PAPEL_ROTULO: Record<Papel | "remover", string> = {
  leitura: "Leitura",
  escrita: "Leitura e escrita",
  dono: "Dono do banco",
  sem: "Sem papel",
  outro: "Outro",
  remover: "Sem acesso",
};
const RECORTES: { id: Recorte; rotulo: string; dica: string }[] = [
  { id: "todos", rotulo: "Todos", dica: "Todos os logins do servidor" },
  { id: "ativos", rotulo: "Ativos", dica: "Entraram nos últimos 30 dias" },
  { id: "sem_acesso", rotulo: "Sem acesso +90 d", dica: "Mais de 90 dias sem entrar, ou sem registro" },
  { id: "desligados", rotulo: "Desligados no RM", dica: "Pessoa vinculada com a ficha demitida no RM" },
  { id: "desativados", rotulo: "Desativados", dica: "Login desabilitado no servidor" },
  { id: "servico", rotulo: "Serviço e Windows", dica: "Contas de serviço, sysadmin e logins do Windows (só leitura)" },
];
const ACAO_ROTULO: Record<string, string> = {
  criar: "Criou o login",
  bancos: "Alterou bancos",
  linked: "Alterou servidores vinculados",
  pessoa: "Vinculou pessoa",
  desativar: "Desativou",
  ativar: "Ativou",
  resetar_senha: "Resetou a senha",
  excluir: "Excluiu",
  email: "E-mail",
  config: "Configuração",
  expiracao_off: "Senha trocada: expiração desligada",
  desativar_inatividade: "Desativado por inatividade",
  desativar_desligado: "Desativado: desligado no RM",
  erro: "Erro",
};

const fmtInt = (v: number) => v.toLocaleString("pt-BR");
const semAcento = (s: string) => s.normalize("NFD").replace(/[̀-ͯ]/g, "").toLowerCase();

function fmtDataHora(iso: string | null | undefined): string {
  if (!iso) return "—";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toLocaleString("pt-BR", { day: "2-digit", month: "2-digit", year: "2-digit", hour: "2-digit", minute: "2-digit" });
}
function fmtData(iso: string | null | undefined): string {
  if (!iso) return "—";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toLocaleDateString("pt-BR", { day: "2-digit", month: "2-digit", year: "numeric" });
}
function haQuanto(dias: number | null): string {
  if (dias === null) return "sem registro";
  if (dias === 0) return "hoje";
  if (dias === 1) return "ontem";
  return `há ${fmtInt(dias)} dias`;
}

function nomeDoAnexo(res: Response, padrao: string): string {
  const disp = res.headers.get("Content-Disposition") ?? "";
  const m = /filename\*?=(?:UTF-8'')?"?([^";]+)"?/i.exec(disp);
  return m ? decodeURIComponent(m[1]) : padrao;
}

async function api<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`/api/bi/usuarios-sql${path}`, {
    cache: "no-store",
    headers: { "Content-Type": "application/json", ...(init?.headers ?? {}) },
    ...init,
  });
  const j = (await res.json().catch(() => null)) as { message?: string; detail?: unknown } | null;
  if (!res.ok) {
    const det = j?.detail as { message?: string; detail?: string } | string | undefined;
    const msg =
      (typeof det === "object" && det && (det.detail || det.message)) ||
      (typeof det === "string" && det) ||
      j?.message ||
      `HTTP ${res.status}`;
    throw new Error(String(msg));
  }
  return j as T;
}

// ---------------------------------------------------------------------------
// Peças
// ---------------------------------------------------------------------------

function Selo({ faixa, dias }: { faixa: Faixa; dias: number | null }) {
  return (
    <span className={`selo f-${faixa}`} title={haQuanto(dias)}>
      <i />
      {FAIXA_ROTULO[faixa]}
    </span>
  );
}

function Th({
  rotulo, chave, ordem, setOrdem, num, titulo,
}: {
  rotulo: string; chave: Ordem["chave"]; ordem: Ordem | null; setOrdem: (o: Ordem) => void; num?: boolean; titulo?: string;
}) {
  const ativa = ordem?.chave === chave;
  return (
    <th scope="col" className={num ? "num" : undefined}>
      <button type="button" onClick={() => setOrdem({ chave, desc: ativa ? !ordem.desc : !!num })} title={titulo}>
        {rotulo}
        {ativa && <span className="seta">{ordem.desc ? "▼" : "▲"}</span>}
      </button>
    </th>
  );
}

/** Escolha de papel por banco — usada no novo usuário e na edição. */
function GradeBancos({
  bancos, valor, onChange, atual,
}: {
  bancos: string[];
  valor: Record<string, PapelEscolha>;
  onChange: (v: Record<string, PapelEscolha>) => void;
  atual?: Record<string, BancoDoLogin>;
}) {
  const [busca, setBusca] = useState("");
  const visiveis = useMemo(() => {
    const q = semAcento(busca.trim());
    return bancos.filter((b) => !q || semAcento(b).includes(q));
  }, [bancos, busca]);
  const marcados = Object.values(valor).filter((p) => p !== "remover").length;
  return (
    <div className="grade-bancos">
      <div className="grade-bancos-topo">
        <label className="busca mini">
          <IconSearch size={13} />
          <input value={busca} onChange={(e) => setBusca(e.target.value)} placeholder="Filtrar banco" aria-label="Filtrar banco" />
        </label>
        <span className="meta">
          <b>{marcados}</b> {marcados === 1 ? "banco" : "bancos"}
        </span>
      </div>
      <div className="rolagem curta">
        <table className="tab">
          <thead>
            <tr>
              <th scope="col">Banco</th>
              <th scope="col">Acesso</th>
            </tr>
          </thead>
          <tbody>
            {visiveis.length === 0 && (
              <tr><td className="vazio" colSpan={2}>Nenhum banco com esse nome.</td></tr>
            )}
            {visiveis.map((b) => {
              const a = atual?.[b];
              const outro = a?.papel === "outro";
              const v = valor[b] ?? (a ? (a.papel as PapelEscolha) : "remover");
              return (
                <tr key={b}>
                  <td className="nome">
                    <b>{b}</b>
                    {a && <span>{outro ? `papéis: ${a.roles.join(", ")}` : `hoje: ${PAPEL_ROTULO[a.papel]}`}</span>}
                  </td>
                  <td>
                    {outro ? (
                      <span className="meta" title="Papel que a tela não administra; mexa pelo SSMS">não administrado aqui</span>
                    ) : (
                      <select
                        className="sel"
                        value={v}
                        onChange={(e) => onChange({ ...valor, [b]: e.target.value as PapelEscolha })}
                        aria-label={`Acesso ao banco ${b}`}
                      >
                        <option value="remover">— sem acesso</option>
                        <option value="leitura">Leitura</option>
                        <option value="escrita">Leitura e escrita</option>
                        <option value="dono">Dono do banco</option>
                        {a && a.papel === "sem" && <option value="sem">Usuário sem papel</option>}
                      </select>
                    )}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}

/** Checkbox por servidor vinculado controlado; a família ERP aparece como aberta. */
function ListaLinked({
  servidores, permitidos, onChange,
}: {
  servidores: LinkedServer[]; permitidos: Set<string>; onChange: (s: Set<string>) => void;
}) {
  return (
    <ul className="lista-ls">
      {servidores.map((ls) => {
        const aberto = ls.modelo === "aberto";
        const manual = ls.modelo === "permissao" && !ls.libera_pela_tela;
        const on = aberto || permitidos.has(ls.nome);
        return (
          <li key={ls.nome} className={aberto ? "aberto" : undefined}>
            <label>
              <input
                type="checkbox"
                checked={on}
                disabled={aberto}
                onChange={(e) => {
                  const n = new Set(permitidos);
                  if (e.target.checked) n.add(ls.nome); else n.delete(ls.nome);
                  onChange(n);
                }}
              />
              <span className="ls-nome">{ls.nome}</span>
              <span className="ls-meta">
                {aberto
                  ? "aberto a todos (não controlado)"
                  : ls.modelo === "bloqueio"
                    ? `regra de bloqueio · remoto ${ls.remoto_padrao ?? "?"}`
                    : manual
                      ? "lista de permissão · liberar exige credencial (manual)"
                      : "lista de permissão"}
              </span>
            </label>
          </li>
        );
      })}
    </ul>
  );
}

/** Busca no RM (BancoRH): nome -> chapa e setor. */
function BuscaRm({ onEscolher }: { onEscolher: (p: PessoaRm) => void }) {
  const [q, setQ] = useState("");
  const [lista, setLista] = useState<PessoaRm[]>([]);
  const [aberta, setAberta] = useState(false);
  const [buscando, setBuscando] = useState(false);
  const t = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => {
    if (t.current) clearTimeout(t.current);
    if (q.trim().length < 3) { setLista([]); return; }
    t.current = setTimeout(async () => {
      setBuscando(true);
      try {
        const r = await api<{ pessoas: PessoaRm[] }>(`/pessoas?q=${encodeURIComponent(q.trim())}`);
        setLista(r.pessoas);
        setAberta(true);
      } catch {
        setLista([]);
      } finally {
        setBuscando(false);
      }
    }, 300);
    return () => { if (t.current) clearTimeout(t.current); };
  }, [q]);

  return (
    <div className="busca-rm">
      <label className="busca">
        <IconUser size={14} />
        <input
          value={q}
          onChange={(e) => setQ(e.target.value)}
          onFocus={() => lista.length > 0 && setAberta(true)}
          onBlur={() => setTimeout(() => setAberta(false), 150)}
          placeholder="Buscar pessoa no RM (nome)"
          aria-label="Buscar pessoa no RM"
        />
        {buscando && <span className="meta">…</span>}
      </label>
      {aberta && lista.length > 0 && (
        <ul className="sugestoes" role="listbox">
          {lista.map((p) => (
            <li key={p.chapa}>
              <button type="button" onMouseDown={(e) => e.preventDefault()} onClick={() => { onEscolher(p); setQ(p.nome); setAberta(false); }}>
                <b>{p.nome}</b>
                <span>{p.setor ?? p.codsecao ?? "setor não informado"} · chapa {p.chapa}</span>
              </button>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

/**
 * Gaveta que desliza da direita (pedido do Kevin, 04/11/2026: a tabela na tela toda e o
 * login abre numa gaveta suave, em vez do quadro ao lado). Mesmo desenho da gaveta do
 * gestor na Jornada de Trabalho: véu que clareia junto, entrada com desaceleração,
 * saída mais curta; fecha no véu, no X ou com Esc. Fecha em dois tempos: `sai` toca o
 * deslize e só depois a gaveta desmonta.
 */
function Gaveta({
  titulo, subtitulo, extra, onFechar, children,
}: {
  titulo: string; subtitulo?: string; extra?: React.ReactNode; onFechar: () => void; children: React.ReactNode;
}) {
  const [saindo, setSaindo] = useState(false);
  const fechar = useCallback(() => {
    setSaindo((s) => {
      if (s) return s;
      const parado = typeof window !== "undefined" && window.matchMedia?.("(prefers-reduced-motion: reduce)").matches;
      window.setTimeout(onFechar, parado ? 0 : SAIDA_MS);
      return true;
    });
  }, [onFechar]);
  useEffect(() => {
    const h = (e: KeyboardEvent) => { if (e.key === "Escape") fechar(); };
    window.addEventListener("keydown", h);
    const antes = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    return () => { window.removeEventListener("keydown", h); document.body.style.overflow = antes; };
  }, [fechar]);
  return (
    <>
      <div className={saindo ? "usql-veu sai" : "usql-veu"} onClick={fechar} aria-hidden="true" />
      <aside className={saindo ? "usql usql-gav sai" : "usql usql-gav"} role="dialog" aria-modal="true" aria-labelledby="usql-gav-t">
        <div className="gav-cab">
          <div className="gav-cab-txt">
            <h2 id="usql-gav-t">{titulo}</h2>
            {subtitulo && <p>{subtitulo}</p>}
          </div>
          {extra}
          <button type="button" className="gav-fecha" onClick={fechar} aria-label="Fechar">
            <IconClose size={16} />
          </button>
        </div>
        <div className="gav-corpo">{children}</div>
      </aside>
    </>
  );
}

function SenhaTemporaria({ login, senha, email }: { login: string; senha: string; email: { enviado: boolean; erro: string | null } | null }) {
  const [copiado, setCopiado] = useState(false);
  async function copiar() {
    try {
      await navigator.clipboard.writeText(`Login: ${login}\nSenha temporária: ${senha}`);
      setCopiado(true);
      setTimeout(() => setCopiado(false), 2000);
    } catch { /* sem clipboard: a senha está na tela */ }
  }
  return (
    <div className="senha-box" role="status">
      <p className="senha-titulo">Senha temporária de <b>{login}</b></p>
      <code className="senha">{senha}</code>
      <p className="meta">
        Aparece só agora. O SQL Server pede a nova senha na primeira conexão; depois da troca ela não expira.
      </p>
      <div className="acoes">
        <button type="button" className="btn" onClick={() => void copiar()}>{copiado ? "Copiado" : "Copiar login e senha"}</button>
        {email && (
          <span className={`meta ${email.enviado ? "ok" : "alerta"}`}>
            {email.enviado ? "E-mail enviado." : `E-mail não enviado: ${email.erro ?? "erro"}`}
          </span>
        )}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// A tela
// ---------------------------------------------------------------------------

export default function UsuariosSql() {
  const [dados, setDados] = useState<Visao | null>(null);
  const [carregando, setCarregando] = useState(true);
  const [erro, setErro] = useState<string | null>(null);
  const [busca, setBusca] = useState("");
  const [recorte, setRecorte] = useState<Recorte>("todos");
  const [ordem, setOrdem] = useState<Ordem | null>(null);
  const [aberto, setAberto] = useState<Aberto>(null);
  const [visaoTipo, setVisaoTipo] = useState<VisaoTipo>("logins");
  const [mostrarEventos, setMostrarEventos] = useState(false);
  const [exportando, setExportando] = useState(false);
  const [erroExcel, setErroExcel] = useState<string | null>(null);

  // ---- Excel: a planilha do controle (Logins, Bancos, Servidores vinculados, Histórico)
  async function exportar() {
    setExportando(true);
    setErroExcel(null);
    try {
      const res = await fetch("/api/bi/usuarios-sql/excel", { cache: "no-store" });
      if (!res.ok) {
        const j = (await res.json().catch(() => null)) as { detail?: { message?: string } } | null;
        throw new Error(j?.detail?.message || `HTTP ${res.status}`);
      }
      const blob = await res.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = nomeDoAnexo(res, "usuarios-sql-server.xlsx");
      document.body.appendChild(a);
      a.click();
      a.remove();
      setTimeout(() => URL.revokeObjectURL(url), 2000);
    } catch (e) {
      setErroExcel(e instanceof Error ? e.message : "Não consegui gerar a planilha");
    } finally {
      setExportando(false);
    }
  }

  const carregar = useCallback(async () => {
    setCarregando(true);
    setErro(null);
    try {
      setDados(await api<Visao>("/visao"));
    } catch (e) {
      setErro(e instanceof Error ? e.message : "Não consegui ler o servidor");
    } finally {
      setCarregando(false);
    }
  }, []);

  useEffect(() => { void carregar(); }, [carregar]);

  // ---- derivados -----------------------------------------------------------
  const linhas = useMemo(() => {
    if (!dados) return [];
    const q = semAcento(busca.trim());
    let l = dados.logins.filter((x) => {
      if (recorte === "todos") return true;
      if (recorte === "servico") return x.protegido;
      if (x.protegido) return false;
      if (recorte === "ativos") return x.faixa === "ate30" && !x.desativado;
      if (recorte === "sem_acesso") return !x.desativado && (x.faixa === "91a120" || x.faixa === "mais120" || x.faixa === "nunca");
      if (recorte === "desligados") return x.pessoa?.rm_situacao === "desligado";
      if (recorte === "desativados") return x.desativado;
      return true;
    });
    if (q) {
      l = l.filter((x) =>
        semAcento(x.login).includes(q) ||
        semAcento(x.pessoa?.nome ?? "").includes(q) ||
        semAcento(x.pessoa?.email ?? "").includes(q) ||
        semAcento(x.pessoa?.setor ?? "").includes(q) ||
        semAcento(x.pessoa?.finalidade ?? "").includes(q) ||
        x.bancos.some((b) => semAcento(b.banco).includes(q)),
      );
    }
    if (ordem) {
      const { chave, desc } = ordem;
      const val = (x: LoginApi): string | number => {
        if (chave === "pessoa") return x.pessoa?.nome ?? "";
        if (chave === "bancos") return x.bancos.length;
        if (chave === "ultimo_acesso") return x.ultimo_acesso ?? "";
        const v = x[chave];
        return typeof v === "number" || typeof v === "string" ? v : v ? 1 : 0;
      };
      l = [...l].sort((a, b) => {
        const va = val(a), vb = val(b);
        const c = typeof va === "number" && typeof vb === "number" ? va - vb : String(va).localeCompare(String(vb), "pt-BR");
        return desc ? -c : c;
      });
    } else {
      l = [...l].sort((a, b) => a.login.localeCompare(b.login, "pt-BR"));
    }
    return l;
  }, [dados, busca, recorte, ordem]);

  const kpis = useMemo(() => {
    const pessoas = (dados?.logins ?? []).filter((x) => !x.protegido);
    return {
      pessoas: pessoas.length,
      ativos: pessoas.filter((x) => !x.desativado && x.faixa === "ate30").length,
      mais90: pessoas.filter((x) => !x.desativado && (x.faixa === "91a120" || x.faixa === "mais120")).length,
      nunca: pessoas.filter((x) => !x.desativado && x.faixa === "nunca").length,
      desativados: pessoas.filter((x) => x.desativado).length,
      desligados: pessoas.filter((x) => !x.desativado && x.pessoa?.rm_situacao === "desligado" && !x.pessoa.excecao_desligado).length,
      trocaPendente: pessoas.filter((x) => !x.desativado && x.must_change).length,
      servico: (dados?.logins ?? []).filter((x) => x.protegido).length,
    };
  }, [dados]);

  const selecionado = useMemo(
    () => (aberto?.tipo === "detalhe" ? dados?.logins.find((x) => x.login === aberto.login) ?? null : null),
    [dados, aberto],
  );
  const lsControlados = useMemo(() => (dados?.linked_servers ?? []).filter((l) => l.controlado).length, [dados]);
  const fecharGaveta = useCallback(() => setAberto(null), []);

  // ---- visão por banco: quem tem usuário em cada banco, por papel ---------------
  type LinhaBanco = { banco: string; total: number; leitura: number; escrita: number; dono: number; outro: number; desativados: number; logins: { x: LoginApi; papel: Papel }[] };
  const porBanco = useMemo<LinhaBanco[]>(() => {
    if (!dados) return [];
    const q = semAcento(busca.trim());
    const mapa = new Map<string, LinhaBanco>();
    for (const b of dados.bancos) mapa.set(b, { banco: b, total: 0, leitura: 0, escrita: 0, dono: 0, outro: 0, desativados: 0, logins: [] });
    for (const x of dados.logins) {
      for (const b of x.bancos) {
        const l = mapa.get(b.banco);
        if (!l) continue;
        l.total += 1;
        if (b.papel === "leitura") l.leitura += 1;
        else if (b.papel === "escrita") l.escrita += 1;
        else if (b.papel === "dono") l.dono += 1;
        else l.outro += 1;
        if (x.desativado) l.desativados += 1;
        l.logins.push({ x, papel: b.papel });
      }
    }
    let lista = [...mapa.values()];
    if (q) lista = lista.filter((l) => semAcento(l.banco).includes(q) || l.logins.some((u) => semAcento(u.x.login).includes(q) || semAcento(u.x.pessoa?.nome ?? "").includes(q)));
    return lista.sort((a, b) => b.total - a.total || a.banco.localeCompare(b.banco, "pt-BR"));
  }, [dados, busca]);

  // ---- visão por servidor vinculado: quem passa em cada um -------------------------
  type LinhaServidor = { ls: LinkedServer; permitidos: LoginApi[]; bloqueados: number };
  const porServidor = useMemo<LinhaServidor[]>(() => {
    if (!dados) return [];
    const q = semAcento(busca.trim());
    let lista = dados.linked_servers.map((ls) => {
      const permitidos = dados.logins.filter((x) => x.linked[ls.nome] === "permitido");
      return { ls, permitidos, bloqueados: dados.logins.length - permitidos.length };
    });
    if (q) lista = lista.filter((l) => semAcento(l.ls.nome).includes(q) || l.permitidos.some((x) => semAcento(x.login).includes(q) || semAcento(x.pessoa?.nome ?? "").includes(q)));
    return lista;
  }, [dados, busca]);

  const bancoAberto = aberto?.tipo === "banco" ? porBanco.find((l) => l.banco === aberto.banco) ?? null : null;
  const servidorAberto = aberto?.tipo === "servidor" ? porServidor.find((l) => l.ls.nome === aberto.nome) ?? null : null;

  function escolher(login: string) {
    setAberto({ tipo: "detalhe", login });
  }

  // ---- render ---------------------------------------------------------------
  return (
    <div className="usql">
      <div className="usql-bar">
        <div className="seg" role="group" aria-label="Visão">
          {VISOES.map((v) => (
            <button key={v.id} type="button" aria-pressed={visaoTipo === v.id} onClick={() => setVisaoTipo(v.id)}>
              {v.rotulo}
            </button>
          ))}
        </div>
        {visaoTipo === "logins" && (
          <div className="seg" role="group" aria-label="Recorte de logins">
            {RECORTES.map((r) => (
              <button key={r.id} type="button" aria-pressed={recorte === r.id} onClick={() => setRecorte(r.id)} title={r.dica}>
                {r.rotulo}
              </button>
            ))}
          </div>
        )}
        <label className="busca">
          <IconSearch size={15} />
          <input
            type="search"
            value={busca}
            onChange={(e) => setBusca(e.target.value)}
            placeholder="Buscar login, pessoa, e-mail, setor ou banco"
            aria-label="Buscar login, pessoa, e-mail, setor ou banco"
          />
          {busca && (
            <button type="button" className="limpar" onClick={() => setBusca("")} aria-label="Limpar busca">
              <IconClose size={13} />
            </button>
          )}
        </label>
        <span className="espaco" />
        {dados && (
          <span className="meta" title={`${dados.servidor} (${dados.endereco})`}>
            <b>{dados.servidor}</b> · atualizado {fmtDataHora(dados.gerado_em)}
          </span>
        )}
        <button type="button" className="btn" onClick={() => void carregar()} disabled={carregando} title="Reler o servidor">
          <IconRefresh size={15} />
          Atualizar
        </button>
        <button
          type="button"
          className="btn btn-excel"
          onClick={() => void exportar()}
          disabled={exportando || carregando || !dados}
          title="Baixa a planilha com 4 abas: Logins, Bancos, Servidores vinculados e Histórico"
        >
          <IconExcel size={16} />
          {exportando ? "Gerando planilha…" : "Exportar Excel"}
        </button>
        <button
          type="button"
          className="btn btn-primario"
          onClick={() => setAberto({ tipo: "novo" })}
          disabled={!dados || !dados.setup_ok || !dados.pode_editar}
          title={
            dados && !dados.pode_editar
              ? "Você só visualiza esta tela (falta o nível Edição)"
              : dados && !dados.setup_ok
                ? "Rode o setup do servidor antes"
                : "Criar um login no SQL Server"
          }
        >
          <IconUser size={15} />
          Novo usuário
        </button>
      </div>

      {erroExcel && <p className="erro" role="alert">Planilha: {erroExcel}</p>}
      {erro && <p className="erro" role="alert">{erro}</p>}
      {carregando && !dados && <div className="esqueleto" aria-hidden="true" />}

      {dados && !dados.pode_editar && (
        <p className="aviso">
          <IconInfo size={15} className="mt-[1px] shrink-0" />
          <span>Somente visualização: você vê os logins, os acessos e o histórico. Criar, alterar e excluir exige o nível Edição, dado em Gerenciar usuários.</span>
        </p>
      )}
      {dados && !dados.setup_ok && (
        <p className="aviso">
          <IconInfo size={15} className="mt-[1px] shrink-0" />
          <span>
            O setup do servidor ainda não foi rodado (<code>deploy/sqlserver/acessos_sql_setup.sql</code>, como <code>sa</code> no servidor).
            Sem ele a tela só lista os logins: não há último acesso, cadastro de pessoa nem histórico, e não dá para criar.
          </span>
        </p>
      )}
      {dados && dados.setup_ok && !dados.audit_ligado && (
        <p className="aviso">
          <IconInfo size={15} className="mt-[1px] shrink-0" />
          <span>O registro de login com sucesso (audit <code>Portal_Logins</code>) está desligado: o último acesso só conta as sessões abertas agora.</span>
        </p>
      )}
      {dados && !dados.email_configurado && (
        <p className="aviso">
          <IconInfo size={15} className="mt-[1px] shrink-0" />
          <span>E-mail não configurado neste ambiente (PORTAL_MAIL_*): a senha temporária aparece na tela, mas não vai por e-mail.</span>
        </p>
      )}
      {dados && kpis.desligados > 0 && (
        <p className="erro destaque" role="alert">
          <span>
            <b>{fmtInt(kpis.desligados)}</b> {kpis.desligados === 1 ? "pessoa desligada no RM ainda tem" : "pessoas desligadas no RM ainda têm"} login ativo.
            {dados.config.desativar_desligados ? " O job de 15 min vai desativar." : " Decida na gaveta de cada um: desativar, excluir ou marcar a exceção."}
          </span>
          <button type="button" className="btn btn-perigo-suave" onClick={() => { setRecorte("desligados"); setBusca(""); }}>
            Ver quem
          </button>
        </p>
      )}

      {dados && (
        <>
          <dl className="kpis">
            <div className="kpi">
              <dt>Logins de pessoas</dt>
              <dd>{fmtInt(kpis.pessoas)}</dd>
              <dd className="pe">mais <b>{fmtInt(kpis.servico)}</b> de serviço, sysadmin e Windows</dd>
            </div>
            <div className="kpi">
              <dt>Ativos · 30 dias</dt>
              <dd className="ok">{fmtInt(kpis.ativos)}</dd>
              <dd className="pe">{dados.audit_desde ? `registro desde ${fmtData(dados.audit_desde)}` : "sem audit ligado"}</dd>
            </div>
            <div className="kpi">
              <dt>Sem acesso há +90 dias</dt>
              <dd className={kpis.mais90 > 0 ? "alerta" : "ok"}>{fmtInt(kpis.mais90)}</dd>
              <dd className="pe">e <b>{fmtInt(kpis.nunca)}</b> sem registro nenhum</dd>
            </div>
            <div className="kpi">
              <dt>Desativados</dt>
              <dd>{fmtInt(kpis.desativados)}</dd>
              <dd className="pe">
                {dados.config.dias_inatividade > 0 ? `automático após ${dados.config.dias_inatividade} dias` : "desativação automática desligada"}
              </dd>
            </div>
            <div className="kpi">
              <dt>Desligados no RM com login ativo</dt>
              <dd className={kpis.desligados > 0 ? "alerta" : "ok"}>{fmtInt(kpis.desligados)}</dd>
              <dd className="pe">
                {dados.config.desativar_desligados ? "o job de 15 min desativa sozinho" : "a tela avisa; a decisão é sua"}
              </dd>
            </div>
            <div className="kpi">
              <dt>Troca de senha pendente</dt>
              <dd className={kpis.trocaPendente > 0 ? "alerta" : "ok"}>{fmtInt(kpis.trocaPendente)}</dd>
              <dd className="pe">ainda com a senha temporária</dd>
            </div>
          </dl>

          {visaoTipo === "bancos" && (
            <div className="grade">
              <section className="quadro c12" aria-labelledby="usql-bancos">
                <div className="quadro-topo">
                  <div>
                    <h2 id="usql-bancos">Bancos</h2>
                    <p>{fmtInt(porBanco.length)} bancos · quem tem usuário em cada um, por papel · clique para ver a lista</p>
                  </div>
                </div>
                <div className="quadro-corpo">
                  <div className="rolagem">
                    <table className="tab">
                      <thead>
                        <tr>
                          <th scope="col">Banco</th>
                          <th scope="col" className="num">Usuários</th>
                          <th scope="col" className="num">Leitura</th>
                          <th scope="col" className="num">Leitura e escrita</th>
                          <th scope="col" className="num">Dono</th>
                          <th scope="col" className="num">Outro / sem papel</th>
                          <th scope="col" className="num">Desativados</th>
                          <th scope="col">Quem</th>
                        </tr>
                      </thead>
                      <tbody>
                        {porBanco.length === 0 && <tr><td className="vazio" colSpan={8}>Nada aqui com essa busca.</td></tr>}
                        {porBanco.map((l) => (
                          <tr key={l.banco} className="clic" tabIndex={0} aria-selected={aberto?.tipo === "banco" && aberto.banco === l.banco}
                            onClick={() => setAberto({ tipo: "banco", banco: l.banco })}
                            onKeyDown={(e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); setAberto({ tipo: "banco", banco: l.banco }); } }}>
                            <td className="nome"><b>{l.banco}</b></td>
                            <td className={`num ${l.total === 0 ? "zero" : ""}`}>{fmtInt(l.total)}</td>
                            <td className={`num ${l.leitura === 0 ? "zero" : ""}`}>{fmtInt(l.leitura)}</td>
                            <td className={`num ${l.escrita === 0 ? "zero" : ""}`}>{fmtInt(l.escrita)}</td>
                            <td className={`num ${l.dono === 0 ? "zero" : ""}`}>{fmtInt(l.dono)}</td>
                            <td className={`num ${l.outro === 0 ? "zero" : ""}`}>{fmtInt(l.outro)}</td>
                            <td className={`num ${l.desativados === 0 ? "zero" : ""}`}>{fmtInt(l.desativados)}</td>
                            <td className="quem" title={l.logins.map((u) => u.x.login).join(", ")}>
                              {l.logins.slice(0, 6).map((u) => u.x.login).join(", ")}{l.logins.length > 6 ? ` +${l.logins.length - 6}` : ""}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              </section>
            </div>
          )}

          {visaoTipo === "servidores" && (
            <div className="grade">
              <section className="quadro c12" aria-labelledby="usql-servidores">
                <div className="quadro-topo">
                  <div>
                    <h2 id="usql-servidores">Servidores vinculados</h2>
                    <p>quem passa em cada servidor vinculado do {dados.servidor} · clique para ver a lista</p>
                  </div>
                </div>
                <div className="quadro-corpo">
                  <div className="rolagem">
                    <table className="tab">
                      <thead>
                        <tr>
                          <th scope="col">Servidor</th>
                          <th scope="col">Modelo</th>
                          <th scope="col">Usuário remoto padrão</th>
                          <th scope="col" className="num">Liberados</th>
                          <th scope="col" className="num">Bloqueados</th>
                          <th scope="col">Quem passa</th>
                        </tr>
                      </thead>
                      <tbody>
                        {porServidor.length === 0 && <tr><td className="vazio" colSpan={6}>Nada aqui com essa busca.</td></tr>}
                        {porServidor.map((l) => (
                          <tr key={l.ls.nome} className="clic" tabIndex={0} aria-selected={aberto?.tipo === "servidor" && aberto.nome === l.ls.nome}
                            onClick={() => setAberto({ tipo: "servidor", nome: l.ls.nome })}
                            onKeyDown={(e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); setAberto({ tipo: "servidor", nome: l.ls.nome }); } }}>
                            <td className="nome"><b>{l.ls.nome}</b><span>{l.ls.data_source ?? ""}</span></td>
                            <td>
                              {l.ls.modelo === "aberto" ? <span className="pill">aberto a todos</span>
                                : l.ls.modelo === "bloqueio" ? <span className="pill ok">lista de bloqueio</span>
                                  : <span className="pill ok">lista de permissão{l.ls.libera_pela_tela ? "" : " · manual"}</span>}
                            </td>
                            <td>{l.ls.remoto_padrao ?? <span className="meta">— (sem padrão)</span>}</td>
                            <td className="num">{l.ls.modelo === "aberto" ? "todos" : fmtInt(l.permitidos.length)}</td>
                            <td className={`num ${l.ls.modelo === "aberto" ? "zero" : ""}`}>{l.ls.modelo === "aberto" ? "0" : fmtInt(l.bloqueados)}</td>
                            <td className="quem" title={l.ls.modelo === "aberto" ? "todo login do servidor" : l.permitidos.map((x) => x.login).join(", ")}>
                              {l.ls.modelo === "aberto" ? <span className="meta">todo login do servidor</span>
                                : `${l.permitidos.slice(0, 6).map((x) => x.login).join(", ")}${l.permitidos.length > 6 ? ` +${l.permitidos.length - 6}` : ""}`}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              </section>
            </div>
          )}

          <div className="grade" hidden={visaoTipo !== "logins"}>
            <section className="quadro c12" aria-labelledby="usql-lista">
              <div className="quadro-topo">
                <div>
                  <h2 id="usql-lista">Logins</h2>
                  <p>{fmtInt(linhas.length)} de {fmtInt(dados.logins.length)} · clique numa linha para ver e editar</p>
                </div>
              </div>
              <div className="quadro-corpo">
                <div className="rolagem">
                  <table className="tab">
                    <thead>
                      <tr>
                        <Th rotulo="Login" chave="login" ordem={ordem} setOrdem={setOrdem} />
                        <Th rotulo="Pessoa · setor" chave="pessoa" ordem={ordem} setOrdem={setOrdem} />
                        <Th rotulo="Bancos" chave="bancos" ordem={ordem} setOrdem={setOrdem} num titulo="Bancos em que tem usuário" />
                        <Th rotulo="Serv. vinc." chave="linked_permitidos" ordem={ordem} setOrdem={setOrdem} num titulo={`Servidores vinculados liberados, de ${lsControlados} controlados`} />
                        <Th rotulo="Último acesso" chave="ultimo_acesso" ordem={ordem} setOrdem={setOrdem} />
                        <th scope="col">Senha</th>
                        <Th rotulo="Situação" chave="desativado" ordem={ordem} setOrdem={setOrdem} />
                      </tr>
                    </thead>
                    <tbody>
                      {linhas.length === 0 && (
                        <tr><td className="vazio" colSpan={7}>Nada aqui com esse recorte.</td></tr>
                      )}
                      {linhas.map((x) => (
                        <tr
                          key={x.login}
                          className="clic"
                          tabIndex={0}
                          aria-selected={aberto?.tipo === "detalhe" && aberto.login === x.login}
                          onClick={() => escolher(x.login)}
                          onKeyDown={(e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); escolher(x.login); } }}
                        >
                          <td className="nome">
                            <b>{x.login}</b>
                            <span>{x.tipo === "sql" ? (x.sysadmin ? "sysadmin" : x.roles_servidor.join(", ") || "login SQL") : x.tipo === "windows" ? "login do Windows" : x.tipo}</span>
                          </td>
                          <td className="nome">
                            <b>
                              {x.pessoa?.generico
                                ? <><span className="pill ml0" title={x.pessoa.finalidade ?? "Login genérico"}>genérico</span>{x.pessoa.finalidade ? ` ${x.pessoa.finalidade}` : ""}</>
                                : x.pessoa?.nome ?? <span className="sem">— sem pessoa vinculada</span>}
                              {x.pessoa?.rm_situacao === "desligado" && (
                                <span className={`pill ml ${x.pessoa.excecao_desligado ? "" : "alerta"}`} title={(x.pessoa.rm_demissao ? `Desligado no RM em ${fmtData(x.pessoa.rm_demissao)}` : "Desligado no RM") + (x.pessoa.excecao_desligado ? " · exceção: o login fica" : "")}>
                                  desligado{x.pessoa.rm_demissao ? ` ${fmtData(x.pessoa.rm_demissao)}` : ""}{x.pessoa.excecao_desligado ? " · exceção" : ""}
                                </span>
                              )}
                              {x.pessoa?.rm_situacao === "nao_encontrado" && (
                                <span className="pill ml" title="A chapa vinculada não existe na cópia do RM">chapa não achada</span>
                              )}
                            </b>
                            <span>{x.pessoa?.setor ?? x.pessoa?.email ?? ""}</span>
                          </td>
                          <td className="num chips-td" title={x.bancos.map((b) => `${b.banco}: ${PAPEL_ROTULO[b.papel]}`).join("\n")}>
                            {x.bancos.length === 0 ? <span className="zero">0</span> : fmtInt(x.bancos.length)}
                          </td>
                          <td className={`num ${x.linked_permitidos === 0 ? "zero" : ""}`} title={Object.entries(x.linked).filter(([, s]) => s === "permitido").map(([n]) => n).join(", ") || "nenhum"}>
                            {fmtInt(x.linked_permitidos)}
                          </td>
                          <td className="quando">
                            {x.desativado ? (
                              <span className="selo sem">—</span>
                            ) : (
                              <>
                                <Selo faixa={x.faixa} dias={x.dias_sem_acesso} />
                                <span>{x.ultimo_acesso ? fmtDataHora(x.ultimo_acesso) : "sem registro"}{x.conectado_agora ? " · conectado agora" : ""}</span>
                              </>
                            )}
                          </td>
                          <td>
                            {x.tipo !== "sql" ? (
                              <span className="meta">Windows</span>
                            ) : x.must_change ? (
                              <span className="pill alerta" title="Ainda com a senha temporária">troca pendente</span>
                            ) : x.expiracao ? (
                              <span className="pill" title="Expiração ligada: o job desliga na próxima madrugada">expira</span>
                            ) : (
                              <span className="pill ok" title={`Senha definida em ${fmtDataHora(x.senha_em)}`}>não expira</span>
                            )}
                          </td>
                          <td>
                            {x.desativado ? <span className="pill off">desativado</span> : x.travado ? <span className="pill alerta">travado</span> : <span className="pill ok">ativo</span>}
                            {x.protegido && <span className="pill" title="Conta de serviço, sysadmin ou Windows: a tela não altera">protegido</span>}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
              <p className="quadro-pe">
                Último acesso = login com sucesso registrado pelo audit (a cada 15 min) ou sessão aberta agora. Antes do audit não há histórico.
              </p>
            </section>
          </div>

          {aberto?.tipo === "novo" && (
            <Gaveta
              titulo="Novo usuário"
              subtitulo={`Login SQL no ${dados.servidor}. A senha temporária é gerada e enviada por e-mail; a pessoa troca no primeiro acesso.`}
              onFechar={fecharGaveta}
            >
              <NovoUsuario
                dados={dados}
                onFechar={fecharGaveta}
                onAtualizar={carregar}
                onCriado={async (login) => { await carregar(); setAberto({ tipo: "detalhe", login }); }}
              />
            </Gaveta>
          )}
          {bancoAberto && (
            <Gaveta
              key={`banco-${bancoAberto.banco}`}
              titulo={bancoAberto.banco}
              subtitulo={`${fmtInt(bancoAberto.total)} usuários · ${fmtInt(bancoAberto.leitura)} leitura · ${fmtInt(bancoAberto.escrita)} leitura e escrita · ${fmtInt(bancoAberto.dono)} dono · ${fmtInt(bancoAberto.outro)} outro`}
              onFechar={fecharGaveta}
            >
              <ListaDeLogins
                itens={bancoAberto.logins.map((u) => ({ x: u.x, info: PAPEL_ROTULO[u.papel] }))}
                vazio="Nenhum usuário neste banco."
                onAbrir={(login) => setAberto({ tipo: "detalhe", login })}
              />
            </Gaveta>
          )}
          {servidorAberto && (
            <Gaveta
              key={`ls-${servidorAberto.ls.nome}`}
              titulo={servidorAberto.ls.nome}
              subtitulo={servidorAberto.ls.modelo === "aberto"
                ? "Aberto a todos: qualquer login do servidor passa (família ERP, fora do controle)"
                : `${servidorAberto.ls.modelo === "bloqueio" ? "Lista de bloqueio" : "Lista de permissão"} · remoto ${servidorAberto.ls.remoto_padrao ?? "—"} · ${fmtInt(servidorAberto.permitidos.length)} liberados, ${fmtInt(servidorAberto.bloqueados)} bloqueados`}
              onFechar={fecharGaveta}
            >
              <ListaDeLogins
                itens={servidorAberto.permitidos.map((x) => ({ x, info: "liberado" }))}
                vazio="Ninguém liberado neste servidor."
                onAbrir={(login) => setAberto({ tipo: "detalhe", login })}
              />
            </Gaveta>
          )}
          {selecionado && (
            <Gaveta
              key={selecionado.login}
              titulo={selecionado.login}
              subtitulo={[
                selecionado.tipo === "sql" ? "Login SQL" : selecionado.tipo === "windows" ? "Login do Windows" : selecionado.tipo,
                selecionado.sysadmin ? "sysadmin" : null,
                selecionado.criado_em ? `criado em ${fmtData(selecionado.criado_em)}` : null,
                selecionado.pessoa?.nome ?? null,
              ].filter(Boolean).join(" · ")}
              extra={selecionado.desativado ? <span className="pill off gav-pill">desativado</span> : <span className="pill ok gav-pill">ativo</span>}
              onFechar={fecharGaveta}
            >
              <Detalhe
                x={selecionado}
                dados={dados}
                onMudou={carregar}
                onExcluido={async () => { setAberto(null); await carregar(); }}
              />
            </Gaveta>
          )}

          <div className="grade">
            <section className="quadro c5" aria-labelledby="usql-config">
              <div className="quadro-topo">
                <div>
                  <h2 id="usql-config">Desativação automática</h2>
                  <p>Contas de serviço, sysadmin e <code>sa</code> nunca entram. Desativar guarda o histórico; excluir é decisão de gente, pela gaveta.</p>
                </div>
              </div>
              <div className="quadro-corpo">
                <ConfigDesligados valor={dados.config.desativar_desligados} desabilitado={!dados.setup_ok || !dados.pode_editar} onSalvo={carregar} />
                <p className="meta">
                  Pessoa vinculada pela chapa cuja ficha no RM está demitida (cópia diária do RM em <code>BancoRH</code>). Quem foi transferido entre coligadas segue ativo.
                </p>
                <ConfigInatividade valor={dados.config.dias_inatividade} desabilitado={!dados.setup_ok || !dados.pode_editar} onSalvo={carregar} />
                <p className="meta">
                  Job das 02:30. Conta a partir de {dados.audit_desde ? fmtData(dados.audit_desde) : "quando o audit for ligado"}: ninguém é desativado por não ter histórico anterior. Zero desliga.
                </p>
              </div>
            </section>

            <section className="quadro c7" aria-labelledby="usql-eventos">
              <div className="quadro-topo">
                <div>
                  <h2 id="usql-eventos">Histórico</h2>
                  <p>O que a tela e os jobs fizeram, por quem e quando · {fmtInt(dados.eventos.length)} últimos</p>
                </div>
                <button type="button" className="btn" onClick={() => setMostrarEventos((v) => !v)}>
                  {mostrarEventos ? "Recolher" : "Mostrar"}
                </button>
              </div>
              {mostrarEventos && (
                <div className="quadro-corpo">
                  <div className="rolagem">
                    <table className="tab">
                      <thead>
                        <tr>
                          <th scope="col">Quando</th>
                          <th scope="col">Quem</th>
                          <th scope="col">Ação</th>
                          <th scope="col">Login</th>
                          <th scope="col">Detalhe</th>
                        </tr>
                      </thead>
                      <tbody>
                        {dados.eventos.length === 0 && <tr><td className="vazio" colSpan={5}>Nada registrado ainda.</td></tr>}
                        {dados.eventos.map((ev) => (
                          <tr key={ev.id}>
                            <td className="quando"><b>{fmtDataHora(ev.em)}</b></td>
                            <td>{ev.por ?? "—"}</td>
                            <td>{ACAO_ROTULO[ev.acao] ?? ev.acao}</td>
                            <td><b>{ev.login_alvo ?? "—"}</b></td>
                            <td className="detalhe" title={ev.detalhe ?? undefined}>{ev.detalhe ?? ""}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}
            </section>
          </div>
        </>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Gaveta: quem está num banco ou num servidor vinculado
// ---------------------------------------------------------------------------

function ListaDeLogins({ itens, vazio, onAbrir }: { itens: { x: LoginApi; info: string }[]; vazio: string; onAbrir: (login: string) => void }) {
  const ordenados = useMemo(() => [...itens].sort((a, b) => a.x.login.localeCompare(b.x.login, "pt-BR")), [itens]);
  return (
    <div className="detalhe">
      <div className="rolagem">
        <table className="tab">
          <thead>
            <tr>
              <th scope="col">Login</th>
              <th scope="col">Pessoa · setor</th>
              <th scope="col">Acesso</th>
              <th scope="col">Último acesso</th>
              <th scope="col">Situação</th>
            </tr>
          </thead>
          <tbody>
            {ordenados.length === 0 && <tr><td className="vazio" colSpan={5}>{vazio}</td></tr>}
            {ordenados.map(({ x, info }) => (
              <tr key={x.login} className="clic" tabIndex={0} onClick={() => onAbrir(x.login)}
                onKeyDown={(e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); onAbrir(x.login); } }}
                title="Abrir o login">
                <td className="nome"><b>{x.login}</b><span>{x.tipo === "sql" ? (x.sysadmin ? "sysadmin" : "login SQL") : x.tipo}</span></td>
                <td className="nome"><b>{x.pessoa?.nome ?? <span className="sem">—</span>}</b><span>{x.pessoa?.setor ?? ""}</span></td>
                <td>{info}</td>
                <td className="quando">
                  {x.desativado ? <span className="selo sem">—</span> : <><Selo faixa={x.faixa} dias={x.dias_sem_acesso} /><span>{x.ultimo_acesso ? fmtDataHora(x.ultimo_acesso) : "sem registro"}</span></>}
                </td>
                <td>
                  {x.desativado ? <span className="pill off">desativado</span> : <span className="pill ok">ativo</span>}
                  {x.protegido && <span className="pill">protegido</span>}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <p className="meta">Clique num login para abrir a gaveta dele.</p>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Painel: detalhe e edição de um login
// ---------------------------------------------------------------------------

function Detalhe({
  x, dados, onMudou, onExcluido,
}: {
  x: LoginApi; dados: Visao; onMudou: () => Promise<void>; onExcluido: () => Promise<void>;
}) {
  const atualMapa = useMemo(() => Object.fromEntries(x.bancos.map((b) => [b.banco, b])), [x.bancos]);
  const [bancos, setBancos] = useState<Record<string, PapelEscolha>>({});
  const [permitidos, setPermitidos] = useState<Set<string>>(
    () => new Set(Object.entries(x.linked).filter(([n, s]) => s === "permitido" && dados.linked_servers.find((l) => l.nome === n)?.controlado).map(([n]) => n)),
  );
  const [pessoa, setPessoa] = useState<Pessoa>({
    nome: x.pessoa?.nome ?? null, email: x.pessoa?.email ?? null, chapa: x.pessoa?.chapa ?? null, setor: x.pessoa?.setor ?? null,
    excecao_desligado: x.pessoa?.excecao_desligado ?? false,
    generico: x.pessoa?.generico ?? false, finalidade: x.pessoa?.finalidade ?? null,
  });
  const [ocupado, setOcupado] = useState<string | null>(null);
  const [msg, setMsg] = useState<string | null>(null);
  const [erro, setErro] = useState<string | null>(null);
  const [senha, setSenha] = useState<{ senha: string; email: { enviado: boolean; erro: string | null } | null } | null>(null);
  const [confirmaExclusao, setConfirmaExclusao] = useState(false);

  const bancosMudaram = Object.keys(bancos).some((b) => (bancos[b] !== ((atualMapa[b]?.papel as PapelEscolha | undefined) ?? "remover")));
  const permitidosAtuais = useMemo(() => new Set(Object.entries(x.linked).filter(([, s]) => s === "permitido").map(([n]) => n)), [x.linked]);
  const linkedMudou = dados.linked_servers.some((l) => l.controlado && permitidos.has(l.nome) !== permitidosAtuais.has(l.nome));
  const pessoaMudou = (pessoa.nome ?? "") !== (x.pessoa?.nome ?? "") || (pessoa.email ?? "") !== (x.pessoa?.email ?? "") || (pessoa.setor ?? "") !== (x.pessoa?.setor ?? "") || (pessoa.chapa ?? "") !== (x.pessoa?.chapa ?? "")
    || !!pessoa.excecao_desligado !== !!x.pessoa?.excecao_desligado
    || !!pessoa.generico !== !!x.pessoa?.generico || (pessoa.finalidade ?? "") !== (x.pessoa?.finalidade ?? "");

  async function rodar(nome: string, fn: () => Promise<string | null>) {
    setOcupado(nome);
    setErro(null);
    setMsg(null);
    try {
      const m = await fn();
      if (m) setMsg(m);
      await onMudou();
    } catch (e) {
      setErro(e instanceof Error ? e.message : "Falhou");
    } finally {
      setOcupado(null);
    }
  }

  const soLeitura = x.protegido || !dados.pode_editar;

  return (
    <div className="detalhe">
      {x.protegido && (
        <p className="aviso">
          <IconInfo size={15} className="mt-[1px] shrink-0" />
          <span>Conta de serviço, sysadmin ou do Windows: a tela mostra, mas não altera. Mexa pelo SSMS.</span>
        </p>
      )}
      {x.pessoa?.rm_situacao === "desligado" && !x.desativado && !pessoa.excecao_desligado && (
        <p className="erro" role="alert">
          Pessoa desligada no RM{x.pessoa.rm_demissao ? ` em ${fmtData(x.pessoa.rm_demissao)}` : ""} e o login continua ativo.
          {dados.config.desativar_desligados && !x.protegido ? " O job de 15 min vai desativar; " : " "}Desative ou exclua agora nas ações abaixo, ou marque a exceção em Pessoa se o acesso deve continuar.
        </p>
      )}
      {x.pessoa?.rm_situacao === "desligado" && !x.desativado && pessoa.excecao_desligado && (
        <p className="aviso">
          <IconInfo size={15} className="mt-[1px] shrink-0" />
          <span>Ficha desligada no RM{x.pessoa.rm_demissao ? ` em ${fmtData(x.pessoa.rm_demissao)}` : ""}, com exceção marcada: o login fica e o job não desativa.</span>
        </p>
      )}
      {x.pessoa?.rm_situacao === "desligado" && x.desativado && (
        <p className="aviso">
          <IconInfo size={15} className="mt-[1px] shrink-0" />
          <span>Pessoa desligada no RM{x.pessoa.rm_demissao ? ` em ${fmtData(x.pessoa.rm_demissao)}` : ""}; o login já está desativado. Se não precisar mais do histórico, exclua.</span>
        </p>
      )}
      {erro && <p className="erro" role="alert">{erro}</p>}
      {msg && <p className="ok-msg" role="status">{msg}</p>}
      {senha && <SenhaTemporaria login={x.login} senha={senha.senha} email={senha.email} />}

      <div className="bloco">
        <h3>Acesso</h3>
        <dl className="fatos">
          <div><dt>Último acesso</dt><dd>{x.ultimo_acesso ? `${fmtDataHora(x.ultimo_acesso)} (${haQuanto(x.dias_sem_acesso)})` : "sem registro"}{x.conectado_agora ? " · conectado agora" : ""}</dd></div>
          <div><dt>De onde</dt><dd>{x.ultimo_host || "—"}{x.ultimo_programa ? ` · ${x.ultimo_programa}` : ""}</dd></div>
          <div><dt>Acessos registrados</dt><dd>{x.total_acessos != null ? fmtInt(x.total_acessos) : "—"}</dd></div>
          <div><dt>Senha</dt><dd>{x.tipo !== "sql" ? "Windows" : x.must_change ? "troca pendente (temporária)" : x.expiracao ? "expira (o job desliga após a troca)" : `não expira · definida em ${fmtDataHora(x.senha_em)}`}</dd></div>
        </dl>
      </div>

      <div className="bloco">
        <h3>Pessoa</h3>
        {!soLeitura && (
          <label className="check" title="Login que não é de uma pessoa: integração, planilha de área, parceiro. Fica fora da busca do RM e da regra de desligado.">
            <input type="checkbox" checked={!!pessoa.generico} onChange={(e) => setPessoa({ ...pessoa, generico: e.target.checked, ...(e.target.checked ? { chapa: null } : {}) })} />
            <span>Login genérico (não é uma pessoa)</span>
          </label>
        )}
        {!soLeitura && !pessoa.generico && <BuscaRm onEscolher={(p) => setPessoa((v) => ({ ...v, nome: p.nome, chapa: p.chapa, setor: p.setor ?? p.codsecao }))} />}
        <div className="form-grid">
          {pessoa.generico ? (
            <>
              <label className="campo"><span>Finalidade</span><input value={pessoa.finalidade ?? ""} onChange={(e) => setPessoa({ ...pessoa, finalidade: e.target.value })} disabled={soLeitura} maxLength={200} placeholder="ex.: planilhas Excel das áreas" /></label>
              <label className="campo"><span>Responsável</span><input value={pessoa.nome ?? ""} onChange={(e) => setPessoa({ ...pessoa, nome: e.target.value })} disabled={soLeitura} maxLength={200} placeholder="quem responde por este login" /></label>
              <label className="campo"><span>E-mail do responsável</span><input type="email" value={pessoa.email ?? ""} onChange={(e) => setPessoa({ ...pessoa, email: e.target.value })} disabled={soLeitura} maxLength={254} /></label>
              <label className="campo"><span>Setor</span><input value={pessoa.setor ?? ""} onChange={(e) => setPessoa({ ...pessoa, setor: e.target.value })} disabled={soLeitura} maxLength={200} /></label>
            </>
          ) : (
            <>
              <label className="campo"><span>Nome</span><input value={pessoa.nome ?? ""} onChange={(e) => setPessoa({ ...pessoa, nome: e.target.value })} disabled={soLeitura} maxLength={200} /></label>
              <label className="campo"><span>E-mail</span><input type="email" value={pessoa.email ?? ""} onChange={(e) => setPessoa({ ...pessoa, email: e.target.value })} disabled={soLeitura} maxLength={254} /></label>
              <label className="campo"><span>Setor</span><input value={pessoa.setor ?? ""} onChange={(e) => setPessoa({ ...pessoa, setor: e.target.value })} disabled={soLeitura} maxLength={200} /></label>
              <label className="campo"><span>Chapa (RM)</span><input value={pessoa.chapa ?? ""} onChange={(e) => setPessoa({ ...pessoa, chapa: e.target.value })} disabled={soLeitura} maxLength={16} /></label>
            </>
          )}
        </div>
        {!soLeitura && !pessoa.generico && (
          <label className="check" title="Para quem sai do quadro mas continua precisando do acesso, como quem vira PJ">
            <input type="checkbox" checked={!!pessoa.excecao_desligado} onChange={(e) => setPessoa({ ...pessoa, excecao_desligado: e.target.checked })} />
            <span>Não desativar automaticamente se a ficha for desligada no RM (ex.: virou PJ)</span>
          </label>
        )}
        {!soLeitura && (
          <div className="acoes">
            <button type="button" className="btn btn-primario" disabled={!pessoaMudou || !!ocupado}
              onClick={() => void rodar("pessoa", async () => {
                await api(`/logins/${encodeURIComponent(x.login)}/pessoa`, { method: "PUT", body: JSON.stringify({ nome: pessoa.nome || null, email: pessoa.email || null, chapa: pessoa.generico ? null : (pessoa.chapa || null), setor: pessoa.setor || null, excecao_desligado: !!pessoa.excecao_desligado, generico: !!pessoa.generico, finalidade: pessoa.finalidade || null }) });
                return "Pessoa salva.";
              })}>
              {ocupado === "pessoa" ? "Salvando…" : "Salvar pessoa"}
            </button>
          </div>
        )}
      </div>

      <div className="bloco">
        <h3>Bancos</h3>
        {soLeitura ? (
          <ul className="lista-simples">
            {x.bancos.length === 0 && <li className="meta">Nenhum banco.</li>}
            {x.bancos.map((b) => <li key={b.banco}><b>{b.banco}</b> <span className="meta">{b.papel === "outro" ? b.roles.join(", ") : PAPEL_ROTULO[b.papel]}</span></li>)}
          </ul>
        ) : (
          <>
            <GradeBancos bancos={dados.bancos} valor={bancos} onChange={setBancos} atual={atualMapa} />
            <div className="acoes">
              <button type="button" className="btn btn-primario" disabled={!bancosMudaram || !!ocupado}
                onClick={() => void rodar("bancos", async () => {
                  const lista = Object.entries(bancos).map(([banco, papel]) => ({ banco, papel }));
                  const r = await api<{ feitos: string[] }>(`/logins/${encodeURIComponent(x.login)}/bancos`, { method: "PUT", body: JSON.stringify({ bancos: lista }) });
                  setBancos({});
                  return r.feitos.length ? `Bancos: ${r.feitos.join("; ")}` : "Nada a mudar.";
                })}>
                {ocupado === "bancos" ? "Aplicando…" : "Salvar bancos"}
              </button>
              {bancosMudaram && <button type="button" className="btn" onClick={() => setBancos({})}>Desfazer</button>}
            </div>
          </>
        )}
      </div>

      <div className="bloco">
        <h3>Servidores vinculados</h3>
        {soLeitura ? (
          <ul className="lista-simples">
            {dados.linked_servers.map((l) => <li key={l.nome}><b>{l.nome}</b> <span className="meta">{l.modelo === "aberto" ? "aberto" : x.linked[l.nome] ?? "?"}</span></li>)}
          </ul>
        ) : (
          <>
            <ListaLinked servidores={dados.linked_servers} permitidos={permitidos} onChange={setPermitidos} />
            <div className="acoes">
              <button type="button" className="btn btn-primario" disabled={!linkedMudou || !!ocupado}
                onClick={() => void rodar("linked", async () => {
                  const r = await api<{ feitos: string[]; manuais: string[] }>(`/logins/${encodeURIComponent(x.login)}/linked`, { method: "PUT", body: JSON.stringify({ permitidos: [...permitidos] }) });
                  const partes = [...r.feitos];
                  if (r.manuais.length) partes.push(`manual: ${r.manuais.join("; ")}`);
                  return partes.length ? partes.join(" · ") : "Nada a mudar.";
                })}>
                {ocupado === "linked" ? "Aplicando…" : "Salvar servidores"}
              </button>
            </div>
          </>
        )}
      </div>

      {!soLeitura && (
        <div className="bloco">
          <h3>Ações</h3>
          <div className="acoes">
            {x.desativado ? (
              <button type="button" className="btn" disabled={!!ocupado} onClick={() => void rodar("ativar", async () => { await api(`/logins/${encodeURIComponent(x.login)}/ativar`, { method: "POST", body: "{}" }); return "Login ativado."; })}>
                {ocupado === "ativar" ? "…" : "Ativar"}
              </button>
            ) : (
              <button type="button" className="btn" disabled={!!ocupado} onClick={() => void rodar("desativar", async () => { await api(`/logins/${encodeURIComponent(x.login)}/desativar`, { method: "POST", body: "{}" }); return "Login desativado: não conecta mais, os acessos ficam guardados."; })}>
                {ocupado === "desativar" ? "…" : "Desativar"}
              </button>
            )}
            <button type="button" className="btn" disabled={!!ocupado} onClick={() => void rodar("reset", async () => {
              const r = await api<{ senha_temporaria: string; email: { enviado: boolean; erro: string | null } | null; email_destino: string | null }>(`/logins/${encodeURIComponent(x.login)}/resetar-senha`, { method: "POST", body: JSON.stringify({ enviar_email: true }) });
              setSenha({ senha: r.senha_temporaria, email: r.email });
              return r.email_destino ? null : "Sem e-mail cadastrado: passe a senha por outro canal.";
            })}>
              {ocupado === "reset" ? "…" : "Resetar senha"}
            </button>
            <span className="espaco" />
            {confirmaExclusao ? (
              <>
                <span className="meta alerta">Excluir o login e os usuários dele nos bancos?</span>
                <button type="button" className="btn btn-perigo" disabled={!!ocupado} onClick={() => void (async () => {
                  setOcupado("excluir"); setErro(null);
                  try { await api(`/logins/${encodeURIComponent(x.login)}`, { method: "DELETE" }); await onExcluido(); }
                  catch (e) { setErro(e instanceof Error ? e.message : "Falhou"); setOcupado(null); }
                })()}>
                  {ocupado === "excluir" ? "Excluindo…" : "Sim, excluir"}
                </button>
                <button type="button" className="btn" onClick={() => setConfirmaExclusao(false)}>Não</button>
              </>
            ) : (
              <button type="button" className="btn btn-perigo-suave" disabled={!!ocupado} onClick={() => setConfirmaExclusao(true)}>Excluir</button>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Painel: novo usuário
// ---------------------------------------------------------------------------

function NovoUsuario({ dados, onFechar, onAtualizar, onCriado }: {
  dados: Visao; onFechar: () => void;
  /** Recarrega a lista atrás da gaveta assim que o login existe (Kevin, 04/11: "tive que atualizar a tela pra aparecer"). */
  onAtualizar: () => Promise<void>;
  onCriado: (login: string) => Promise<void>;
}) {
  const [login, setLogin] = useState("");
  const [nome, setNome] = useState("");
  const [email, setEmail] = useState("");
  const [setor, setSetor] = useState("");
  const [chapa, setChapa] = useState("");
  const [bancos, setBancos] = useState<Record<string, PapelEscolha>>({});
  const [permitidos, setPermitidos] = useState<Set<string>>(new Set());
  const [enviarEmail, setEnviarEmail] = useState(true);
  const [enviando, setEnviando] = useState(false);
  const [erro, setErro] = useState<string | null>(null);
  const [resultado, setResultado] = useState<{ login: string; senha: string; email: { enviado: boolean; erro: string | null } | null; manuais: string[] } | null>(null);

  function sugerirLogin(n: string) {
    const partes = semAcento(n).replace(/[^a-z\s]/g, "").trim().split(/\s+/).filter(Boolean);
    if (partes.length === 0) return;
    const sug = partes.length === 1 ? partes[0] : `${partes[0]}${partes[partes.length - 1]}`;
    if (!login) setLogin(sug.slice(0, 64));
  }

  const loginOk = /^[A-Za-z][A-Za-z0-9_.-]{2,63}$/.test(login);
  const existe = dados.logins.some((x) => x.login.toLowerCase() === login.toLowerCase());

  async function criar() {
    setEnviando(true);
    setErro(null);
    try {
      const lista = Object.entries(bancos).filter(([, p]) => p !== "remover").map(([banco, papel]) => ({ banco, papel }));
      const r = await api<{ login: string; senha_temporaria: string; email: { enviado: boolean; erro: string | null } | null; manuais: string[] }>("/logins", {
        method: "POST",
        body: JSON.stringify({ login, nome: nome || null, email: email || null, setor: setor || null, chapa: chapa || null, bancos: lista, linked_permitidos: [...permitidos], enviar_email: enviarEmail && !!email }),
      });
      setResultado({ login: r.login, senha: r.senha_temporaria, email: r.email, manuais: r.manuais });
      void onAtualizar();
    } catch (e) {
      setErro(e instanceof Error ? e.message : "Não consegui criar");
    } finally {
      setEnviando(false);
    }
  }

  if (resultado) {
    return (
      <div className="detalhe">
        <p className="ok-msg" role="status">Usuário <b>{resultado.login}</b> criado e ativo.</p>
        <SenhaTemporaria login={resultado.login} senha={resultado.senha} email={resultado.email} />
        {resultado.manuais.length > 0 && (
          <p className="aviso"><IconInfo size={15} className="mt-[1px] shrink-0" /><span>Pendente no SSMS: {resultado.manuais.join("; ")}</span></p>
        )}
        <div className="acoes">
          <button type="button" className="btn btn-primario" onClick={() => void onCriado(resultado.login)}>Abrir o login</button>
          <button type="button" className="btn" onClick={() => { setResultado(null); setLogin(""); setNome(""); setEmail(""); setSetor(""); setChapa(""); setBancos({}); setPermitidos(new Set()); }}>Criar outro</button>
        </div>
      </div>
    );
  }

  return (
    <form className="detalhe" onSubmit={(e) => { e.preventDefault(); if (loginOk && !existe) void criar(); }}>
      {erro && <p className="erro" role="alert">{erro}</p>}

      <div className="bloco">
        <h3>Pessoa</h3>
        <BuscaRm onEscolher={(p) => { setNome(p.nome); setChapa(p.chapa); setSetor(p.setor ?? p.codsecao ?? ""); sugerirLogin(p.nome); }} />
        <div className="form-grid">
          <label className="campo"><span>Nome</span><input value={nome} onChange={(e) => { setNome(e.target.value); }} onBlur={() => sugerirLogin(nome)} maxLength={200} /></label>
          <label className="campo"><span>E-mail</span><input type="email" value={email} onChange={(e) => setEmail(e.target.value)} placeholder="nome@empresa.com.br" maxLength={254} /></label>
          <label className="campo"><span>Setor</span><input value={setor} onChange={(e) => setSetor(e.target.value)} maxLength={200} /></label>
          <label className="campo"><span>Chapa (RM)</span><input value={chapa} onChange={(e) => setChapa(e.target.value)} maxLength={16} /></label>
        </div>
      </div>

      <div className="bloco">
        <h3>Login</h3>
        <label className="campo">
          <span>Nome do login</span>
          <input value={login} onChange={(e) => setLogin(e.target.value.trim())} placeholder="nomesobrenome" autoCapitalize="off" autoCorrect="off" spellCheck={false} maxLength={64} required />
        </label>
        {login && !loginOk && <p className="meta alerta">Comece com letra; só letras, números, _ . - (3 a 64).</p>}
        {existe && <p className="meta alerta">Já existe um login com esse nome.</p>}
        <label className="check">
          <input type="checkbox" checked={enviarEmail} onChange={(e) => setEnviarEmail(e.target.checked)} disabled={!dados.email_configurado || !email} />
          <span>Enviar login e senha temporária por e-mail{!email ? " (informe o e-mail)" : ""}{!dados.email_configurado ? " (e-mail não configurado)" : ""}</span>
        </label>
      </div>

      <div className="bloco">
        <h3>Bancos</h3>
        <GradeBancos bancos={dados.bancos} valor={bancos} onChange={setBancos} />
      </div>

      <div className="bloco">
        <h3>Servidores vinculados</h3>
        <p className="meta">Desmarcado = bloqueado. A família ERP não é controlada.</p>
        <ListaLinked servidores={dados.linked_servers} permitidos={permitidos} onChange={setPermitidos} />
      </div>

      <div className="acoes fim">
        <button type="submit" className="btn btn-primario" disabled={enviando || !loginOk || existe}>
          {enviando ? "Criando…" : "Criar usuário"}
        </button>
        <button type="button" className="btn" onClick={onFechar} disabled={enviando}>Cancelar</button>
      </div>
    </form>
  );
}

// ---------------------------------------------------------------------------
// Configuração: desligados no RM
// ---------------------------------------------------------------------------

function ConfigDesligados({ valor, desabilitado, onSalvo }: { valor: boolean; desabilitado: boolean; onSalvo: () => Promise<void> }) {
  const [salvando, setSalvando] = useState(false);
  const [erro, setErro] = useState<string | null>(null);
  return (
    <div className="config-linha">
      <label className="check">
        <input
          type="checkbox"
          checked={valor}
          disabled={desabilitado || salvando}
          onChange={(e) => void (async () => {
            setSalvando(true); setErro(null);
            try { await api("/config", { method: "PUT", body: JSON.stringify({ desativar_desligados: e.target.checked }) }); await onSalvo(); }
            catch (err) { setErro(err instanceof Error ? err.message : "Falhou"); }
            finally { setSalvando(false); }
          })()}
        />
        <span>Desativar sozinho o login de quem for desligado no RM (job de 15 min). Desligado = a tela só avisa e você decide.</span>
      </label>
      {salvando && <span className="meta">salvando…</span>}
      {erro && <span className="meta alerta">{erro}</span>}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Configuração: dias de inatividade
// ---------------------------------------------------------------------------

function ConfigInatividade({ valor, desabilitado, onSalvo }: { valor: number; desabilitado: boolean; onSalvo: () => Promise<void> }) {
  const [dias, setDias] = useState(String(valor));
  const [salvando, setSalvando] = useState(false);
  const [erro, setErro] = useState<string | null>(null);
  useEffect(() => { setDias(String(valor)); }, [valor]);
  const n = Number(dias);
  const valido = Number.isInteger(n) && n >= 0 && n <= 3650;
  return (
    <div className="config-linha">
      <label className="campo inline">
        <span>Desativar após</span>
        <input type="number" min={0} max={3650} value={dias} onChange={(e) => setDias(e.target.value)} disabled={desabilitado} aria-label="Dias sem acesso para desativar" />
        <span>dias sem acesso</span>
      </label>
      <button type="button" className="btn btn-primario" disabled={desabilitado || salvando || !valido || n === valor}
        onClick={() => void (async () => {
          setSalvando(true); setErro(null);
          try { await api("/config", { method: "PUT", body: JSON.stringify({ dias_inatividade: n }) }); await onSalvo(); }
          catch (e) { setErro(e instanceof Error ? e.message : "Falhou"); }
          finally { setSalvando(false); }
        })()}>
        {salvando ? "Salvando…" : "Salvar"}
      </button>
      {n === 0 && <span className="meta">desligado</span>}
      {erro && <span className="meta alerta">{erro}</span>}
    </div>
  );
}

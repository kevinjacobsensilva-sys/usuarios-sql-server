# Trechos de integração no front (Next.js, App Router)

## `components/icons.tsx` — ícone da tela

```tsx
/** SQL Server Management Studio: o cilindro do banco com a chave de manutenção
 * (Configurações > Usuários SQL Server). No traço das outras, cor do menu. */
export function IconSsms({ size, className }: IconProps) {
  return (
    <svg {...base(size)} className={className} aria-hidden="true">
      <ellipse cx="11" cy="5.5" rx="7" ry="2.5" />
      <path d="M4 5.5v6c0 1.4 3.1 2.5 7 2.5 1.1 0 2.1-.1 3-.2" />
      <path d="M4 11.5v6c0 1.4 3.1 2.5 7 2.5.7 0 1.4 0 2-.1" />
      <path d="M18 5.5v5" />
      <path d="M15.2 17.3a2.6 2.6 0 1 0 3.4-3.4l2.4-2.4-1.5-1.5-2.4 2.4a2.6 2.6 0 0 0-3.4 3.4l-2.6 2.6 1.5 1.5Z" />
    </svg>
  );
}
```

## `lib/pages.ts` — título e subtítulo

```ts
  "/usuarios-sql": {
    title: "Usuários SQL Server",
    subtitle: "Logins do SQL Server: quem tem acesso a quê, há quanto tempo não entra, e a criação do acesso sem abrir o SSMS",
  },
```

## `lib/workspaces.ts` — item do menu

```ts
  // T.I. -- Usuarios SQL Server (Kevin, 2026-11-04): os logins do SQL Server pela
  // tela. Nivel /usuarios-sql/editar (Gerenciar Usuarios) libera criar/alterar/excluir.
  {
    href: "/usuarios-sql",
    label: "Usuários SQL Server",
    desc: "Logins do SQL Server: quem acessa o quê, último acesso, criação do acesso com bancos e servidores vinculados",
    icon: IconSsms,
    workspaceId: "ti",
  },
  // Base Unica de Fornecedores / SRM Lite (Compras, 2026-10-08): em que ponto
```

## `app/(bi)/usuarios/GerenciarUsuarios.client.tsx` — nível de edição na tela de permissões

```ts
  {
    path: "/usuarios-sql/editar",
    de: "/usuarios-sql",
    titulo: "Edição",
    descricao: "Cria logins, altera bancos e servidores vinculados, desativa, reseta senha, exclui e configura a inatividade.",
    base: "Somente visualização",
    baseDescricao: "Vê os logins, quem tem acesso a quê, o último acesso e o histórico.",
  },
```

O client importa `IconClose, IconExcel, IconInfo, IconRefresh, IconSearch, IconUser` de
`@/components/icons` e usa os tokens de cor do portal (`--card`, `--border`, `--muted-foreground`...).

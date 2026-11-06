# Trecho do workflow de deploy (GitHub Actions)

O deploy grava as variáveis da tela no `.env` da API a partir dos secrets do repositório.
Secret ausente = linha vazia = a tela diz o que falta (nada mais quebra).

```yaml

        run: |

          f="$STACK_DIR/deploy/.env.portal.$ENVN"

          [ -f "$f" ] || { echo "::warning::$f nao existe; e-mail da API nao configurado"; exit 0; }

          for k in PORTAL_MAIL_TENANT_ID PORTAL_MAIL_CLIENT_ID PORTAL_MAIL_CLIENT_SECRET PORTAL_MAIL_FROM PORTAL_PORTAL_URL; do

            v="${!k}"

            grep -v "^$k=" "$f" > "$f.tmp" && mv "$f.tmp" "$f"

            printf '%s=%s\n' "$k" "$v" >> "$f"

          done

          echo "e-mail: from=$([ -n "$PORTAL_MAIL_FROM" ] && echo ok || echo AUSENTE) tenant=$([ -n "$PORTAL_MAIL_TENANT_ID" ] && echo ok || echo AUSENTE) client=$([ -n "$PORTAL_MAIL_CLIENT_SECRET" ] && echo ok || echo AUSENTE)"

```

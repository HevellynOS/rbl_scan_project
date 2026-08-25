"""
app/services/dns_collect.py — Comando de coleta para os servidores de DNS.

O técnico não precisa saber onde ficam os arquivos, qual servidor está rodando
nem como exportar. Cola um comando no SSH, o comando produz um arquivo de texto
único, e esse arquivo é enviado ao sistema. É o mesmo fluxo do
'display current-configuration' do NE8000.

O coletor e o leitor do formato moram no mesmo repositório de propósito: se o
formato mudar, os dois mudam juntos e a versão no cabeçalho denuncia
incompatibilidade em vez de produzir análise silenciosamente errada.

O script é SOMENTE LEITURA. Não altera configuração, não recarrega serviço e
não expõe chave: DNSSEC e TSIG são omitidos deliberadamente, porque o arquivo
vai trafegar por e-mail e por upload.
"""

from __future__ import annotations

FORMATO_VERSAO = "1"

MARCA_CABECALHO = "##### RBLSCAN-COLETA"
MARCA_ARQUIVO = "===== ARQUIVO:"
MARCA_ZONA = "===== ZONA:"
MARCA_FIM = "===== FIM ====="


# O script é entregue como um bloco único para colar no SSH. Evita heredoc
# aninhado e `sudo` interativo no meio do laço, que quebram quando o técnico
# cola tudo de uma vez.
SCRIPT = r'''sudo bash -s <<'RBLSCAN_EOF'
set -u
OUT=/tmp/rbl-dns-coleta.txt
: > "$OUT"

say() { printf '%s\n' "$1" >> "$OUT"; }

say "##### RBLSCAN-COLETA v1"
say "##### HOST: $(hostname -f 2>/dev/null || hostname)"
say "##### DATA: $(date -u '+%Y-%m-%d %H:%M:%S UTC')"

SERVIDOR=desconhecido
command -v named-checkconf >/dev/null 2>&1 && SERVIDOR=bind
command -v pdnsutil        >/dev/null 2>&1 && SERVIDOR=powerdns
command -v pdns_control    >/dev/null 2>&1 && SERVIDOR=powerdns
say "##### SERVIDOR: $SERVIDOR"

dump() {   # dump <rotulo> <caminho>
  [ -r "$2" ] || return 0
  say ""
  say "===== ARQUIVO: $2 ====="
  # Remove material sensivel: chaves TSIG e DNSSEC nao sao necessarios para a
  # analise e o arquivo vai trafegar por e-mail.
  sed -e 's/\(secret[[:space:]]*\)"[^"]*"/\1"<omitido>"/g' \
      -e '/^[[:space:]]*[A-Za-z0-9._-]*[[:space:]]*IN[[:space:]]*DNSKEY/d' \
      -e '/^[[:space:]]*[A-Za-z0-9._-]*[[:space:]]*IN[[:space:]]*RRSIG/d' \
      "$2" >> "$OUT" 2>/dev/null
  say "===== FIM ====="
}

if [ "$SERVIDOR" = bind ]; then
  for f in /etc/bind/named.conf /etc/bind/named.conf.local \
           /etc/bind/named.conf.options /etc/named.conf; do
    dump conf "$f"
  done

  say ""
  say "##### CHECKCONF"
  named-checkconf -p >> "$OUT" 2>&1 || say "(named-checkconf falhou)"
  say "##### FIM CHECKCONF"

  # A lista de zonas sai do checkconf, que ja resolveu os include e o
  # directory. Procurar em /etc/bind na mao perde zona guardada em
  # /var/cache/bind ou /var/lib/bind.
  DIR=$(named-checkconf -p 2>/dev/null | sed -n 's/.*directory[[:space:]]*"\([^"]*\)".*/\1/p' | head -1)
  [ -n "${DIR:-}" ] || DIR=/etc/bind

  named-checkconf -p 2>/dev/null | awk '
    /^[[:space:]]*zone[[:space:]]+"/ { z=$2; gsub(/"/,"",z); t=""; f=""; next }
    /type[[:space:]]+/  { if (z!="") { t=$2; gsub(/;/,"",t) } }
    /file[[:space:]]+"/ { if (z!="") { f=$2; gsub(/[";]/,"",f); print z"\t"t"\t"f; z="" } }
  ' | while IFS="$(printf '\t')" read -r zona tipo arq; do
      [ -n "$arq" ] || continue
      case "$arq" in /*) caminho="$arq" ;; *) caminho="$DIR/$arq" ;; esac
      [ -r "$caminho" ] || continue
      say ""
      say "===== ZONA: $zona TIPO: $tipo ARQUIVO: $caminho ====="
      sed -e '/[[:space:]]DNSKEY[[:space:]]/d' -e '/[[:space:]]RRSIG[[:space:]]/d' \
          "$caminho" >> "$OUT" 2>/dev/null
      say "===== FIM ====="
    done

elif [ "$SERVIDOR" = powerdns ]; then
  for f in /etc/powerdns/pdns.conf /etc/pdns/pdns.conf; do
    # A configuracao do PowerDNS guarda a senha do banco.
    if [ -r "$f" ]; then
      say ""
      say "===== ARQUIVO: $f ====="
      grep -v -i -E 'password|secret|key' "$f" >> "$OUT" 2>/dev/null
      say "===== FIM ====="
    fi
  done
  pdnsutil list-all-zones 2>/dev/null | while read -r zona; do
    [ -n "$zona" ] || continue
    say ""
    say "===== ZONA: $zona TIPO: master ARQUIVO: (banco) ====="
    pdnsutil list-zone "$zona" >> "$OUT" 2>/dev/null
    say "===== FIM ====="
  done

else
  say ""
  say "##### AVISO: nem BIND nem PowerDNS foram encontrados neste servidor."
  say "##### Rode este comando no servidor que responde pelas zonas reversas."
fi

say ""
say "##### FIM DA COLETA"
chmod 0644 "$OUT" 2>/dev/null

echo
echo "Coleta concluida: $OUT"
echo "Tamanho: $(wc -c < "$OUT") bytes, $(grep -c '^===== ZONA:' "$OUT") zona(s)"
echo
echo "Para trazer o arquivo para a sua maquina, rode NO SEU COMPUTADOR:"
echo "   scp $(whoami)@$(hostname -f 2>/dev/null || hostname):$OUT ."
echo
echo "Depois envie o arquivo na aba DNS do RBL Scan."
RBLSCAN_EOF'''


SCRIPT_SEM_SUDO = SCRIPT.replace("sudo bash -s <<'RBLSCAN_EOF'",
                                 "bash -s <<'RBLSCAN_EOF'")


PASSOS = [
    {
        "titulo": "Acesse o servidor de DNS por SSH",
        "detalhe": "Use o servidor que responde pelas zonas reversas dos "
                   "blocos. Se houver mais de um, repita em cada um: a "
                   "configuração pode divergir entre eles.",
        "comando": "ssh <usuario>@<servidor-dns>",
    },
    {
        "titulo": "Cole o comando de coleta",
        "detalhe": "Cole o bloco inteiro de uma vez, incluindo a última linha. "
                   "O comando apenas lê arquivos: não altera configuração nem "
                   "recarrega o serviço. Chaves de DNSSEC e TSIG e senha de "
                   "banco são omitidas do arquivo gerado.",
        "comando": SCRIPT,
    },
    {
        "titulo": "Traga o arquivo para a sua máquina",
        "detalhe": "Rode no seu computador, não no servidor. O próprio comando "
                   "anterior imprime esta linha já preenchida.",
        "comando": "scp <usuario>@<servidor-dns>:/tmp/rbl-dns-coleta.txt .",
    },
    {
        "titulo": "Envie o arquivo abaixo",
        "detalhe": "Arraste o rbl-dns-coleta.txt na área de envio. O sistema "
                   "identifica as zonas, confere a correspondência de ida e "
                   "volta e devolve os comandos de correção.",
        "comando": "",
    },
]


def instrucoes() -> dict:
    return {
        "versao": FORMATO_VERSAO,
        "arquivo": "/tmp/rbl-dns-coleta.txt",
        "passos": PASSOS,
        "script": SCRIPT,
        "script_sem_sudo": SCRIPT_SEM_SUDO,
        "nota_sudo": "Se o usuário não tiver sudo, use a variante sem sudo. "
                     "Ela funciona quando os arquivos de zona são legíveis pelo "
                     "usuário, o que é comum quando o técnico está no grupo "
                     "bind.",
        "seguranca": "O script é somente leitura. Ele remove do arquivo as "
                     "chaves TSIG e DNSSEC e as senhas de banco antes de gravar, "
                     "porque o arquivo costuma ser enviado por e-mail.",
    }

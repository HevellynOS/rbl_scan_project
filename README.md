# RBL Scan

Auditoria de reputação de blocos IP, de DNS reverso e de configuração de rede,
para provedor.

A ferramenta existe para responder uma pergunta que a saída em texto esconde:
**quais endereços estão listados por configuração e quais estão listados por
emissão real de spam.** Só o segundo grupo volta a listar depois de uma
remoção, e é ele que precisa de contenção antes de qualquer ticket.

```
POLÍTICA    PBL (127.0.0.10/.11), RATS-NoPtr, RATS-Dyna
            Deriva de rDNS ausente ou genérico. Sai corrigindo DNS.

EMISSÃO     SBL, CSS, XBL, DroneBL, Barracuda, SpamCop, PSBL, blocklist.de,
            GBUdb, Mailspike
            Spam ou abuso observado. NÃO sai corrigindo DNS.
```

Corrigir o reverso antes de conter a emissão é contraproducente: rDNS limpo
aumenta a entregabilidade, então o spam passa a chegar melhor. Essa ordem
atravessa toda a ferramenta, do plano de ação ao relatório em PDF.

## As três abas

**Varredura de bloco.** Consulta o CIDR contra as listas e desenha o mapa do
bloco, uma célula por endereço, cor por classificação. Num `/23`, campo
uniforme significa problema de configuração e pontos espalhados significam
infecção. Monta o plano de ação na ordem correta e cruza os emissores com as
faixas de CGNAT dos equipamentos analisados.

**Análise de configuração.** Recebe os exports dos equipamentos, aponta o que
causa ou vai causar listagem e gera o script de correção com a explicação de
cada item. Reconhece MikroTik RouterOS e Huawei VRP pelo conteúdo do arquivo,
não pela extensão.

**DNS.** Auditoria de PTR separando ausente de genérico, estado da delegação
das zonas in-addr.arpa, geração do arquivo de zona e relatório executivo em PDF
para entregar a terceiros.

## Estrutura

```
rbl_scan_project/
├── backend/
│   ├── app/
│   │   ├── main.py              monta rotas, WebSocket e interface embutida
│   │   ├── api/                 HTTP, agrupado por assunto
│   │   │   ├── routes_rbl.py      varredura, correlação, exportação
│   │   │   ├── routes_dns.py      geração de zona reversa
│   │   │   └── routes_reports.py  análise, script, markdown, PDF
│   │   ├── core/
│   │   │   ├── config.py          único ponto que lê variável de ambiente
│   │   │   └── security.py        valida o que entra, controla o que sai
│   │   ├── database/
│   │   │   ├── connection.py      repositório (hoje em memória)
│   │   │   ├── models.py          formato dos registros
│   │   │   └── migrations/
│   │   ├── services/
│   │   │   ├── rbl_service.py     varredura multi-RBL e auditoria de rDNS
│   │   │   ├── dns_service.py     cruzamento e geração de zona
│   │   │   └── report_service.py  relatório executivo em PDF
│   │   ├── parsers/
│   │   │   ├── rsc_parser.py      MikroTik RouterOS
│   │   │   └── vrp_parser.py      Huawei VRP
│   │   └── analyzers/
│   │       ├── rsc_analyzer.py    verificações RouterOS + despacho
│   │       └── vrp_analyzer.py    verificações VRP
│   ├── assets/                  logo usada no PDF
│   ├── tests/                   suíte + exports usados como fixture
│   ├── doctor.py                diagnóstico de resolução DNS
│   ├── launcher.py              ponto de entrada do executável
│   ├── rblscan.spec             empacotamento PyInstaller
│   ├── .env.example
│   ├── requirements.txt
│   └── README.md
├── frontend/
│   └── src/
│       ├── App.tsx              abas, console e composição
│       ├── theme.tsx            alternador claro/escuro
│       ├── useScan.ts           WebSocket e estado da varredura
│       ├── types.ts
│       ├── styles.css
│       └── components/
│           ├── BlockMap.tsx       mapa do bloco
│           ├── Panels.tsx         resumo, plano, listas, diagnóstico
│           ├── IpTable.tsx        tabela filtrável
│           ├── ConfigAnalysis.tsx upload e achados
│           ├── Correlate.tsx      correlação e gerador de zona
│           └── DnsTab.tsx         auditoria de reverso e relatório
├── build.ps1
├── .gitignore
└── README.md
```

## Por que o scan roda no backend

Navegador não faz consulta DNS arbitrária. E mesmo que fizesse, as RBLs
precisam ver **o seu resolver recursivo**: resolver público (8.8.8.8, 1.1.1.1)
é recusado e responde NXDOMAIN, o que faria o bloco parecer limpo.

## Como rodar

Backend:

```bash
cd backend
pip install -r requirements.txt
cp .env.example .env        # preencha SPAMHAUS_DQS_KEY
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

No Windows:

```powershell
cd backend
py -m pip install -r requirements.txt
Copy-Item .env.example .env
notepad .env
uvicorn app.main:app --port 8000
```

Frontend:

```bash
cd frontend
npm install
npm run dev          # http://localhost:5173, com proxy para :8000
```

Os dois comandos do backend precisam rodar **de dentro de `backend/`**: `app` é
o pacote raiz, e da raiz do projeto o Python não o encontra.

Confirme que a chave foi lida antes de varrer:

```bash
curl localhost:8000/api/health      # "dqs_key": true
```

### Variáveis

Ficam em `backend/.env`. O `.gitignore` protege o arquivo; só o `.env.example`
é versionado. Variável exportada no shell tem precedência sobre o arquivo, o
que serve para uma varredura pontual com outro resolver.

| Variável | Efeito |
|---|---|
| `SPAMHAUS_DQS_KEY` | Sem ela a ZEN é pulada, que é a lista mais relevante |
| `RBLSCAN_RESOLVER` | Resolver recursivo padrão |
| `RBLSCAN_MAX` | Teto de endereços por varredura (padrão 4096) |
| `RBLSCAN_MAX_FILES` | Arquivos de configuração por análise (padrão 10) |
| `RBLSCAN_ORIGINS` | Origens liberadas no CORS |
| `RBLSCAN_DATABASE_URL` | Vazio mantém o repositório em memória |

## Antes da primeira varredura

Use **Testar listas**. Ele consulta `127.0.0.2`, que é a entrada de teste
padrão das DNSBLs. Lista que responde `sem resposta` está bloqueando o seu
resolver, e todo resultado dela viria vazio, indistinguível de "limpo". A
varredura faz essa verificação sozinha e exclui quem não responder, com aviso
nomeado.

Barracuda exige registrar o IP do seu resolver no site deles. Sem isso responde
NXDOMAIN sempre.

Se várias listas falharem ao mesmo tempo, o problema é o resolver.
`backend/doctor.py` testa o padrão do sistema e os que você indicar, lado a
lado, e emite um veredito:

```bash
python doctor.py --resolver 10.0.0.53
```

## Uso justo

Um `/24` no perfil `core` são cerca de 2.000 consultas DNS; um `/23`, o dobro.
As listas públicas bloqueiam resolver abusivo, e aí você perde visibilidade em
toda a operação, não só naquele bloco. O padrão de 8 consultas simultâneas por
lista é conservador de propósito. Uma varredura por bloco por dia é suficiente.

## Fabricantes suportados

| Fabricante | Como exportar |
|---|---|
| MikroTik RouterOS | `/export file=backup` |
| Huawei VRP (NE8000, NE40E, NE20E) | `display current-configuration` |

Duas verificações existem só para VRP, porque não têm equivalente no RouterOS:
ACL definida mas não aplicada em nenhuma interface, e regra de bloqueio anulada
por um `permit` de número menor. Nos dois casos a regra está escrita e não
bloqueia nada.

O script gerado usa `!!` como marcador de explicação nos blocos Huawei, porque
no VRP o `#` é separador de seção e daria erro se colado no CLI.

## Segurança do que sai

O relatório em PDF é feito para deixar a empresa. `app/core/security.py` mantém
uma lista explícita do que nunca pode entrar nele: faixas privadas e de CGNAT,
modelo e versão de equipamento, regras de tradução, comunidade SNMP, chaves.
O texto digitado pelo operador passa por essa checagem antes de o documento ser
gerado.

Os endereços com emissão ativa aparecem no relatório apenas como quantidade.
Enumerá-los num documento externo equivale a publicar onde estão as máquinas
comprometidas do cliente.

## Testes

```bash
cd backend
pip install pytest
pytest -q
```

Rodam sem rede. Os casos vieram de defeitos reais e servem de regressão: o `#`
indentado do VRP arrancando blocos do pai, o falso positivo de PTR genérico em
domínio contendo "cliente", o regex de modelo capturando o sysname, o `#` usado
como comentário em comandos Huawei.

Atenção: `tests/exemplo-ne40.txt` é configuração real de equipamento. Contém
hash de senha de console, chave pública e faixas internas. Decida se anonimiza
antes de versionar.

## Banco de dados

`app/database/connection.py` traz um repositório em memória com a mesma
interface que a implementação real vai ter, então trocar não mexe em nenhuma
rota. Para ligar um banco: defina `RBLSCAN_DATABASE_URL`, implemente
`SqlRepository` seguindo o `Protocol` do arquivo, e faça `get_repository()`
devolver a nova implementação.

Enquanto a variável estiver definida sem implementação, a aplicação falha em
vez de cair no repositório em memória em silêncio: dado que o operador pensa
estar persistido e não está é pior que erro visível.

O que o banco resolve é o histórico por bloco. Sem série temporal não há como
comparar antes e depois de uma remediação, que é a evidência exigida nos
pedidos de remoção.

## Gerar o executável (Windows)

```powershell
.\build.ps1
```

Sai `backend\dist\RBLScan.exe`, arquivo único com a interface embutida. Abrir
sobe o servidor em `127.0.0.1` e abre o navegador; fechar o console encerra.

O PyInstaller não faz compilação cruzada: para um `.exe` de Windows, rode o
build no Windows. O `.env` fica **ao lado** do executável, não dentro dele, e
editar a chave não exige recompilar.

## Limitações conhecidas

- Só IPv4 na varredura. Enumerar IPv6 é inviável; consulte apenas os `/128` em
  uso.
- O cruzamento automático com a varredura funciona para RouterOS, não para VRP.
  O RouterOS publica o mapeamento no próprio `netmap`, então dá para calcular o
  assinante offline; o Huawei aloca as portas internamente, e a identificação
  exige `display nat mapping` no equipamento.
- Sem banco, o histórico morre com o processo.
- A heurística de rDNS genérico é aproximação do que Spamhaus e SpamRATS
  avaliam, não uma reprodução dos critérios deles.
- A auditoria enxerga apenas o que está no arquivo enviado. Uma `traffic-policy`
  aplicada mas definida fora do export é sinalizada como não verificável, em vez
  de presumida.

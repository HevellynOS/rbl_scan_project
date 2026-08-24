# Backend — RBL Scan

FastAPI. As regras de negócio ficam em `app/services` e `app/analyzers`; as
rotas só compõem.

## Estrutura

```
app/
  main.py               monta rotas, WebSocket e a interface embutida
  api/                  HTTP, agrupado por assunto
    routes_rbl.py         varredura, correlação, exportação CSV/JSON
    routes_dns.py         geração de zona reversa
    routes_reports.py     análise de configuração, script, markdown, PDF
  core/
    config.py             único ponto que lê variáveis de ambiente
    security.py           valida o que entra, controla o que sai
  database/
    connection.py         repositório (hoje em memória)
    models.py             formato dos registros
    migrations/           vazio até o banco entrar
  services/
    rbl_service.py        varredura multi-RBL e auditoria de rDNS
    dns_service.py        cruzamento e geração de zona
    report_service.py     relatório executivo em PDF
  parsers/
    rsc_parser.py         MikroTik RouterOS
    vrp_parser.py         Huawei VRP
  analyzers/
    rsc_analyzer.py       verificações RouterOS + despacho por fabricante
    vrp_analyzer.py       verificações VRP
assets/                 logo usada no PDF
tests/                  suíte + exports reais usados como fixture
```

## Rodar

```bash
cd backend
pip install -r requirements.txt
cp .env.example .env        # preencha SPAMHAUS_DQS_KEY
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

Confirme que a chave foi lida antes de varrer:

```bash
curl localhost:8000/api/health      # "dqs_key": true
```

## Testes

```bash
pip install pytest
pytest -q
```

Rodam sem rede. Os casos vieram de defeitos reais e servem de regressão: o
`#` indentado do VRP, o falso positivo de PTR genérico em domínio com
"cliente", o modelo capturando o sysname, o `#` como comentário em comandos
Huawei.

## Banco de dados

`app/database/connection.py` traz um repositório em memória com a mesma
interface que a implementação real vai ter. Reiniciar o processo apaga tudo,
e é isso que o banco resolve: sem série histórica por bloco não há como
comparar antes e depois de uma remediação, que é a evidência exigida nos
pedidos de remoção.

Para ligar um banco:

1. defina `RBLSCAN_DATABASE_URL` no `.env`
2. implemente `SqlRepository` seguindo o `Protocol` do arquivo
3. faça `get_repository()` devolver a nova implementação

Enquanto a variável estiver definida sem implementação, a aplicação falha em
vez de cair no repositório em memória em silêncio: dado que o operador pensa
estar persistido e não está é pior que erro visível.

Trate a base como dado sensível de rede. O relatório em JSON contém endereços
de assinante e mapeamento de CGNAT.

## Fabricantes suportados

| Fabricante | Como exportar |
|---|---|
| MikroTik RouterOS | `/export file=backup` |
| Huawei VRP (NE8000, NE40E, NE20E) | `display current-configuration` |

A detecção é pelo conteúdo, não pela extensão.

Duas verificações existem só para VRP, porque não têm equivalente no
RouterOS: ACL definida mas não aplicada em nenhuma interface, e regra de
bloqueio anulada por um `permit` de número menor.

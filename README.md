# RBL Scan

Varredura de blocos CIDR contra múltiplas DNSBLs, com auditoria de DNS reverso.

A ferramenta existe para responder uma pergunta que a saída em texto esconde:
**quais IPs estão listados por configuração e quais estão listados por emissão
real de spam.** Só o segundo grupo volta a listar depois de uma remoção, e é ele
que precisa de contenção antes de qualquer ticket.

```
POLÍTICA    PBL (127.0.0.10/.11), RATS-NoPtr, RATS-Dyna
            Deriva de rDNS ausente ou genérico. Sai corrigindo DNS.

EMISSÃO     SBL, CSS, XBL, Barracuda, SpamCop, PSBL, blocklist.de, GBUdb…
            Spam ou abuso observado. NÃO sai corrigindo DNS.
```

## Estrutura

```
rbl-scan/
├── README.md
├── backend/
│   ├── rbl_core.py
│   ├── api.py
│   └── requirements.txt
└── frontend/
    ├── index.html
    ├── package.json
    ├── tsconfig.json
    ├── vite.config.ts
    └── src/
        ├── main.tsx
        ├── App.tsx
        ├── types.ts
        ├── useScan.ts
        ├── styles.css
        └── components/
            ├── BlockMap.tsx
            ├── Panels.tsx
            └── IpTable.tsx
```

## Por que o scan roda no backend

Navegador não faz consulta DNS arbitrária. E mesmo que fizesse, as RBLs precisam
ver **o seu resolver recursivo** — resolver público (8.8.8.8, 1.1.1.1) é recusado
e responde NXDOMAIN, o que faria o bloco parecer limpo.

## Como rodar

Backend:

```bash
cd backend
pip install -r requirements.txt
export SPAMHAUS_DQS_KEY="sua_chave"        # portal.spamhaus.com/dqs
export RBLSCAN_RESOLVER="10.0.0.53"        # opcional: recursivo padrão
uvicorn api:app --host 0.0.0.0 --port 8000
```

Frontend:

```bash
cd frontend
npm install
npm run dev          # http://localhost:5173, com proxy para :8000
```

Variáveis:

| Variável | Efeito |
|---|---|
| `SPAMHAUS_DQS_KEY` | Sem ela, a ZEN é pulada — que é a lista mais relevante |
| `RBLSCAN_RESOLVER` | Resolver recursivo padrão |
| `RBLSCAN_MAX` | Teto de endereços por varredura (padrão 4096) |
| `RBLSCAN_ORIGINS` | Origens liberadas no CORS |

## Antes da primeira varredura

Use **Testar listas**. Ele consulta `127.0.0.2`, que é a entrada de teste padrão
das DNSBLs. Lista que responde `sem resposta` está bloqueando o seu resolver — e
todo resultado dela viria vazio, indistinguível de "limpo".

Barracuda exige registrar o IP do resolver no site deles. Sem isso responde
NXDOMAIN sempre.

## Uso justo

Um `/24` no perfil `core` são ~2.000 consultas DNS; um `/23`, o dobro. As listas
públicas têm política de uso justo e bloqueiam resolver abusivo — e aí você perde
visibilidade em toda a operação, não só naquele bloco. O padrão de 8 consultas
simultâneas por lista é conservador de propósito. Uma varredura por bloco por dia
é suficiente.

## Limitações conhecidas

- Só IPv4. Enumerar IPv6 é inviável; consulte apenas os `/128` em uso.
- Os relatórios ficam em memória no processo. Reiniciou o uvicorn, perdeu o
  histórico — se precisar de série temporal, persista em banco.
- A heurística de rDNS genérico é aproximação do que Spamhaus e SpamRATS avaliam,
  não uma reprodução dos critérios deles.

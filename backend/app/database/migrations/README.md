# RBL Scan

Auditoria de reputação de blocos IP e de configuração de rede, para provedor.

A ferramenta existe para responder uma pergunta que a saída em texto esconde:
**quais endereços estão listados por configuração e quais estão listados por
emissão real de spam.** Só o segundo grupo volta a listar depois de uma
remoção, e é ele que precisa de contenção antes de qualquer ticket.

```
POLÍTICA    PBL (127.0.0.10/.11), RATS-NoPtr, RATS-Dyna
            Deriva de rDNS ausente ou genérico. Sai corrigindo DNS.

EMISSÃO     SBL, CSS, XBL, DroneBL, Barracuda, SpamCop, PSBL…
            Spam ou abuso observado. NÃO sai corrigindo DNS.
```

Corrigir o reverso antes de conter a emissão é contraproducente: rDNS limpo
aumenta a entregabilidade, então o spam passa a chegar melhor.

## Estrutura

```
rbl_scan_project/
├── backend/      FastAPI — veja backend/README.md
└── frontend/     React + TypeScript + Vite
```

## Rodar

```bash
cd backend
pip install -r requirements.txt
cp .env.example .env
uvicorn app.main:app --port 8000
```

```bash
cd frontend
npm install
npm run dev          # http://localhost:5173, com proxy para :8000
```

## As três abas

**Varredura de bloco** — consulta o CIDR contra as listas, desenha o mapa do
bloco (uma célula por endereço, cor por classificação), monta o plano de ação
e cruza os emissores com as faixas de CGNAT dos equipamentos analisados.

**Análise de configuração** — recebe os exports de RouterOS e Huawei VRP,
aponta o que causa ou vai causar listagem, e gera o script de correção com a
explicação de cada item.

**DNS** — auditoria de PTR separando ausente de genérico, estado da delegação
das zonas reversas, geração do arquivo de zona e relatório executivo em PDF
para entregar a terceiros.

## Antes da primeira varredura

Use **Testar listas**. Consulta `127.0.0.2`, que é a entrada de teste padrão
das DNSBLs. Lista que responde `sem resposta` está bloqueando o seu resolver,
e todo resultado dela viria vazio, indistinguível de "limpo".

Use um resolver recursivo próprio. Resolver público (8.8.8.8, 1.1.1.1) é
recusado pelas listas, e o scan não erra: ele reporta o bloco como limpo, que
é bem pior. `backend/doctor.py` diagnostica isso.

## Uso justo

Um `/24` no perfil `core` são cerca de 2.000 consultas DNS; um `/23`, o dobro.
As listas públicas bloqueiam resolver abusivo, e aí você perde visibilidade em
toda a operação, não só naquele bloco. Uma varredura por bloco por dia basta.

## Gerar o executável (Windows)

```powershell
.\build.ps1
```

Sai `backend\dist\RBLScan.exe`, arquivo único com a interface embutida. O
PyInstaller não faz compilação cruzada: para um `.exe` de Windows, rode o
build no Windows.

## Limitações conhecidas

- Só IPv4 na varredura. Enumerar IPv6 é inviável.
- O cruzamento automático com a varredura funciona para RouterOS, não para
  VRP: o Huawei não publica a tabela de tradução na configuração, então a
  identificação do assinante exige `display nat mapping` no equipamento.
- Sem banco, o histórico morre com o processo.
- A heurística de rDNS genérico é aproximação do que Spamhaus e SpamRATS
  avaliam, não uma reprodução dos critérios deles.

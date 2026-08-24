"""
correlate.py — Cruza a varredura de RBL com a análise de configuração.

A varredura diz QUAIS IPs públicos estão listados. A análise do .rsc diz COMO
esses IPs mapeiam para assinantes. Separadas, cada metade obriga o operador a
fazer o cruzamento na mão. Juntas, respondem a pergunta que importa: quem está
por trás do IP que a lista apontou.

Também gera o arquivo de zona reversa, porque a auditoria identifica exatamente
quais faixas são de assinante (nomenclatura genérica é correta e protege a rede)
e quais são de serviço (precisam de nome próprio e registro A).
"""

from __future__ import annotations

import ipaddress
from datetime import datetime, timezone

from rsc_analyzer import NetmapRule


def _nets(values: list[str]) -> list:
    out = []
    for v in values:
        try:
            out.append(ipaddress.ip_network(v, strict=False))
        except ValueError:
            pass
    return out


def correlate(report: dict, analysis: dict) -> dict:
    """report = saída da varredura; analysis = saída de analyze()."""
    rows = {r["ip"]: r for r in report.get("rows", [])}
    emissores = [ip for ip, r in rows.items() if r["classification"] == "behavior"]
    emissores.sort(key=lambda i: int(ipaddress.ip_address(i)))

    devices = []
    cobertos: set[str] = set()

    for d in analysis.get("devices", []):
        cg = d.get("cgnat", {})
        pubs = _nets(cg.get("public", []))
        if not pubs:
            continue

        regras = [NetmapRule(**n) for n in cg.get("netmaps", [])]
        achados = []

        for ip_s in emissores:
            ip = ipaddress.ip_address(ip_s)
            faixa = next((p for p in pubs if ip in p), None)
            if faixa is None:
                continue
            cobertos.add(ip_s)

            # Cada faixa de portas gera um candidato. Sem a porta de origem do
            # relatório de abuso, todos são candidatos legítimos.
            cands = []
            for r in regras:
                sub = r.subscriber_for(ip)
                if sub is None:
                    continue
                cands.append({
                    "assinante": sub,
                    "portas": (f"{r.port_lo}-{r.port_hi}"
                               if r.port_lo else "todas"),
                    "chain": r.chain,
                    "faixa_privada": r.src_net,
                })
            # dedup por (assinante, portas)
            vistos = set()
            unicos = []
            for c in cands:
                k = (c["assinante"], c["portas"])
                if k not in vistos:
                    vistos.add(k)
                    unicos.append(c)
            unicos.sort(key=lambda c: c["portas"])

            achados.append({
                "ip": ip_s,
                "faixa_publica": str(faixa),
                "listas": rows[ip_s]["lists"],
                "motivos": rows[ip_s]["reasons"],
                "candidatos": unicos[:80],
                "total_candidatos": len(unicos),
                "rastreavel": bool(unicos) and cg.get("deterministic", False),
            })

        if achados:
            devices.append({
                "identity": d.get("identity", d.get("file", "")),
                "file": d.get("file", ""),
                "role": d.get("role", ""),
                "deterministic": cg.get("deterministic", False),
                "achados": achados,
            })

    orfaos = [ip for ip in emissores if ip not in cobertos]

    return {
        "network": report.get("network", ""),
        "emissores": len(emissores),
        "cobertos": len(cobertos),
        "devices": devices,
        "orfaos": orfaos,
        "aviso_orfaos": (
            f"{len(orfaos)} IP(s) com emissão não caem em nenhuma faixa de CGNAT "
            f"dos equipamentos enviados. Ou são clientes com IP fixo, ou existe "
            f"CGNAT em outro equipamento que não foi analisado. Envie o backup do "
            f"concentrador e da borda para fechar o mapa."
            if orfaos else ""),
        "como_usar": (
            "Sem a porta de origem, cada IP público tem um candidato por faixa "
            "de portas. A porta vem do relatório de abuso da lista (DroneBL, "
            "SpamCop e Barracuda fornecem) ou do seu próprio log de conexões. "
            "Com ela, o candidato é único."),
    }


# --------------------------------------------------------------------------
def build_zone(
    cidr: str,
    domain: str,
    ns: list[str],
    email: str,
    report: dict | None = None,
    analysis: dict | None = None,
    prefixo_pool: str = "cliente",
) -> dict:
    """Gera a zona reversa e os registros A correspondentes.

    Duas classes de endereço, com tratamento oposto:
      - faixa de CGNAT/assinante  -> nomenclatura genérica está CORRETA. O PBL
        ali protege a rede: é o que impede o CPE infectado de entregar spam
        direto. Sai com $GENERATE.
      - endereço de serviço       -> precisa de nome próprio e do registro A.
        Sai com marcador <NOME> para ser preenchido, nunca inventado.
    """
    net = ipaddress.ip_network(cidr, strict=False)
    if net.version != 4:
        raise ValueError("Só IPv4.")
    if net.prefixlen < 24:
        raise ValueError("Gere uma zona por /24.")

    o = str(net.network_address).split(".")
    zone = f"{o[2]}.{o[1]}.{o[0]}.in-addr.arpa"
    serial = datetime.now(timezone.utc).strftime("%Y%m%d") + "01"
    dom = domain.strip().rstrip(".")
    mail = email.strip().replace("@", ".").rstrip(".") or "hostmaster." + dom

    # Faixas de CGNAT vindas da análise
    cgnat_nets = []
    if analysis:
        for d in analysis.get("devices", []):
            cgnat_nets += _nets(d.get("cgnat", {}).get("public", []))

    def em_cgnat(ip) -> bool:
        return any(ip in n for n in cgnat_nets)

    # Endereços que a varredura mostrou como infraestrutura (têm PTR hoje)
    com_ptr = set()
    if report:
        com_ptr = {r["ip"] for r in report.get("rows", [])
                   if r.get("ptr_status") in ("generico", "ok")}

    pools: list[tuple[int, int]] = []
    servicos: list[tuple[int, str]] = []

    inicio = None
    for i, ip in enumerate(net):
        last = int(str(ip).split(".")[-1])
        is_pool = em_cgnat(ip) and str(ip) not in com_ptr
        if is_pool:
            if inicio is None:
                inicio = last
        else:
            if inicio is not None:
                pools.append((inicio, last - 1))
                inicio = None
            servicos.append((last, str(ip)))
    if inicio is not None:
        pools.append((inicio, int(str(list(net)[-1]).split(".")[-1])))

    L = [
        f"; Zona reversa de {net}",
        f"; Gerada em {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
        ";",
        "; ORDEM DE APLICACAO",
        ";   1. Suba esta zona em DOIS servidores AUTORITATIVOS (BIND, NSD,",
        ";      PowerDNS ou Knot). Resolver recursivo NAO serve, e o DNS do",
        ";      RouterOS tambem nao: nenhum dos dois responde SOA por zona.",
        ";   2. Confirme que respondem:  dig SOA " + zone + " @<ip-do-servidor>",
        ";   3. SO ENTAO delegue no registro.br ou pelo upstream. Inverter a",
        ";      ordem gera lame delegation, pior que a ausencia de delegacao.",
        ";",
        "; ATENCAO: cada PTR precisa de um registro A correspondente apontando",
        "; de volta para o mesmo IP (FCrDNS). PTR sem o A e metade da",
        "; configuracao, e muito MX rejeita so por isso. Os registros A estao",
        "; no bloco ao final deste arquivo, para a zona direta de " + dom + ".",
        ";",
        "$TTL 3600",
        f"@   IN  SOA {ns[0] if ns else '<NS1>'}. {mail}. (",
        f"        {serial}   ; serial",
        "        3600         ; refresh",
        "        900          ; retry",
        "        1209600      ; expire",
        "        3600 )       ; minimum",
        "",
    ]
    for n in (ns or ["<NS1>", "<NS2>"]):
        L.append(f"@   IN  NS  {n.rstrip('.')}.")
    L.append("")

    if pools:
        L += [
            "; --- FAIXAS DE ASSINANTE (CGNAT) ---",
            "; Nomenclatura generica aqui esta CORRETA e e desejavel: o PBL da",
            "; Spamhaus sobre faixa de assinante impede que CPE infectado",
            "; entregue spam direto no MX de terceiro. NAO peca remocao do PBL",
            "; destas faixas: ele protege a reputacao do bloco inteiro.",
            "; Cliente que precisa enviar e-mail usa submissao autenticada na 587.",
            "",
        ]
        for lo, hi in pools:
            L.append(f"$GENERATE {lo}-{hi} $ IN PTR "
                     f"{prefixo_pool}-$.{dom}.")
        L.append("")

    if servicos:
        L += [
            "; --- ENDERECOS DE SERVICO ---",
            "; Preencha <NOME> com um nome que NAO contenha os octetos do IP.",
            "; Embutir o IP no hostname e a assinatura que faz a Spamhaus",
            "; inferir faixa dinamica mesmo havendo PTR. Use a funcao:",
            ";   mx1, smtp, gw-<pop>, srv-<servico>, olt-<local>",
            "",
        ]
        for last, ip in servicos[:64]:
            L.append(f"{last}\tIN  PTR  <NOME>.{dom}.\t; {ip}")
        if len(servicos) > 64:
            L.append(f"; ... mais {len(servicos) - 64} enderecos de servico")
        L.append("")

    # Zona direta: os A que faltam
    forward = [
        f"; Registros A para a zona direta de {dom}",
        "; Sem estes, o FCrDNS falha e o PTR nao tem valor.",
        "",
    ]
    if pools:
        for lo, hi in pools:
            forward.append(f"$GENERATE {lo}-{hi} {prefixo_pool}-$ IN A "
                           f"{o[0]}.{o[1]}.{o[2]}.$")
    for last, ip in servicos[:64]:
        forward.append(f"<NOME>\tIN  A  {ip}\t; casar com o PTR de .{last}")

    return {
        "zone_name": zone,
        "domain": dom,
        "reverse": "\n".join(L),
        "forward": "\n".join(forward),
        "pools": [f"{lo}-{hi}" for lo, hi in pools],
        "servicos": len(servicos),
        "aviso": ("Nenhuma faixa de CGNAT foi identificada: todos os endereços "
                  "saíram como serviço. Se este bloco tem pool de assinante, "
                  "envie o .rsc do CGNAT na aba de análise antes de gerar a "
                  "zona, senão o PBL será removido de faixa onde ele protege."
                  if not pools else ""),
    }

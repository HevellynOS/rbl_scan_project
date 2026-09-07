"""
app/services/delegation_service.py — Verificação da cadeia de delegação.

Fecha o buraco que a validação por arquivo não alcança.

O CASO QUE MOTIVOU ESTE MÓDULO
------------------------------
Um provedor tinha a zona reversa correta no servidor dele, com os PTR
apontando para nomes sob o próprio domínio, e tinha também os registros A
correspondentes, com $GENERATE certinho. Pelo arquivo, estava tudo certo.

Só que o domínio estava delegado no registro.br para os servidores de uma
hospedagem, não para os do provedor. Ou seja: os registros A existiam num
servidor que ninguém no mundo consulta. Toda consulta ia para a hospedagem,
que não tinha aqueles nomes, e respondia NXDOMAIN.

A validação por arquivo dizia "correto". A varredura dizia "1023 de 1024
falhando". As duas estavam certas, e faltava a peça do meio: para onde o
domínio está delegado.

Por isso a verificação aqui é AO VIVO e segue a cadeia:

    1. quem o pai (registro.br) aponta como autoritativo do domínio
    2. quem o pai aponta como autoritativo de cada zona reversa
    3. se os servidores do provedor estão nessas listas
    4. se cada servidor autoritativo realmente responde os nomes

Sem o passo 3, um trabalho inteiro pode ser feito num servidor invisível.
"""

from __future__ import annotations

import asyncio
import ipaddress
import re
from collections import defaultdict
from dataclasses import dataclass, field

import dns.asyncresolver
import dns.exception
import dns.flags
import dns.resolver


@dataclass
class ChainConfig:
    resolver: str | None = None
    timeout: float = 4.0
    amostras: int = 4          # nomes testados por domínio


@dataclass
class ServidorInfo:
    nome: str
    ips: list[str] = field(default_factory=list)
    responde: bool = False
    autoritativo: bool = False
    detalhe: str = ""


class ChainChecker:
    def __init__(self, cfg: ChainConfig):
        self.cfg = cfg
        self.r = dns.asyncresolver.Resolver(configure=True)
        if cfg.resolver:
            self.r.nameservers = [cfg.resolver]
        self.r.timeout = cfg.timeout
        self.r.lifetime = cfg.timeout * 2

    async def _q(self, nome, tipo, servidor: str | None = None):
        """Consulta. Com servidor, pergunta direto a ele, sem recursão: é o
        único jeito de saber o que aquele servidor específico responde."""
        if servidor:
            r = dns.asyncresolver.Resolver(configure=False)
            r.nameservers = [servidor]
            r.timeout = self.cfg.timeout
            r.lifetime = self.cfg.timeout * 2
            return await r.resolve(nome, tipo, raise_on_no_answer=False)
        return await self.r.resolve(nome, tipo, raise_on_no_answer=False)

    async def ns_do_dominio(self, dominio: str) -> tuple[list[str], str]:
        try:
            ans = await self._q(dominio, "NS")
            nomes = sorted(str(x.target).rstrip(".").lower() for x in ans)
            return nomes, ""
        except dns.resolver.NXDOMAIN:
            return [], "o domínio não existe na hierarquia do DNS"
        except dns.resolver.NoAnswer:
            return [], "o domínio existe mas não declara servidores"
        except Exception as e:
            return [], f"consulta falhou: {type(e).__name__}"

    async def resolve_ips(self, nome: str) -> list[str]:
        ips: list[str] = []
        for tipo in ("A", "AAAA"):
            try:
                ans = await self._q(nome, tipo)
                ips += [x.address for x in ans]
            except Exception:
                pass
        return sorted(set(ips))

    async def pergunta_direto(self, servidor_ip: str, nome: str,
                              tipo: str) -> tuple[bool, list[str], bool, str]:
        """(respondeu, valores, autoritativo, detalhe)."""
        try:
            r = dns.asyncresolver.Resolver(configure=False)
            r.nameservers = [servidor_ip]
            r.timeout = self.cfg.timeout
            r.lifetime = self.cfg.timeout * 2
            resp = await r.resolve(nome, tipo, raise_on_no_answer=False)
            aa = bool(resp.response.flags & dns.flags.AA)
            vals = [x.to_text() for x in resp.rrset] if resp.rrset else []
            return True, vals, aa, ""
        except dns.resolver.NXDOMAIN:
            return True, [], False, "respondeu que o nome não existe"
        except (dns.exception.Timeout, dns.resolver.LifetimeTimeout):
            return False, [], False, "sem resposta"
        except Exception as e:
            return False, [], False, type(e).__name__



def extrai_dominios(analise: dict) -> dict[str, list[dict]]:
    """Domínios usados nos PTR, com amostras de nome e endereço.

    Sai da análise de arquivos: são os nomes que o reverso publica e que
    precisam existir do outro lado.
    """
    por_dominio: dict[str, list[dict]] = defaultdict(list)
    for f in analise.get("findings", []):
        for s in f.get("samples", []):
            nome = (s.get("nome") or "").rstrip(".")
            ip = s.get("ip") or ""
            if not nome or not ip or "." not in nome:
                continue
            por_dominio[_dominio_registravel(nome)].append(
                {"nome": nome, "ip": ip})
    return {d: v[:40] for d, v in por_dominio.items()}


def galho_comum(nomes: list[str], dominio: str) -> str:
    """Maior sufixo comum aos nomes, abaixo do domínio.

    De '0.92.pop.prov.net.br' e '5.93.pop.prov.net.br' resulta
    'pop.prov.net.br'. É o menor pedaço que precisa ser delegado quando o
    domínio fica com terceiros: dois registros NS resolvem o bloco inteiro,
    sem mexer em site nem em e-mail.
    """
    base = dominio.split(".")
    candidatos = []
    for n in nomes:
        labels = n.rstrip(".").lower().split(".")
        if len(labels) <= len(base):
            continue
        candidatos.append(labels[:-len(base)])
    if not candidatos:
        return ""
    comum: list[str] = []
    for i in range(1, min(len(c) for c in candidatos) + 1):
        sufixo = candidatos[0][-i]
        if all(c[-i] == sufixo for c in candidatos):
            comum.insert(0, sufixo)
        else:
            break
    return ".".join(comum + base) if comum else ""


def _dominio_registravel(nome: str) -> str:
    partes = nome.rstrip(".").lower().split(".")
    if len(partes) <= 2:
        return nome.rstrip(".").lower()
    segundo = {"com", "net", "org", "gov", "edu", "co", "ne", "or", "adv",
               "eng", "ind", "inf", "psi", "rec", "srv", "tur", "tv"}
    corte = 3 if len(partes) >= 4 and partes[-2] in segundo else 2
    return ".".join(partes[-corte:])


# --------------------------------------------------------------------------
async def check_chain(
    dominios: dict[str, list[dict]],
    zonas_reversas: list[str],
    servidores_locais: list[str],
    cfg: ChainConfig | None = None,
) -> dict:
    """Segue a cadeia e diz onde cada peça mora.

    servidores_locais: nomes ou IPs dos servidores do provedor, tirados do
    named.conf ou informados na tela. É contra essa lista que se decide se o
    domínio está delegado para eles ou para terceiros.
    """
    cfg = cfg or ChainConfig()
    ck = ChainChecker(cfg)

    locais_nome = {s.rstrip(".").lower() for s in servidores_locais
                   if s and not _e_ip(s)}
    locais_ip = {s for s in servidores_locais if _e_ip(s)}
    for nome in list(locais_nome):
        locais_ip.update(await ck.resolve_ips(nome))

    resultados = []
    for dominio, amostras in dominios.items():
        ns, erro = await ck.ns_do_dominio(dominio)
        servidores = []
        for n in ns:
            ips = await ck.resolve_ips(n)
            info = ServidorInfo(nome=n, ips=ips)
            if ips:
                ok, vals, aa, det = await ck.pergunta_direto(
                    ips[0], dominio, "SOA")
                info.responde = ok
                info.autoritativo = aa
                info.detalhe = det
            else:
                info.detalhe = "o nome do servidor não resolve"
            servidores.append(info)

        ips_ns = {ip for s in servidores for ip in s.ips}
        nosso = bool(locais_nome & set(ns)) or bool(locais_ip & ips_ns)

        # Testa nomes reais em cada servidor autoritativo.
        testes = []
        for a in amostras[:cfg.amostras]:
            linha = {"nome": a["nome"], "ip_esperado": a["ip"], "por_servidor": []}
            for s in servidores:
                if not s.ips:
                    continue
                ok, vals, aa, det = await ck.pergunta_direto(
                    s.ips[0], a["nome"], "A")
                linha["por_servidor"].append({
                    "servidor": s.nome,
                    "respondeu": ok,
                    "valores": vals,
                    "confere": a["ip"] in vals,
                    "detalhe": det,
                })
            testes.append(linha)

        nomes = [a["nome"] for a in amostras]
        galho = galho_comum(nomes, dominio)

        resultados.append({
            "dominio": dominio,
            "erro": erro,
            "ns": ns,
            "servidores": [vars(s) for s in servidores],
            "hospedado_por_nos": nosso,
            "galho_sugerido": galho,
            "amostras": testes,
            "nomes_no_ptr": len(amostras),
        })

    # Zonas reversas: mesma pergunta, lado do .arpa
    reversas = []
    for z in zonas_reversas:
        ns, erro = await ck.ns_do_dominio(z)
        ips_ns: set[str] = set()
        for n in ns:
            ips_ns.update(await ck.resolve_ips(n))
        reversas.append({
            "zona": z,
            "erro": erro,
            "ns": ns,
            "hospedado_por_nos": bool(locais_nome & set(ns)) or
                                 bool(locais_ip & ips_ns),
        })

    return {
        "dominios": resultados,
        "reversas": reversas,
        "servidores_locais": sorted(locais_nome | locais_ip),
        "achados": _achados(resultados, reversas),
    }


def _e_ip(v: str) -> bool:
    try:
        ipaddress.ip_address(v.strip())
        return True
    except ValueError:
        return False


def _achados(dominios: list[dict], reversas: list[dict]) -> list[dict]:
    out = []

    for d in dominios:
        if d["erro"]:
            out.append({
                "id": f"dominio-sem-ns-{d['dominio']}",
                "severidade": 3,
                "titulo": f"O domínio {d['dominio']} não declara servidores",
                "detalhe": d["erro"],
                "porque":
                    "Os nomes publicados no DNS reverso apontam para este "
                    "domínio. Se ele não resolve, a verificação de ida e volta "
                    "falha para todos os endereços de uma vez, "
                    "independentemente de os registros existirem em algum "
                    "servidor.",
                "correcao": [
                    f"; Verifique o registro do domínio {d['dominio']}.",
                    "; Se ele foi trocado ou expirou, os PTR precisam ser",
                    "; refeitos apontando para um domínio ativo.",
                ],
            })
            continue

        if not d["hospedado_por_nos"]:
            galho = d["galho_sugerido"] or f"<galho>.{d['dominio']}"
            terceiros = ", ".join(d["ns"]) or "(desconhecido)"
            out.append({
                "id": f"dominio-em-terceiros-{d['dominio']}",
                "severidade": 3,
                "titulo": f"{d['dominio']} está delegado para servidores de terceiros",
                "detalhe": f"Autoritativos hoje: {terceiros}",
                "porque":
                    f"Os {d['nomes_no_ptr']} nomes publicados no DNS reverso "
                    f"pertencem a este domínio, mas quem responde por ele na "
                    f"internet são os servidores acima. Mesmo que os registros "
                    f"existam no servidor do provedor, ninguém os consulta: "
                    f"toda pergunta vai para o autoritativo declarado no "
                    f"registro, e ele responde que o nome não existe. É o erro "
                    f"que faz um trabalho inteiro de DNS ficar invisível.",
                "correcao": [
                    "; OPÇÃO RECOMENDADA: delegar apenas o galho usado nos",
                    "; nomes reversos, sem mexer em site nem em e-mail.",
                    ";",
                    f"; No painel de {terceiros.split(',')[0]}, na zona",
                    f"; {d['dominio']}, criar dois registros NS:",
                    ";",
                    f";   {galho}.   IN NS   <SEU-NS1>.",
                    f";   {galho}.   IN NS   <SEU-NS2>.",
                    ";",
                    "; E no servidor do provedor, criar a zona correspondente",
                    f"; com os registros A dos nomes sob {galho}.",
                    ";",
                    "; Dois registros lá resolvem o bloco inteiro. Migrar o",
                    "; domínio todo também funciona, mas leva junto site,",
                    "; e-mail e SPF, e exige um segundo autoritativo em outro",
                    "; caminho de rede antes de trocar a delegação.",
                ],
            })
            continue

        # Delegado corretamente: os nomes respondem?
        falhas = []
        for a in d["amostras"]:
            for s in a["por_servidor"]:
                if not s["confere"]:
                    falhas.append((a["nome"], s["servidor"], s["valores"],
                                   s["detalhe"]))
        if falhas:
            out.append({
                "id": f"nome-nao-responde-{d['dominio']}",
                "severidade": 3,
                "titulo": f"Servidores de {d['dominio']} não respondem os nomes do reverso",
                "detalhe": "; ".join(
                    f"{n} em {s}: {', '.join(v) or (det or 'sem resposta')}"
                    for n, s, v, det in falhas[:4]),
                "porque":
                    "O domínio está delegado para os servidores certos, mas "
                    "eles não devolvem o endereço esperado para os nomes "
                    "publicados no reverso. Ou a zona não carregou, ou o nome "
                    "da zona no named.conf não bate com o conteúdo do arquivo.",
                "correcao": [
                    "; No servidor autoritativo:",
                    "sudo named-checkconf",
                    f"sudo named-checkzone {d['dominio']} <arquivo-da-zona>",
                    "sudo journalctl -u named | grep -i 'zone' | tail -20",
                    ";",
                    "; Divergência entre o nome declarado no named.conf e o",
                    "; nome dentro do arquivo faz o BIND recusar a zona",
                    "; inteira, e a versão anterior continua no ar sem aviso.",
                ],
            })

    for z in reversas:
        if z["erro"] or not z["ns"]:
            out.append({
                "id": f"reversa-sem-delegacao-{z['zona']}",
                "severidade": 3,
                "titulo": f"A zona reversa {z['zona']} não está delegada",
                "detalhe": z["erro"] or "nenhum servidor declarado",
                "porque":
                    "Sem delegação, os PTR existem apenas no servidor local e "
                    "nenhum resolver da internet sabe a quem perguntar.",
                "correcao": [
                    "; A delegação do reverso é feita no registro.br, em",
                    "; NUMERAÇÃO, sobre o bloco, opção Configurar DNS.",
                    "; Informe os servidores que respondem pela zona.",
                    ";",
                    "; Pré-requisito: o domínio dos servidores precisa estar",
                    "; ativo e com os nomes ns1/ns2 resolvendo, senão a",
                    "; delegação é recusada.",
                ],
            })
        elif not z["hospedado_por_nos"]:
            out.append({
                "id": f"reversa-em-terceiros-{z['zona']}",
                "severidade": 2,
                "titulo": f"A zona reversa {z['zona']} está delegada para terceiros",
                "detalhe": f"Autoritativos: {', '.join(z['ns'])}",
                "porque":
                    "Os PTR desta faixa são publicados por outro operador. "
                    "Alterações feitas no servidor do provedor não produzem "
                    "efeito nenhum enquanto a delegação apontar para lá.",
                "correcao": [
                    "; Ou peça ao operador atual que publique os registros,",
                    "; ou troque a delegação no registro.br para os seus",
                    "; servidores. Não faça as duas coisas ao mesmo tempo.",
                ],
            })

    out.sort(key=lambda a: -a["severidade"])
    return out

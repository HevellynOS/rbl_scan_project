"""
rbl_core.py — Nucleo do RBL Scan.

Refatoracao do rbl_scan.py para uso como biblioteca: a varredura vira um
gerador assincrono que emite eventos conforme os resultados chegam, para a
interface pintar o mapa do bloco em tempo real em vez de esperar o fim.

Classificacao central (e o ponto inteiro da ferramenta):
    POLICY    — listagem derivada de configuracao (rDNS ausente/generico).
                Sai corrigindo DNS.
    BEHAVIOR  — spam/abuso efetivamente observado.
                NAO sai corrigindo DNS; volta a listar apos qualquer remocao.
"""

from __future__ import annotations

import asyncio
import ipaddress
import re
import time
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from typing import AsyncIterator

import dns.asyncresolver
import dns.exception
import dns.resolver
import dns.reversename


# --------------------------------------------------------------------------
# Registro de RBLs
# --------------------------------------------------------------------------
@dataclass
class Rbl:
    name: str
    zone: str
    severity: int          # 3=critico 2=relevante 1=nicho
    profile: str           # core | full
    note: str
    delist: str = ""
    codes: dict = field(default_factory=dict)
    needs_key: bool = False
    needs_registration: bool = False


RBLS: list[Rbl] = [
    Rbl("SPAMHAUS-ZEN", "zen.dq.spamhaus.net", 3, "core",
        "Composite SBL+CSS+XBL+PBL. A lista mais adotada do mundo.",
        "https://check.spamhaus.org/",
        codes={
            "127.0.0.2":  "SBL — fonte de spam (ticket do dono da rede)",
            "127.0.0.3":  "CSS — padrão snowshoe",
            "127.0.0.4":  "XBL — máquina comprometida",
            "127.0.0.5":  "XBL — máquina comprometida",
            "127.0.0.6":  "XBL — máquina comprometida",
            "127.0.0.7":  "XBL — máquina comprometida",
            "127.0.0.9":  "DROP — range hijackado ou totalmente malicioso",
            "127.0.0.10": "PBL declarado pelo próprio ISP",
            "127.0.0.11": "PBL inferido pela Spamhaus (rDNS genérico)",
        },
        needs_key=True),
    Rbl("SPAMCOP", "bl.spamcop.net", 3, "core",
        "Spamtraps e denúncias. Expira sozinha em ~24h sem novo spam.",
        "https://www.spamcop.net/bl.shtml",
        codes={"127.0.0.2": "Reportado como fonte de spam"}),
    Rbl("BARRACUDA", "b.barracudacentral.org", 3, "core",
        "Muito usada no mundo corporativo. Exige registrar o IP do resolver.",
        "https://www.barracudacentral.org/rbl/removal-request",
        codes={"127.0.0.2": "Reputação ruim segundo a Barracuda"},
        needs_registration=True),
    Rbl("SPAMRATS", "all.spamrats.com", 2, "core",
        "Separa falta de reverso (NoPtr) de comportamento (Spam).",
        "https://www.spamrats.com/lookup.php",
        codes={
            "127.0.0.36": "RATS-Dyna — rDNS com padrão de IP dinâmico",
            "127.0.0.37": "RATS-NoPtr — sem registro PTR",
            "127.0.0.38": "RATS-Spam — comportamento de spam observado",
            "127.0.0.43": "RATS-Auth — ataque a autenticação",
        }),
    Rbl("PSBL", "psbl.surriel.com", 2, "core",
        "Passive Spam Block List. Remoção self-service imediata.",
        "https://psbl.org/remove",
        codes={"127.0.0.2": "Spamtrap hit"}),
    Rbl("BLOCKLIST-DE", "bl.blocklist.de", 2, "core",
        "Alimentada por fail2ban. Indica host comprometido em brute-force.",
        "https://www.blocklist.de/en/delist.html",
        codes={"127.0.0.2": "Ataque reportado (SSH/SMTP/etc)"}),
    Rbl("MAILSPIKE-BL", "bl.mailspike.net", 2, "core",
        "Reputação de envio. 127.0.0.10-12 são os níveis de bloqueio.",
        "https://mailspike.org/iplookup.html",
        codes={"127.0.0.10": "Pior reputação possível",
               "127.0.0.11": "Reputação muito ruim",
               "127.0.0.12": "Reputação ruim"}),
    Rbl("GBUDB", "truncate.gbudb.net", 2, "core",
        "Só lista IPs com histórico exclusivamente ruim. Auto-expira.",
        "https://www.gbudb.com/truncate/index.jsp",
        codes={"127.0.0.2": "Tráfego exclusivamente ruim"}),
    Rbl("DRONEBL", "dnsbl.dronebl.org", 2, "full",
        "Proxies abertos, bots e máquinas comprometidas.",
        "https://dronebl.org/lookup"),
    Rbl("UCEPROTECT-L1", "dnsbl-1.uceprotect.net", 1, "full",
        "Nível 1 lista IP individual. Auto-expira em 7 dias.",
        "https://www.uceprotect.net/en/rblcheck.php",
        codes={"127.0.0.2": "IP individual listado"}),
    Rbl("UCEPROTECT-L2", "dnsbl-2.uceprotect.net", 1, "full",
        "Lista a alocação inteira por poucos IPs sujos. Muito agressiva — "
        "vários operadores ignoram. Não pague por remoção expressa.",
        "https://www.uceprotect.net/en/rblcheck.php",
        codes={"127.0.0.2": "Alocação/range listado"}),
    Rbl("UCEPROTECT-L3", "dnsbl-3.uceprotect.net", 1, "full",
        "Lista o ASN inteiro. Serve para monitorar o AS, não para delistar IP.",
        "https://www.uceprotect.net/en/rblcheck.php",
        codes={"127.0.0.2": "ASN listado"}),
    Rbl("BACKSCATTERER", "ips.backscatterer.org", 1, "full",
        "Lista quem gera backscatter (bounce para remetente forjado).",
        "https://www.backscatterer.org/?target=test",
        codes={"127.0.0.2": "Fonte de backscatter"}),
    Rbl("INTERSERVER", "rbl.interserver.net", 1, "full",
        "Lista própria da InterServer.", "https://rbl.interserver.net/"),
    Rbl("S5H", "all.s5h.net", 1, "full",
        "Lista comunitária agregada.", "https://www.usenix.org.uk/content/rbl.html"),
]

RBL_BY_NAME = {r.name: r for r in RBLS}

# Codigos que significam POLITICA, nao comportamento observado.
POLICY_CODES: set[tuple[str, str]] = {
    ("SPAMHAUS-ZEN", "127.0.0.10"),
    ("SPAMHAUS-ZEN", "127.0.0.11"),
    ("SPAMRATS", "127.0.0.36"),
    ("SPAMRATS", "127.0.0.37"),
}


# --------------------------------------------------------------------------
# Heuristica de rDNS generico
# --------------------------------------------------------------------------
GENERIC_RE = re.compile("|".join([
    r"dinamic", r"dynamic", r"dyn\d", r"dhcp", r"pppoe", r"ppp-?\d",
    r"dsl", r"adsl", r"gpon", r"cable", r"cabo", r"wireless", r"wifi",
    r"client", r"cliente", r"customer", r"user", r"assinante", r"pool",
    r"cgnat", r"nat\d", r"generic", r"unassigned", r"no-?reverse",
]), re.IGNORECASE)

SECOND_LEVEL = {"com", "net", "org", "gov", "edu", "mil", "co", "ne", "or", "ac"}


def host_part(fqdn: str) -> str:
    """Descarta o dominio registravel: 'cliente' em mail.cliente.com.br nao e
    sinal de faixa dinamica, mas em pppoe.cliente.provedor.net.br e."""
    labels = fqdn.split(".")
    if len(labels) < 3:
        return labels[0] if labels else ""
    suffix = 3 if len(labels) >= 4 and labels[-2] in SECOND_LEVEL else 2
    return ".".join(labels[:-suffix]) if len(labels) > suffix else ""


def ptr_looks_generic(ip: str, ptr: str) -> tuple[bool, str]:
    if not ptr:
        return True, "sem PTR"
    low = ptr.rstrip(".").lower()
    if GENERIC_RE.search(host_part(low)):
        return True, "palavra-chave de faixa dinâmica no hostname"
    octets = ip.split(".")
    for sep in ("-", ".", "x", "_"):
        if sep.join(octets) in low or sep.join(reversed(octets)) in low:
            return True, "PTR contém os octetos do IP"
    if "".join(octets) in re.sub(r"[^0-9]", "", low):
        return True, "PTR contém os dígitos do IP"
    if re.search(r"\d{6,}", low):
        return True, "sequência numérica longa no PTR"
    return False, ""


# --------------------------------------------------------------------------
def _rev_zone(net) -> str:
    """192.0.2.0/24 -> 2.0.192.in-addr.arpa"""
    o = str(net.network_address).split(".")
    return f"{o[2]}.{o[1]}.{o[0]}.in-addr.arpa"


def reverse_ipv4(ip: str) -> str:
    return ".".join(reversed(ip.split(".")))


def collapse(ips: list[str]) -> list[str]:
    nets = [ipaddress.ip_network(f"{i}/32") for i in ips]
    return [str(n) for n in ipaddress.collapse_addresses(nets)]


@dataclass
class ScanConfig:
    cidr: str
    profile: str = "core"
    lists: list[str] | None = None
    dqs_key: str | None = None
    resolver: str | None = None
    concurrency: int = 40
    per_zone: int = 8
    timeout: float = 3.0
    check_rdns: bool = True


class Scanner:
    """Emite eventos conforme varre. Nao acumula estado de apresentacao —
    a agregacao final e feita em build_report()."""

    def __init__(self, cfg: ScanConfig):
        self.cfg = cfg
        self.resolver = dns.asyncresolver.Resolver(configure=True)
        if cfg.resolver:
            self.resolver.nameservers = [cfg.resolver]
        self.resolver.timeout = cfg.timeout
        self.resolver.lifetime = cfg.timeout * 2
        self.global_sem = asyncio.Semaphore(cfg.concurrency)
        self.zone_sem: dict[str, asyncio.Semaphore] = defaultdict(
            lambda: asyncio.Semaphore(cfg.per_zone))
        self.dead_zones: set[str] = set()
        self.warnings: list[str] = []
        self.queried: dict[str, int] = defaultdict(int)
        self.negative: dict[str, int] = defaultdict(int)   # NXDOMAIN = resposta válida
        self.errors: dict[str, int] = defaultdict(int)     # sem resposta = desconhecido
        self.error_kinds: dict[str, set] = defaultdict(set)
        self.listed: dict[str, int] = defaultdict(int)
        self.cancelled = False

    def selected_rbls(self) -> list[Rbl]:
        rbls = [r for r in RBLS if self.cfg.profile == "full" or r.profile == "core"]
        if self.cfg.lists:
            wanted = {n.upper() for n in self.cfg.lists}
            rbls = [r for r in rbls if r.name in wanted]
        if not self.cfg.dqs_key:
            skipped = [r.name for r in rbls if r.needs_key]
            if skipped:
                self.warnings.append(
                    f"Sem chave DQS — {', '.join(skipped)} não será consultada. "
                    "É a lista mais relevante; obtenha a chave em portal.spamhaus.com/dqs.")
            rbls = [r for r in rbls if not r.needs_key]
        return rbls

    def zone_for(self, rbl: Rbl) -> str:
        return f"{self.cfg.dqs_key}.{rbl.zone}" if rbl.needs_key else rbl.zone

    async def _resolve(self, qname: str, rtype: str):
        async with self.global_sem:
            return await self.resolver.resolve(qname, rtype)

    async def check(self, ip: str, rbl: Rbl) -> dict | None:
        if rbl.zone in self.dead_zones or self.cancelled:
            return None
        qname = f"{reverse_ipv4(ip)}.{self.zone_for(rbl)}"
        self.queried[rbl.name] += 1
        async with self.zone_sem[rbl.zone]:
            try:
                answer = await self._resolve(qname, "A")
            except dns.resolver.NXDOMAIN:
                # Resposta negativa AUTORITATIVA: o IP realmente não está na lista.
                self.negative[rbl.name] += 1
                return None
            except (dns.resolver.NoAnswer, dns.resolver.NoNameservers) as e:
                # NoNameservers = todos os servidores falharam. Isso NÃO é
                # "não listado" — é consulta sem resposta, e tratar como limpo
                # foi o que fez o scanner pintar blocos sujos de verde.
                self.errors[rbl.name] += 1
                self.error_kinds[rbl.name].add(type(e).__name__)
                return None
            except (dns.exception.Timeout, dns.resolver.LifetimeTimeout):
                self.errors[rbl.name] += 1
                self.error_kinds[rbl.name].add("Timeout")
                return None
            except Exception as e:
                self.errors[rbl.name] += 1
                self.error_kinds[rbl.name].add(type(e).__name__)
                return None

        codes = sorted(r.address for r in answer)
        if any(c.startswith("127.255.255.") for c in codes):
            self.dead_zones.add(rbl.zone)
            self.warnings.append(
                f"{rbl.name} retornou {codes[0]}: chave inválida, cota excedida ou "
                f"resolver público em uso. Zona desativada — resultados incompletos.")
            return None

        entries = []
        for c in codes:
            entries.append({
                "code": c,
                "meaning": rbl.codes.get(c, f"código {c}"),
                "kind": "policy" if (rbl.name, c) in POLICY_CODES else "behavior",
            })
        self.listed[rbl.name] += 1
        return {"ip": ip, "rbl": rbl.name, "severity": rbl.severity, "entries": entries}

    async def ptr_audit(self, ip: str) -> dict:
        ptr = ""
        try:
            ans = await self._resolve(dns.reversename.from_address(ip), "PTR")
            ptr = str(ans[0]).rstrip(".")
        except Exception:
            ptr = ""
        fcrdns = None
        if ptr:
            try:
                fwd = await self._resolve(ptr, "A")
                fcrdns = ip in [r.address for r in fwd]
            except Exception:
                fcrdns = False
        generic, reason = ptr_looks_generic(ip, ptr)
        # Status explicito. "sem PTR" e "PTR generico" tem correcoes OPOSTAS:
        # um precisa de registro criado, o outro de renomeacao. Somar os dois
        # num numero so foi o que fez o plano dizer "corrigir 256" quando eram
        # 199 ausentes e 57 mal nomeados.
        status = "ausente" if not ptr else ("generico" if generic else "ok")
        # "generic" so faz sentido quando existe PTR. Sem PTR e outro problema,
        # com outra correcao: um precisa de registro criado, o outro de
        # renomeacao. Somar os dois num numero so esconde isso.
        return {"ip": ip, "ptr": ptr, "has_ptr": bool(ptr), "fcrdns": fcrdns,
                "generic": bool(ptr) and generic, "issue": reason,
                "status": status}

    async def check_delegation(self, net) -> list[dict]:
        """A zona reversa existe na hierarquia do DNS?

        Distingue 'os registros PTR faltam' de 'ninguem foi delegado como
        responsavel pelo reverso'. No segundo caso, criar PTR nao adianta:
        nenhum resolver do mundo sabe a quem perguntar.

        Cobre /24 e maiores. Para prefixos menores a delegacao e classless
        (RFC 2317) e depende do upstream, fora do que da para inferir aqui.
        """
        if net.prefixlen > 24:
            return [{"zone": None, "status": "nao-aplicavel",
                     "detail": f"{net} e menor que /24: a delegacao reversa e "
                               f"classless (RFC 2317) e depende do upstream."}]

        zones = [f"{o[2]}.{o[1]}.{o[0]}.in-addr.arpa"
                 for o in ([str(s.network_address).split(".") for s in
                            net.subnets(new_prefix=24)][:16])]
        out = []
        for z in zones:
            entry = {"zone": z, "status": "", "detail": "", "ns": []}
            try:
                ans = await self._resolve(z, "NS")
                entry["ns"] = sorted(str(r.target).rstrip(".") for r in ans)
                entry["status"] = "delegada"
                entry["detail"] = ", ".join(entry["ns"])
                try:
                    await self._resolve(z, "SOA")
                except Exception:
                    entry["status"] = "lame"
                    entry["detail"] = (f"NS delegado ({', '.join(entry['ns'])}) mas "
                                       f"sem SOA: os servidores nao respondem "
                                       f"autoritativamente pela zona.")
            except dns.resolver.NXDOMAIN:
                entry["status"] = "sem-delegacao"
                entry["detail"] = ("A zona nao existe na hierarquia. Criar PTR nao "
                                   "adianta: ninguem consegue perguntar por eles.")
            except Exception as e:
                entry["status"] = "erro"
                entry["detail"] = type(e).__name__
            out.append(entry)
        return out

    async def check_delegation(self, net) -> list[dict]:
        """Delegacao das zonas in-addr.arpa que cobrem o bloco.

        Distingue duas situacoes que a auditoria confundia:
          - zona NAO delegada  -> criar PTR nao adianta, ninguem consegue
                                  perguntar por eles
          - zona delegada, PTR ausente -> so faltam os registros
        Blocos maiores que /24 tem uma zona por /24. Menores herdam a zona do
        /24 que os contem (ou usam delegacao RFC 2317, fora do escopo aqui).
        """
        zones: list[str] = []
        if net.prefixlen >= 24:
            base = ipaddress.ip_network(f"{net.network_address}/24", strict=False)
            zones = [_rev_zone(base)]
        else:
            zones = [_rev_zone(sub) for sub in net.subnets(new_prefix=24)][:16]

        out = []
        for z in zones:
            entry = {"zone": z, "delegated": False, "ns": [], "soa": "", "detail": ""}
            try:
                ans = await self._resolve(z, "NS")
                entry["ns"] = sorted(str(r.target).rstrip(".") for r in ans)
                entry["delegated"] = True
            except dns.resolver.NXDOMAIN:
                entry["detail"] = ("A zona nao existe na hierarquia do DNS. "
                                   "Nenhum servidor foi apontado como responsavel "
                                   "pelo reverso deste bloco: criar PTR em um "
                                   "servidor qualquer nao torna o registro "
                                   "visivel. A delegacao precisa ser feita no "
                                   "registro.br ou pelo upstream que alocou o "
                                   "bloco.")
            except (dns.resolver.NoAnswer, dns.resolver.NoNameservers):
                entry["detail"] = ("A zona responde mas nao devolveu NS. Pode ser "
                                   "delegacao incompleta ou servidor que nao "
                                   "responde autoritativamente (lame delegation).")
            except Exception as e:
                entry["detail"] = f"Consulta falhou: {type(e).__name__}"

            if entry["delegated"]:
                try:
                    soa = await self._resolve(z, "SOA")
                    entry["soa"] = str(soa[0].mname).rstrip(".")
                except Exception:
                    entry["detail"] = ("NS existe mas a zona nao devolve SOA. "
                                       "Lame delegation: cada consulta reversa "
                                       "vira timeout, o que e pior que a ausencia.")
            out.append(entry)
        return out

    async def verify_zones(self, rbls: list[Rbl] | None = None,
                           attempts: int = 2) -> list[dict]:
        """127.0.0.2 e a entrada de teste padrao da maioria das DNSBLs.

        Tenta mais de uma vez: uma lista lenta que perde o primeiro pacote UDP
        seria excluida da varredura inteira por causa de um unico timeout."""
        out = []
        for rbl in rbls if rbls is not None else self.selected_rbls():
            result = None
            for attempt in range(attempts):
                try:
                    ans = await self._resolve(f"2.0.0.127.{self.zone_for(rbl)}", "A")
                    result = {"rbl": rbl.name, "status": "ok",
                              "detail": ", ".join(sorted(r.address for r in ans))}
                    break
                except dns.resolver.NXDOMAIN:
                    result = {"rbl": rbl.name, "status": "sem_resposta",
                              "detail": "NXDOMAIN na entrada de teste — zona morta, "
                                        "ou seu resolver está bloqueado por ela"}
                    break
                except Exception as e:
                    result = {"rbl": rbl.name, "status": "falha",
                              "detail": f"{type(e).__name__}"
                                        f"{f' após {attempts} tentativas' if attempt == attempts - 1 else ''}"}
                    if attempt < attempts - 1:
                        await asyncio.sleep(0.4)
            out.append(result)
        return out

    async def run(self) -> AsyncIterator[dict]:
        net = ipaddress.ip_network(self.cfg.cidr, strict=False)
        ips = [str(i) for i in net]
        rbls = self.selected_rbls()
        started = time.time()

        # Pré-voo obrigatório: consulta a entrada de teste 127.0.0.2 em cada
        # lista. Sem isso, uma lista que bloqueia o resolver responde nada e o
        # bloco inteiro sai pintado de "limpo" — falso negativo silencioso, que
        # é o pior resultado possível numa ferramenta de auditoria.
        probe = await self.verify_zones(rbls)
        alive = {p["rbl"] for p in probe if p["status"] == "ok"}
        for p in probe:
            if p["status"] != "ok":
                rbl = RBL_BY_NAME[p["rbl"]]
                self.dead_zones.add(rbl.zone)
                extra = (" Esta lista exige registrar o IP do seu resolver no site "
                         "dela — provavelmente é isso." if rbl.needs_registration else "")
                self.warnings.append(
                    f"{p['rbl']} não respondeu à consulta de teste ({p['detail']}). "
                    f"Excluída da varredura — os resultados dela seriam "
                    f"indistinguíveis de 'limpo'.{extra}")
        rbls = [r for r in rbls if r.name in alive]

        if not rbls:
            yield {"type": "error",
                   "message": "Nenhuma lista respondeu à consulta de teste. "
                              "Quase sempre é o resolver: DNS público (8.8.8.8, "
                              "1.1.1.1) é recusado pelas DNSBLs. Configure um "
                              "recursivo próprio em Mais opções."}
            return

        delegation = await self.check_delegation(net) if self.cfg.check_rdns else []

        total_q = len(ips) * len(rbls) + (len(ips) * 2 if self.cfg.check_rdns else 0)
        yield {"type": "start", "network": str(net), "ips": len(ips),
               "rbls": [r.name for r in rbls], "queries": total_q,
               "warnings": self.warnings, "probe": probe,
               "delegation": delegation}

        hits: list[dict] = []
        ptrs: list[dict] = []
        done = 0
        queue: asyncio.Queue = asyncio.Queue()

        async def worker(ip: str):
            local = []
            for rbl in rbls:
                r = await self.check(ip, rbl)
                if r:
                    local.append(r)
            ptr = await self.ptr_audit(ip) if self.cfg.check_rdns else None
            await queue.put((ip, local, ptr))

        tasks = [asyncio.create_task(worker(ip)) for ip in ips]

        try:
            for _ in ips:
                ip, local, ptr = await queue.get()
                hits.extend(local)
                if ptr:
                    ptrs.append(ptr)
                done += 1
                yield {"type": "ip", "ip": ip, "hits": local, "ptr": ptr,
                       "done": done, "total": len(ips),
                       "classification": classify_ip(local)}
        finally:
            for t in tasks:
                t.cancel()

        diagnostics = []
        for r in rbls:
            q = self.queried.get(r.name, 0)
            err = self.errors.get(r.name, 0)
            diagnostics.append({
                "rbl": r.name,
                "queried": q,
                "listed": self.listed.get(r.name, 0),
                "negative": self.negative.get(r.name, 0),
                "errors": err,
                "error_kinds": sorted(self.error_kinds.get(r.name, set())),
                "reliable": q > 0 and err / q < 0.1,
            })
            if q and err / q >= 0.1:
                self.warnings.append(
                    f"{r.name}: {err} de {q} consultas sem resposta "
                    f"({', '.join(sorted(self.error_kinds[r.name]))}). "
                    f"O resultado desta lista está incompleto — não confie no "
                    f"'limpo' dela.")

        yield {"type": "done",
               "report": build_report(net, hits, ptrs, rbls,
                                      self.warnings, diagnostics,
                                      round(time.time() - started, 1),
                                      delegation)}


def classify_ip(hits_for_ip: list[dict]) -> str:
    """clean | policy | behavior — o eixo que a interface pinta."""
    if not hits_for_ip:
        return "clean"
    for h in hits_for_ip:
        if any(e["kind"] == "behavior" for e in h["entries"]):
            return "behavior"
    return "policy"


def build_report(net, hits, ptrs, rbls, warnings, diagnostics, elapsed,
                 delegation=None) -> dict:
    total = net.num_addresses
    by_rbl: dict[str, list[str]] = defaultdict(list)
    meanings: dict[str, set] = defaultdict(set)
    per_ip: dict[str, list[dict]] = defaultdict(list)

    for h in hits:
        by_rbl[h["rbl"]].append(h["ip"])
        per_ip[h["ip"]].append(h)
        for e in h["entries"]:
            meanings[h["rbl"]].add(e["meaning"])

    behavior_ips = sorted(
        [ip for ip, hs in per_ip.items() if classify_ip(hs) == "behavior"],
        key=lambda i: int(ipaddress.ip_address(i)))
    policy_ips = sorted(
        [ip for ip, hs in per_ip.items() if classify_ip(hs) == "policy"],
        key=lambda i: int(ipaddress.ip_address(i)))

    ptr_map = {p["ip"]: p for p in ptrs}
    no_ptr = [p for p in ptrs if p["status"] == "ausente"]
    generic = [p for p in ptrs if p["status"] == "generico"]
    ok_ptr = [p for p in ptrs if p["status"] == "ok"]
    com_ptr = [p for p in ptrs if p["has_ptr"]]
    broken = [p for p in com_ptr if p["fcrdns"] is False]
    clean_ptr = [p for p in ok_ptr if p["fcrdns"]]

    # Amostra de PTR generico: sem ver um exemplo, "generico" nao diz nada a
    # quem vai corrigir.
    sample = next((p for p in generic if p["ptr"]), None)

    lists_out = []
    for r in sorted(rbls, key=lambda x: (-x.severity, x.name)):
        if r.name not in by_rbl:
            continue
        ips = by_rbl[r.name]
        lists_out.append({
            "name": r.name, "severity": r.severity, "note": r.note,
            "delist": r.delist, "count": len(ips),
            "prefixes": collapse(ips), "meanings": sorted(meanings[r.name]),
        })

    rows = []
    for ip in sorted(set(list(per_ip) + [p["ip"] for p in ptrs
                                         if p["status"] != "ok"]),
                     key=lambda i: int(ipaddress.ip_address(i))):
        hs = per_ip.get(ip, [])
        p = ptr_map.get(ip, {})
        rows.append({
            "ip": ip,
            "classification": classify_ip(hs),
            "lists": sorted({h["rbl"] for h in hs}),
            "reasons": sorted({e["meaning"] for h in hs for e in h["entries"]}),
            "ptr": p.get("ptr", ""),
            "ptr_status": p.get("status", ""),
            "ptr_generic": p.get("status") == "generico",
            "fcrdns": p.get("fcrdns"),
        })

    # --- Plano ---
    plan = []
    if behavior_ips:
        plan.append({
            "kind": "behavior",
            "title": f"Conter a emissão — {len(behavior_ips)} IP(s)",
            "body": "Listagem comportamental: spam ou abuso efetivamente "
                    "observado. Não sai corrigindo rDNS e volta a listar depois "
                    "de qualquer remoção. Isole os hosts e bloqueie saída na "
                    "porta 25 no BNG, liberando só os MTAs autorizados.",
            "prefixes": collapse(behavior_ips),
        })

    # Zona nao delegada vem ANTES de qualquer coisa de PTR: sem delegacao,
    # criar registro nao produz efeito nenhum.
    nao_delegadas = [d for d in (delegation or []) if not d["delegated"]]
    lame = [d for d in (delegation or []) if d["delegated"] and not d["soa"]]
    if nao_delegadas:
        plan.append({
            "kind": "delegacao",
            "title": f"Delegar a zona reversa — {len(nao_delegadas)} zona(s)",
            "body": "A zona in-addr.arpa não existe na hierarquia do DNS. "
                    "Enquanto isso não for resolvido, criar PTR não produz "
                    "efeito: nenhum resolver do mundo sabe a quem perguntar. "
                    "Suba a zona em dois servidores autoritativos respondendo "
                    "SOA e só então delegue no registro.br ou pelo upstream. "
                    "Inverter a ordem gera lame delegation, pior que a ausência.",
            "prefixes": [d["zone"] for d in nao_delegadas],
        })
    elif lame:
        plan.append({
            "kind": "delegacao",
            "title": f"Corrigir lame delegation — {len(lame)} zona(s)",
            "body": "A zona tem NS apontado mas não devolve SOA. Cada consulta "
                    "reversa vira timeout, o que é pior que a ausência de "
                    "delegação. Confirme que os servidores delegados respondem "
                    "autoritativamente pela zona.",
            "prefixes": [d["zone"] for d in lame],
        })

    if no_ptr:
        plan.append({
            "kind": "rdns-ausente",
            "title": f"Criar PTR ausente — {len(no_ptr)} IP(s)",
            "body": ("Sem registro PTR nenhum. Alimenta RATS-NoPtr e o PBL "
                     "inferido pela Spamhaus."
                     + (" Faça DEPOIS da contenção: rDNS limpo aumenta a "
                        "entregabilidade, e antes de conter os emissores só faz "
                        "o spam chegar." if behavior_ips else "")),
            "prefixes": collapse([p["ip"] for p in no_ptr]),
        })

    if generic:
        ex = (f' Exemplo: {sample["ip"]} responde "{sample["ptr"]}" '
              f'({sample["issue"]}).' if sample else "")
        plan.append({
            "kind": "rdns-generico",
            "title": f"Renomear PTR genérico — {len(generic)} IP(s)",
            "body": ("O registro existe, mas a nomenclatura tem assinatura de "
                     "faixa dinâmica, então a Spamhaus infere espaço de usuário "
                     "final mesmo com PTR presente. Ter reverso não é o mesmo "
                     "que ter reverso aceitável." + ex +
                     " Para faixa de assinante em CGNAT isso está correto e "
                     "protege a rede: renomeie apenas o que é infraestrutura ou "
                     "cliente com serviço."),
            "prefixes": collapse([p["ip"] for p in generic]),
        })

    # Taxa de falha de FCrDNS: 100% e configuracao ausente, nao erro pontual.
    if broken:
        taxa = len(broken) / len(com_ptr) if com_ptr else 0
        sistemico = taxa >= 0.8
        plan.append({
            "kind": "fcrdns",
            "title": (f"Criar os registros A que faltam — {len(broken)} de "
                      f"{len(com_ptr)} PTR(s)"),
            "body": ((f"FALHA SISTEMÁTICA: {len(broken)} de {len(com_ptr)} "
                      f"({taxa:.0%}) dos PTRs não resolvem de volta para o IP. "
                      "Taxa nessa ordem não é erro pontual, é metade da "
                      "configuração: a zona reversa foi criada e a direta não. "
                      "Cada nome publicado no PTR precisa de um registro A "
                      "apontando de volta para o mesmo IP."
                      if sistemico else
                      f"{len(broken)} PTR(s) não resolvem de volta para o IP. "
                      "Falta o registro A correspondente.")
                     + " Muito MX rejeita só por isso."),
            "prefixes": collapse([p["ip"] for p in broken]),
        })

    plan.append({
        "kind": "delist",
        "title": "Só então pedir remoção",
        "body": ("Com evidência de remediação anexada. Remoção sem conter a emissão "
                 "falha e cada reincidência encurta o prazo até a listagem escalar "
                 "para o range ou o ASN." if behavior_ips else
                 "Com evidência de remediação anexada."),
        "prefixes": [],
    })

    return {
        "network": str(net),
        "total": total,
        "elapsed": elapsed,
        "listed": len(per_ip),
        "counts": {
            "behavior": len(behavior_ips),
            "policy": len(policy_ips),
            "clean": total - len(per_ip),
        },
        "rdns": {
            "no_ptr": len(no_ptr),
            "generic": len(generic),
            "with_ptr": len(com_ptr),
            "fcrdns_broken": len(broken),
            "fcrdns_rate": round(len(broken) / len(com_ptr), 3) if com_ptr else 0,
            "fcrdns_systemic": bool(com_ptr) and len(broken) / len(com_ptr) >= 0.8,
            "clean": len(clean_ptr),
            "audited": len(ptrs),
            "no_ptr_prefixes": collapse([p["ip"] for p in no_ptr]) if no_ptr else [],
            "generic_prefixes": collapse([p["ip"] for p in generic]) if generic else [],
            "sample_generic": ({"ip": sample["ip"], "ptr": sample["ptr"],
                                "issue": sample["issue"]} if sample else None),
        },
        "delegation": delegation or [],
        "lists": lists_out,
        "rows": rows,
        "plan": plan,
        "warnings": warnings,
        "diagnostics": diagnostics,
    }

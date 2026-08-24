"""
vrp_analyzer.py — Auditoria de configuração Huawei VRP voltada a blacklists.

Mesmas perguntas do analisador RouterOS, traduzidas para o modelo do VRP. Os
Achados usam a estrutura compartilhada, então a interface e o relatório não
precisam saber de qual fabricante veio o equipamento.

DIFERENÇAS QUE IMPORTAM EM RELAÇÃO AO ROUTEROS
----------------------------------------------
1. ACL não bloqueia nada sozinha. No RouterOS a regra de firewall já é o
   bloqueio; no VRP a ACL é só uma definição, e ela precisa ser aplicada com
   traffic-filter ou dentro de um traffic-policy/traffic-behavior. ACL correta
   e não aplicada é o falso positivo clássico de auditoria de VRP, e aqui isso
   é verificado explicitamente.

2. Ordem de regra é por número, não por posição no arquivo. 'rule 5 permit ip'
   anula qualquer deny de número maior, ainda que o deny apareça depois no
   texto. Também é verificado.

3. O CGNAT do VRP é determinístico quando há 'nat port-range': o mapeamento
   assinante/porta é calculável, como o netmap do RouterOS.
"""

from __future__ import annotations

import ipaddress
import re

from rsc_analyzer import Finding
from vrp_parser import (
    Block,
    VrpConfig,
    as_network,
    is_private,
    portas_da_regra,
)

CPE_ADMIN_TCP = [23, 2323, 22, 8291]
CPE_PROXY_TCP = [1080, 3128, 8118, 8080, 8888]
CPE_EXPLOIT_TCP = [5555, 37215, 52869, 49152]
CPE_AMPLIF_UDP = [53, 123, 161, 1900, 11211]

COMUNIDADES_PADRAO = {"public", "private", "admin", "cisco", "huawei", "default"}


# --------------------------------------------------------------------------
class Acl:
    """Uma ACL com as regras já ordenadas por número, que é a ordem de
    avaliação real do VRP."""

    def __init__(self, bloco: Block):
        self.bloco = bloco
        m = re.search(r"acl\s+(?:number\s+)?(?:name\s+)?(\S+)", bloco.text)
        self.nome = m.group(1) if m else "?"
        self.regras: list[tuple[int, str]] = []
        for c in bloco.children:
            if not c.text.startswith("rule"):
                continue
            mm = re.match(r"rule\s+(\d+)\s+(.*)", c.text)
            if mm:
                self.regras.append((int(mm.group(1)), mm.group(2)))
        self.regras.sort(key=lambda r: r[0])

    @property
    def permite_qualquer(self) -> tuple[bool, int | None]:
        """'rule N permit' sem origem nem protocolo libera tudo. Numa ACL de
        restricao (SNMP, VTY, gerencia) isso anula as regras anteriores e a
        protecao vira decorativa."""
        for num, corpo in self.regras:
            if re.fullmatch(r"permit(\s+ip)?", corpo.strip()):
                return True, num
        return False, None

    def bloqueia(self, porta: int, proto: str = "tcp") -> tuple[bool, str]:
        """Percorre na ordem de avaliação. Retorna (bloqueia, motivo).

        Um permit amplo antes do deny torna o deny inalcançável — é a causa
        mais comum de 'a regra existe mas não funciona' em VRP.
        """
        for num, corpo in self.regras:
            largo = bool(re.match(r"(permit|deny)\s+ip\b", corpo)) and \
                "port" not in corpo
            portas = portas_da_regra(corpo)
            casa_proto = proto in corpo or largo
            if corpo.startswith("permit") and largo:
                return False, (f"a regra {num} libera todo o tráfego antes de "
                               f"qualquer bloqueio da porta {porta}")
            if corpo.startswith("deny") and casa_proto and porta in portas:
                return True, f"regra {num}"
            if corpo.startswith("permit") and casa_proto and porta in portas:
                return False, f"a regra {num} libera a porta {porta}"
        return False, ""


def _acls(cfg: VrpConfig) -> dict[str, Acl]:
    out = {}
    for b in cfg.sections("acl "):
        a = Acl(b)
        out[a.nome] = a
    return out


def _aplicadas(cfg: VrpConfig) -> set[str]:
    """Nomes de ACL efetivamente aplicadas: traffic-filter em interface, ou
    referenciadas por um traffic-behavior/classifier em uso."""
    usadas: set[str] = set()
    for b in cfg.root.walk():
        t = b.text
        if m := re.search(r"traffic-filter\s+(?:inbound|outbound)\s+acl\s+"
                          r"(?:name\s+)?(\S+)", t):
            usadas.add(m.group(1))
        if m := re.search(r"if-match\s+acl\s+(?:name\s+)?(\S+)", t):
            usadas.add(m.group(1))
        if m := re.search(r"nat outbound\s+(\S+)", t):
            usadas.add(m.group(1))
    return usadas


def _policies(cfg: VrpConfig) -> tuple[set[str], set[str]]:
    """(policies aplicadas, policies definidas neste arquivo).

    'traffic-policy X inbound global-acl' aplica no equipamento inteiro, e nao
    aparece dentro de nenhuma interface. Se a policy foi aplicada mas nao esta
    definida no export, a auditoria nao consegue saber o que ela faz — e isso
    precisa ser dito, nao presumido.
    """
    aplicadas, definidas = set(), set()
    for b in cfg.root.walk():
        t = b.text
        if m := re.match(r"traffic-policy\s+(\S+)\s+(inbound|outbound)", t):
            aplicadas.add(m.group(1))
        elif m := re.match(r"traffic-policy\s+(\S+)$", t):
            definidas.add(m.group(1))
        elif m := re.match(r"traffic-policy\s+(\S+)\s", t) and b.children:
            definidas.add(m.group(1))
    return aplicadas, definidas


# --------------------------------------------------------------------------
class CgnatVrp:
    def __init__(self):
        self.public: set[str] = set()
        self.private: set[str] = set()
        self.instancias: list[str] = []
        self.port_range: int | None = None
        self.extended: int | None = None
        self.deterministic = False
        self.subscribers_per_ip = 0


def _cgnat(cfg: VrpConfig) -> CgnatVrp:
    cg = CgnatVrp()

    # Endereços do próprio equipamento não entram na faixa pública de CGNAT:
    # incluí-los numa regra de bloqueio de administração derruba o acesso.
    proprios: set[str] = set()
    for i in cfg.sections("interface"):
        for c in i.find("ip address"):
            w = c.words
            if len(w) >= 4:
                proprios.add(w[2])

    for inst in cfg.sections("nat instance"):
        nome = inst.words[2] if len(inst.words) > 2 else "?"
        cg.instancias.append(nome)
        for b in inst.walk():
            t = b.text
            # section <id> <inicio> <fim>  ou  section <id> <ip> <mascara>
            if m := re.match(r"section\s+\S+\s+(\d+\.\d+\.\d+\.\d+)\s+"
                             r"(\d+\.\d+\.\d+\.\d+)", t):
                a, bfim = m.group(1), m.group(2)
                if bfim.startswith("255."):
                    net = as_network(a, bfim)
                    if net and not is_private(net):
                        cg.public.add(str(net))
                else:
                    try:
                        faixa = ipaddress.summarize_address_range(
                            ipaddress.ip_address(a), ipaddress.ip_address(bfim))
                        for n in faixa:
                            if not is_private(n) and str(n.network_address) not in proprios:
                                cg.public.add(str(n))
                    except ValueError:
                        pass
            if m := re.match(r"nat port-range\s+(\d+)", t):
                cg.port_range = int(m.group(1))
            if m := re.search(r"extended-port-range\s+(\d+)", t):
                cg.extended = int(m.group(1))

    for i in cfg.sections("interface"):
        if not i.find("nat bind"):
            continue
        for c in i.find("ip address"):
            w = c.words
            if len(w) >= 4:
                net = as_network(w[2], w[3])
                if is_private(net):
                    cg.private.add(str(net))

    # Num BNG o CGNAT costuma ficar em outro equipamento, mas as faixas de
    # assinante estao aqui, nos 'ip pool ... bas local'. Sao elas que importam
    # para uRPF e para deteccao de emissor.
    for pool in cfg.sections("ip pool"):
        gw = pool.first("gateway")
        if gw and len(gw.words) >= 3:
            net = as_network(gw.words[1], gw.words[2])
            if is_private(net):
                cg.private.add(str(net))

    cg.deterministic = cg.port_range is not None
    if cg.port_range:
        # 65535 menos as portas reservadas, dividido pelas portas por assinante
        cg.subscribers_per_ip = max(1, (65535 - 1024) // cg.port_range)
    return cg


# --------------------------------------------------------------------------
def detect_role(cfg: VrpConfig) -> tuple[str, list[str]]:
    razoes, papeis = [], []
    bgp = cfg.sections("bgp ")
    if bgp:
        pares = sum(1 for b in bgp[0].walk() if b.text.startswith("peer ")
                    and "as-number" in b.text)
        razoes.append(f"BGP com {pares} vizinho(s)" if pares else "processo BGP")
        papeis.append("borda")
    nats = cfg.sections("nat instance")
    if nats:
        razoes.append(f"{len(nats)} instância(s) de CGNAT")
        papeis.append("cgnat")
    bas = [b for b in cfg.root.walk()
           if b.text.startswith(("bas", "interface Virtual-Template"))
           or "pppoe" in b.text.lower()]
    if bas or cfg.sections("radius-server"):
        razoes.append("terminação de assinante (BAS/PPPoE)")
        papeis.append("concentrador")
    return ("+".join(papeis) if papeis else "indefinido", razoes)


# --------------------------------------------------------------------------
def check_smtp(cfg: VrpConfig, acls: dict[str, Acl], usadas: set[str]) -> list[Finding]:
    bloqueia, problemas, evidencia = [], [], []

    for nome, acl in acls.items():
        ok, motivo = acl.bloqueia(25, "tcp")
        tem_regra = any(25 in portas_da_regra(c) for _, c in acl.regras)
        if ok and nome in usadas:
            bloqueia.append(nome)
            evidencia.append(f"ACL {nome}, {motivo}, aplicada")
        elif ok and nome not in usadas:
            problemas.append((nome, "não está aplicada em nenhuma interface "
                                    "nem em traffic-policy"))
        elif tem_regra and motivo:
            problemas.append((nome, motivo))

    if bloqueia:
        out = [Finding(
            id="smtp-ok", severity=0, role="qualquer",
            title="Porta 25 de saída já bloqueada e aplicada",
            evidence=evidencia,
            why="A contenção básica de SMTP direto está no lugar e a ACL está "
                "efetivamente vinculada.",
            rbl_link="Isso descarta SMTP direto como causa das listagens. "
                     "Havendo listagem comportamental, o vetor é outro — "
                     "tipicamente CPE atuando como proxy ou bot.",
            commands=[])]
        out += _achado_acl_inerte(problemas)
        return out

    if problemas:
        return _achado_acl_inerte(problemas, severidade=3) or []

    return [Finding(
        id="smtp-aberto", severity=3, role="cgnat+concentrador",
        title="Porta 25 de saída sem bloqueio",
        evidence=["Nenhuma ACL ativa nega tcp destination-port 25."],
        why="Assinante residencial não tem motivo para falar SMTP direto com MX "
            "de terceiro. Um CPE infectado usa essa porta para entregar spam "
            "direto, e o IP público do CGNAT é quem aparece como remetente.",
        rbl_link="É a causa direta de SBL, CSS e XBL na Spamhaus, e de listagem "
                 "em SpamCop e Barracuda. Diferente do PBL, essas não saem "
                 "corrigindo DNS: relistam enquanto a emissão continuar.",
        commands=[
            "!! ACL de saida. No VRP a ACL sozinha nao bloqueia nada:",
            "!! ela PRECISA ser aplicada na interface (passo 2).",
            "acl number 3500",
            " rule 5 permit tcp source <IP-DO-MTA-PROPRIO> 0 destination-port eq smtp",
            " rule 10 deny tcp destination-port eq smtp",
            " rule 15 permit ip",
            "quit",
            "!!",
            "!! Passo 2 - aplicar na interface que recebe o trafego do assinante.",
            "!! Troque pela interface real:",
            "interface <INTERFACE-DOS-CLIENTES>",
            " traffic-filter inbound acl 3500",
            "quit",
        ],
        risk="A regra 5 abre exceção para o MTA próprio: preencha o IP ou "
             "remova a linha. NÃO libere a 25 para assinante nem para relay de "
             "terceiro; cliente usa 587 com autenticação. Aplicar traffic-filter "
             "em interface de produção derruba sessões que casem com a regra.",
        manual=True,
    )]


def _achado_acl_inerte(problemas, severidade: int = 2) -> list[Finding]:
    if not problemas:
        return []
    return [Finding(
        id="acl-smtp-inerte", severity=severidade, role="borda",
        title=f"Regra de bloqueio da porta 25 sem efeito em {len(problemas)} ACL(s)",
        evidence=[f"ACL {n}: {m}" for n, m in problemas],
        why="A regra existe, mas não produz bloqueio. No VRP a ACL é apenas uma "
            "definição: sem traffic-filter na interface ou referência em "
            "traffic-policy ela não filtra nada. E a avaliação segue a ordem "
            "numérica das regras, então um permit de número menor torna o deny "
            "inalcançável mesmo aparecendo antes no arquivo.",
        rbl_link="Na prática o equipamento está na mesma situação de quem não "
                 "tem bloqueio nenhum: o SMTP direto continua saindo.",
        commands=[
            "!! Conferir onde cada ACL esta aplicada:",
            "!!   display acl all",
            "!!   display traffic-filter applied-record",
            "!!",
            "!! Se o problema for falta de aplicacao:",
            "!! interface <INTERFACE-DOS-CLIENTES>",
            "!!  traffic-filter inbound acl <NUMERO>",
            "!!",
            "!! Se o problema for ordem, renumere o deny para ANTES do permit",
            "!! amplo. No VRP nao ha 'mover': remova e recrie com numero menor.",
        ],
        risk="Aplicar traffic-filter em interface de produção passa a descartar "
             "tráfego imediatamente. Valide a ACL antes.",
        manual=True,
    )]


def check_cpe(cfg: VrpConfig, cg: CgnatVrp, acls: dict[str, Acl],
              usadas: set[str]) -> list[Finding]:
    if not cg.public:
        return []
    cobertas: set[int] = set()
    for nome, acl in acls.items():
        if nome not in usadas:
            continue
        for _, corpo in acl.regras:
            if corpo.startswith("deny"):
                cobertas |= portas_da_regra(corpo)

    grupos = [
        (CPE_ADMIN_TCP, "tcp", "telnet/ssh/winbox expostos na internet"),
        (CPE_PROXY_TCP, "tcp", "portas de proxy aberto"),
        (CPE_EXPLOIT_TCP, "tcp", "portas de exploração (Mirai/Huawei/UPnP)"),
        (CPE_AMPLIF_UDP, "udp", "resolver/NTP/SNMP abertos — amplificação"),
    ]
    faltando = [(p, proto, d) for p, proto, d in grupos
                if not set(p).issubset(cobertas)]
    if not faltando:
        return [Finding(
            id="cpe-protegido", severity=0, role="cgnat",
            title="Superfície de entrada dos CPEs já coberta",
            evidence=[f"Faixas públicas de CGNAT: {', '.join(sorted(cg.public))}"],
            why="As portas típicas de administração, proxy e amplificação já têm "
                "regra de bloqueio aplicada.",
            rbl_link="Reduz muito a chance de novas listagens em DroneBL e XBL.",
            commands=[])]

    cmds = [
        "!! Protecao de entrada nos CPEs, no sentido internet -> assinante.",
        "!! Comeca so REGISTRANDO (logging), sem descartar. Rode 24h, veja o",
        "!! que aparece em 'display acl 3600' e so entao troque para deny.",
        "!!",
        "acl number 3600",
    ]
    n = 5
    for portas, proto, desc in faltando:
        faltam = sorted(set(portas) - cobertas)
        for dest in sorted(cg.public):
            rede = ipaddress.ip_network(dest, strict=False)
            wildcard = str(ipaddress.ip_address(
                int(ipaddress.ip_address("255.255.255.255")) - int(rede.netmask)))
            lista = " ".join(str(p) for p in faltam[:8])
            cmds.append(f" !! {desc}")
            for p in faltam:
                cmds.append(f" rule {n} permit {proto} destination "
                            f"{rede.network_address} {wildcard} "
                            f"destination-port eq {p} logging")
                n += 5
            if len(lista.split()) < len(faltam):
                pass
    cmds += [
        " rule 9000 permit ip",
        "quit",
        "!!",
        "!! Aplicar na interface de TRANSITO, sentido de entrada:",
        "interface <INTERFACE-DE-UPLINK>",
        " traffic-filter inbound acl 3600",
        "quit",
        "!!",
        "!! Depois de observar, troque 'permit ... logging' por 'deny ...'",
    ]

    return [Finding(
        id="cpe-exposto", severity=3, role="cgnat",
        title=f"CPEs expostos: {len(faltando)} grupo(s) de portas sem bloqueio",
        evidence=[f"Faixas públicas do CGNAT: {', '.join(sorted(cg.public))}"]
                 + [f"Sem cobertura: {d} "
                    f"({','.join(str(p) for p in sorted(set(ports) - cobertas))})"
                    for ports, _, d in faltando],
        why="CPE com administração ou proxy alcançável da internet é comprometido "
            "em horas por varredura automatizada. Depois disso ele passa a "
            "retransmitir tráfego de terceiros usando o IP público do CGNAT como "
            "origem.",
        rbl_link="É o vetor típico de DroneBL (código 127.0.0.6) e de XBL na "
                 "Spamhaus. Não adianta corrigir rDNS: enquanto o CPE estiver "
                 "aberto, a listagem volta depois de cada remoção.",
        commands=cmds,
        risk="As regras saem como permit com logging, então não descartam nada. "
             "Antes de trocar para deny, confira se algum cliente usa 8080/8888 "
             "legitimamente: quem tem serviço publicado não deveria estar em "
             "CGNAT, deveria ter IP fixo.",
        manual=True,
    )]


def check_mgmt(cfg: VrpConfig, acls_ref: dict[str, Acl]) -> list[Finding]:
    out = []

    telnet = [b for b in cfg.root.walk()
              if re.match(r"telnet (ipv6 )?server enable", b.text)]
    if telnet:
        out.append(Finding(
            id="telnet-aberto", severity=3, role="borda",
            title="Servidor Telnet habilitado",
            evidence=[b.text for b in telnet],
            why="Telnet transmite credenciais em texto claro. Num roteador de "
                "borda isso expõe o acesso administrativo a qualquer um no "
                "caminho do tráfego.",
            rbl_link="Credencial capturada em equipamento de borda leva ao pior "
                     "cenário de listagem: o tráfego passa a poder ser originado "
                     "com o espaço IP inteiro do provedor, o que escala a "
                     "listagem para o ASN.",
            commands=["undo telnet server enable",
                      "undo telnet ipv6 server enable",
                      "!! use STELNET (SSH):",
                      "stelnet server enable"],
            risk="Confirme que o SSH está habilitado e testado ANTES de "
                 "desligar o telnet, sob risco de perder o acesso.",
        ))

    # SNMP com comunidade padrão
    for b in cfg.root.walk():
        if m := re.match(r"snmp-agent community (read|write) (?:cipher )?(\S+)",
                         b.text):
            modo, com = m.group(1), m.group(2)
            if com.lower() in COMUNIDADES_PADRAO:
                out.append(Finding(
                    id=f"snmp-padrao-{modo}", severity=3 if modo == "write" else 2,
                    role="borda",
                    title=f"Comunidade SNMP de {modo} com valor padrão",
                    evidence=[b.text],
                    why=("Comunidade de escrita padrão permite alterar a "
                         "configuração do equipamento remotamente."
                         if modo == "write" else
                         "Comunidade de leitura padrão expõe topologia, "
                         "interfaces e tabelas do equipamento."),
                    rbl_link="Leitura expõe o mapa da rede; escrita permite "
                             "redirecionar tráfego. Ambos levam ao "
                             "comprometimento que escala a listagem.",
                    commands=[
                        f"undo snmp-agent community {modo} {com}",
                        "!! Substitua por comunidade propria e restrinja a origem:",
                        "!! acl number 2001",
                        "!!  rule 5 permit source <REDE-DE-GERENCIA> 0.0.0.255",
                        "!!  rule 10 deny",
                        "!! quit",
                        f"!! snmp-agent community {modo} cipher <NOVA-COMUNIDADE> acl 2001",
                        "!! Melhor ainda: migrar para SNMPv3 com autenticacao.",
                    ],
                    risk="Trocar a comunidade quebra o monitoramento até o Zabbix "
                         "ou equivalente ser atualizado. Faça os dois na mesma "
                         "janela.",
                    manual=True,
                ))

    ftp = [b for b in cfg.root.walk()
           if re.match(r"(FTP|ftp) (ipv6 )?server enable", b.text)]
    if ftp:
        out.append(Finding(
            id="ftp-habilitado", severity=2, role="borda",
            title="Servidor FTP habilitado no equipamento",
            evidence=[b.text for b in ftp],
            why="FTP transmite credenciais e arquivos em texto claro. Em "
                "roteador de borda costuma ficar ligado por causa de uma "
                "atualização antiga de imagem e nunca mais ser desligado.",
            rbl_link="Mais uma via de acesso administrativo exposta. "
                     "Comprometimento do equipamento de borda escala a listagem "
                     "para além do bloco.",
            commands=["undo FTP server enable",
                      "undo FTP ipv6 server enable",
                      "!! Para transferir arquivo use SFTP sobre SSH:",
                      "sftp server enable"],
            risk="Confirme que nenhuma rotina de backup usa FTP antes de "
                 "desligar.",
            manual=True,
        ))

    if [b for b in cfg.root.walk() if re.match(r"http (secure-)?server enable",
                                               b.text)]:
        out.append(Finding(
            id="http-aberto", severity=2, role="borda",
            title="Servidor web de gerência habilitado",
            evidence=[b.text for b in cfg.root.walk()
                      if re.match(r"http (secure-)?server enable", b.text)],
            why="Interface web de administração ampla a superfície de ataque do "
                "equipamento sem necessidade operacional na maioria dos casos.",
            rbl_link="Mesmo risco das demais vias de administração expostas.",
            commands=["undo http server enable",
                      "undo http secure-server enable"],
            risk="Verifique se alguma automação usa a API web antes.",
            manual=True,
        ))

    # SNMP com ACL: verificar se a ACL de fato restringe
    snmp_acl = None
    for b in cfg.root.walk():
        if m := re.match(r"snmp-agent acl (?:name )?(\S+)", b.text):
            snmp_acl = m.group(1)
    if snmp_acl and snmp_acl in acls_ref:
        aberta, num = acls_ref[snmp_acl].permite_qualquer
        if aberta:
            out.append(Finding(
                id="snmp-acl-permissiva", severity=2, role="borda",
                title=f"ACL de SNMP ({snmp_acl}) termina liberando qualquer origem",
                evidence=[f"ACL {snmp_acl}: a regra {num} é um permit sem "
                          f"origem, então libera todo o resto",
                          "snmp-agent acl " + snmp_acl],
                why="A ACL restringe origens específicas nas primeiras regras, "
                    "mas a última libera qualquer endereço. Na avaliação por "
                    "ordem numérica, o efeito é o mesmo de não haver restrição "
                    "nenhuma: qualquer origem que alcance o equipamento consegue "
                    "consultar o SNMP.",
                rbl_link="SNMP acessível expõe topologia, interfaces e tabelas "
                         "de roteamento, que é o levantamento que antecede o "
                         "comprometimento do equipamento.",
                commands=[
                    f"acl name {snmp_acl}",
                    f" undo rule {num}",
                    " rule 1000 deny",
                    "quit",
                    "!!",
                    "!! Confira antes quais origens legitimas consultam o SNMP:",
                    "!!   display snmp-agent statistics",
                    "!! e garanta que todas estao nas regras de permit.",
                ],
                risk="Fechar a ACL derruba o monitoramento de qualquer coletor "
                     "cuja origem não esteja nas regras de permit. Levante os "
                     "coletores antes.",
                manual=True,
            ))

    # VTY sem ACL
    # 'user-interface maximum-vty 21' e um ajuste global e 'con 0' e o console
    # fisico: nenhum dos dois aceita ACL de origem. Sem esse filtro, os dois
    # apareciam como achado e o alerta virava ruido.
    vtys = [v for v in cfg.sections("user-interface vty")
            if re.match(r"user-interface vty\s+\d", v.text)]
    sem_acl = [v for v in vtys
               if not any(re.search(r"\bacl\b", c.text) for c in v.children)]
    if sem_acl:
        out.append(Finding(
            id="vty-sem-acl", severity=3, role="borda",
            title="Acesso administrativo (VTY) sem restrição de origem",
            evidence=[v.text for v in sem_acl],
            why="Sem ACL vinculada à VTY, o equipamento aceita tentativa de "
                "login administrativo de qualquer endereço que consiga alcançá-lo.",
            rbl_link="É a porta de entrada para o comprometimento do equipamento "
                     "de borda, cenário em que a listagem deixa de ser do bloco e "
                     "passa a ser do ASN.",
            commands=[
                "!! NAO aplique as cegas num equipamento remoto: ACL errada aqui",
                "!! tranca voce do lado de fora e exige acesso fisico/console.",
                "!!",
                "!! acl number 2000",
                "!!  rule 5 permit source <SUA-REDE-DE-GERENCIA> 0.0.0.255",
                "!!  rule 10 deny",
                "!! quit",
                "!! user-interface vty 0 4",
                "!!  acl 2000 inbound",
                "!!  protocol inbound ssh",
                "!! quit",
                "!!",
                "!! Faca em janela de manutencao, com acesso alternativo garantido.",
            ],
            risk="MUITO ALTO se aplicado às cegas. Por isso sai comentado.",
            manual=True,
        ))
    return out


def check_policy_opaca(cfg: VrpConfig) -> list[Finding]:
    aplicadas, definidas = _policies(cfg)
    opacas = sorted(aplicadas - definidas)
    if not opacas:
        return []
    return [Finding(
        id="policy-nao-visivel", severity=1, role="qualquer",
        title=f"{len(opacas)} traffic-policy aplicada sem definição no arquivo",
        evidence=[f"traffic-policy {n}" for n in opacas],
        why="A política está aplicada no equipamento, mas o classifier e o "
            "behavior que a compõem não aparecem neste export. Sem eles não há "
            "como saber o que ela filtra.",
        rbl_link="Se algum bloqueio relevante (porta 25, por exemplo) estiver "
                 "dentro dessa política, a auditoria pode estar apontando como "
                 "ausente algo que já existe. Vale conferir antes de aplicar as "
                 "correções sugeridas.",
        commands=[
            "!! Para ver o que a politica faz, no equipamento:",
            "!!   display traffic-policy user-defined " + opacas[0],
            "!!   display traffic-classifier user-defined",
            "!!   display traffic-behavior user-defined",
            "!!",
            "!! Se o export foi feito com 'display current-configuration',",
            "!! rode tambem os comandos acima e junte a saida ao arquivo.",
        ],
        manual=True,
    )]


def check_urpf(cfg: VrpConfig, cg: CgnatVrp) -> list[Finding]:
    if not cg.private:
        return []
    urpf = [b for b in cfg.root.walk() if re.search(r"\bip urpf\b", b.text)]
    if urpf:
        return [Finding(
            id="urpf-ok", severity=0, role="cgnat+concentrador",
            title="Verificação de origem (uRPF) ativa",
            evidence=[b.text.strip() for b in urpf[:4]],
            why="O equipamento descarta pacote cuja origem não seja compatível "
                "com a rota de retorno, o que impede o assinante de forjar "
                "endereço de origem.",
            rbl_link="Fecha a via de amplificação e reflexão, que é uma das "
                     "formas de o espaço IP do provedor entrar em bases de "
                     "reputação sem que haja spam envolvido.",
            commands=[])]
    return [Finding(
        id="urpf-ausente", severity=2, role="cgnat+concentrador",
        title="Sem verificação de origem (uRPF) nas interfaces de assinante",
        evidence=[f"Faixas de assinante: {', '.join(sorted(cg.private))}"],
        why="Sem uRPF, um assinante pode emitir pacote com endereço de origem "
            "forjado, e o equipamento encaminha normalmente.",
        rbl_link="Origem forjada é usada em ataques de amplificação e reflexão. "
                 "Participar disso lista o espaço IP do provedor em várias bases "
                 "de reputação, inclusive nas que se está tentando limpar.",
        commands=[
            "!! Aplicar na interface voltada ao assinante, nao no transito.",
            "interface <INTERFACE-DOS-CLIENTES>",
            " ip urpf strict",
            "quit",
            "!!",
            "!! Em topologia com caminho assimetrico use 'loose' no lugar de",
            "!! 'strict', senao trafego legitimo passa a ser descartado.",
        ],
        risk="uRPF strict em interface com roteamento assimétrico descarta "
             "tráfego válido. Confirme a topologia antes.",
        manual=True,
    )]


def check_cgnat(cfg: VrpConfig, cg: CgnatVrp) -> list[Finding]:
    if not cg.instancias:
        return []
    if cg.deterministic:
        ev = [f"{len(cg.instancias)} instância(s): {', '.join(cg.instancias)}",
              f"{cg.port_range} portas por assinante"
              + (f" (+{cg.extended} estendidas)" if cg.extended else ""),
              f"~{cg.subscribers_per_ip} assinantes por IP público"]
        if cg.public:
            ev.append(f"Público: {', '.join(sorted(cg.public))}")
        return [Finding(
            id="cgnat-deterministico", severity=0, role="cgnat",
            title="CGNAT determinístico — assinante identificável sem log",
            evidence=ev,
            why="Com faixa fixa de portas por assinante, o par endereço público "
                "mais porta de origem identifica o cliente sem depender de log "
                "de NAT.",
            rbl_link="É o que permite tratar um endereço listado: a lista informa "
                     "o IP público, e você chega ao assinante. Sem isso, a única "
                     "saída seria bloquear o IP público e derrubar todos os "
                     "clientes que o compartilham.",
            commands=[
                "!! Nenhuma acao necessaria. Para localizar o assinante:",
                "!!   display nat mapping instance <NOME> protocol tcp \\",
                "!!           global-address <IP-PUBLICO> global-port <PORTA>",
                "!! A porta vem do relatorio de abuso da lista.",
            ])]
    return [Finding(
        id="cgnat-sem-rastreio", severity=2, role="cgnat",
        title="CGNAT sem faixa de portas — assinante não rastreável",
        evidence=[f"Instâncias: {', '.join(cg.instancias)}",
                  "Nenhum 'nat port-range' configurado"],
        why="Sem alocação determinística de portas, não há como saber qual "
            "assinante usava o endereço público em dado momento, a menos que "
            "haja log de sessão, que é caro e raramente existe.",
        rbl_link="Quando a lista aponta o endereço público, não se chega ao "
                 "responsável. Resta bloquear o IP inteiro, derrubando todos os "
                 "clientes que o compartilham.",
        commands=[
            "!! Definir faixa de portas por assinante torna o mapeamento",
            "!! calculavel. O numero define quantos clientes cabem por IP",
            "!! publico: 512 portas -> ~126 assinantes por endereco.",
            "!!",
            "!! nat instance <NOME> id <N>",
            "!!  nat port-range 512 extended-port-range 512",
            "!! quit",
            "!!",
            "!! ATENCAO: alterar a alocacao derruba as sessoes ativas do",
            "!! CGNAT. Faca em janela de manutencao.",
        ],
        risk="Mudança de alocação de portas encerra todas as sessões em curso.",
        manual=True,
    )]


def check_rdns(cfg: VrpConfig, cg: CgnatVrp) -> list[Finding]:
    publicos = set(cg.public)
    for i in cfg.sections("interface"):
        for c in i.find("ip address"):
            w = c.words
            if len(w) >= 4:
                net = as_network(w[2], w[3])
                if net and not is_private(net):
                    publicos.add(str(net))
    for b in cfg.root.walk():
        if m := re.match(r"network\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)",
                         b.text):
            net = as_network(m.group(1), m.group(2))
            if net and not is_private(net):
                publicos.add(str(net))
    if not publicos:
        return []
    return [Finding(
        id="rdns-verificar", severity=2, role="borda",
        title="DNS reverso: verificar delegação das faixas públicas",
        evidence=[f"Faixas públicas encontradas: {', '.join(sorted(publicos)[:8])}"],
        why="O reverso não fica no equipamento, então não dá para auditar por "
            "aqui. Mas ausência de PTR é a causa mais comum de listagem em "
            "massa: atinge o bloco inteiro de uma vez.",
        rbl_link="Alimenta o PBL inferido pela Spamhaus e o RATS-NoPtr. Diferente "
                 "das listagens comportamentais, essas saem corrigindo DNS — mas "
                 "só depois de conter qualquer emissão ativa.",
        commands=[
            "!! Use a aba DNS deste sistema, que audita o bloco inteiro e",
            "!! verifica a delegacao das zonas in-addr.arpa.",
            "!!",
            "!! IMPORTANTE: reverso limpo AUMENTA a entregabilidade. Faca isto",
            "!! DEPOIS de conter os emissores, nunca antes.",
        ],
        manual=True,
    )]


# --------------------------------------------------------------------------
def analyze_vrp(cfg: VrpConfig) -> tuple[list[Finding], dict, str, list[str]]:
    acls = _acls(cfg)
    usadas = _aplicadas(cfg)
    cg = _cgnat(cfg)
    role, razoes = detect_role(cfg)

    findings: list[Finding] = []
    findings += check_smtp(cfg, acls, usadas)
    findings += check_cpe(cfg, cg, acls, usadas)
    findings += check_mgmt(cfg, acls)
    findings += check_policy_opaca(cfg)
    findings += check_urpf(cfg, cg)
    findings += check_cgnat(cfg, cg)
    findings += check_rdns(cfg, cg)
    findings.sort(key=lambda f: (-f.severity, f.id))

    cgnat_dict = {
        "public": sorted(cg.public),
        "private": sorted(cg.private),
        "deterministic": cg.deterministic,
        "rules": len(cg.instancias),
        "subscribers_per_ip": cg.subscribers_per_ip,
        # O VRP não expõe mapeamento estático como o netmap do RouterOS: a
        # tradução exige consultar o equipamento com 'display nat mapping'.
        "netmaps": [],
    }
    return findings, cgnat_dict, role, razoes

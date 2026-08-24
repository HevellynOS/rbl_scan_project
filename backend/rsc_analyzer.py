"""
rsc_analyzer.py — Auditoria de configuracao RouterOS voltada a blacklists.

A pergunta que este modulo responde: dado o export de um equipamento, o que
nele explica (ou vai causar) listagem em RBL, e o que fazer a respeito.

Estrutura: cada verificacao devolve zero ou mais Achados. Um Achado carrega
a evidencia encontrada no arquivo, a explicacao do porque aquilo importa, os
comandos de correcao e o risco de aplicar. O relatorio final e a soma disso.

Principio de projeto: NADA aqui gera comando habilitado por padrao quando o
comando pode derrubar cliente. Regra de risco alto sai como action=log ou
disabled=yes, com instrucao de promocao. Auditoria que causa incidente e pior
que auditoria nenhuma.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone

from rsc_parser import Config, Item, as_network, is_private, parse

SEV_LABEL = {3: "crítico", 2: "importante", 1: "recomendado", 0: "informativo"}

# Portas cuja exposicao em CPE e vetor conhecido de listagem
CPE_ADMIN_TCP = [23, 2323, 22, 8291]
CPE_PROXY_TCP = [1080, 3128, 8118, 8080, 8888]
CPE_EXPLOIT_TCP = [5555, 37215, 52869, 49152]
CPE_AMPLIF_UDP = [53, 123, 161, 1900, 11211]


@dataclass
class Finding:
    id: str
    severity: int
    role: str                    # borda | cgnat | concentrador | qualquer
    title: str
    evidence: list[str] = field(default_factory=list)
    why: str = ""
    rbl_link: str = ""           # ligacao explicita com listagem
    commands: list[str] = field(default_factory=list)
    risk: str = ""
    manual: bool = False         # exige decisao humana antes de aplicar

    def to_dict(self) -> dict:
        return {
            "id": self.id, "severity": self.severity, "role": self.role,
            "title": self.title, "evidence": self.evidence, "why": self.why,
            "rbl_link": self.rbl_link, "commands": self.commands,
            "risk": self.risk, "manual": self.manual,
            "severity_label": SEV_LABEL[self.severity],
        }


# --------------------------------------------------------------------------
# Deteccao de papel do equipamento
# --------------------------------------------------------------------------
def detect_role(cfg: Config) -> tuple[str, list[str]]:
    reasons = []
    has_bgp = cfg.has_path("/routing bgp connection")
    netmaps = [i for i in cfg.by_path("/ip firewall nat") if i.get("action") == "netmap"]
    has_pppoe = cfg.has_path("/interface pppoe-server server")
    has_radius = cfg.has_path("/radius")

    if has_bgp:
        reasons.append(f"{len(cfg.by_path('/routing bgp connection'))} sessão(ões) BGP")
    if netmaps:
        reasons.append(f"{len(netmaps)} regras netmap (CGNAT)")
    if has_pppoe:
        reasons.append("servidor PPPoE")
    if has_radius:
        reasons.append("cliente RADIUS")

    roles = []
    if has_bgp:
        roles.append("borda")
    if netmaps:
        roles.append("cgnat")
    if has_pppoe or has_radius:
        roles.append("concentrador")
    return ("+".join(roles) if roles else "indefinido", reasons)


# --------------------------------------------------------------------------
# Mapa do CGNAT
# --------------------------------------------------------------------------
@dataclass
class NetmapRule:
    """Um mapeamento netmap. Guardado individualmente porque e o que permite
    traduzir IP publico listado numa RBL para o assinante responsavel."""
    chain: str
    src_net: str
    dst_net: str
    port_lo: int | None
    port_hi: int | None
    protocol: str

    def subscriber_for(self, public) -> str | None:
        """netmap mapeia por deslocamento: o n-esimo endereco do prefixo de
        origem vira o n-esimo do prefixo de destino."""
        src = as_network(self.src_net)
        dst = as_network(self.dst_net)
        if src is None or dst is None or public not in dst:
            return None
        off = int(public) - int(dst.network_address)
        if off >= src.num_addresses:
            return None
        return str(ipaddress.ip_address(int(src.network_address) + off))


@dataclass
class CgnatMap:
    public_addrs: set[str] = field(default_factory=set)
    private_nets: set[str] = field(default_factory=set)
    deterministic: bool = False
    rules: int = 0
    port_blocks: int = 0
    subscribers_per_ip: int = 0
    netmaps: list[NetmapRule] = field(default_factory=list)


def map_cgnat(cfg: Config) -> CgnatMap:
    m = CgnatMap()

    # Enderecos do proprio equipamento. Precisam ficar FORA da lista de bloqueio:
    # incluir o loopback do roteador numa regra que derruba portas de
    # administracao e o caminho mais curto para perder o acesso a ele.
    own: set[str] = set()
    for i in cfg.by_path("/ip address"):
        n = as_network(i.get("address"))
        if n:
            own.add(str(n.network_address))

    for i in cfg.by_path("/ip firewall nat"):
        # Só netmap conta como CGNAT de assinante. src-nat avulso costuma ser
        # NAT de servico (VPN, teste) e nao deve entrar na lista de bloqueio.
        if i.get("action") != "netmap":
            continue
        m.rules += 1
        ports = i.get("to-ports")
        if ports:
            m.port_blocks += 1
        lo = hi = None
        if ports and "-" in ports:
            try:
                a, _, b = ports.partition("-")
                lo, hi = int(a), int(b)
            except ValueError:
                lo = hi = None
        if i.get("src-address") and i.get("to-addresses"):
            m.netmaps.append(NetmapRule(
                chain=i.get("chain"), src_net=i.get("src-address"),
                dst_net=i.get("to-addresses"), port_lo=lo, port_hi=hi,
                protocol=i.get("protocol", "")))

        dst = i.get("to-addresses")
        if dst:
            n = as_network(dst)
            if n and not is_private(n) and str(n.network_address) not in own:
                m.public_addrs.add(dst)

        src = i.get("src-address")
        if src:
            n = as_network(src)
            if is_private(n):
                # Agrupa /32 soltos no prefixo que os contem, senao um CGNAT
                # com uma regra por assinante gera centenas de entradas.
                m.private_nets.add(src if n.prefixlen < 32 else str(n.supernet(new_prefix=24)))

    m.deterministic = m.port_blocks > 0
    if m.public_addrs and m.private_nets:
        try:
            priv = sum(as_network(p).num_addresses for p in m.private_nets
                       if as_network(p))
            pub = sum(as_network(p).num_addresses for p in m.public_addrs
                      if as_network(p))
            m.subscribers_per_ip = int(priv / pub) if pub else 0
        except Exception:
            pass
    return m


# --------------------------------------------------------------------------
# Verificacoes
# --------------------------------------------------------------------------
def check_smtp(cfg: Config) -> list[Finding]:
    """Porta 25 saindo da rede e a causa numero um de SBL/CSS."""
    out = []
    blocks = []
    for path in ("/ip firewall raw", "/ip firewall filter"):
        for i in cfg.by_path(path):
            if i.get("action") != "drop" or i.disabled:
                continue
            if 25 in i.ports("dst-port"):
                blocks.append((path, i))

    if not blocks:
        out.append(Finding(
            id="smtp-aberto", severity=3, role="cgnat+concentrador",
            title="Porta 25 de saída sem bloqueio",
            evidence=["Nenhuma regra ativa derrubando dst-port 25."],
            why="Assinante residencial não tem motivo para falar SMTP direto com "
                "MX de terceiro. Um CPE infectado usa essa porta para entregar spam "
                "direto, e o IP público do CGNAT é quem aparece como remetente.",
            rbl_link="É a causa direta de SBL, CSS e XBL na Spamhaus, e de listagem "
                     "em SpamCop e Barracuda. Diferente do PBL, essas não saem "
                     "corrigindo DNS: relistam enquanto a emissão continuar.",
            commands=[
                "# Bloqueio de SMTP direto saindo da rede.",
                "# Cliente legítimo passa a usar submissão autenticada na 587.",
                "/ip firewall raw",
                'add chain=prerouting action=drop protocol=tcp dst-port=25 \\',
                '    comment="RBL: SMTP direto - assinante usa 587 autenticado"',
            ],
            risk="Se o provedor opera MTA próprio, crie a exceção ANTES desta regra "
                 "(veja o achado sobre MTA autorizado). Sem isso, o servidor de "
                 "e-mail de vocês para de enviar.",
        ))
        return out

    ev = [f"{p} linha {i.line_no}: {(i.comment or 'sem comentário')[:60]}"
          for p, i in blocks]

    # A regra existe. Ela quebra o MTA proprio?
    mta_lists = {i.get("list") for i in cfg.by_path("/ip firewall address-list")
                 if "MTA" in i.get("list", "").upper()}
    has_exception = any(
        i.get("action") == "accept" and 25 in i.ports("dst-port") and not i.disabled
        for i in cfg.by_path("/ip firewall raw") + cfg.by_path("/ip firewall filter"))

    src_blocked = any(25 in i.ports("src-port") and not i.disabled
                      for _, i in blocks
                      for _ in [1] if i.get("src-port"))
    src_blocked = any(
        i.get("action") == "drop" and not i.disabled and 25 in i.ports("src-port")
        for i in cfg.by_path("/ip firewall raw"))

    if mta_lists and not has_exception:
        out.append(Finding(
            id="mta-sem-excecao", severity=2, role="borda",
            title="Lista de MTA autorizado existe, mas nenhuma regra a utiliza",
            evidence=ev + [f"Listas encontradas: {', '.join(sorted(mta_lists))}"],
            why="A lista foi criada mas nenhuma regra a referencia. Ou ela é "
                "inofensiva e está sobrando, ou alguém pretendia liberar SMTP e "
                "não concluiu.",
            rbl_link="Relevante porque a liberação, se for feita errada, reabre "
                     "exatamente o caminho de spam que a regra da 25 fecha.",
            commands=[
                "# Só aplique se o provedor tem servidor de e-mail PRÓPRIO.",
                "# PASSO 1 - descubra o número da regra que bloqueia a 25:",
                "#   /ip firewall raw print where dst-port~\"25\"",
                "# PASSO 2 - troque o 7 pelo número real nas duas linhas:",
                "# /ip firewall raw add chain=prerouting action=accept protocol=tcp \\",
                '#     dst-port=25 src-address-list=MTA-AUTORIZADO place-before=7 \\',
                '#     comment="SMTP saindo do MTA próprio"',
                "# /ip firewall raw add chain=prerouting action=accept protocol=tcp \\",
                '#     dst-port=25 dst-address-list=MTA-AUTORIZADO place-before=7 \\',
                '#     comment="SMTP entrando no MTA próprio"',
            ],
            risk="NÃO libere a 25 para assinante, nem para o relay do provedor de "
                 "e-mail: isso devolve aos CPEs infectados o caminho de saída. "
                 "Cliente usa 587 com autenticação.",
            manual=True,
        ))

    if src_blocked:
        out.append(Finding(
            id="smtp-srcport", severity=1, role="borda",
            title="Bloqueio de src-port 25 impede receber e-mail",
            evidence=[f"/ip firewall raw linha {i.line_no}: src-port com 25"
                      for i in cfg.by_path("/ip firewall raw")
                      if i.get("action") == "drop" and 25 in i.ports("src-port")],
            why="Bloquear a porta 25 como ORIGEM derruba as respostas de MTAs "
                "remotos. Isso impede receber e-mail, não enviar — efeito "
                "diferente do pretendido pelo bloqueio de dst-port.",
            rbl_link="Não causa listagem, mas se o provedor montar MTA próprio "
                     "para responder a pedidos de remoção, ele não vai receber "
                     "as respostas.",
            commands=["# Nenhuma ação automática. Só relevante se houver MTA próprio."],
            risk="Manter como está é aceitável se o provedor não opera e-mail.",
            manual=True,
        ))

    if not out:
        out.append(Finding(
            id="smtp-ok", severity=0, role="qualquer",
            title="Porta 25 de saída já bloqueada",
            evidence=ev,
            why="A contenção básica de SMTP direto está no lugar.",
            rbl_link="Isso descarta SMTP direto como causa das listagens. Se ainda "
                     "há XBL, CSS ou listagem comportamental, o vetor é outro — "
                     "tipicamente CPE atuando como proxy ou bot.",
            commands=[],
        ))
    return out


def check_cpe_exposure(cfg: Config, cg: CgnatMap) -> list[Finding]:
    """Superficie de entrada nos CPEs: vetor de DroneBL e XBL."""
    if not cg.public_addrs:
        return []

    covered: set[int] = set()
    for i in cfg.by_path("/ip firewall raw") + cfg.by_path("/ip firewall filter"):
        if i.get("action") != "drop" or i.disabled:
            continue
        covered |= i.ports("dst-port")

    groups = [
        ("admin", CPE_ADMIN_TCP, "tcp", "telnet/ssh/winbox expostos na internet",
         "CPE-ADMIN"),
        ("proxy", CPE_PROXY_TCP, "tcp", "portas de proxy aberto", "CPE-PROXY"),
        ("exploit", CPE_EXPLOIT_TCP, "tcp",
         "portas de exploração conhecidas (Mirai/Huawei/UPnP)", "CPE-EXPLOIT"),
        ("amplif", CPE_AMPLIF_UDP, "udp",
         "resolver/NTP/SNMP abertos — amplificação", "CPE-AMPLIF"),
    ]

    missing = [(name, ports, proto, desc, prefix)
               for name, ports, proto, desc, prefix in groups
               if not set(ports).issubset(covered)]
    if not missing:
        return [Finding(
            id="cpe-protegido", severity=0, role="cgnat",
            title="Superfície de entrada dos CPEs já coberta",
            evidence=[f"Faixas públicas de CGNAT: {', '.join(sorted(cg.public_addrs))}"],
            why="As portas típicas de administração, proxy e amplificação já têm "
                "regra de bloqueio.",
            rbl_link="Reduz muito a chance de novas listagens em DroneBL e XBL.",
            commands=[],
        )]

    cmds = [
        "# Protecao de entrada nos CPEs.",
        "# Saem como action=log DE PROPOSITO. Rode 24h, veja o que aparece em",
        "#   /log print where message~\"CPE-\"",
        "# e so entao promova para drop:",
        "#   /ip firewall raw set [find where comment~\"RBL-CPE:\"] action=drop",
        "",
        "/ip firewall address-list",
    ]
    for addr in sorted(cg.public_addrs):
        cmds.append(f'add address={addr} list=CGNAT-PUBLICO \\')
        cmds.append('    comment="RBL: faixa publica do CGNAT"')
    cmds += ["", "/ip firewall raw"]
    for name, ports, proto, desc, prefix in missing:
        faltando = sorted(set(ports) - covered)
        cmds.append(f'add chain=prerouting action=log log-prefix="{prefix}" \\')
        cmds.append(f'    protocol={proto} in-interface-list=LINKS \\')
        cmds.append(f'    dst-address-list=CGNAT-PUBLICO \\')
        cmds.append(f'    dst-port={",".join(str(p) for p in faltando)} \\')
        cmds.append(f'    comment="RBL-CPE: {desc}"')

    return [Finding(
        id="cpe-exposto", severity=3, role="cgnat",
        title=f"CPEs expostos: {len(missing)} grupo(s) de portas sem bloqueio",
        evidence=[f"Faixas públicas do CGNAT: {', '.join(sorted(cg.public_addrs))}"]
                 + [f"Sem cobertura: {desc} "
                    f"({','.join(str(p) for p in sorted(set(ports) - covered))})"
                    for _, ports, _, desc, _ in missing],
        why="CPE com administração ou proxy alcançável da internet é comprometido "
            "em questão de horas por varredura automatizada. Depois disso ele "
            "passa a retransmitir tráfego de terceiros usando o IP público do "
            "CGNAT como origem.",
        rbl_link="É o vetor típico de DroneBL (código 127.0.0.6) e de XBL na "
                 "Spamhaus. Diferente do PBL, não adianta corrigir rDNS: enquanto "
                 "o CPE estiver aberto, a listagem volta depois de cada remoção.",
        commands=cmds,
        risk="Aplicar como log é inofensivo. Antes de promover para drop, confira "
             "se algum cliente usa 8080/8888 legitimamente — quem tem serviço "
             "publicado não deveria estar em CGNAT, deveria ter IP fixo.",
    )]


def check_tr069(cfg: Config, cg: CgnatMap) -> list[Finding]:
    if not cg.public_addrs:
        return []
    covered: set[int] = set()
    for i in cfg.by_path("/ip firewall raw"):
        if i.get("action") == "drop" and not i.disabled:
            covered |= i.ports("dst-port")
    if 7547 in covered:
        return []
    return [Finding(
        id="tr069-exposto", severity=2, role="cgnat",
        title="TR-069 (7547) alcançável de fora",
        evidence=["Nenhuma regra ativa cobre a porta 7547 na faixa do CGNAT."],
        why="A porta de auto-configuração dos CPEs, exposta, permite que terceiros "
            "tentem provisionar o equipamento do assinante.",
        rbl_link="CPE reprovisionado por terceiro vira bot; é uma das entradas para "
                 "XBL e DroneBL.",
        commands=[
            "# HABILITAR SOMENTE SE A ACS DE VOCES FOR INTERNA.",
            "# Se a ACS fica fora da rede, esta regra quebra o provisionamento",
            "# de TODOS os CPEs. Confirme antes de trocar disabled=yes por no.",
            "/ip firewall raw",
            'add chain=prerouting action=drop protocol=tcp dst-port=7547,58000 \\',
            '    in-interface-list=LINKS dst-address-list=CGNAT-PUBLICO \\',
            '    disabled=yes comment="RBL-CPE: TR-069 - so se a ACS for interna"',
        ],
        risk="Alto se a ACS for externa. Por isso sai desabilitada.",
        manual=True,
    )]


def check_input_chain(cfg: Config) -> list[Finding]:
    """Roteador sem chain=input e o proprio equipamento exposto."""
    inputs = [i for i in cfg.by_path("/ip firewall filter")
              if i.get("chain") == "input" and not i.disabled]
    if inputs:
        return []
    return [Finding(
        id="sem-input", severity=3, role="borda",
        title="Nenhuma regra em chain=input — o equipamento está sem firewall próprio",
        evidence=[f"{len(cfg.by_path('/ip firewall filter'))} regras em filter, "
                  f"nenhuma em chain=input."],
        why="Todo o firewall existente protege o tráfego que ATRAVESSA o roteador. "
            "Nada protege o roteador em si: os serviços de administração ficam "
            "expostos conforme o que estiver em /ip service.",
        rbl_link="Um roteador de borda comprometido é o pior caso possível — ele "
                 "pode ser usado para retransmitir tráfego de terceiros com o "
                 "espaço IP inteiro do provedor, o que escala a listagem do bloco "
                 "para o ASN.",
        commands=[
            "# NAO aplique isto por copiar e colar num equipamento remoto.",
            "# Regra de input errada tranca voce do lado de fora.",
            "#",
            "# Ordem segura, em janela de manutencao e com acesso alternativo:",
            "#   1. Restrinja /ip service primeiro (reversivel pelo console serial)",
            "#   2. Verifique que ainda consegue acessar",
            "#   3. So entao monte a chain=input",
            "#",
            "# Esqueleto, com a faixa de gerencia a preencher:",
            "# /ip firewall address-list",
            '# add address=<SUA-FAIXA-DE-GERENCIA> list=GERENCIA \\',
            '#     comment="rede de onde o NOC administra"',
            "# /ip firewall filter",
            '# add chain=input action=accept connection-state=established,related',
            '# add chain=input action=drop connection-state=invalid',
            '# add chain=input action=accept src-address-list=GERENCIA',
            '# add chain=input action=accept protocol=icmp limit=10,20:packet',
            "# (regras dos protocolos que o equipamento precisa: BGP, OSPF, RADIUS)",
            '# add chain=input action=drop in-interface-list=LINKS',
        ],
        risk="MUITO ALTO se aplicado às cegas. Por isso sai comentado.",
        manual=True,
    )]


def check_services(cfg: Config) -> list[Finding]:
    out = []
    for i in cfg.by_path("/ip service"):
        m = re.match(r"^set\s+(\S+)", i.raw)
        name = m.group(1) if m else "?"
        if i.get("disabled") == "yes":
            continue
        addr = i.get("address", "")
        aberto = addr in ("", "0.0.0.0/0") or "0.0.0.0/0" in addr

        if name == "telnet" and aberto:
            out.append(Finding(
                id="telnet-aberto", severity=3, role="borda",
                title="Telnet habilitado e aberto para a internet",
                evidence=[i.raw.strip()],
                why="Telnet transmite credenciais em texto claro. Porta alta não "
                    "protege: varredura encontra em minutos.",
                rbl_link="Credencial capturada em roteador de borda leva ao pior "
                         "cenário de listagem — o ASN inteiro.",
                commands=["/ip service set telnet disabled=yes"],
                risk="Baixo: o SSH continua disponível. Confirme que ninguém usa "
                     "telnet em automação antes.",
            ))
        elif name in ("ssh", "winbox", "api", "www", "www-ssl", "ftp") and aberto:
            out.append(Finding(
                id=f"servico-aberto-{name}", severity=2, role="borda",
                title=f"Serviço {name} acessível de qualquer origem",
                evidence=[i.raw.strip()],
                why="Administração exposta à internet inteira. Porta não-padrão "
                    "reduz ruído de varredura, mas não é controle de acesso.",
                rbl_link="Mesmo risco do telnet: comprometimento do equipamento de "
                         "borda escala a listagem para além do bloco.",
                commands=[
                    f"# Restrinja à faixa de gerência do NOC.",
                    f"# TESTE EM JANELA DE MANUTENCAO com acesso alternativo",
                    f"# garantido: faixa errada = perda do equipamento.",
                    f"# /ip service set {name} address=<SUA-FAIXA-DE-GERENCIA>",
                ],
                risk="ALTO se a faixa estiver errada. Por isso sai comentado.",
                manual=True,
            ))

    ssh_fw = [i for i in cfg.by_path("/ip ssh")
              if i.get("forwarding-enabled") in ("remote", "both", "yes")]
    if ssh_fw:
        out.append(Finding(
            id="ssh-forwarding", severity=3, role="borda",
            title="Encaminhamento SSH remoto habilitado",
            evidence=[i.raw.strip() for i in ssh_fw],
            why="Com forwarding remoto, quem tiver uma credencial SSH consegue abrir "
                "uma porta de escuta no roteador que reencaminha tráfego para "
                "qualquer destino. O equipamento vira relay.",
            rbl_link="É literalmente o comportamento que DroneBL e XBL detectam. "
                     "Um relay na borda emite com o espaço IP do provedor.",
            commands=[
                "# Desabilite se ninguém da equipe usa túnel SSH pelo roteador.",
                "/ip ssh set forwarding-enabled=no",
            ],
            risk="Quebra quem depender de túnel SSH por este equipamento. Confirme "
                 "com a equipe antes.",
        ))

    pptp = [i for i in cfg.by_path("/interface pptp-server server")
            if i.get("enabled") == "yes"]
    if pptp:
        out.append(Finding(
            id="pptp-ativo", severity=2, role="borda",
            title="Servidor PPTP habilitado",
            evidence=[i.raw.strip() for i in pptp],
            why="PPTP tem falhas conhecidas de criptografia e o próprio RouterOS "
                "marca como inseguro no export.",
            rbl_link="Credencial de VPN comprometida dá acesso interno à rede, com "
                     "as mesmas consequências do acesso administrativo.",
            commands=[
                "# Migre os usuários para L2TP/IPsec antes de desligar.",
                "# /interface pptp-server server set enabled=no",
            ],
            risk="Desliga o acesso VPN de quem ainda usa PPTP. Migre primeiro.",
            manual=True,
        ))
    return out


def check_detection(cfg: Config, cg: CgnatMap) -> list[Finding]:
    """Sem deteccao, voce descobre a infeccao pela RBL — tarde demais."""
    has = any(i.get("action") == "add-src-to-address-list" and not i.disabled
              for i in cfg.by_path("/ip firewall filter"))
    if has or not cg.private_nets:
        return []
    faixas = sorted(cg.private_nets)
    alvo = faixas[0]
    return [Finding(
        id="sem-deteccao", severity=1, role="cgnat",
        title="Nenhuma detecção de surto de conexões por assinante",
        evidence=[f"Faixas privadas em CGNAT: {', '.join(faixas[:6])}"
                  + (f" (+{len(faixas)-6})" if len(faixas) > 6 else "")],
        why="Sem detecção própria, a primeira notícia de que um assinante está "
            "infectado vem da RBL — quando o dano à reputação do bloco já ocorreu.",
        rbl_link="Detectar antes permite tratar o assinante e pedir remoção com "
                 "evidência de remediação, que é o que as listas exigem.",
        commands=[
            "# Marca assinante que abre conexoes muito acima do normal.",
            "# NAO bloqueia nada: so alimenta uma address-list para triagem.",
            "#",
            "# Limiar inicial folgado de proposito. Comecar apertado marca",
            "# cliente de torrent junto com bot e a lista vira lixo.",
            "# Deixe rodar 24h, veja quem caiu, e so entao aperte:",
            "#   /ip firewall address-list print where list=CGNAT-SURTO",
            "#",
            "# CUSTO DE CPU: roda em todo connection-state=new da faixa.",
            "# Acompanhe /system resource print nos primeiros minutos.",
            "/ip firewall filter",
            f'add chain=forward action=jump jump-target=DETECTA-SURTO \\',
            f'    protocol=tcp connection-state=new src-address={alvo} \\',
            f'    comment="RBL: inicio deteccao de surto"',
            'add chain=DETECTA-SURTO action=return \\',
            '    dst-limit=100,200,src-address/1m \\',
            '    comment="RBL: taxa normal - segue o fluxo"',
            'add chain=DETECTA-SURTO action=add-src-to-address-list \\',
            '    address-list=CGNAT-SURTO address-list-timeout=12h \\',
            '    comment="RBL: acima da taxa - so marca"',
            'add chain=DETECTA-SURTO action=log log-prefix="SURTO-CGNAT" \\',
            '    limit=5,10:packet comment="RBL: log limitado"',
        ],
        risk="Não bloqueia tráfego. O custo é CPU no plano de controle. Se houver "
             "mais faixas privadas além da primeira, replique o jump para cada uma.",
    )]


def check_cgnat_traceability(cfg: Config, cg: CgnatMap) -> list[Finding]:
    if not cg.rules:
        return []
    if cg.deterministic:
        return [Finding(
            id="cgnat-deterministico", severity=0, role="cgnat",
            title="CGNAT determinístico — assinante identificável sem log",
            evidence=[f"{cg.rules} regras netmap, {cg.port_blocks} com faixa de portas",
                      f"Público: {', '.join(sorted(cg.public_addrs)[:4])}",
                      f"~{cg.subscribers_per_ip} assinantes por IP público"
                      if cg.subscribers_per_ip else ""],
            why="O mapeamento por faixa de portas é fixo, então IP público mais porta "
                "de origem identificam o assinante sem precisar de log de NAT.",
            rbl_link="É o que permite tratar um IP listado: a lista informa o IP "
                     "público, e você chega ao assinante exato. Sem isso, a única "
                     "saída seria bloquear o IP público e derrubar centenas de "
                     "clientes junto.",
            commands=[
                "# Nenhuma acao necessaria. Para traduzir um IP listado:",
                "#   python cgnat_lookup.py <backup.rsc> --ip <publico> --porta <porta>",
                "# A porta vem do relatorio de abuso da lista.",
            ],
        )]
    return [Finding(
        id="cgnat-sem-rastreio", severity=2, role="cgnat",
        title="CGNAT sem faixa de portas — assinante não rastreável",
        evidence=[f"{cg.rules} regras de tradução, nenhuma com to-ports"],
        why="Sem mapeamento determinístico por porta, não há como saber qual "
            "assinante estava usando o IP público em dado momento, a menos que "
            "haja log de conexões — que é caro e raramente existe.",
        rbl_link="Quando a lista aponta o IP público, você não consegue chegar ao "
                 "responsável. Resta bloquear o IP inteiro, derrubando todos os "
                 "clientes que compartilham ele.",
        commands=[
            "# Reestruturar CGNAT para netmap com faixas de porta e um trabalho",
            "# de planejamento, nao um comando. Envolve dimensionar quantos",
            "# assinantes por IP publico e quantas portas por assinante.",
            "# Fora do escopo de correcao automatica.",
        ],
        risk="Mudança estrutural de NAT derruba todas as sessões ativas.",
        manual=True,
    )]


def check_dns_recursion(cfg: Config) -> list[Finding]:
    dns = cfg.by_path("/ip dns")
    if not any(i.get("allow-remote-requests") == "yes" for i in dns):
        return []
    covered = any(i.get("action") == "drop" and not i.disabled and 53 in i.ports("dst-port")
                  for i in cfg.by_path("/ip firewall raw"))
    if covered:
        return []
    return [Finding(
        id="dns-aberto", severity=3, role="borda",
        title="Resolver DNS respondendo a consultas remotas sem filtro",
        evidence=[i.raw.strip() for i in dns if i.get("allow-remote-requests") == "yes"],
        why="Resolver aberto é usado em ataques de amplificação: o atacante forja a "
            "origem e a resposta, muito maior que a pergunta, vai para a vítima.",
        rbl_link="Participar de amplificação lista o IP em várias RBLs — inclusive "
                 "nas que vocês estão tentando limpar.",
        commands=[
            "# Feche a recursao para fora, mantendo para a rede interna.",
            "/ip firewall raw",
            'add chain=prerouting action=drop protocol=udp dst-port=53 \\',
            '    in-interface-list=LINKS \\',
            '    comment="RBL: recursao DNS aberta - amplificacao"',
            'add chain=prerouting action=drop protocol=tcp dst-port=53 \\',
            '    in-interface-list=LINKS \\',
            '    comment="RBL: recursao DNS aberta - amplificacao"',
        ],
        risk="Se algum cliente aponta o DNS diretamente para o IP público do "
             "roteador de fora da rede, ele para de resolver.",
    )]


def check_rdns(cfg: Config) -> list[Finding]:
    """rDNS nao esta no .rsc, mas o PBL depende dele — e o mais comum de todos."""
    publicos = set()
    for i in cfg.by_path("/ip address"):
        n = as_network(i.get("address"))
        if n and not is_private(n):
            publicos.add(str(n))
    for i in cfg.by_path("/ip firewall nat"):
        n = as_network(i.get("to-addresses"))
        if n and not is_private(n):
            publicos.add(str(n))
    if not publicos:
        return []
    return [Finding(
        id="rdns-verificar", severity=2, role="borda",
        title="DNS reverso: verificar delegação das faixas públicas",
        evidence=[f"Faixas públicas encontradas: {', '.join(sorted(publicos)[:8])}"],
        why="O reverso não fica no equipamento, então não dá para auditar por aqui. "
            "Mas ausência de PTR é a causa mais comum de listagem em massa: ela "
            "atinge o bloco inteiro de uma vez.",
        rbl_link="Alimenta o PBL inferido pela Spamhaus (127.0.0.11) e o RATS-NoPtr. "
                 "Diferente das listagens comportamentais, essas SAEM corrigindo "
                 "DNS — mas só depois de conter qualquer emissão ativa.",
        commands=[
            "# Verificacao fora do equipamento. Para cada /24:",
            "#   nslookup -type=NS <terceiro>.<segundo>.<primeiro>.in-addr.arpa",
            "#",
            "# NXDOMAIN = a zona reversa nao existe na hierarquia. Criar PTRs",
            "# nao adianta: ninguem consegue perguntar por eles.",
            "#",
            "# Ordem obrigatoria:",
            "#   1. Suba a zona em DOIS servidores AUTORITATIVOS respondendo SOA",
            "#      (recursivo nao serve; DNS do RouterOS nao serve)",
            "#   2. Só entao delegue no registro.br / upstream",
            "#   3. Inverter isso gera lame delegation, pior que a ausencia",
            "#",
            "# IMPORTANTE: reverso limpo AUMENTA a entregabilidade. Faca isto",
            "# DEPOIS de conter os emissores, nunca antes.",
        ],
        manual=True,
    )]


# --------------------------------------------------------------------------
def _analisa_routeros(name: str, text: str) -> dict:
    cfg = parse(text, name)
    role, reasons = detect_role(cfg)
    cg = map_cgnat(cfg)

    findings: list[Finding] = []
    findings += check_smtp(cfg)
    findings += check_cpe_exposure(cfg, cg)
    findings += check_tr069(cfg, cg)
    findings += check_input_chain(cfg)
    findings += check_services(cfg)
    findings += check_dns_recursion(cfg)
    findings += check_detection(cfg, cg)
    findings += check_cgnat_traceability(cfg, cg)
    findings += check_rdns(cfg)
    findings.sort(key=lambda f: (-f.severity, f.id))

    return {
        "file": name,
        "vendor": "MikroTik",
        "identity": cfg.identity or "(sem identity)",
        "model": cfg.model,
        "version": cfg.version,
        "role": role,
        "role_reasons": reasons,
        "rules": len(cfg.items),
        "cgnat": {
            "public": sorted(cg.public_addrs),
            "private": sorted(cg.private_nets),
            "deterministic": cg.deterministic,
            "rules": cg.rules,
            "subscribers_per_ip": cg.subscribers_per_ip,
            # Necessario para o cruzamento com a varredura: e o que traduz
            # IP publico listado numa RBL para o assinante responsavel.
            "netmaps": [asdict(n) for n in cg.netmaps],
        },
        "findings": [f.to_dict() for f in findings],
        "_findings": findings,
    }


def _analisa_vrp(name: str, text: str) -> dict:
    from vrp_analyzer import analyze_vrp
    from vrp_parser import parse as parse_vrp

    cfg = parse_vrp(text, name)
    findings, cgnat, role, razoes = analyze_vrp(cfg)
    return {
        "file": name,
        "vendor": "Huawei",
        "identity": cfg.sysname or "(sem sysname)",
        "model": cfg.model,
        "version": cfg.version,
        "role": role,
        "role_reasons": razoes,
        "rules": sum(1 for _ in cfg.all_lines()),
        "cgnat": cgnat,
        "findings": [f.to_dict() for f in findings],
        "_findings": findings,
    }


def analyze(files: list[tuple[str, str]]) -> dict:
    """files = [(nome, conteudo)]. Detecta o fabricante e delega."""
    from vrp_parser import parece_vrp

    devices = []
    all_findings: list[tuple[str, Finding]] = []

    for name, text in files:
        d = _analisa_vrp(name, text) if parece_vrp(text) \
            else _analisa_routeros(name, text)
        findings = d.pop("_findings")

        devices.append({
            **d,
            "counts": {
                "critico": sum(1 for f in findings if f.severity == 3),
                "importante": sum(1 for f in findings if f.severity == 2),
                "recomendado": sum(1 for f in findings if f.severity == 1),
                "informativo": sum(1 for f in findings if f.severity == 0),
            },
        })
        all_findings += [(d["identity"], f) for f in findings]

    return {
        "generated": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "devices": devices,
        "totals": {
            "critico": sum(1 for _, f in all_findings if f.severity == 3),
            "importante": sum(1 for _, f in all_findings if f.severity == 2),
            "recomendado": sum(1 for _, f in all_findings if f.severity == 1),
            "informativo": sum(1 for _, f in all_findings if f.severity == 0),
            "manual": sum(1 for _, f in all_findings if f.manual),
        },
        "rsc": build_rsc(devices),
        "report": build_report(devices),
    }


def build_rsc(devices: list[dict]) -> str:
    """Script de correcao, um bloco por equipamento, na ordem de aplicacao."""
    L = [
        "# " + "=" * 70,
        "#  SCRIPT DE CORRECAO — gerado pelo RBL Scan",
        f"#  {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
        "# " + "=" * 70,
        "#",
        "#  LEIA ANTES DE APLICAR",
        "#",
        "#  1. NAO importe este arquivo inteiro de uma vez num equipamento em",
        "#     producao. Aplique um bloco por vez, conferindo o efeito.",
        "#",
        "#  2. Linhas comentadas com # exigem decisao sua (faixa de gerencia,",
        "#     numero de regra, confirmacao com a equipe). Elas NAO viram",
        "#     configuracao se voce importar o arquivo — de proposito.",
        "#",
        "#  3. Regras de risco saem como action=log ou disabled=yes. Promova",
        "#     para drop depois de observar, nao antes.",
        "#",
        "#  4. Para aplicar sem depender do buffer do terminal:",
        "#       /import file-name=<este-arquivo>.rsc",
        "#     Colar no terminal embaralha linhas longas.",
        "#",
        "#  ORDEM RECOMENDADA, independente do que este arquivo contem:",
        "#    a) conter emissao (SMTP, superficie de CPE)",
        "#    b) fechar administracao do proprio equipamento",
        "#    c) corrigir DNS reverso",
        "#    d) so entao pedir remocao nas listas",
        "#",
        "#  Reverso limpo AUMENTA a entregabilidade. Fazer (c) antes de (a)",
        "#  apenas faz o spam chegar melhor.",
        "#",
    ]
    fabricantes = {d.get("vendor", "?") for d in devices}
    if len(fabricantes) > 1:
        L += [
            "#  ATENCAO: este arquivo cobre equipamentos de FABRICANTES",
            f"#  DIFERENTES ({', '.join(sorted(fabricantes))}). Cada bloco usa a",
            "#  sintaxe do seu proprio equipamento e NAO e intercambiavel.",
            "#  Confira o cabecalho de cada bloco antes de aplicar.",
            "#",
        ]
    for d in devices:
        huawei = d.get("vendor") == "Huawei"
        marca = "!!" if huawei else "#"
        L += ["", f"{marca} " + "=" * 70,
              f"{marca}  {d['identity']}   [{d['role']}]",
              f"{marca}  {d.get('vendor', '?')} {d['model']} {d['version']}".rstrip(),
              f"{marca}  origem: {d['file']}",
              f"{marca} " + "=" * 70]
        if huawei:
            L += [
                "!!",
                "!!  SINTAXE HUAWEI VRP. Nao cole este bloco num RouterOS.",
                "!!  Linhas iniciadas por '!!' sao EXPLICACAO, nao comandos:",
                "!!  no VRP o '#' e separador de secao e daria erro no CLI.",
                "!!  Cole apenas as linhas de comando, a partir de system-view.",
                "!!",
            ]
        aplicaveis = [f for f in d["findings"] if f["commands"]]
        if not aplicaveis:
            L.append(f"{marca} Nenhuma correcao aplicavel neste equipamento.")
            continue
        for f in aplicaveis:
            L += ["",
                  f"{marca} --- [{f['severity_label'].upper()}] {f['title']} ---",
                  f"{marca} {f['why'][:200]}"]
            if f["risk"]:
                L.append(f"{marca} RISCO: {f['risk'][:200]}")
            if f["manual"]:
                L.append(f"{marca} EXIGE DECISAO SUA - revise antes de aplicar.")
            L += f["commands"]
    L += ["", "# " + "=" * 70, "#  FIM", "# " + "=" * 70]
    return "\n".join(L)


def build_report(devices: list[dict]) -> str:
    """Explicacao em markdown, para acompanhar o script."""
    L = ["# Análise de configuração — causas de listagem em RBL", "",
         f"Gerado em {datetime.now(timezone.utc).strftime('%d/%m/%Y %H:%M UTC')}.", "",
         "## Como ler",
         "",
         "As listagens se dividem em duas naturezas, e o tratamento é oposto:",
         "",
         "- **Política** (PBL, RATS-NoPtr): derivam de configuração, tipicamente "
         "ausência de DNS reverso. Saem corrigindo DNS.",
         "- **Comportamento** (SBL, CSS, XBL, DroneBL, Barracuda, SpamCop): há "
         "emissão real acontecendo. **Não saem corrigindo DNS** e relistam depois "
         "de qualquer remoção.",
         "",
         "Corrigir o reverso antes de conter a emissão é contraproducente: rDNS "
         "limpo aumenta a entregabilidade, então o spam passa a chegar melhor.",
         ""]
    for d in devices:
        so = ("RouterOS" if d.get("vendor") == "MikroTik"
              else "VRP" if d.get("vendor") == "Huawei" else "")
        L += [f"## {d['identity']}", "",
              f"Arquivo `{d['file']}` · {d.get('vendor', '')} {d['model']} · "
              f"{so} {d['version']} · {d['rules']} linhas de configuração",
              "",
              f"**Papel detectado:** {d['role']}"
              + (f" ({', '.join(d['role_reasons'])})" if d["role_reasons"] else ""),
              ""]
        cg = d["cgnat"]
        if cg["rules"]:
            L += [f"**CGNAT:** {cg['rules']} regras de tradução, "
                  f"{'determinístico por faixa de portas' if cg['deterministic'] else 'sem mapeamento por porta'}."]
            if cg["public"]:
                L.append(f"Endereços públicos de saída: `{'`, `'.join(cg['public'][:6])}`")
            if cg["subscribers_per_ip"]:
                L.append(f"Aproximadamente {cg['subscribers_per_ip']} assinantes por "
                         f"IP público — por isso bloquear um IP listado atinge "
                         f"centenas de clientes.")
            L.append("")

        c = d["counts"]
        L += [f"**Achados:** {c['critico']} críticos, {c['importante']} importantes, "
              f"{c['recomendado']} recomendados, {c['informativo']} informativos.", ""]

        for f in d["findings"]:
            L += [f"### [{f['severity_label']}] {f['title']}", ""]
            if f["evidence"]:
                L += ["**O que foi encontrado:**", ""]
                L += [f"- `{e}`" for e in f["evidence"] if e]
                L.append("")
            if f["why"]:
                L += ["**Por que importa:** " + f["why"], ""]
            if f["rbl_link"]:
                L += ["**Ligação com as listagens:** " + f["rbl_link"], ""]
            if f["risk"]:
                L += ["**Risco de aplicar:** " + f["risk"], ""]
            if f["manual"]:
                L += ["> Este item exige decisão sua. Os comandos saem comentados "
                      "no script e não viram configuração se você importar o "
                      "arquivo.", ""]
    L += ["## Depois de aplicar", "",
          "1. Rode a varredura do bloco novamente e compare a contagem de "
          "emissão observada.",
          "2. Só peça remoção quando a emissão estiver em zero e o reverso no ar.",
          "3. Anexe a evidência de remediação ao pedido: as listas pedem isso, e "
          "remoção repetida sem correção encurta o prazo até a listagem escalar "
          "para o range ou o ASN.", ""]
    return "\n".join(L)

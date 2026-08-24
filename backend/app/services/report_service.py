"""
dns_report.py — Relatório executivo de DNS reverso, em PDF.

Destino: empresas, parceiros e terceiros (o provedor de DNS do cliente, o
upstream que aloca o bloco, o time de TI de quem reclamou de entrega). Gente
que precisa entender o cenário e agir, mas que não é do NOC.

O QUE ENTRA E O QUE NÃO ENTRA
-----------------------------
A regra é uma só: o relatório usa apenas dado que já é público na internet ou
agregado a ponto de não expor a rede.

ENTRA (público e verificável por qualquer um):
  - o bloco CIDR e os prefixos agregados
  - contagem de PTR ausente, genérico e sem forward-confirm
  - estado da delegação das zonas in-addr.arpa e os NS declarados
  - um exemplo de PTR, porque sem ele "genérico" não significa nada para
    quem vai corrigir
  - quantas listas de reputação afetam o bloco, agregado

NÃO ENTRA (exposição de rede ou de cliente):
  - faixas privadas de CGNAT e mapeamento de assinante: é a topologia interna
  - identidade, modelo e versão de equipamento vindos do .rsc: quem lê não
    precisa, e serve de mapa para quem quiser atacar
  - IPs individuais com listagem comportamental: enumerar endereço por
    endereço equivale a publicar onde estão as máquinas comprometidas do
    cliente. O relatório informa a QUANTIDADE e o efeito, sem apontar quais
  - IP do resolver recursivo, chave DQS, qualquer credencial

Se um campo novo for adicionado ao relatório, ele precisa passar por essa
mesma pergunta antes.
"""

from __future__ import annotations

import ipaddress
import os
import sys
from datetime import datetime, timezone
from io import BytesIO

from reportlab.lib import colors
from reportlab.lib.enums import TA_JUSTIFY
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    BaseDocTemplate,
    Frame,
    Image,
    KeepTogether,
    PageTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
)

# Identidade visual
NAVY = colors.HexColor("#0C283C")
INK = colors.HexColor("#12171F")
MUTED = colors.HexColor("#5D6875")
RULE = colors.HexColor("#C6CED7")
BAD = colors.HexColor("#B8362A")
WARN = colors.HexColor("#B08414")
OK = colors.HexColor("#2C7355")
SOFT = colors.HexColor("#F2F5F8")


def _hex(c) -> str:
    """reportlab exige o '#' dentro do markup de Paragraph."""
    return "#" + c.hexval()[2:]


def _logo_path() -> str | None:
    from app.core.config import assets_dir
    p = os.path.join(assets_dir(), "logo-pronetworks.png")
    return p if os.path.exists(p) else None


def _styles():
    ss = getSampleStyleSheet()
    return {
        "h1": ParagraphStyle("h1", parent=ss["Title"], fontName="Helvetica-Bold",
                             fontSize=17, leading=21, textColor=NAVY,
                             alignment=0, spaceAfter=2),
        "sub": ParagraphStyle("sub", fontName="Helvetica", fontSize=9.5,
                              leading=13, textColor=MUTED, spaceAfter=14),
        "h2": ParagraphStyle("h2", fontName="Helvetica-Bold", fontSize=11,
                             leading=14, textColor=NAVY, spaceBefore=16,
                             spaceAfter=6),
        "h3": ParagraphStyle("h3", fontName="Helvetica-Bold", fontSize=9.5,
                             leading=12, textColor=INK, spaceBefore=9,
                             spaceAfter=3),
        "p": ParagraphStyle("p", fontName="Helvetica", fontSize=9.5, leading=14,
                            textColor=INK, alignment=TA_JUSTIFY, spaceAfter=7),
        "small": ParagraphStyle("small", fontName="Helvetica", fontSize=8,
                                leading=11, textColor=MUTED, spaceAfter=4),
        "mono": ParagraphStyle("mono", fontName="Courier", fontSize=8.5,
                               leading=12, textColor=INK, spaceAfter=6),
        "cell": ParagraphStyle("cell", fontName="Helvetica", fontSize=8.5,
                               leading=11.5, textColor=INK),
        "cellb": ParagraphStyle("cellb", fontName="Helvetica-Bold", fontSize=8.5,
                                leading=11.5, textColor=INK),
    }


def _dominio_de(ptr: str, ip: str = "") -> str:
    """Deriva o domínio a partir do PTR de exemplo, descartando os rótulos
    iniciais que repetem o endereço. Cobre os dois formatos usuais:
    '45.232.243.1.forteinternet.net.br' e '45-232-243-1.dinamico.prov.net.br'.
    """
    import re
    if not ptr:
        return "provedor.net.br"
    labels = [l for l in ptr.rstrip(".").split(".") if l]
    digitos = re.sub(r"\D", "", ip)

    def repete_o_ip(label: str) -> bool:
        if label.isdigit():
            return True
        so_num = re.sub(r"\D", "", label)
        # rótulo formado só por números e separadores, contendo os octetos
        if so_num and re.fullmatch(r"[\d\-_x]+", label, re.I):
            return not digitos or so_num in digitos or digitos in so_num
        return False

    while len(labels) > 2 and repete_o_ip(labels[0]):
        labels.pop(0)
    # descarta um rótulo descritivo de faixa dinâmica logo após os números
    if len(labels) > 2 and re.fullmatch(
            r"(din[aâ]mico|dynamic|dyn|dsl|adsl|pppoe|pool|cgnat|client[es]?|"
            r"cliente|user|customer)", labels[0], re.I):
        labels.pop(0)
    return ".".join(labels) if len(labels) >= 2 else ptr


def _quantidade(titulo: str) -> str:
    """Extrai o primeiro número do título gerado pela ferramenta."""
    import re
    m = re.search(r"(\d+)", titulo)
    return m.group(1) if m else ""


def _collapse(ips: list[str], limite: int = 8) -> str:
    if not ips:
        return "—"
    nets = [ipaddress.ip_network(i, strict=False) for i in ips]
    col = [str(n) for n in ipaddress.collapse_addresses(nets)]
    if len(col) <= limite:
        return "  ".join(col)
    return "  ".join(col[:limite]) + f"  (+{len(col) - limite})"


class _Doc(BaseDocTemplate):
    """Rodapé com paginação e uma faixa navy no topo de cada página."""

    def __init__(self, buf, **kw):
        super().__init__(buf, pagesize=A4, leftMargin=20 * mm, rightMargin=20 * mm,
                         topMargin=18 * mm, bottomMargin=20 * mm, **kw)
        frame = Frame(self.leftMargin, self.bottomMargin, self.width, self.height,
                      id="corpo")
        self.addPageTemplates([PageTemplate(id="padrao", frames=[frame],
                                            onPage=self._decor)])
        self.rodape = ""

    def _decor(self, canvas, doc):
        canvas.saveState()
        canvas.setFillColor(NAVY)
        canvas.rect(0, A4[1] - 4 * mm, A4[0], 4 * mm, stroke=0, fill=1)
        canvas.setFont("Helvetica", 7.5)
        canvas.setFillColor(MUTED)
        canvas.drawString(20 * mm, 12 * mm, self.rodape)
        canvas.drawRightString(A4[0] - 20 * mm, 12 * mm, f"Página {doc.page}")
        canvas.setStrokeColor(RULE)
        canvas.setLineWidth(0.5)
        canvas.line(20 * mm, 15 * mm, A4[0] - 20 * mm, 15 * mm)
        canvas.restoreState()


def build_pdf(
    report: dict,
    cliente: str = "",
    preparado_por: str = "",
    observacoes: str = "",
    dominio_exemplo: str = "",
) -> bytes:
    S = _styles()
    r = report["rdns"]
    net = report["network"]
    total = report["total"]
    agora = datetime.now(timezone.utc).astimezone()

    delegation = report.get("delegation", [])
    nao_deleg = [d for d in delegation if not d["delegated"]]
    lame = [d for d in delegation if d["delegated"] and not d["soa"]]

    com_ptr = r["with_ptr"]
    sem_ptr = r["no_ptr"]
    generico = r["generic"]
    quebrado = r["fcrdns_broken"]
    correto = r["clean"]
    comportamental = report["counts"]["behavior"]

    story: list = []

    # ---------------- Cabeçalho ----------------
    logo = _logo_path()
    if logo:
        img = Image(logo, width=52 * mm, height=52 / 5.18 * mm)
        img.hAlign = "LEFT"
        story.append(img)
        story.append(Spacer(1, 12))

    story.append(Paragraph("Diagnóstico de DNS reverso", S["h1"]))
    linha = f"Bloco {net} &nbsp;·&nbsp; {total} endereços auditados"
    if cliente.strip():
        linha = f"{cliente.strip()} &nbsp;·&nbsp; " + linha
    story.append(Paragraph(linha + f"<br/>Emitido em {agora.strftime('%d/%m/%Y às %H:%M')}",
                           S["sub"]))

    # ---------------- Situação em uma frase ----------------
    if nao_deleg:
        veredito = (
            f"A zona de DNS reverso do bloco {net} não está delegada. Enquanto "
            f"isso não for resolvido, nenhum registro criado será visível na "
            f"internet, e o bloco continuará sendo tratado como espaço sem "
            f"identificação pelos servidores de e-mail do mundo inteiro."
        )
        tom = BAD
    elif sem_ptr == total:
        veredito = (
            f"Nenhum dos {total} endereços do bloco {net} possui registro de DNS "
            f"reverso. Servidores de e-mail e sistemas de reputação tratam espaço "
            f"sem reverso como faixa residencial não identificada, o que restringe "
            f"a entrega de mensagens e o acesso a serviços que validam a origem."
        )
        tom = BAD
    elif sem_ptr or quebrado or generico:
        partes = []
        if sem_ptr:
            partes.append(f"{sem_ptr} sem registro")
        if generico:
            partes.append(f"{generico} com nomenclatura inadequada")
        if quebrado:
            partes.append(f"{quebrado} sem confirmação direta")
        veredito = (
            f"O DNS reverso do bloco {net} está parcialmente configurado: de "
            f"{total} endereços, {', '.join(partes)}. A configuração existente "
            f"não é suficiente para que o bloco seja reconhecido como "
            f"infraestrutura legítima."
        )
        tom = WARN
    else:
        veredito = (
            f"O DNS reverso do bloco {net} está corretamente configurado nos "
            f"{total} endereços auditados."
        )
        tom = OK

    caixa = Table([[Paragraph(f"<b>Situação</b><br/>{veredito}", S["cell"])]],
                  colWidths=[170 * mm])
    caixa.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), SOFT),
        ("LINEBEFORE", (0, 0), (0, -1), 3, tom),
        ("LEFTPADDING", (0, 0), (-1, -1), 10),
        ("RIGHTPADDING", (0, 0), (-1, -1), 10),
        ("TOPPADDING", (0, 0), (-1, -1), 9),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 9),
    ]))
    story.append(caixa)

    # ---------------- O que é e por que importa ----------------
    story.append(Paragraph("O que é DNS reverso, e por que ele decide a entrega",
                           S["h2"]))
    story.append(Paragraph(
        "O DNS comum responde qual endereço IP corresponde a um nome. O DNS "
        "reverso responde o contrário: dado um endereço IP, qual é o nome dele. "
        "É a checagem mais barata que existe para distinguir infraestrutura de "
        "uma máquina doméstica qualquer, e por isso praticamente todo servidor "
        "de e-mail do mundo a executa antes de aceitar uma conexão.", S["p"]))
    story.append(Paragraph(
        "Endereço sem nome reverso tem a mesma assinatura de um computador "
        "residencial infectado tentando entregar mensagem diretamente. O "
        "destinatário não tem como diferenciar um do outro, então trata os dois "
        "da mesma forma: rejeita, atrasa ou classifica como não confiável. O "
        "efeito não se limita a e-mail. Sistemas que validam a origem da conexão, "
        "inclusive portais corporativos e de governo, usam o mesmo sinal.", S["p"]))
    story.append(Paragraph(
        "Existem três formas distintas de o reverso falhar, e cada uma exige uma "
        "correção diferente. Confundi-las é o motivo mais comum de o problema "
        "persistir depois de uma tentativa de conserto.", S["p"]))

    # ---------------- Quadro de auditoria ----------------
    story.append(Paragraph("Resultado da auditoria", S["h2"]))

    def linha_tab(rot, val, den, desc, cor):
        return [
            Paragraph(f"<b>{rot}</b>", S["cellb"]),
            Paragraph(f"<font color='{_hex(cor)}'><b>{val}</b></font> "
                      f"<font size='7' color='#5D6875'>de {den}</font>", S["cell"]),
            Paragraph(desc, S["cell"]),
        ]

    dados = [[
        Paragraph("<b>Verificação</b>", S["cellb"]),
        Paragraph("<b>Resultado</b>", S["cellb"]),
        Paragraph("<b>O que significa</b>", S["cellb"]),
    ]]
    dados.append(linha_tab(
        "Sem registro reverso", sem_ptr, total,
        "O endereço não tem nome nenhum associado. É o caso mais grave: o "
        "destinatário não consegue identificar de onde a conexão vem.",
        BAD if sem_ptr else OK))
    dados.append(linha_tab(
        "Nome inadequado", generico, total,
        "O registro existe, mas o nome embute o próprio endereço IP. Esse padrão "
        "é a assinatura de faixa residencial dinâmica: os sistemas de reputação o "
        "classificam como espaço de usuário final mesmo havendo registro.",
        WARN if generico else OK))
    dados.append(linha_tab(
        "Sem confirmação direta", quebrado, com_ptr,
        "O nome publicado no reverso não aponta de volta para o mesmo endereço. "
        "A verificação em duas vias falha, e muitos servidores rejeitam a conexão "
        "apenas por isso.",
        BAD if quebrado else OK))
    dados.append(linha_tab(
        "Configuração correta", correto, total,
        "Nome próprio, sem o endereço embutido, e com a correspondência de ida e "
        "volta confirmada.",
        OK if correto else WARN))

    # O cabeçalho branco precisa da cor no próprio Paragraph, senão o texto
    # sai preto sobre a faixa navy.
    dados[0] = [Paragraph(f"<font color='white'><b>{t}</b></font>", S["cellb"])
                for t in ("Verificação", "Resultado", "O que significa")]
    tab = Table(dados, colWidths=[38 * mm, 25 * mm, 107 * mm], repeatRows=1)
    tab.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), NAVY),
        ("LINEBELOW", (0, 0), (-1, -1), 0.4, RULE),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 7),
        ("RIGHTPADDING", (0, 0), (-1, -1), 7),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    story.append(tab)

    if r.get("fcrdns_systemic"):
        story.append(Spacer(1, 8))
        story.append(Paragraph(
            f"<b>Observação.</b> A falha de confirmação direta atinge "
            f"{int(r['fcrdns_rate'] * 100)}% dos registros existentes. Uma taxa "
            f"nessa ordem não é resultado de erros pontuais: indica que a zona "
            f"reversa foi criada sem a contrapartida na zona direta. Cada nome "
            f"publicado no reverso precisa de um registro correspondente "
            f"apontando de volta para o mesmo endereço.", S["p"]))

    amostra = r.get("sample_generic")
    if amostra:
        story.append(Paragraph(
            f"Exemplo do padrão inadequado encontrado: o endereço "
            f"<font face='Courier'>{amostra['ip']}</font> responde com o nome "
            f"<font face='Courier'>{amostra['ptr']}</font>. O nome repete os "
            f"números do próprio endereço, que é exatamente o formato usado em "
            f"faixas residenciais dinâmicas.", S["p"]))

    # ---------------- Como fica quando está correto ----------------
    # Seção acrescentada depois de o provedor de DNS observar, com razão, que
    # o documento dizia o que estava errado sem mostrar o alvo. Diagnóstico sem
    # exemplo do resultado esperado não é acionável.
    dominio = dominio_exemplo.strip() or _dominio_de(
        (amostra or {}).get("ptr", ""), (amostra or {}).get("ip", ""))
    o = net.split("/")[0].split(".")
    ip_srv = f"{o[0]}.{o[1]}.{o[2]}.1"
    ip_pool = f"{o[0]}.{o[1]}.{o[2]}.64"
    atual = (amostra or {}).get("ptr") or f"{ip_srv}.{dominio}"

    story.append(Paragraph("Como fica quando está correto", S["h2"]))
    story.append(Paragraph(
        "Cada endereço precisa de <b>dois</b> registros, não de um. O primeiro "
        "informa qual é o nome daquele endereço; o segundo confirma que aquele "
        "nome realmente pertence a ele. Servidores de destino consultam os dois "
        "e recusam a conexão quando apenas um existe. É exatamente esse segundo "
        "registro que falta hoje em todos os nomes já publicados neste bloco.",
        S["p"]))

    ex = [[Paragraph("<font color='white'><b>Situação</b></font>", S["cellb"]),
           Paragraph("<font color='white'><b>Registro do endereço para o nome</b></font>",
                     S["cellb"]),
           Paragraph("<font color='white'><b>Registro do nome para o endereço</b></font>",
                     S["cellb"])]]
    ex.append([
        Paragraph(f"<font color='{_hex(BAD)}'><b>Como está hoje</b></font>", S["cell"]),
        Paragraph(f"<font face='Courier' size='7.5'>{ip_srv} &rarr; {atual}</font>",
                  S["cell"]),
        Paragraph(f"<font color='{_hex(BAD)}'>não existe</font>", S["cell"]),
    ])
    ex.append([
        Paragraph("<b>Endereço de infraestrutura</b><br/>"
                  "<font size='7.5' color='#5D6875'>equipamentos, servidores, "
                  "clientes com serviço publicado</font>", S["cell"]),
        Paragraph(f"<font face='Courier' size='7.5'>{ip_srv} &rarr; "
                  f"gw-pop01.{dominio}</font>", S["cell"]),
        Paragraph(f"<font face='Courier' size='7.5'>gw-pop01.{dominio} &rarr; "
                  f"{ip_srv}</font>", S["cell"]),
    ])
    ex.append([
        Paragraph("<b>Faixa de assinante</b><br/>"
                  "<font size='7.5' color='#5D6875'>endereços compartilhados ou "
                  "distribuídos a clientes finais</font>", S["cell"]),
        Paragraph(f"<font face='Courier' size='7.5'>{ip_pool} &rarr; "
                  f"cliente-64.pop01.{dominio}</font>", S["cell"]),
        Paragraph(f"<font face='Courier' size='7.5'>cliente-64.pop01.{dominio} "
                  f"&rarr; {ip_pool}</font>", S["cell"]),
    ])
    te = Table(ex, colWidths=[42 * mm, 64 * mm, 64 * mm], repeatRows=1)
    te.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), NAVY),
        ("LINEBELOW", (0, 0), (-1, -1), 0.4, RULE),
        ("BACKGROUND", (0, 1), (-1, 1), colors.HexColor("#FBF0EE")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 7),
        ("RIGHTPADDING", (0, 0), (-1, -1), 7),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    story.append(te)
    story.append(Spacer(1, 9))

    story.append(Paragraph("Por que os dois casos são tratados de forma diferente",
                           S["h3"]))
    story.append(Paragraph(
        "Endereço de infraestrutura precisa de nome que descreva a função, sem "
        "repetir os números do endereço. É o que permite ao destinatário "
        "reconhecer que a conexão vem de um servidor operado por uma empresa, e "
        "não de um computador residencial.", S["p"]))
    story.append(Paragraph(
        "Faixa de assinante é o caso oposto, e aqui há um mal-entendido comum "
        "que convém esclarecer: nome padronizado que identifica o espaço como "
        "sendo de cliente final <b>não é defeito</b>. Pelo contrário, é o "
        "comportamento desejado. Ele sinaliza aos servidores de destino que "
        "aquele espaço não deve entregar mensagem diretamente, o que protege a "
        "reputação do bloco inteiro quando o equipamento de um assinante é "
        "comprometido. O cliente que precisa enviar mensagem usa o servidor de "
        "envio do provedor, com autenticação, e não é afetado.", S["p"]))
    story.append(Paragraph(
        "O que vale para os dois casos, sem exceção, é a correspondência de ida "
        "e volta. Publicar o nome sem o registro que aponta de volta deixa a "
        "configuração pela metade, e é a situação encontrada hoje em todos os "
        "nomes já existentes neste bloco.", S["p"]))
    story.append(Paragraph(
        "Os nomes usados acima são ilustrativos. A relação completa dos "
        "endereços, com a separação entre faixa de assinante e endereço de "
        "serviço, acompanha este documento em arquivo próprio, pronto para ser "
        "carregado no servidor de DNS.", S["small"]))

    # ---------------- Delegação ----------------
    if delegation:
        story.append(Paragraph("Delegação das zonas reversas", S["h2"]))
        story.append(Paragraph(
            "Criar registros reversos só produz efeito se a zona correspondente "
            "estiver delegada na hierarquia mundial do DNS, ou seja, se houver "
            "servidores oficialmente apontados como responsáveis por ela. Sem "
            "essa delegação, os registros existem apenas localmente e nenhum "
            "servidor da internet consegue consultá-los.", S["p"]))

        dz = [[Paragraph("<font color='white'><b>Zona</b></font>", S["cellb"]),
               Paragraph("<font color='white'><b>Situação</b></font>", S["cellb"]),
               Paragraph("<font color='white'><b>Servidores responsáveis</b></font>",
                         S["cellb"])]]
        for d in delegation:
            if d["delegated"] and d["soa"]:
                sit, cor = "Delegada", OK
            elif d["delegated"]:
                sit, cor = "Delegação incompleta", WARN
            else:
                sit, cor = "Não delegada", BAD
            dz.append([
                Paragraph(f"<font face='Courier'>{d['zone']}</font>", S["cell"]),
                Paragraph(f"<font color='{_hex(cor)}'><b>{sit}</b></font>",
                          S["cell"]),
                Paragraph(", ".join(d["ns"]) or "nenhum declarado", S["cell"]),
            ])
        tz = Table(dz, colWidths=[52 * mm, 38 * mm, 80 * mm], repeatRows=1)
        tz.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), NAVY),
            ("LINEBELOW", (0, 0), (-1, -1), 0.4, RULE),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 7),
            ("RIGHTPADDING", (0, 0), (-1, -1), 7),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ]))
        story.append(tz)

        if nao_deleg:
            story.append(Spacer(1, 8))
            story.append(Paragraph(
                "<b>Este é o item de maior prioridade.</b> Enquanto a delegação "
                "não existir, qualquer registro criado permanece invisível para "
                "a internet, e o esforço de configuração não produz resultado "
                "algum.", S["p"]))
        if lame:
            story.append(Spacer(1, 8))
            story.append(Paragraph(
                "<b>Atenção.</b> Há zona com servidores apontados que não "
                "respondem de forma autoritativa. Nessa condição cada consulta "
                "reversa fica sem resposta até expirar o tempo limite, o que é "
                "pior para a entrega do que a ausência de delegação.", S["p"]))

    # ---------------- Plano ----------------
    # O texto do plano vem da ferramenta com jargão de NOC (nomes de listas,
    # códigos de retorno). Aqui ele é reescrito no mesmo registro do restante
    # do documento, porque quem lê não é do time de rede.
    TEXTO_PASSO = {
        "delegacao":
            "As zonas de DNS reverso deste bloco precisam ser delegadas na "
            "hierarquia mundial do DNS. Isso é feito junto ao registro que "
            "detém a alocação do bloco, ou junto à operadora que o forneceu. "
            "Enquanto não houver delegação, nenhum registro criado será "
            "consultável pela internet.",
        "rdns-ausente":
            "Estes endereços não têm nome reverso associado. É preciso criar um "
            "registro para cada um. Endereços destinados a assinantes podem "
            "receber nome padronizado gerado automaticamente; endereços de "
            "serviço devem receber nome próprio, que identifique a função.",
        "rdns-generico":
            "Estes endereços já têm registro, mas o nome repete os números do "
            "próprio endereço IP. Esse formato é característico de faixa "
            "residencial dinâmica e faz com que os sistemas de reputação tratem "
            "o espaço como sendo de usuário final. Endereços de infraestrutura "
            "e de clientes com serviço publicado precisam de nome que descreva "
            "a função, sem os números do endereço.",
        "fcrdns":
            "Cada nome publicado no reverso precisa existir também no sentido "
            "direto, apontando de volta para o mesmo endereço. Hoje essa "
            "correspondência de ida e volta não se completa, e muitos servidores "
            "de destino recusam a conexão exclusivamente por esse motivo.",
    }
    TITULO_PASSO = {
        "delegacao": "Delegar as zonas de DNS reverso",
        "rdns-ausente": "Criar os registros reversos ausentes",
        "rdns-generico": "Substituir os nomes inadequados",
        "fcrdns": "Publicar a correspondência direta dos nomes",
    }

    passos = [p for p in report.get("plan", [])
              if p["kind"] in TEXTO_PASSO]
    if passos:
        story.append(Paragraph("Correções necessárias, em ordem", S["h2"]))
        for i, p in enumerate(passos, 1):
            quantos = "".join(c for c in p["title"] if c.isdigit() or c == " ")
            titulo = TITULO_PASSO[p["kind"]]
            n = _quantidade(p["title"])
            if n:
                titulo += f" ({n} endereços)" if p["kind"] != "delegacao" else \
                          f" ({n} zonas)"
            bloco = [
                Paragraph(f"{i}. {titulo}", S["h3"]),
                Paragraph(TEXTO_PASSO[p["kind"]], S["p"]),
            ]
            if p["prefixes"]:
                bloco.append(Paragraph(
                    "Faixas afetadas: " + _collapse(p["prefixes"]), S["mono"]))
            story.append(KeepTogether(bloco))

        story.append(Paragraph("Ordem de execução do lado do DNS", S["h3"]))
        story.append(Paragraph(
            "A zona precisa estar no ar e respondendo de forma autoritativa em "
            "pelo menos dois servidores <b>antes</b> de a delegação ser "
            "solicitada. Fazer o inverso resulta em delegação apontando para "
            "servidor que não responde, situação que degrada a entrega mais do "
            "que a configuração ausente.", S["p"]))

    # ---------------- Ressalva sobre ordem geral ----------------
    if comportamental:
        story.append(Paragraph("Ressalva importante sobre a ordem dos trabalhos",
                               S["h2"]))
        story.append(Paragraph(
            f"A auditoria identificou <b>{comportamental} endereços</b> deste "
            f"bloco com indício de envio indevido em curso, apontado por sistemas "
            f"independentes de reputação. Essa condição não é causada pelo DNS e "
            f"não se resolve corrigindo o reverso.", S["p"]))
        story.append(Paragraph(
            "A ordem importa: um DNS reverso bem configurado aumenta a taxa de "
            "entrega do bloco. Se ele for corrigido antes de o envio indevido ser "
            "contido, o resultado prático é o tráfego indesejado passar a ser "
            "entregue com mais eficiência, o que agrava a reputação em vez de "
            "recuperá-la. A contenção na rede precisa vir primeiro; a correção do "
            "DNS, logo em seguida.", S["p"]))
        story.append(Paragraph(
            "Os endereços envolvidos não são identificados neste documento por "
            "se tratar de informação sensível da rede. A relação completa está "
            "disponível ao responsável técnico do provedor.", S["small"]))

    # ---------------- Observações ----------------
    if observacoes.strip():
        story.append(Paragraph("Observações", S["h2"]))
        for par in observacoes.strip().split("\n"):
            if par.strip():
                story.append(Paragraph(par.strip(), S["p"]))

    # ---------------- Método ----------------
    story.append(Paragraph("Como estes dados foram obtidos", S["h2"]))
    story.append(Paragraph(
        f"Foram consultados os registros públicos de DNS reverso dos {total} "
        f"endereços do bloco, um a um, seguidos da verificação de correspondência "
        f"direta de cada nome encontrado e da checagem de delegação das zonas "
        f"correspondentes. Todas as informações apresentadas são públicas e podem "
        f"ser reproduzidas de forma independente com ferramentas padrão de "
        f"consulta DNS.", S["p"]))
    story.append(Paragraph(
        "Este documento trata exclusivamente da camada de DNS. Detalhes de "
        "topologia interna, configuração de equipamentos e identificação de "
        "assinantes foram deliberadamente omitidos por serem informação sensível "
        "da rede auditada.", S["small"]))

    buf = BytesIO()
    doc = _Doc(buf)
    doc.rodape = (f"Diagnóstico de DNS reverso · {net}"
                  + (f" · {preparado_por.strip()}" if preparado_por.strip() else "")
                  + " · Pro Networks")
    doc.build(story)
    return buf.getvalue()

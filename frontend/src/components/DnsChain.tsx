import { useEffect, useState } from "react";
import type { ChainResult, DnsValidation } from "../types";

/**
 * Cadeia de delegação, incluindo DNS de terceiros.
 *
 * A validação por arquivo enxerga só o servidor de quem enviou. Este painel
 * consulta a hierarquia real e responde a pergunta que faltava: para onde o
 * domínio está delegado.
 *
 * O caso que motivou: provedor com zona reversa correta, registros A corretos,
 * e o domínio delegado no registro.br para a hospedagem. Os registros existiam
 * num servidor que ninguém consulta.
 */
export default function DnsChain({ analise }: { analise: DnsValidation | null }) {
  const [dominios, setDominios] = useState("");
  const [reversas, setReversas] = useState("");
  const [locais, setLocais] = useState("");
  const [res, setRes] = useState<ChainResult | null>(null);
  const [busy, setBusy] = useState(false);
  const [erro, setErro] = useState<string | null>(null);
  const [aberto, setAberto] = useState<string | null>(null);
  const [copiado, setCopiado] = useState("");

  // Pré-preenche com o que a validação de arquivos encontrou. Continua
  // editável: um provedor costuma ter domínio em uso nos PTR que não aparece
  // nos arquivos enviados.
  useEffect(() => {
    if (!analise) return;
    const doms = new Set<string>();
    analise.findings.forEach((f) =>
      f.samples.forEach((s) => {
        if (s.dominio) doms.add(s.dominio);
        else if (s.nome && s.nome.includes(".")) {
          const p = s.nome.replace(/\.$/, "").split(".");
          const seg = ["com", "net", "org", "gov", "edu"];
          const corte = p.length >= 4 && seg.includes(p[p.length - 2]) ? 3 : 2;
          doms.add(p.slice(-corte).join("."));
        }
      })
    );
    if (doms.size > 0) setDominios(Array.from(doms).join("\n"));
    const revs = analise.arquivos.filter((a) => a.reversa && a.origin)
      .map((a) => a.origin);
    if (revs.length > 0) setReversas(revs.join("\n"));
  }, [analise]);

  function linhas(v: string): string[] {
    return v.split("\n").map((l) => l.trim().replace(/\.$/, "")).filter(Boolean);
  }

  async function verificar() {
    setBusy(true);
    setErro(null);
    setRes(null);
    try {
      const amostras: Record<string, { nome: string; ip: string }[]> = {};
      analise?.findings.forEach((f) =>
        f.samples.forEach((s) => {
          if (!s.nome || !s.ip) return;
          const p = s.nome.replace(/\.$/, "").split(".");
          const seg = ["com", "net", "org", "gov", "edu"];
          const corte = p.length >= 4 && seg.includes(p[p.length - 2]) ? 3 : 2;
          const d = p.slice(-corte).join(".");
          (amostras[d] ??= []).push({ nome: s.nome.replace(/\.$/, ""), ip: s.ip });
        })
      );
      const r = await fetch("/api/dns/chain", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          dominios: linhas(dominios),
          zonas_reversas: linhas(reversas),
          servidores_locais: linhas(locais),
          amostras,
        }),
      });
      const d = await r.json();
      if (!r.ok) {
        setErro(d?.detail ?? `HTTP ${r.status}`);
        return;
      }
      setRes(d);
    } catch {
      setErro("Falha ao falar com o backend.");
    } finally {
      setBusy(false);
    }
  }

  function copiar(t: string, qual: string) {
    navigator.clipboard.writeText(t);
    setCopiado(qual);
    setTimeout(() => setCopiado(""), 2000);
  }

  return (
    <>
      <section className="panel panel-wide">
        <h2 className="eyebrow">Cadeia de delegação e DNS de terceiros</h2>
        <p className="lede">
          A validação de arquivos enxerga só o servidor de quem enviou. Aqui a
          consulta é feita contra a hierarquia real: para onde cada domínio está
          delegado, quem responde por ele hoje, e se os nomes do reverso de fato
          resolvem. Registro correto num servidor para o qual o domínio não está
          delegado é registro invisível.
        </p>

        <div className="cadeia-form">
          <Area
            id="ch-dom"
            rot="Domínios usados nos nomes reversos"
            v={dominios}
            set={setDominios}
            ph={"provedor.net.br\noutrodominio.com.br"}
            dica="um por linha; preenchido a partir da validação"
          />
          <Area
            id="ch-rev"
            rot="Zonas reversas"
            v={reversas}
            set={setReversas}
            ph={"92.191.181.in-addr.arpa"}
            dica="um por linha"
          />
          <Area
            id="ch-loc"
            rot="Seus servidores autoritativos"
            v={locais}
            set={setLocais}
            ph={"dns1.provedor.net.br\n181.191.92.18"}
            dica="nome ou IP; é contra esta lista que se decide o que é de terceiros"
          />
        </div>

        <div className="analyze-actions">
          <button type="button" className="primary" onClick={verificar} disabled={busy}>
            {busy ? "Consultando a hierarquia…" : "Verificar cadeia"}
          </button>
        </div>

        {erro && <div className="notice notice-warn">{erro}</div>}
      </section>

      {res && (
        <>
          {res.achados.length > 0 && (
            <section className="panel panel-wide">
              <h2 className="eyebrow">O que a cadeia revelou</h2>
              <ul className="findings">
                {res.achados.map((a) => (
                  <li key={a.id} className="finding">
                    <button
                      type="button"
                      className="finding-head"
                      onClick={() => setAberto(aberto === a.id ? null : a.id)}
                      aria-expanded={aberto === a.id}
                    >
                      <span
                        className={`sev-tag sev-${
                          a.severidade === 3 ? "crítico" : "importante"
                        }`}
                      >
                        {a.severidade === 3 ? "crítico" : "importante"}
                      </span>
                      <span className="finding-title">{a.titulo}</span>
                      <span className="finding-caret">
                        {aberto === a.id ? "−" : "+"}
                      </span>
                    </button>

                    {aberto === a.id && (
                      <div className="finding-body">
                        {a.detalhe && <p className="muted-text">{a.detalhe}</p>}
                        <h4>Por que importa</h4>
                        <p>{a.porque}</p>
                        {a.correcao.length > 0 && (
                          <>
                            <div className="zone-head">
                              <h4 className="gov-h4">Como corrigir</h4>
                              <button
                                type="button"
                                className="link"
                                onClick={() => copiar(a.correcao.join("\n"), a.id)}
                              >
                                {copiado === a.id ? "copiado" : "copiar"}
                              </button>
                            </div>
                            <pre className="cmds">{a.correcao.join("\n")}</pre>
                          </>
                        )}
                      </div>
                    )}
                  </li>
                ))}
              </ul>
            </section>
          )}

          <section className="panel panel-wide">
            <h2 className="eyebrow">Onde cada peça mora</h2>

            {res.dominios.length > 0 && (
              <>
                <h4 className="gov-h4">Domínios</h4>
                <div className="table-wrap">
                  <table className="ips">
                    <thead>
                      <tr>
                        <th scope="col">Domínio</th>
                        <th scope="col">Hospedagem</th>
                        <th scope="col">Autoritativos declarados</th>
                        <th scope="col">Nomes no PTR</th>
                      </tr>
                    </thead>
                    <tbody>
                      {res.dominios.map((d) => (
                        <tr key={d.dominio}>
                          <td className="col-ip">{d.dominio}</td>
                          <td>
                            <span
                              className={`tag tag-${
                                d.erro ? "behavior" : d.hospedado_por_nos ? "clean" : "policy"
                              }`}
                            >
                              {d.erro
                                ? "não resolve"
                                : d.hospedado_por_nos
                                  ? "seus servidores"
                                  : "terceiros"}
                            </span>
                          </td>
                          <td className="col-lists">
                            {d.ns.join(", ") || d.erro || "—"}
                          </td>
                          <td className="col-reason">{d.nomes_no_ptr}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </>
            )}

            {res.reversas.length > 0 && (
              <>
                <h4 className="gov-h4">Zonas reversas</h4>
                <div className="table-wrap">
                  <table className="ips">
                    <thead>
                      <tr>
                        <th scope="col">Zona</th>
                        <th scope="col">Delegação</th>
                        <th scope="col">Autoritativos declarados</th>
                      </tr>
                    </thead>
                    <tbody>
                      {res.reversas.map((z) => (
                        <tr key={z.zona}>
                          <td className="col-ip">{z.zona}</td>
                          <td>
                            <span
                              className={`tag tag-${
                                !z.ns.length ? "behavior" : z.hospedado_por_nos ? "clean" : "policy"
                              }`}
                            >
                              {!z.ns.length
                                ? "não delegada"
                                : z.hospedado_por_nos
                                  ? "seus servidores"
                                  : "terceiros"}
                            </span>
                          </td>
                          <td className="col-lists">
                            {z.ns.join(", ") || z.erro || "—"}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </>
            )}

            {res.dominios.some((d) => d.amostras.length > 0) && (
              <>
                <h4 className="gov-h4">Teste dos nomes, servidor a servidor</h4>
                <div className="table-wrap">
                  <table className="ips">
                    <thead>
                      <tr>
                        <th scope="col">Nome</th>
                        <th scope="col">Esperado</th>
                        <th scope="col">Servidor</th>
                        <th scope="col">Respondeu</th>
                      </tr>
                    </thead>
                    <tbody>
                      {res.dominios.flatMap((d) =>
                        d.amostras.flatMap((a) =>
                          a.por_servidor.map((s) => (
                            <tr key={`${a.nome}-${s.servidor}`}>
                              <td className="col-ip">{a.nome}</td>
                              <td className="col-lists">{a.ip_esperado}</td>
                              <td className="col-lists">{s.servidor}</td>
                              <td className="col-reason">
                                {s.confere ? (
                                  <span className="tag tag-clean">confere</span>
                                ) : (
                                  <>
                                    <span className="missing">
                                      {s.valores.join(", ") || s.detalhe || "nada"}
                                    </span>
                                  </>
                                )}
                              </td>
                            </tr>
                          ))
                        )
                      )}
                    </tbody>
                  </table>
                </div>
              </>
            )}
          </section>
        </>
      )}
    </>
  );
}

function Area({
  id, rot, v, set, ph, dica,
}: {
  id: string; rot: string; v: string;
  set: (s: string) => void; ph: string; dica: string;
}) {
  return (
    <div className="field">
      <label htmlFor={id}>{rot}</label>
      <textarea
        id={id}
        className="gov-textarea"
        rows={4}
        value={v}
        onChange={(e) => set(e.target.value)}
        placeholder={ph}
        spellCheck={false}
      />
      <span className="field-hint">{dica}</span>
    </div>
  );
}

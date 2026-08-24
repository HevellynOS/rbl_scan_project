import { useEffect, useState } from "react";
import type { Correlation, ZoneResult } from "../types";

/* ------------------------------------------------------------ correlação */
export function Correlation({
  cidr,
  hasAnalysis,
}: {
  cidr: string;
  hasAnalysis: boolean;
}) {
  const [data, setData] = useState<Correlation | null>(null);
  const [msg, setMsg] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [open, setOpen] = useState<string | null>(null);

  // Cruza sozinho assim que os dois lados existem. Antes exigia um clique em
  // "cruzar", que era uma etapa sem decisão nenhuma: se há varredura e há
  // configuração, o cruzamento é sempre desejado.
  useEffect(() => {
    if (!cidr || !hasAnalysis) {
      setData(null);
      return;
    }
    let vivo = true;
    setBusy(true);
    setMsg(null);
    fetch(`/api/correlate/${cidr}`)
      .then(async (res) => {
        const body = await res.json();
        if (!vivo) return;
        if (!res.ok) {
          setMsg(body?.detail ?? `HTTP ${res.status}`);
          setData(null);
        } else {
          setData(body);
        }
      })
      .catch(() => vivo && setMsg("Falha ao consultar o backend."))
      .finally(() => vivo && setBusy(false));
    return () => {
      vivo = false;
    };
  }, [cidr, hasAnalysis]);

  if (!hasAnalysis) {
    return (
      <section className="panel panel-wide">
        <h2 className="eyebrow">Quem está atrás dos IPs listados</h2>
        <p className="empty">
          Envie o backup do CGNAT na aba de análise de configuração. O
          cruzamento acontece sozinho e traduz cada IP público listado nos
          assinantes que o compartilham.
        </p>
      </section>
    );
  }

  return (
    <section className="panel panel-wide">
      <h2 className="eyebrow">Quem está atrás dos IPs listados</h2>

      {busy && <p className="empty">Cruzando com a configuração…</p>}
      {msg && <div className="notice notice-warn">{msg}</div>}

      {data && (
        <>
          <p className="panel-note" style={{ marginTop: 0 }}>
            {data.emissores} IP(s) com emissão · {data.cobertos} mapeados em faixas
            de CGNAT conhecidas
          </p>

          {data.orfaos.length > 0 && (
            <div className="notice notice-warn">{data.aviso_orfaos}</div>
          )}

          {data.devices.map((d) => (
            <div key={d.file} className="corr-dev">
              <div className="dev-head">
                <h3 className="corr-dev-name">{d.identity}</h3>
                <span className="dev-role">{d.role}</span>
              </div>

              <ul className="findings">
                {d.achados.map((a) => (
                  <li key={a.ip} className="finding">
                    <button
                      type="button"
                      className="finding-head"
                      onClick={() => setOpen(open === a.ip ? null : a.ip)}
                      aria-expanded={open === a.ip}
                    >
                      <span className="tag tag-behavior">emissão</span>
                      <span className="finding-title">{a.ip}</span>
                      <span className="corr-count">
                        {a.total_candidatos} candidato(s)
                      </span>
                      <span className="finding-caret">{open === a.ip ? "−" : "+"}</span>
                    </button>

                    {open === a.ip && (
                      <div className="finding-body">
                        <h4>Listagens</h4>
                        <p>
                          {a.listas.join(" · ")}
                          <br />
                          <span className="muted-text">{a.motivos.join(" · ")}</span>
                        </p>

                        <h4>Faixa pública de CGNAT</h4>
                        <p>{a.faixa_publica}</p>

                        <h4>Assinantes que compartilham este endereço</h4>
                        <div className="table-wrap">
                          <table className="ips">
                            <thead>
                              <tr>
                                <th scope="col">Assinante</th>
                                <th scope="col">Faixa de portas</th>
                                <th scope="col">Chain</th>
                                <th scope="col">Faixa privada</th>
                              </tr>
                            </thead>
                            <tbody>
                              {a.candidatos.map((c) => (
                                <tr key={`${c.assinante}-${c.portas}`}>
                                  <td className="col-ip">{c.assinante}</td>
                                  <td>{c.portas}</td>
                                  <td className="col-lists">{c.chain}</td>
                                  <td className="col-lists">{c.faixa_privada}</td>
                                </tr>
                              ))}
                            </tbody>
                          </table>
                        </div>
                      </div>
                    )}
                  </li>
                ))}
              </ul>
            </div>
          ))}

          <p className="panel-note">{data.como_usar}</p>
        </>
      )}
    </section>
  );
}

/* ------------------------------------------------------- zona reversa */
export function ZoneBuilder({ cidr }: { cidr: string }) {
  const [domain, setDomain] = useState("");
  const [ns1, setNs1] = useState("");
  const [ns2, setNs2] = useState("");
  const [email, setEmail] = useState("");
  const [prefixo, setPrefixo] = useState("cliente");
  const [out, setOut] = useState<ZoneResult | null>(null);
  const [msg, setMsg] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [copied, setCopied] = useState("");

  async function generate() {
    setBusy(true);
    setMsg(null);
    try {
      const res = await fetch("/api/zone", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          cidr,
          domain,
          ns: [ns1, ns2].map((n) => n.trim()).filter(Boolean),
          email,
          prefixo_pool: prefixo,
        }),
      });
      const body = await res.json();
      if (!res.ok) {
        setMsg(body?.detail ?? `HTTP ${res.status}`);
        setOut(null);
      } else {
        setOut(body);
      }
    } catch {
      setMsg("Falha ao consultar o backend.");
    } finally {
      setBusy(false);
    }
  }

  function copy(text: string, which: string) {
    navigator.clipboard.writeText(text);
    setCopied(which);
    setTimeout(() => setCopied(""), 2000);
  }

  return (
    <section className="panel panel-wide">
      <h2 className="eyebrow">Zona reversa</h2>
      <p className="lede">
        Gera a zona in-addr.arpa e os registros A correspondentes. Faixa de
        assinante sai com nomenclatura genérica de propósito: o PBL ali protege a
        rede. Endereço de serviço sai com marcador para você nomear.
      </p>

      <div className="gov-form">
        <div className="field">
          <label htmlFor="z-dom">Domínio</label>
          <input
            id="z-dom"
            value={domain}
            onChange={(e) => setDomain(e.target.value)}
            placeholder="provedor.net.br"
            spellCheck={false}
          />
          <span className="field-hint">usado nos nomes reversos</span>
        </div>
        <div className="field">
          <label htmlFor="z-ns1">NS primário</label>
          <input
            id="z-ns1"
            value={ns1}
            onChange={(e) => setNs1(e.target.value)}
            placeholder="ns1.provedor.net.br"
            spellCheck={false}
          />
          <span className="field-hint" />
        </div>
        <div className="field">
          <label htmlFor="z-ns2">NS secundário</label>
          <input
            id="z-ns2"
            value={ns2}
            onChange={(e) => setNs2(e.target.value)}
            placeholder="ns2.provedor.net.br"
            spellCheck={false}
          />
          <span className="field-hint">dois são o mínimo</span>
        </div>
        <div className="field">
          <label htmlFor="z-mail">E-mail do responsável</label>
          <input
            id="z-mail"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            placeholder="hostmaster@provedor.net.br"
            spellCheck={false}
          />
          <span className="field-hint" />
        </div>
        <div className="field">
          <label htmlFor="z-pref">Prefixo do pool</label>
          <input
            id="z-pref"
            value={prefixo}
            onChange={(e) => setPrefixo(e.target.value)}
            placeholder="cliente"
            spellCheck={false}
          />
          <span className="field-hint">sem os octetos do IP</span>
        </div>
      </div>

      <div className="analyze-actions">
        <button
          type="button"
          className="primary"
          onClick={generate}
          disabled={busy || !domain.trim()}
        >
          {busy ? "Gerando…" : "Gerar zona"}
        </button>
      </div>

      {msg && (
        <div className="notice notice-warn" style={{ marginTop: 12 }}>
          {msg}
        </div>
      )}

      {out && (
        <>
          {out.aviso && (
            <div className="notice notice-warn" style={{ marginTop: 12 }}>
              {out.aviso}
            </div>
          )}

          <p className="panel-note">
            Zona <code>{out.zone_name}</code> · {out.pools.length} faixa(s) de
            assinante · {out.servicos} endereço(s) de serviço a nomear
          </p>

          <div className="zone-head">
            <h4 className="gov-h4">Zona reversa</h4>
            <button
              type="button"
              className="link"
              onClick={() => copy(out.reverse, "rev")}
            >
              {copied === "rev" ? "copiado" : "copiar"}
            </button>
          </div>
          <pre className="cmds">{out.reverse}</pre>

          <div className="zone-head">
            <h4 className="gov-h4">Registros A da zona direta</h4>
            <button
              type="button"
              className="link"
              onClick={() => copy(out.forward, "fwd")}
            >
              {copied === "fwd" ? "copiado" : "copiar"}
            </button>
          </div>
          <pre className="cmds">{out.forward}</pre>
        </>
      )}
    </section>
  );
}

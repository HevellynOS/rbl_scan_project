import { useCallback, useEffect, useRef, useState } from "react";
import type { ColetaHelp, DnsValidation, DnsFinding } from "../types";

/**
 * Validação da configuração do servidor de DNS.
 *
 * A varredura enxerga o resultado das consultas; aqui a auditoria é sobre o
 * arquivo, então dá para apontar a linha onde o erro foi escrito. É o único
 * caminho para pegar PTR publicado sem o registro A correspondente antes de o
 * problema chegar na rede.
 */
export default function DnsConfigCheck() {
  const [files, setFiles] = useState<File[]>([]);
  const [busy, setBusy] = useState(false);
  const [erro, setErro] = useState<string | null>(null);
  const [res, setRes] = useState<DnsValidation | null>(null);
  const [dragging, setDragging] = useState(false);
  const [open, setOpen] = useState<string | null>(null);
  const [help, setHelp] = useState<ColetaHelp | null>(null);
  const [semSudo, setSemSudo] = useState(false);
  const [copiado, setCopiado] = useState("");
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    fetch("/api/dns/collect-help")
      .then((r) => (r.ok ? r.json() : null))
      .then(setHelp)
      .catch(() => setHelp(null));
  }, []);

  function copiar(texto: string, qual: string) {
    navigator.clipboard.writeText(texto);
    setCopiado(qual);
    setTimeout(() => setCopiado(""), 2000);
  }

  const addFiles = useCallback((incoming: FileList | null) => {
    if (!incoming) return;
    setErro(null);
    setFiles((prev) => {
      const nomes = new Set(prev.map((f) => f.name));
      return [...prev, ...Array.from(incoming).filter((f) => !nomes.has(f.name))]
        .slice(0, 30);
    });
  }, []);

  async function validar() {
    if (files.length === 0) return;
    setBusy(true);
    setErro(null);
    setRes(null);
    try {
      const body = new FormData();
      files.forEach((f) => body.append("files", f));
      const r = await fetch("/api/dns/validate", { method: "POST", body });
      const data = await r.json();
      if (!r.ok) {
        setErro(data?.detail ?? `HTTP ${r.status}`);
        return;
      }
      setRes(data);
    } catch {
      setErro("Falha ao falar com o backend.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <>
      <section className="panel panel-wide">
        <h2 className="eyebrow">Validar configuração do servidor de DNS</h2>
        <p className="lede">
          Acesse o servidor por SSH, cole o comando abaixo e envie o arquivo
          gerado. Não é preciso saber onde ficam as zonas nem qual servidor está
          rodando: o comando descobre sozinho, tanto em BIND quanto em PowerDNS.
        </p>

        {help && (
          <ol className="coleta">
            {help.passos.map((p, i) => (
              <li key={p.titulo} className="coleta-passo">
                <span className="plan-index">{i + 1}</span>
                <div className="plan-body">
                  <h3>{p.titulo}</h3>
                  <p>{p.detalhe}</p>
                  {p.comando && (
                    <>
                      <div className="zone-head">
                        <span className="coleta-rotulo">
                          {i === 1 ? "cole no servidor" : "no seu computador"}
                        </span>
                        <button
                          type="button"
                          className="link"
                          onClick={() =>
                            copiar(
                              i === 1 && semSudo ? help.script_sem_sudo : p.comando,
                              p.titulo
                            )
                          }
                        >
                          {copiado === p.titulo ? "copiado" : "copiar"}
                        </button>
                      </div>
                      <pre className="cmds coleta-cmd">
                        {i === 1 && semSudo ? help.script_sem_sudo : p.comando}
                      </pre>
                      {i === 1 && (
                        <label className="check coleta-check">
                          <input
                            type="checkbox"
                            checked={semSudo}
                            onChange={(e) => setSemSudo(e.target.checked)}
                          />
                          Usuário sem sudo
                        </label>
                      )}
                    </>
                  )}
                </div>
              </li>
            ))}
          </ol>
        )}

        {help && <p className="panel-note">{help.seguranca}</p>}

        <div
          className={`drop${dragging ? " is-over" : ""}`}
          onDragOver={(e) => {
            e.preventDefault();
            setDragging(true);
          }}
          onDragLeave={() => setDragging(false)}
          onDrop={(e) => {
            e.preventDefault();
            setDragging(false);
            addFiles(e.dataTransfer.files);
          }}
          onClick={() => inputRef.current?.click()}
          role="button"
          tabIndex={0}
          onKeyDown={(e) => e.key === "Enter" && inputRef.current?.click()}
        >
          <input
            ref={inputRef}
            type="file"
            multiple
            hidden
            onChange={(e) => addFiles(e.target.files)}
          />
          <strong>Arraste os arquivos de zona aqui</strong>
          <span>ou clique para escolher, até 30 arquivos</span>
          <code className="drop-hint">
            /etc/bind/db.* · named.conf.local · pdnsutil list-zone
          </code>
        </div>

        {files.length > 0 && (
          <ul className="filelist">
            {files.map((f) => (
              <li key={f.name}>
                <span className="file-name">{f.name}</span>
                <span className="file-size">{Math.max(1, Math.round(f.size / 1024))} KB</span>
                <button
                  type="button"
                  className="link"
                  onClick={() => setFiles((p) => p.filter((x) => x.name !== f.name))}
                >
                  remover
                </button>
              </li>
            ))}
          </ul>
        )}

        <div className="analyze-actions">
          <button
            type="button"
            className="primary"
            onClick={validar}
            disabled={busy || files.length === 0}
          >
            {busy ? "Validando…" : "Validar configuração"}
          </button>
          {files.length > 0 && (
            <button type="button" className="ghost" onClick={() => setFiles([])}>
              Limpar
            </button>
          )}
        </div>

        {erro && (
          <div className="notice notice-error" style={{ marginTop: 12 }}>
            {erro}
          </div>
        )}
      </section>

      {res && (
        <>
          {(res.coleta?.host || res.avisos.length > 0) && (
            <section className="panel panel-wide">
              <h2 className="eyebrow">Coleta</h2>
              {res.coleta?.host && (
                <p className="panel-note" style={{ marginTop: 0 }}>
                  {res.coleta.host} · {res.coleta.servidor} ·{" "}
                  {res.coleta.partes} arquivo(s) · coletado em {res.coleta.data}
                </p>
              )}
              {res.avisos.map((a) => (
                <div key={a} className="notice notice-warn">
                  {a}
                </div>
              ))}
            </section>
          )}

          <section className="panel panel-wide">
            <h2 className="eyebrow">Correspondência de ida e volta</h2>
            <div className="rdns-row">
              <Card
                label="PTR conferidos"
                value={res.resumo.ptr_ok}
                of={res.resumo.ptr_total}
                tone="ok"
                hint="Nome existe e volta para o mesmo endereço."
              />
              <Card
                label="Sem registro A"
                value={res.resumo.ptr_sem_a}
                of={res.resumo.ptr_total}
                tone="bad"
                hint="O nome publicado não existe na zona direta."
              />
              <Card
                label="Apontando para outro IP"
                value={res.resumo.ptr_divergente}
                of={res.resumo.ptr_total}
                tone="bad"
                hint="O A existe mas leva a endereço diferente."
              />
              <Card
                label="Nome genérico"
                value={res.resumo.genericos}
                of={res.resumo.ptr_total}
                tone="warn"
                hint="Repete os números do endereço."
              />
            </div>

            {res.resumo.ptr_nao_verificavel > 0 && (
              <p className="amostra">
                {res.resumo.ptr_nao_verificavel} PTR apontam para domínio cujo
                arquivo não foi enviado. Sem a zona direta não há como conferir a
                volta.
              </p>
            )}

            {res.arquivos.length > 0 && (
              <div className="table-wrap" style={{ marginTop: 14 }}>
                <table className="ips">
                  <thead>
                    <tr>
                      <th scope="col">Arquivo</th>
                      <th scope="col">Zona</th>
                      <th scope="col">Tipo</th>
                      <th scope="col">Registros</th>
                    </tr>
                  </thead>
                  <tbody>
                    {res.arquivos.map((a) => (
                      <tr key={a.nome}>
                        <td className="col-ip">{a.nome}</td>
                        <td className="col-lists">
                          {a.origin || "(não identificada)"}
                          {a.cidr && ` · ${a.cidr}`}
                        </td>
                        <td>
                          <span className={`tag tag-${a.reversa ? "policy" : "clean"}`}>
                            {a.reversa ? "reversa" : "direta"}
                          </span>
                        </td>
                        <td className="col-reason">
                          {a.registros}
                          {a.gerados > 0 && ` (${a.gerados} de $GENERATE)`}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}

            {res.ignorados.length > 0 && (
              <p className="panel-note">
                Não reconhecidos como zona ou named.conf: {res.ignorados.join(", ")}
              </p>
            )}
          </section>

          {res.remediacao.blocos.length > 0 && (
            <section className="panel panel-wide">
              <h2 className="eyebrow">O que aplicar no servidor</h2>
              <p className="lede">
                Blocos prontos, na ordem. Os marcados como decisão exigem que
                você saiba o que é infraestrutura e o que é faixa de assinante.
              </p>
              {res.remediacao.blocos.map((b, i) => (
                <div key={b.id} className="fix-bloco">
                  <div className="zone-head">
                    <h3 className="fix-titulo">
                      <span className="plan-index">{i + 1}</span>
                      {b.titulo}
                    </h3>
                    <button
                      type="button"
                      className="link"
                      onClick={() => copiar(b.conteudo, b.id)}
                    >
                      {copiado === b.id ? "copiado" : "copiar"}
                    </button>
                  </div>
                  {b.arquivo && <p className="fix-arquivo">{b.arquivo}</p>}
                  <pre className="cmds">{b.conteudo}</pre>
                  {b.nota && <p className="fix-nota">{b.nota}</p>}
                </div>
              ))}
            </section>
          )}

          <section className="panel panel-wide">
            <h2 className="eyebrow">Achados</h2>
            {res.findings.length === 0 ? (
              <p className="empty">
                Nenhum problema encontrado nos arquivos enviados.
              </p>
            ) : (
              <ul className="findings">
                {res.findings.map((f) => (
                  <Achado
                    key={f.id}
                    f={f}
                    open={open === f.id}
                    onToggle={() => setOpen(open === f.id ? null : f.id)}
                  />
                ))}
              </ul>
            )}
          </section>
        </>
      )}
    </>
  );
}

function Achado({
  f,
  open,
  onToggle,
}: {
  f: DnsFinding;
  open: boolean;
  onToggle: () => void;
}) {
  return (
    <li className={`finding sev-${f.severity_label}`}>
      <button type="button" className="finding-head" onClick={onToggle} aria-expanded={open}>
        <span className={`sev-tag sev-${f.severity_label}`}>{f.severity_label}</span>
        <span className="finding-title">{f.title}</span>
        <span className="finding-caret">{open ? "−" : "+"}</span>
      </button>

      {open && (
        <div className="finding-body">
          {f.detail && <p className="muted-text">{f.detail}</p>}

          {f.why && (
            <>
              <h4>Por que importa</h4>
              <p>{f.why}</p>
            </>
          )}

          {f.samples.length > 0 && "nome" in (f.samples[0] ?? {}) && (
            <>
              <h4>Onde está</h4>
              <div className="table-wrap">
                <table className="ips">
                  <thead>
                    <tr>
                      <th scope="col">Endereço</th>
                      <th scope="col">Nome no PTR</th>
                      <th scope="col">Resolve para</th>
                      <th scope="col">Origem</th>
                    </tr>
                  </thead>
                  <tbody>
                    {f.samples.map((s, i) => (
                      <tr key={`${s.ip}-${i}`}>
                        <td className="col-ip">{s.ip}</td>
                        <td className="col-lists">{s.nome}</td>
                        <td className="col-reason">
                          {s.encontrado && s.encontrado.length > 0 ? (
                            s.encontrado.join(", ")
                          ) : (
                            <span className="missing">não existe</span>
                          )}
                          {s.motivo && <span className="muted-text">{s.motivo}</span>}
                        </td>
                        <td className="col-reason">
                          {s.arquivo}
                          {s.linha ? `:${s.linha}` : ""}
                          {s.gerado && <span className="flag">$GENERATE</span>}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              {f.count > f.samples.length && (
                <p className="panel-note">
                  Mostrando {f.samples.length} de {f.count}.
                </p>
              )}
            </>
          )}

          {f.samples.length > 0 && !("nome" in (f.samples[0] ?? {})) && (
            <>
              <h4>Onde está</h4>
              <p className="plan-prefixes">
                {f.samples
                  .map((s) => s.ip ?? `linha ${s.linha}: ${s.erro ?? ""}`)
                  .join("  ")}
                {f.count > f.samples.length && `  … +${f.count - f.samples.length}`}
              </p>
            </>
          )}

          {f.fix.length > 0 && (
            <>
              <h4>Como corrigir</h4>
              <pre className="cmds">{f.fix.join("\n")}</pre>
            </>
          )}
        </div>
      )}
    </li>
  );
}

function Card({
  label,
  value,
  of,
  tone,
  hint,
}: {
  label: string;
  value: number;
  of: number;
  tone: "ok" | "warn" | "bad";
  hint: string;
}) {
  return (
    <div className={`rdns-card tone-${value === 0 ? "neutro" : tone}`}>
      <span className="rdns-label">{label}</span>
      <span className="rdns-value">
        {value}
        <span className="stat-of">/{of}</span>
      </span>
      <span className="rdns-hint">{hint}</span>
    </div>
  );
}

import { useCallback, useRef, useState } from "react";
import type { Analysis, Finding } from "../types";

const SEV_ORDER = ["crítico", "importante", "recomendado", "informativo"];

export default function ConfigAnalysis({
  result,
  onResult,
}: {
  result: Analysis | null;
  onResult: (a: Analysis | null) => void;
}) {
  const [files, setFiles] = useState<File[]>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [dragging, setDragging] = useState(false);
  const [open, setOpen] = useState<string | null>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  const addFiles = useCallback((incoming: FileList | null) => {
    if (!incoming) return;
    const picked = Array.from(incoming).filter((f) =>
      /\.(rsc|cfg|txt|conf|log)$/i.test(f.name)
    );
    if (picked.length === 0) {
      setError(
        "Formato não reconhecido. Envie .rsc do RouterOS ou .cfg/.txt do Huawei VRP."
      );
      return;
    }
    setError(null);
    setFiles((prev) => {
      const names = new Set(prev.map((f) => f.name));
      return [...prev, ...picked.filter((f) => !names.has(f.name))].slice(0, 10);
    });
  }, []);

  async function run() {
    if (files.length === 0) return;
    setBusy(true);
    setError(null);
    onResult(null);
    try {
      const body = new FormData();
      files.forEach((f) => body.append("files", f));
      const res = await fetch("/api/analyze", { method: "POST", body });
      if (!res.ok) {
        const detail = await res.json().catch(() => null);
        throw new Error(detail?.detail ?? `Falhou com HTTP ${res.status}`);
      }
      onResult(await res.json());
    } catch (e) {
      setError(e instanceof Error ? e.message : "Falha ao analisar.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <>
      <section className="panel panel-wide">
        <h2 className="eyebrow">Análise de configuração</h2>
        <p className="lede">
          Envie o export de cada equipamento: borda, CGNAT, concentrador.
          Reconhece MikroTik RouterOS (<code>/export</code>) e Huawei VRP
          (<code>display current-configuration</code>) na família NE8000, NE40E
          e NE20E. A análise procura o que na configuração causa ou vai causar
          listagem, e devolve um script de correção com a explicação de cada
          item.
        </p>

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
            accept=".rsc,.cfg,.txt,.conf,.log"
            hidden
            onChange={(e) => addFiles(e.target.files)}
          />
          <strong>Arraste os arquivos de configuração aqui</strong>
          <span>ou clique para escolher, até 10 equipamentos por análise</span>
          <code className="drop-hint">
            .rsc do RouterOS · .cfg ou .txt do Huawei VRP
          </code>
        </div>

        {files.length > 0 && (
          <ul className="filelist">
            {files.map((f) => (
              <li key={f.name}>
                <span className="file-name">{f.name}</span>
                <span className="file-size">{Math.round(f.size / 1024)} KB</span>
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
            onClick={run}
            disabled={busy || files.length === 0}
          >
            {busy ? "Analisando…" : "Analisar configuração"}
          </button>
          {result && (
            <>
              <a className="ghost as-button" href="/api/analysis/export/rsc">
                Baixar script .rsc
              </a>
              <a className="ghost as-button" href="/api/analysis/export/md">
                Baixar explicação
              </a>
            </>
          )}
        </div>

        {error && (
          <div className="notice notice-error" style={{ marginTop: 12 }}>
            {error}
          </div>
        )}
      </section>

      {result && (
        <>
          <section className="panel panel-wide">
            <h2 className="eyebrow">Resumo</h2>
            <div className="sev-row">
              {SEV_ORDER.map((s) => (
                <div key={s} className={`sev-box sev-${s}`}>
                  <span className="sev-count">
                    {result.totals[s as keyof typeof result.totals] ?? 0}
                  </span>
                  <span className="sev-name">{s}</span>
                </div>
              ))}
            </div>
            {result.totals.manual > 0 && (
              <p className="panel-note">
                {result.totals.manual} item(ns) saem comentados no script porque
                exigem uma decisão sua — faixa de gerência, número de regra,
                confirmação com a equipe. Importar o arquivo não os aplica.
              </p>
            )}
          </section>

          {result.devices.map((d) => (
            <section key={d.file} className="panel panel-wide">
              <div className="dev-head">
                <h2 className="eyebrow">{d.identity}</h2>
                <span className="dev-role">{d.role}</span>
                <span className="dev-vendor">{d.vendor}</span>
                <span className="dev-meta">
                  {[d.model, d.version].filter(Boolean).join(" · ")}
                  {d.rules ? ` · ${d.rules} linhas` : ""}
                </span>
              </div>

              {d.cgnat.rules > 0 && (
                <p className="dev-cgnat">
                  CGNAT: {d.cgnat.rules} regras
                  {d.cgnat.deterministic
                    ? ", determinístico por faixa de portas"
                    : ", sem mapeamento por porta"}
                  {d.cgnat.public.length > 0 && ` · saída por ${d.cgnat.public.join(", ")}`}
                  {d.cgnat.subscribers_per_ip > 0 &&
                    ` · ~${d.cgnat.subscribers_per_ip} assinantes por IP público`}
                </p>
              )}

              <ul className="findings">
                {d.findings.map((f) => (
                  <FindingRow
                    key={f.id}
                    f={f}
                    open={open === `${d.file}:${f.id}`}
                    onToggle={() =>
                      setOpen(open === `${d.file}:${f.id}` ? null : `${d.file}:${f.id}`)
                    }
                  />
                ))}
              </ul>
            </section>
          ))}
        </>
      )}
    </>
  );
}

function FindingRow({
  f,
  open,
  onToggle,
}: {
  f: Finding;
  open: boolean;
  onToggle: () => void;
}) {
  return (
    <li className={`finding sev-${f.severity_label}`}>
      <button type="button" className="finding-head" onClick={onToggle} aria-expanded={open}>
        <span className={`sev-tag sev-${f.severity_label}`}>{f.severity_label}</span>
        <span className="finding-title">{f.title}</span>
        {f.manual && <span className="flag">decisão sua</span>}
        <span className="finding-caret">{open ? "−" : "+"}</span>
      </button>

      {open && (
        <div className="finding-body">
          {f.evidence.length > 0 && (
            <>
              <h4>O que foi encontrado</h4>
              <ul className="evidence">
                {f.evidence.filter(Boolean).map((e) => (
                  <li key={e}>
                    <code>{e}</code>
                  </li>
                ))}
              </ul>
            </>
          )}
          {f.why && (
            <>
              <h4>Por que importa</h4>
              <p>{f.why}</p>
            </>
          )}
          {f.rbl_link && (
            <>
              <h4>Ligação com as listagens</h4>
              <p>{f.rbl_link}</p>
            </>
          )}
          {f.risk && (
            <>
              <h4>Risco de aplicar</h4>
              <p className="risk">{f.risk}</p>
            </>
          )}
          {f.commands.length > 0 && (
            <>
              <h4>Correção</h4>
              <pre className="cmds">{f.commands.join("\n")}</pre>
            </>
          )}
        </div>
      )}
    </li>
  );
}

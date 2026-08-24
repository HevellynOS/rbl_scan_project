import { useEffect, useMemo, useState } from "react";
import BlockMap from "./components/BlockMap";
import ConfigAnalysis from "./components/ConfigAnalysis";
import { Correlation } from "./components/Correlate";
import DnsTab from "./components/DnsTab";
import IpTable from "./components/IpTable";
import { ActionPlan, Diagnostics, ListTable, Summary } from "./components/Panels";
import { ThemeToggle, useTheme } from "./theme";
import type { Analysis, ScanParams, ZoneCheck } from "./types";
import { parseCidr, useScan } from "./useScan";

export default function App() {
  const [cidr, setCidr] = useState("179.108.72.0/24");
  const [profile, setProfile] = useState<"core" | "full">("core");
  const [resolver, setResolver] = useState("");
  const [advanced, setAdvanced] = useState(false);
  const [concurrency, setConcurrency] = useState(40);
  const [perZone, setPerZone] = useState(8);
  const [checkRdns, setCheckRdns] = useState(true);
  const [focus, setFocus] = useState<string | null>(null);
  const [zones, setZones] = useState<ZoneCheck[] | null>(null);
  const [tab, setTab] = useState<"scan" | "config" | "dns">("scan");
  const [analysis, setAnalysis] = useState<Analysis | null>(null);
  const [verifying, setVerifying] = useState(false);

  const { theme, toggle } = useTheme();
  const scan = useScan();
  const parsed = useMemo(() => parseCidr(cidr), [cidr]);
  const scanning = scan.status === "scanning";

  const live = useMemo(() => {
    let behavior = 0,
      policy = 0,
      clean = 0;
    scan.cells.forEach((c) => {
      if (c.classification === "behavior") behavior++;
      else if (c.classification === "policy") policy++;
      else clean++;
    });
    const size = parsed?.size ?? 0;
    return { behavior, policy, clean, pending: Math.max(0, size - scan.cells.size) };
  }, [scan.cells, parsed]);

  const params = (): ScanParams => ({
    cidr: cidr.trim(),
    profile,
    resolver: resolver.trim() || undefined,
    concurrency,
    per_zone: perZone,
    timeout: 3,
    check_rdns: checkRdns,
  });

  async function verifyZones() {
    setVerifying(true);
    setZones(null);
    try {
      const res = await fetch("/api/verify-zones", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(params()),
      });
      const data = await res.json();
      setZones(data.zones);
    } catch {
      setZones([
        { rbl: "backend", status: "falha", detail: "Backend não respondeu na porta 8000." },
      ]);
    } finally {
      setVerifying(false);
    }
  }

  function download(fmt: "csv" | "json") {
    if (!scan.report) return;
    window.open(`/api/export/${fmt}/${scan.report.network}`, "_blank");
  }

  useEffect(() => {
    if (scan.status === "done") setFocus(null);
  }, [scan.status]);

  const pct = scan.progress.total
    ? Math.round((scan.progress.done / scan.progress.total) * 100)
    : 0;

  return (
    <div className="app">
      <header className="masthead">
        <div className="brand">
          <span className="brand-mark">RBL</span>
          <span className="brand-word">SCAN</span>
        </div>
        <p className="tagline">
          Separa o que é falta de configuração do que é spam saindo de verdade.
        </p>
        <ThemeToggle theme={theme} onToggle={toggle} />
      </header>

      <nav className="tabs" role="tablist">
        <Tab id="scan" atual={tab} onSel={setTab} label="Varredura de bloco" />
        <Tab
          id="config"
          atual={tab}
          onSel={setTab}
          label="Análise de configuração"
          badge={analysis ? String(analysis.devices.length) : undefined}
        />
        <Tab
          id="dns"
          atual={tab}
          onSel={setTab}
          label="DNS"
          badge={
            scan.report
              ? String(scan.report.rdns.no_ptr + scan.report.rdns.generic)
              : undefined
          }
        />
      </nav>

      {tab === "config" && (
        <ConfigAnalysis result={analysis} onResult={setAnalysis} />
      )}

      {tab === "dns" && <DnsTab report={scan.report} />}

      {tab === "scan" && (
        <>
          <section className="console">
            <div className="field field-cidr">
              <label htmlFor="cidr">Bloco</label>
              <input
                id="cidr"
                value={cidr}
                onChange={(e) => setCidr(e.target.value.replace(/\s+/g, ""))}
                placeholder="179.108.72.0/23"
                spellCheck={false}
                disabled={scanning}
              />
              <span className="field-hint">
                {parsed ? `${parsed.size} endereços` : "formato: rede/prefixo"}
              </span>
            </div>

            <div className="field">
              <label htmlFor="profile">Perfil</label>
              <select
                id="profile"
                value={profile}
                onChange={(e) => setProfile(e.target.value as "core" | "full")}
                disabled={scanning}
              >
                <option value="core">core — 8 listas que afetam entrega</option>
                <option value="full">full — 15, inclui nicho e agressivas</option>
              </select>
              <span className="field-hint">
                {profile === "core" ? "o que afeta entrega" : "inclui listas agressivas"}
              </span>
            </div>

            <div className="console-actions">
              <button
                type="button"
                className="primary"
                onClick={() => scan.start(params())}
                disabled={!parsed || scanning}
              >
                {scanning ? "Varrendo…" : "Varrer bloco"}
              </button>
              {scanning ? (
                <button type="button" className="ghost" onClick={scan.stop}>
                  Parar
                </button>
              ) : (
                <button
                  type="button"
                  className="ghost"
                  onClick={verifyZones}
                  disabled={verifying}
                >
                  {verifying ? "Testando…" : "Testar listas"}
                </button>
              )}
              <button
                type="button"
                className="link"
                onClick={() => setAdvanced((v) => !v)}
                aria-expanded={advanced}
              >
                {advanced ? "Menos opções" : "Mais opções"}
              </button>
            </div>

            {advanced && (
              <div className="advanced">
                <div className="field">
                  <label htmlFor="resolver">Resolver recursivo</label>
                  <input
                    id="resolver"
                    value={resolver}
                    onChange={(e) => setResolver(e.target.value)}
                    placeholder="10.0.0.53"
                    spellCheck={false}
                  />
                  <span className="field-hint">
                    Resolver público é recusado pelas listas.
                  </span>
                </div>
                <div className="field field-narrow">
                  <label htmlFor="conc">Simultâneas</label>
                  <input
                    id="conc"
                    type="number"
                    min={1}
                    max={200}
                    value={concurrency}
                    onChange={(e) => setConcurrency(Number(e.target.value))}
                  />
                  <span className="field-hint">consultas em paralelo</span>
                </div>
                <div className="field field-narrow">
                  <label htmlFor="perzone">Por lista</label>
                  <input
                    id="perzone"
                    type="number"
                    min={1}
                    max={50}
                    value={perZone}
                    onChange={(e) => setPerZone(Number(e.target.value))}
                  />
                  <span className="field-hint">acima de 10, a lista bloqueia</span>
                </div>
                <label className="check">
                  <input
                    type="checkbox"
                    checked={checkRdns}
                    onChange={(e) => setCheckRdns(e.target.checked)}
                  />
                  Auditar rDNS junto
                </label>
              </div>
            )}
          </section>

          {scan.error && (
            <div className="notice notice-error">
              <strong>Falhou.</strong> {scan.error}
            </div>
          )}

          {scan.warnings.map((w) => (
            <div key={w} className="notice notice-warn">
              {w}
            </div>
          ))}

          {(scanning || scan.report) && (
            <div className="rail">
              <div className="rail-bar">
                <div className="rail-fill" style={{ width: `${pct}%` }} />
              </div>
              <div className="rail-meta">
                <span>{scan.network ?? cidr}</span>
                <span>
                  {scan.progress.done}/{scan.progress.total} endereços
                </span>
                <span>~{scan.progress.queries} consultas DNS</span>
                <span className="rail-pct">{pct}%</span>
              </div>
            </div>
          )}

          <main className="grid">
            <div className="col-map">
              <BlockMap
                cidr={cidr}
                cells={scan.cells}
                scanning={scanning}
                onPick={setFocus}
              />
              {scan.report && (
                <>
                  <Diagnostics report={scan.report} />
                  <ActionPlan report={scan.report} onGoTo={setTab} />
                </>
              )}
            </div>
            <div className="col-side">
              <Summary report={scan.report} live={live} />
            </div>
          </main>

          {scan.report && (
            <>
              <ListTable report={scan.report} />
              <IpTable report={scan.report} focus={focus} onExport={download} />
              <Correlation
                cidr={scan.report.network}
                hasAnalysis={analysis !== null}
              />
            </>
          )}

          {zones && (
            <section className="panel panel-wide">
              <h2 className="eyebrow">Resposta das listas</h2>
              <p className="panel-note" style={{ margin: "0 0 10px" }}>
                Consulta de teste 127.0.0.2 em cada lista. Lista que não responde
                é excluída da varredura: os resultados dela seriam
                indistinguíveis de "limpo".
              </p>
              <ul className="zones">
                {zones.map((z) => (
                  <li key={z.rbl} className={`zone zone-${z.status}`}>
                    <span className="zone-name">{z.rbl}</span>
                    <span className="zone-status">{z.status.replace("_", " ")}</span>
                    <span className="zone-detail">{z.detail}</span>
                  </li>
                ))}
              </ul>
            </section>
          )}
        </>
      )}

      <footer className="foot">
        Consultas DNS saem do backend, não do navegador. Listas públicas têm
        política de uso justo: uma varredura por bloco por dia é suficiente.
      </footer>
    </div>
  );
}

function Tab({
  id,
  atual,
  onSel,
  label,
  badge,
}: {
  id: "scan" | "config" | "dns";
  atual: string;
  onSel: (t: "scan" | "config" | "dns") => void;
  label: string;
  badge?: string;
}) {
  return (
    <button
      type="button"
      role="tab"
      aria-selected={atual === id}
      className={`tab${atual === id ? " is-on" : ""}`}
      onClick={() => onSel(id)}
    >
      {label}
      {badge && <span className="tab-badge">{badge}</span>}
    </button>
  );
}

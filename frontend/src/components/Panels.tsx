import type { Report } from "../types";

/* ---------------------------------------------------------------- Resumo */
export function Summary({
  report,
  live,
}: {
  report: Report | null;
  live: { behavior: number; policy: number; clean: number; pending: number };
}) {
  const c = report?.counts ?? live;
  const total = report?.total ?? live.behavior + live.policy + live.clean + live.pending;

  return (
    <section className="panel">
      <h2 className="eyebrow">Classificação</h2>

      <ul className="tally">
        <TallyRow
          kind="behavior"
          label="Emissão observada"
          value={c.behavior}
          total={total}
          hint="Spam ou abuso real. Não sai corrigindo DNS."
        />
        <TallyRow
          kind="policy"
          label="Listado por política"
          value={c.policy}
          total={total}
          hint="Deriva do rDNS ausente ou genérico."
        />
        <TallyRow
          kind="clean"
          label="Sem listagem"
          value={c.clean}
          total={total}
        />
        {!report && live.pending > 0 && (
          <TallyRow kind="pending" label="Aguardando" value={live.pending} total={total} />
        )}
      </ul>

      {report && (
        <p className="panel-note">
          Varredura concluída em {report.elapsed}s · {report.listed} de{" "}
          {report.total} endereços listados
        </p>
      )}
    </section>
  );
}

function TallyRow({
  kind,
  label,
  value,
  total,
  hint,
}: {
  kind: string;
  label: string;
  value: number;
  total: number;
  hint?: string;
}) {
  const pct = total ? Math.round((value / total) * 100) : 0;
  return (
    <li className="tally-row">
      <div className="tally-head">
        <span className={`swatch swatch-${kind}`} aria-hidden="true" />
        <span className="tally-label">{label}</span>
        <span className="tally-value">{value}</span>
      </div>
      <div className="tally-bar">
        <div className={`tally-fill tally-fill-${kind}`} style={{ width: `${pct}%` }} />
      </div>
      {hint && <p className="tally-hint">{hint}</p>}
    </li>
  );
}

/* ----------------------------------------------------------- Plano de ação */
const PASSO_ABA: Record<string, "config" | "dns" | null> = {
  behavior: "config",
  delegacao: "dns",
  "rdns-ausente": "dns",
  "rdns-generico": "dns",
  fcrdns: "dns",
  delist: null,
};

const NOME_ABA = { config: "análise de configuração", dns: "DNS" } as const;

export function ActionPlan({
  report,
  onGoTo,
}: {
  report: Report;
  onGoTo: (tab: "config" | "dns") => void;
}) {
  return (
    <section className="panel panel-wide">
      <h2 className="eyebrow">Ordem de ataque</h2>
      <ol className="plan">
        {report.plan.map((step, i) => (
          <li key={step.kind} className={`plan-step plan-${step.kind}`}>
            <span className="plan-index">{i + 1}</span>
            <div className="plan-body">
              <h3>{step.title}</h3>
              <p>{step.body}</p>
              {step.prefixes.length > 0 && (
                <p className="plan-prefixes">
                  {step.prefixes.slice(0, 10).join("  ")}
                  {step.prefixes.length > 10 && ` … +${step.prefixes.length - 10}`}
                </p>
              )}
              {PASSO_ABA[step.kind] && (
                <button
                  type="button"
                  className="link plan-link"
                  onClick={() => onGoTo(PASSO_ABA[step.kind]!)}
                >
                  tratar na aba {NOME_ABA[PASSO_ABA[step.kind]!]} →
                </button>
              )}
            </div>
          </li>
        ))}
      </ol>
    </section>
  );
}

/* -------------------------------------------------------------- Listas */
const SEVERITY_LABEL: Record<number, string> = {
  3: "crítica",
  2: "relevante",
  1: "nicho",
};

export function ListTable({ report }: { report: Report }) {
  if (report.lists.length === 0) {
    return (
      <section className="panel panel-wide">
        <h2 className="eyebrow">Listas</h2>
        <p className="empty">
          Nenhuma listagem encontrada nas listas consultadas. Se você esperava
          listagem aqui, rode a verificação de zonas: lista bloqueada responde
          NXDOMAIN e o bloco parece limpo.
        </p>
      </section>
    );
  }

  return (
    <section className="panel panel-wide">
      <h2 className="eyebrow">Listas</h2>
      <div className="lists">
        {report.lists.map((l) => (
          <article key={l.name} className={`list-card sev-${l.severity}`}>
            <header className="list-head">
              <h3>{l.name}</h3>
              <span className="sev">{SEVERITY_LABEL[l.severity] ?? "—"}</span>
              <span className="list-count">
                {l.count}
                <span className="stat-of">/{report.total}</span>
              </span>
            </header>
            <ul className="reasons">
              {l.meanings.map((m) => (
                <li key={m}>{m}</li>
              ))}
            </ul>
            <p className="list-prefixes">
              {l.prefixes.slice(0, 8).join("  ")}
              {l.prefixes.length > 8 && ` … +${l.prefixes.length - 8}`}
            </p>
            <p className="list-note">{l.note}</p>
            {l.delist && (
              <a className="list-link" href={l.delist} target="_blank" rel="noreferrer">
                Página de remoção ↗
              </a>
            )}
          </article>
        ))}
      </div>
    </section>
  );
}

/* ---------------------------------------------------------- Diagnóstico */
/**
 * Só aparece quando alguma lista teve consulta sem resposta. Existe porque
 * "0 listagens" e "0 respostas" são coisas opostas que pareciam idênticas na
 * tela: falha de resolver saía pintada de verde.
 */
export function Diagnostics({ report }: { report: Report }) {
  const shaky = report.diagnostics.filter((d) => !d.reliable);
  if (shaky.length === 0) return null;

  return (
    <section className="panel panel-wide">
      <h2 className="eyebrow">Confiabilidade da varredura</h2>
      <p className="empty" style={{ marginBottom: 12 }}>
        Consulta sem resposta não é o mesmo que endereço não listado. As listas
        abaixo tiveram falhas e o resultado delas está incompleto.
      </p>
      <table className="ips">
        <thead>
          <tr>
            <th scope="col">Lista</th>
            <th scope="col">Consultas</th>
            <th scope="col">Listados</th>
            <th scope="col">Resposta negativa</th>
            <th scope="col">Sem resposta</th>
            <th scope="col">Falha</th>
          </tr>
        </thead>
        <tbody>
          {shaky.map((d) => (
            <tr key={d.rbl}>
              <td className="col-ip">{d.rbl}</td>
              <td>{d.queried}</td>
              <td>{d.listed}</td>
              <td>{d.negative}</td>
              <td>
                <span className="tag tag-behavior">{d.errors}</span>
              </td>
              <td className="col-reason">{d.error_kinds.join(", ") || "—"}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </section>
  );
}

import { useMemo, useState } from "react";
import type { Report, Row } from "../types";

type Filter = "all" | "behavior" | "policy" | "clean";

const FILTERS: { id: Filter; label: string }[] = [
  { id: "behavior", label: "Emissão" },
  { id: "policy", label: "Política" },
  { id: "clean", label: "Sem listagem" },
  { id: "all", label: "Todos" },
];

export default function IpTable({
  report,
  focus,
  onExport,
}: {
  report: Report;
  focus: string | null;
  onExport: (fmt: "csv" | "json") => void;
}) {
  const [filter, setFilter] = useState<Filter>(
    report.counts.behavior > 0 ? "behavior" : "all"
  );
  const [query, setQuery] = useState("");

  const rows = useMemo(() => {
    const q = query.trim().toLowerCase();
    return report.rows.filter((r) => {
      if (filter !== "all" && r.classification !== filter) return false;
      if (!q) return true;
      return (
        r.ip.includes(q) ||
        r.ptr.toLowerCase().includes(q) ||
        r.lists.some((l) => l.toLowerCase().includes(q)) ||
        r.reasons.some((m) => m.toLowerCase().includes(q))
      );
    });
  }, [report.rows, filter, query]);

  const countFor = (f: Filter) =>
    f === "all" ? report.rows.length : report.rows.filter((r) => r.classification === f).length;

  return (
    <section className="panel panel-wide">
      <div className="table-bar">
        <h2 className="eyebrow">Endereços</h2>
        <div className="chips">
          {FILTERS.map((f) => (
            <button
              key={f.id}
              type="button"
              className={`chip${filter === f.id ? " is-on" : ""}`}
              onClick={() => setFilter(f.id)}
            >
              {f.label}
              <span className="chip-count">{countFor(f.id)}</span>
            </button>
          ))}
        </div>
        <input
          className="search"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder="Filtrar por IP, PTR ou lista"
          aria-label="Filtrar endereços"
        />
        <div className="exports">
          <button type="button" className="ghost" onClick={() => onExport("csv")}>
            Baixar CSV
          </button>
          <button type="button" className="ghost" onClick={() => onExport("json")}>
            Baixar JSON
          </button>
        </div>
      </div>

      {rows.length === 0 ? (
        <p className="empty">Nenhum endereço corresponde a esse filtro.</p>
      ) : (
        <div className="table-wrap">
          <table className="ips">
            <thead>
              <tr>
                <th scope="col">Endereço</th>
                <th scope="col">Classificação</th>
                <th scope="col">Listas</th>
                <th scope="col">Motivo</th>
                <th scope="col">PTR</th>
              </tr>
            </thead>
            <tbody>
              {rows.slice(0, 500).map((r) => (
                <IpRow key={r.ip} row={r} highlight={r.ip === focus} />
              ))}
            </tbody>
          </table>
          {rows.length > 500 && (
            <p className="panel-note">
              Mostrando 500 de {rows.length} linhas. Baixe o CSV para a lista completa.
            </p>
          )}
        </div>
      )}
    </section>
  );
}

function IpRow({ row, highlight }: { row: Row; highlight: boolean }) {
  return (
    <tr className={highlight ? "is-focus" : undefined}>
      <td className="col-ip">{row.ip}</td>
      <td>
        <span className={`tag tag-${row.classification}`}>
          {row.classification === "behavior"
            ? "emissão"
            : row.classification === "policy"
              ? "política"
              : "limpo"}
        </span>
      </td>
      <td className="col-lists">{row.lists.join(" · ") || "—"}</td>
      <td className="col-reason">{row.reasons.join(" · ") || "—"}</td>
      <td className="col-ptr">
        {row.ptr ? (
          <>
            {row.ptr}
            {row.fcrdns === false && <span className="flag">falta registro A</span>}
            {row.ptr_status === "generico" && <span className="flag">genérico</span>}
          </>
        ) : (
          <span className="missing">sem PTR</span>
        )}
      </td>
    </tr>
  );
}

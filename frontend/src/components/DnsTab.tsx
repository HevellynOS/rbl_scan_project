import { useState } from "react";
import type { Report } from "../types";
import { ZoneBuilder } from "./Correlate";
import DnsConfigCheck from "./DnsConfigCheck";

/**
 * Aba DNS. Reúne tudo que depende do DNS reverso: auditoria de PTR, estado da
 * delegação e geração da zona.
 *
 * Ficava espremido na coluna de 300px do resumo, onde o nome da zona e o NS
 * eram truncados. Aqui cada item tem a largura que o conteúdo exige.
 */
export default function DnsTab({ report }: { report: Report | null }) {
  if (!report) {
    // A validação de arquivo de zona não depende de varredura: é auditoria
    // sobre a configuração, não sobre o que está publicado.
    return (
      <>
        <section className="panel panel-wide">
          <h2 className="eyebrow">DNS reverso publicado</h2>
          <p className="empty">
            Rode a varredura de um bloco para ver o estado do que está no ar. A
            auditoria de PTR e a verificação de delegação acontecem junto com
            ela.
          </p>
        </section>
        <DnsConfigCheck />
      </>
    );
  }

  const r = report.rdns;
  const naoDelegadas = report.delegation.filter((d) => !d.delegated);
  const lame = report.delegation.filter((d) => d.delegated && !d.soa);
  const passos = report.plan.filter((p) =>
    ["delegacao", "rdns-ausente", "rdns-generico", "fcrdns"].includes(p.kind)
  );

  return (
    <>
      <section className="panel panel-wide">
        <h2 className="eyebrow">DNS reverso de {report.network}</h2>

        <div className="rdns-row">
          <Card
            label="Sem PTR"
            value={r.no_ptr}
            of={r.audited}
            tone={r.no_ptr ? "bad" : "ok"}
            hint="Nenhum registro. Precisa ser criado."
          />
          <Card
            label="PTR genérico"
            value={r.generic}
            of={r.audited}
            tone={r.generic ? "warn" : "ok"}
            hint="Existe, mas com assinatura de faixa dinâmica."
          />
          <Card
            label="Registro A faltando"
            value={r.fcrdns_broken}
            of={r.with_ptr}
            tone={r.fcrdns_broken ? "bad" : "ok"}
            hint="O PTR não resolve de volta para o IP."
          />
          <Card
            label="PTR correto"
            value={r.clean}
            of={r.audited}
            tone={r.clean ? "ok" : "warn"}
            hint="Nome próprio e forward confirmado."
          />
        </div>

        {r.fcrdns_systemic && (
          <p className="alerta">
            {Math.round(r.fcrdns_rate * 100)}% dos PTRs não resolvem de volta para
            o IP. Taxa nessa ordem é configuração ausente, não erro pontual: a
            zona reversa existe e a direta não. Cada nome publicado no PTR
            precisa de um registro A apontando para o mesmo endereço.
          </p>
        )}

        {r.sample_generic && (
          <p className="amostra">
            Exemplo de PTR genérico: <code>{r.sample_generic.ip}</code> responde{" "}
            <code>{r.sample_generic.ptr}</code> ({r.sample_generic.issue}). Ter
            reverso não é o mesmo que ter reverso aceitável: embutir os octetos
            do IP no hostname é o que faz a Spamhaus inferir espaço de usuário
            final mesmo havendo PTR.
          </p>
        )}
      </section>

      {report.delegation.length > 0 && (
        <section className="panel panel-wide">
          <h2 className="eyebrow">Delegação da zona reversa</h2>

          {naoDelegadas.length > 0 && (
            <div className="notice notice-error">
              {naoDelegadas.length} zona(s) não existem na hierarquia do DNS.
              Enquanto isso não for resolvido, criar PTR não produz efeito:
              nenhum resolver do mundo sabe a quem perguntar.
            </div>
          )}
          {lame.length > 0 && (
            <div className="notice notice-warn">
              {lame.length} zona(s) com NS apontado mas sem SOA. Cada consulta
              reversa vira timeout, o que é pior que a ausência de delegação.
            </div>
          )}

          <div className="table-wrap">
            <table className="ips">
              <thead>
                <tr>
                  <th scope="col">Zona</th>
                  <th scope="col">Estado</th>
                  <th scope="col">Servidores</th>
                  <th scope="col">Observação</th>
                </tr>
              </thead>
              <tbody>
                {report.delegation.map((d) => (
                  <tr key={d.zone}>
                    <td className="col-ip">{d.zone}</td>
                    <td>
                      <span
                        className={`tag tag-${
                          d.delegated ? (d.soa ? "clean" : "policy") : "behavior"
                        }`}
                      >
                        {d.delegated ? (d.soa ? "delegada" : "sem SOA") : "não delegada"}
                      </span>
                    </td>
                    <td className="col-lists">{d.ns.join(", ") || "—"}</td>
                    <td className="col-reason">{d.soa || d.detail || "—"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      )}

      {passos.length > 0 && (
        <section className="panel panel-wide">
          <h2 className="eyebrow">O que corrigir, nesta ordem</h2>
          <ol className="plan">
            {passos.map((step, i) => (
              <li key={step.kind} className={`plan-step plan-${step.kind}`}>
                <span className="plan-index">{i + 1}</span>
                <div className="plan-body">
                  <h3>{step.title}</h3>
                  <p>{step.body}</p>
                  {step.prefixes.length > 0 && (
                    <p className="plan-prefixes">
                      {step.prefixes.slice(0, 10).join("  ")}
                      {step.prefixes.length > 10 &&
                        ` … +${step.prefixes.length - 10}`}
                    </p>
                  )}
                </div>
              </li>
            ))}
          </ol>
          {report.counts.behavior > 0 && (
            <p className="alerta">
              {report.counts.behavior} endereço(s) com emissão ativa. Corrigir o
              reverso antes de contê-los é contraproducente: rDNS limpo aumenta a
              entregabilidade, então o spam passa a chegar melhor.
            </p>
          )}
        </section>
      )}

      <DnsConfigCheck />
      <RelatorioPdf report={report} />
      <ZoneBuilder cidr={report.network} />
    </>
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

/* ------------------------------------------------- relatório executivo */
/**
 * Gera o PDF a partir do relatório que já está em memória no backend. O
 * documento é feito para sair da empresa: usa só dado público (registros DNS,
 * delegação, contagens agregadas) e omite deliberadamente topologia interna,
 * identificação de equipamento e os endereços com emissão ativa.
 */
function RelatorioPdf({ report }: { report: Report }) {
  const [cliente, setCliente] = useState("");
  const [preparado, setPreparado] = useState("");
  const [obs, setObs] = useState("");
  const [dominio, setDominio] = useState("");
  const [busy, setBusy] = useState(false);
  const [erro, setErro] = useState<string | null>(null);

  async function gerar() {
    setBusy(true);
    setErro(null);
    try {
      const res = await fetch("/api/dns-report", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          cidr: report.network,
          cliente,
          preparado_por: preparado,
          observacoes: obs,
          dominio_exemplo: dominio,
        }),
      });
      if (!res.ok) {
        const body = await res.json().catch(() => null);
        setErro(body?.detail ?? `HTTP ${res.status}`);
        return;
      }
      const blob = await res.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `dns-${report.network.replace(/[./]/g, "-")}.pdf`;
      a.click();
      URL.revokeObjectURL(url);
    } catch {
      setErro("Falha ao falar com o backend.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="panel panel-wide">
      <h2 className="eyebrow">Relatório executivo</h2>
      <p className="lede">
        PDF sobre o DNS reverso de {report.network}, escrito para quem não é do
        time de rede: o provedor de DNS, o upstream do bloco, o time de TI de
        quem reclamou de entrega. Inclui uma seção mostrando como fica a
        configuração correta, com exemplo dos dois registros que cada endereço
        precisa ter.
      </p>

      <div className="gov-form">
        <div className="field">
          <label htmlFor="rp-cli">Cliente</label>
          <input
            id="rp-cli"
            value={cliente}
            onChange={(e) => setCliente(e.target.value)}
            placeholder="nome do provedor auditado"
          />
          <span className="field-hint">aparece no cabeçalho</span>
        </div>
        <div className="field">
          <label htmlFor="rp-dom">Domínio nos exemplos</label>
          <input
            id="rp-dom"
            value={dominio}
            onChange={(e) => setDominio(e.target.value)}
            placeholder="detectado automaticamente"
          />
          <span className="field-hint">usado na seção de exemplo</span>
        </div>
        <div className="field">
          <label htmlFor="rp-por">Preparado por</label>
          <input
            id="rp-por"
            value={preparado}
            onChange={(e) => setPreparado(e.target.value)}
            placeholder="responsável técnico"
          />
          <span className="field-hint">aparece no rodapé</span>
        </div>
      </div>

      <div className="field" style={{ marginTop: 12 }}>
        <label htmlFor="rp-obs">Observações</label>
        <textarea
          id="rp-obs"
          className="gov-textarea"
          rows={3}
          value={obs}
          onChange={(e) => setObs(e.target.value)}
          placeholder="Contexto adicional para quem vai ler. Opcional."
        />
        <span className="field-hint">
          Não inclua dado sensível aqui: o documento sai da empresa.
        </span>
      </div>

      <div className="analyze-actions">
        <button type="button" className="primary" onClick={gerar} disabled={busy}>
          {busy ? "Gerando…" : "Gerar relatório PDF"}
        </button>
      </div>

      {erro && (
        <div className="notice notice-warn" style={{ marginTop: 12 }}>
          {erro}
        </div>
      )}

      <p className="panel-note">
        O documento traz apenas informação pública e verificável: registros de
        DNS, estado da delegação e contagens agregadas. Faixas privadas,
        identificação de equipamentos e os endereços com emissão ativa ficam de
        fora por serem informação sensível da rede auditada
        {report.counts.behavior > 0 &&
          ` — os ${report.counts.behavior} endereços nessa condição são citados
           apenas como quantidade`}
        .
      </p>
    </section>
  );
}

import { useState } from "react";
import type { DnsValidation, Report } from "../types";
import { ZoneBuilder } from "./Correlate";
import DnsChain from "./DnsChain";
import DnsConfigCheck from "./DnsConfigCheck";

/**
 * Aba DNS. Reúne tudo que depende do DNS reverso: auditoria de PTR, estado da
 * delegação e geração da zona.
 *
 * Ficava espremido na coluna de 300px do resumo, onde o nome da zona e o NS
 * eram truncados. Aqui cada item tem a largura que o conteúdo exige.
 */
export default function DnsTab({ report }: { report: Report | null }) {
  // A validação de arquivos alimenta a verificação de cadeia: os domínios
  // usados nos PTR saem dela.
  const [validacao, setValidacao] = useState<DnsValidation | null>(null);

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
        <DnsConfigCheck onResultado={setValidacao} />
        <DnsChain analise={validacao} />
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

      <DnsConfigCheck onResultado={setValidacao} />
      <DnsChain analise={validacao} />
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

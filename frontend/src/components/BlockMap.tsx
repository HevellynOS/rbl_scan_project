import { useMemo, useState } from "react";
import type { CellState } from "../useScan";
import { intToIp, parseCidr } from "../useScan";

interface Props {
  cidr: string;
  cells: Map<string, CellState>;
  scanning: boolean;
  onPick: (ip: string) => void;
}

const COLS = 32;

/**
 * Uma célula por endereço do bloco. É a leitura que a saída em texto esconde:
 * campo uniforme = listagem de política (rDNS); pontos espalhados = emissão real.
 */
export default function BlockMap({ cidr, cells, scanning, onPick }: Props) {
  const [hover, setHover] = useState<CellState | null>(null);
  const parsed = useMemo(() => parseCidr(cidr), [cidr]);

  if (!parsed) {
    return (
      <div className="map-empty">
        Informe um bloco no formato <code>179.108.72.0/24</code> para desenhar o mapa.
      </div>
    );
  }

  const { base, size } = parsed;
  const capped = Math.min(size, 4096);
  const addresses = Array.from({ length: capped }, (_, i) => intToIp(base + i));
  const rows = Math.ceil(capped / COLS);

  return (
    <div className="map">
      <div className="map-head">
        <div className="map-axis">
          <span>{intToIp(base)}</span>
          <span className="map-axis-mid">
            {rows} linhas × {COLS} colunas
          </span>
          <span>{intToIp(base + capped - 1)}</span>
        </div>
      </div>

      <div
        className={`map-grid${scanning ? " is-scanning" : ""}`}
        style={{ gridTemplateColumns: `repeat(${COLS}, 1fr)` }}
        onMouseLeave={() => setHover(null)}
        role="group"
        aria-label={`Mapa de endereços de ${cidr}`}
      >
        {addresses.map((ip) => {
          const cell = cells.get(ip);
          const cls = cell?.classification ?? "pending";
          return (
            <button
              key={ip}
              type="button"
              className={`cell cell-${cls}`}
              onMouseEnter={() => cell && setHover(cell)}
              onFocus={() => cell && setHover(cell)}
              onClick={() => onPick(ip)}
              aria-label={`${ip}: ${labelFor(cls)}`}
              title={ip}
            />
          );
        })}
      </div>

      <div className="map-foot">
        {hover ? (
          <div className="probe">
            <span className="probe-ip">{hover.ip}</span>
            <span className={`tag tag-${hover.classification}`}>
              {labelFor(hover.classification)}
            </span>
            {hover.lists.length > 0 && (
              <span className="probe-lists">{hover.lists.join(" · ")}</span>
            )}
            {hover.ptr ? (
              <span className="probe-ptr">{hover.ptr}</span>
            ) : (
              <span className="probe-ptr probe-ptr-missing">sem PTR</span>
            )}
          </div>
        ) : (
          <div className="probe probe-idle">
            Passe o cursor sobre uma célula para ver o endereço e suas listagens.
          </div>
        )}
      </div>

      {size > capped && (
        <p className="map-note">
          Mostrando os primeiros {capped} de {size} endereços.
        </p>
      )}
    </div>
  );
}

function labelFor(c: string): string {
  if (c === "behavior") return "emissão observada";
  if (c === "policy") return "listado por política";
  if (c === "clean") return "sem listagem";
  return "aguardando";
}

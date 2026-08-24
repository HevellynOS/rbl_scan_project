import { useCallback, useEffect, useRef, useState } from "react";
import type {
  Classification,
  Hit,
  Report,
  ScanEvent,
  ScanParams,
} from "./types";

export type Status = "idle" | "scanning" | "done" | "error";

export interface CellState {
  ip: string;
  classification: Classification;
  lists: string[];
  reasons: string[];
  ptr: string;
}

export function ipToInt(ip: string): number {
  return ip.split(".").reduce((acc, o) => acc * 256 + Number(o), 0);
}

export function intToIp(n: number): string {
  return [n >>> 24, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join(".");
}

/** Primeiro endereço e tamanho de um CIDR, sem dependência externa. */
export function parseCidr(cidr: string): { base: number; size: number } | null {
  const m = cidr.trim().match(/^(\d{1,3}(?:\.\d{1,3}){3})\/(\d{1,2})$/);
  if (!m) return null;
  const [, ip, bitsRaw] = m;
  const bits = Number(bitsRaw);
  if (bits < 0 || bits > 32) return null;
  if (ip.split(".").some((o) => Number(o) > 255)) return null;
  const size = 2 ** (32 - bits);
  const base = Math.floor(ipToInt(ip) / size) * size;
  return { base, size };
}

export function useScan() {
  const [status, setStatus] = useState<Status>("idle");
  const [error, setError] = useState<string | null>(null);
  const [warnings, setWarnings] = useState<string[]>([]);
  const [network, setNetwork] = useState<string | null>(null);
  const [progress, setProgress] = useState({ done: 0, total: 0, queries: 0 });
  const [cells, setCells] = useState<Map<string, CellState>>(new Map());
  const [report, setReport] = useState<Report | null>(null);
  const [startedAt, setStartedAt] = useState<number | null>(null);

  const wsRef = useRef<WebSocket | null>(null);
  const bufferRef = useRef<Map<string, CellState>>(new Map());
  const flushRef = useRef<number | null>(null);

  // Um /23 gera 512 eventos. Sem lote, cada um viraria um re-render.
  const scheduleFlush = useCallback(() => {
    if (flushRef.current !== null) return;
    flushRef.current = window.setTimeout(() => {
      flushRef.current = null;
      setCells(new Map(bufferRef.current));
    }, 80);
  }, []);

  const stop = useCallback(() => {
    wsRef.current?.close();
    wsRef.current = null;
  }, []);

  const start = useCallback(
    (params: ScanParams) => {
      stop();
      bufferRef.current = new Map();
      setCells(new Map());
      setReport(null);
      setError(null);
      setWarnings([]);
      setNetwork(null);
      setProgress({ done: 0, total: 0, queries: 0 });
      setStatus("scanning");
      setStartedAt(Date.now());

      const proto = window.location.protocol === "https:" ? "wss:" : "ws:";
      const ws = new WebSocket(`${proto}//${window.location.host}/ws/scan`);
      wsRef.current = ws;

      ws.onopen = () => ws.send(JSON.stringify(params));

      ws.onmessage = (ev) => {
        const data: ScanEvent = JSON.parse(ev.data);
        switch (data.type) {
          case "start":
            setNetwork(data.network);
            setProgress({ done: 0, total: data.ips, queries: data.queries });
            setWarnings(data.warnings);
            break;
          case "ip": {
            const lists = data.hits.map((h: Hit) => h.rbl);
            const reasons = Array.from(
              new Set(data.hits.flatMap((h) => h.entries.map((e) => e.meaning)))
            );
            bufferRef.current.set(data.ip, {
              ip: data.ip,
              classification: data.classification,
              lists,
              reasons,
              ptr: data.ptr?.ptr ?? "",
            });
            setProgress((p) => ({ ...p, done: data.done, total: data.total }));
            scheduleFlush();
            break;
          }
          case "done":
            setCells(new Map(bufferRef.current));
            setReport(data.report);
            setWarnings(data.report.warnings);
            setStatus("done");
            break;
          case "error":
            setError(data.message);
            setStatus("error");
            break;
        }
      };

      ws.onerror = () => {
        setError(
          "Não foi possível falar com o backend. Confirme que o uvicorn está no ar na porta 8000."
        );
        setStatus("error");
      };

      ws.onclose = () => {
        setStatus((s) => (s === "scanning" ? "idle" : s));
      };
    },
    [scheduleFlush, stop]
  );

  useEffect(() => () => stop(), [stop]);

  return {
    status,
    error,
    warnings,
    network,
    progress,
    cells,
    report,
    startedAt,
    start,
    stop,
  };
}

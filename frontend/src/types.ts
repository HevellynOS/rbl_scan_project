export type Classification = "clean" | "policy" | "behavior" | "pending";

export interface Entry {
  code: string;
  meaning: string;
  kind: "policy" | "behavior";
}

export interface Hit {
  ip: string;
  rbl: string;
  severity: number;
  entries: Entry[];
}

export interface PtrAudit {
  ip: string;
  ptr: string;
  fcrdns: boolean | null;
  generic: boolean;
  issue: string;
}

export interface ListSummary {
  name: string;
  severity: number;
  note: string;
  delist: string;
  count: number;
  prefixes: string[];
  meanings: string[];
}

export interface Row {
  ip: string;
  classification: Exclude<Classification, "pending">;
  lists: string[];
  reasons: string[];
  ptr: string;
  ptr_status: "ausente" | "generico" | "ok" | "";
  ptr_generic: boolean;
  fcrdns: boolean | null;
}

export interface Delegation {
  zone: string;
  delegated: boolean;
  ns: string[];
  soa: string;
  detail: string;
}

export interface PlanStep {
  kind:
    | "behavior"
    | "delegacao"
    | "rdns-ausente"
    | "rdns-generico"
    | "fcrdns"
    | "delist";
  title: string;
  body: string;
  prefixes: string[];
}

export interface Report {
  network: string;
  total: number;
  elapsed: number;
  listed: number;
  counts: { behavior: number; policy: number; clean: number };
  rdns: {
    no_ptr: number;
    generic: number;
    with_ptr: number;
    fcrdns_broken: number;
    fcrdns_rate: number;
    fcrdns_systemic: boolean;
    clean: number;
    audited: number;
    no_ptr_prefixes: string[];
    generic_prefixes: string[];
    sample_generic: { ip: string; ptr: string; issue: string } | null;
  };
  delegation: Delegation[];
  lists: ListSummary[];
  rows: Row[];
  plan: PlanStep[];
  warnings: string[];
  diagnostics: Diagnostic[];
}

export interface Diagnostic {
  rbl: string;
  queried: number;
  listed: number;
  negative: number;
  errors: number;
  error_kinds: string[];
  reliable: boolean;
}

export type ScanEvent =
  | {
      type: "start";
      network: string;
      ips: number;
      rbls: string[];
      queries: number;
      warnings: string[];
      probe: ZoneCheck[];
      delegation: Delegation[];
    }
  | {
      type: "ip";
      ip: string;
      hits: Hit[];
      ptr: PtrAudit | null;
      done: number;
      total: number;
      classification: Exclude<Classification, "pending">;
    }
  | { type: "done"; report: Report }
  | { type: "error"; message: string };

export interface ScanParams {
  cidr: string;
  profile: "core" | "full";
  resolver?: string;
  concurrency: number;
  per_zone: number;
  timeout: number;
  check_rdns: boolean;
}

export interface ZoneCheck {
  rbl: string;
  status: "ok" | "sem_resposta" | "falha";
  detail: string;
}

/* ------------------------------------------------ análise de configuração */
export interface Finding {
  id: string;
  severity: number;
  severity_label: string;
  role: string;
  title: string;
  evidence: string[];
  why: string;
  rbl_link: string;
  commands: string[];
  risk: string;
  manual: boolean;
}

export interface DeviceAnalysis {
  file: string;
  vendor: string;
  identity: string;
  model: string;
  version: string;
  role: string;
  role_reasons: string[];
  rules: number;
  cgnat: {
    public: string[];
    private: string[];
    deterministic: boolean;
    rules: number;
    subscribers_per_ip: number;
  };
  findings: Finding[];
  counts: Record<string, number>;
}

export interface Analysis {
  generated: string;
  devices: DeviceAnalysis[];
  totals: {
    crítico: number;
    importante: number;
    recomendado: number;
    informativo: number;
    manual: number;
  };
  rsc: string;
  report: string;
}

/* --------------------------------------------- correlação e zona reversa */
export interface Candidato {
  assinante: string;
  portas: string;
  chain: string;
  faixa_privada: string;
}

export interface AchadoCorrelacao {
  ip: string;
  faixa_publica: string;
  listas: string[];
  motivos: string[];
  candidatos: Candidato[];
  total_candidatos: number;
  rastreavel: boolean;
}

export interface Correlation {
  network: string;
  emissores: number;
  cobertos: number;
  devices: {
    identity: string;
    file: string;
    role: string;
    deterministic: boolean;
    achados: AchadoCorrelacao[];
  }[];
  orfaos: string[];
  aviso_orfaos: string;
  como_usar: string;
}

export interface ZoneResult {
  zone_name: string;
  domain: string;
  reverse: string;
  forward: string;
  pools: string[];
  servicos: number;
  aviso: string;
}

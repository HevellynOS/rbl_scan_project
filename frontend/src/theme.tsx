import { useCallback, useEffect, useState } from "react";

export type Theme = "dark" | "light";

const KEY = "rblscan-theme";

/** Lê a escolha salva; se não houver, segue a preferência do sistema.
 *  O escuro é o padrão quando o sistema não informa nada. */
export function readTheme(): Theme {
  try {
    const saved = localStorage.getItem(KEY);
    if (saved === "dark" || saved === "light") return saved;
  } catch {
    /* localStorage bloqueado (modo privado, política do navegador) */
  }
  if (typeof window !== "undefined" && window.matchMedia) {
    return window.matchMedia("(prefers-color-scheme: light)").matches
      ? "light"
      : "dark";
  }
  return "dark";
}

export function useTheme() {
  const [theme, setTheme] = useState<Theme>(readTheme);

  useEffect(() => {
    document.documentElement.setAttribute("data-theme", theme);
    try {
      localStorage.setItem(KEY, theme);
    } catch {
      /* preferência não persiste, mas a sessão atual funciona */
    }
  }, [theme]);

  // Segue o sistema apenas enquanto o usuário não tiver escolhido.
  useEffect(() => {
    if (!window.matchMedia) return;
    let escolheu = false;
    try {
      escolheu = localStorage.getItem(KEY) !== null;
    } catch {
      /* sem localStorage, trata como não escolhido */
    }
    if (escolheu) return;

    const mq = window.matchMedia("(prefers-color-scheme: light)");
    const onChange = (e: MediaQueryListEvent) => setTheme(e.matches ? "light" : "dark");
    mq.addEventListener("change", onChange);
    return () => mq.removeEventListener("change", onChange);
  }, []);

  const toggle = useCallback(
    () => setTheme((t) => (t === "dark" ? "light" : "dark")),
    []
  );

  return { theme, toggle };
}

export function ThemeToggle({ theme, onToggle }: { theme: Theme; onToggle: () => void }) {
  const indoPara = theme === "dark" ? "claro" : "escuro";
  return (
    <button
      type="button"
      className="theme-toggle"
      onClick={onToggle}
      title={`Mudar para o tema ${indoPara}`}
      aria-label={`Mudar para o tema ${indoPara}`}
    >
      {theme === "dark" ? <SunIcon /> : <MoonIcon />}
      <span>{indoPara}</span>
    </button>
  );
}

function SunIcon() {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"
      strokeLinecap="round" aria-hidden="true">
      <circle cx="12" cy="12" r="4.2" />
      <path d="M12 2v2.6M12 19.4V22M2 12h2.6M19.4 12H22M4.9 4.9l1.9 1.9M17.2 17.2l1.9 1.9M19.1 4.9l-1.9 1.9M6.8 17.2l-1.9 1.9" />
    </svg>
  );
}

function MoonIcon() {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"
      strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <path d="M20.5 14.3A8.6 8.6 0 0 1 9.7 3.5a8.6 8.6 0 1 0 10.8 10.8z" />
    </svg>
  );
}

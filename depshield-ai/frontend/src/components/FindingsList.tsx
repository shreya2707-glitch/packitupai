import { LEVEL_COLOR, shortKey } from "../risk";
import type { Finding } from "../types";

interface Props {
  findings: Finding[];
  selectedId: number | null;
  upgrades: Record<string, string>;
  onSelect: (f: Finding) => void;
  onToggleUpgrade: (f: Finding) => void;
}

export default function FindingsList({ findings, selectedId, upgrades, onSelect, onToggleUpgrade }: Props) {
  if (findings.length === 0) {
    return <p className="py-6 text-muted">No known vulnerabilities in the scanned dependencies.</p>;
  }
  return (
    <ol className="border-t border-rule">
      {findings.map((f) => {
        const selected = f.id === selectedId;
        const color = LEVEL_COLOR[f.risk_level];
        return (
          <li key={f.id} className={`border-b border-l-4 border-b-rule pl-4 pr-2 py-4 ${selected ? "bg-panel" : ""}`} style={{ borderLeftColor: color }}>
            <button onClick={() => onSelect(f)} aria-expanded={selected} className="block w-full text-left">
              <span className="flex items-baseline justify-between gap-3">
                <span className="font-mono text-sm font-medium">
                  {f.package} <span className="text-muted">{f.version}</span>
                </span>
                <span className="text-sm font-semibold" style={{ color }}>
                  {Math.round(f.risk_score)} <span className="font-normal text-muted">{f.risk_level}</span>
                </span>
              </span>
              <span className="mt-0.5 block text-xs text-muted">
                {f.vuln_id}, CVSS {f.cvss.toFixed(1)}, {f.is_dev ? "dev only" : f.is_direct ? "direct" : "transitive"}
              </span>
            </button>

            {f.ai_explanation && <p className="mt-2 max-w-prose text-sm leading-relaxed">{f.ai_explanation}</p>}

            {selected && (
              <div className="mt-3 space-y-3 text-sm">
                {f.summary && <p className="text-muted">{f.summary}</p>}
                <div>
                  <p className="font-medium">Why this score</p>
                  <ul className="mt-1 list-disc space-y-0.5 pl-5 text-muted">{f.reasons.map((r) => <li key={r}>{r}</li>)}</ul>
                </div>
                <div>
                  <p className="font-medium">How it reaches your app</p>
                  <p className="mt-1 break-words font-mono text-xs text-muted">
                    {f.path.map((k) => (k === "app" ? "app" : shortKey(k))).join("  >  ")}
                  </p>
                </div>
                {f.apps.length > 1 && (
                  <p><span className="font-medium">Also used by:</span> <span className="text-muted">{f.apps.join(", ")}</span></p>
                )}
              </div>
            )}

            <label className={`mt-3 flex items-center gap-2 text-sm ${f.recommended_fix ? "" : "text-muted"}`}>
              <input type="checkbox" disabled={!f.recommended_fix} checked={f.package_key in upgrades} onChange={() => onToggleUpgrade(f)} />
              {f.recommended_fix ? (
                <span>Preview upgrade to <span className="font-mono">{f.recommended_fix}</span></span>
              ) : (
                <span>No patched version published</span>
              )}
            </label>
          </li>
        );
      })}
    </ol>
  );
}

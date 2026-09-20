import { LEVELS, LEVEL_COLOR } from "../risk";
import type { Level } from "../types";

export default function RiskBar({ counts }: { counts: Record<Level, number> }) {
  const total = LEVELS.reduce((n, l) => n + counts[l], 0);
  return (
    <div>
      <div className="flex h-2.5 overflow-hidden rounded-sm bg-rule" role="img"
        aria-label={LEVELS.map((l) => `${counts[l]} ${l}`).join(", ")}>
        {total > 0 && LEVELS.map((l) => counts[l] > 0 && (
          <div key={l} style={{ width: `${(counts[l] / total) * 100}%`, background: LEVEL_COLOR[l] }} />
        ))}
      </div>
      <dl className="mt-2 flex flex-wrap gap-x-5 gap-y-1 text-sm">
        {LEVELS.map((l) => (
          <div key={l} className="flex items-center gap-1.5">
            <span className="h-2.5 w-2.5 rounded-sm" style={{ background: LEVEL_COLOR[l] }} aria-hidden />
            <dt className="sr-only">{l}</dt>
            <dd><span className="font-semibold">{counts[l]}</span> <span className="text-muted">{l}</span></dd>
          </div>
        ))}
      </dl>
    </div>
  );
}

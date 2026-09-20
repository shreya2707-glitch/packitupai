import { useCallback, useEffect, useMemo, useState } from "react";
import { api, auth } from "./api";
import DependencyGraph from "./components/DependencyGraph";
import FindingsList from "./components/FindingsList";
import Login from "./components/Login";
import RiskBar from "./components/RiskBar";
import ScanForm from "./components/ScanForm";
import { LEVEL_COLOR } from "./risk";
import type { Finding, GraphData, Scan, Simulation } from "./types";

const cmpVersion = (a: string, b: string) => {
  const pa = a.split(/[.-]/).map((x) => parseInt(x, 10) || 0);
  const pb = b.split(/[.-]/).map((x) => parseInt(x, 10) || 0);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const d = (pa[i] ?? 0) - (pb[i] ?? 0);
    if (d) return d;
  }
  return 0;
};

export default function App() {
  const [authed, setAuthed] = useState(Boolean(auth.get()));
  if (!authed) return <Login onAuthed={() => setAuthed(true)} />;
  return <Dashboard onSignOut={() => { auth.clear(); setAuthed(false); }} />;
}

function Dashboard({ onSignOut }: { onSignOut: () => void }) {
  const [scans, setScans] = useState<Scan[]>([]);
  const [activeId, setActiveId] = useState<number | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [graph, setGraph] = useState<GraphData | null>(null);
  const [selected, setSelected] = useState<Finding | null>(null);
  const [upgrades, setUpgrades] = useState<Record<string, string>>({});
  const [sim, setSim] = useState<Simulation | null>(null);
  const [simBusy, setSimBusy] = useState(false);
  const [error, setError] = useState("");

  const active = scans.find((s) => s.id === activeId) ?? null;

  const refreshScans = useCallback(async () => {
    try {
      setScans(await api.scans());
    } catch (e) {
      setError(e instanceof Error ? e.message : "Could not load scans");
    }
  }, []);

  useEffect(() => { refreshScans(); }, [refreshScans]);

  // Poll while a scan is running.
  useEffect(() => {
    if (!active || !["queued", "running"].includes(active.status)) return;
    const t = setInterval(async () => {
      const fresh = await api.scan(active.id).catch(() => null);
      if (fresh) setScans((all) => all.map((s) => (s.id === fresh.id ? fresh : s)));
    }, 2000);
    return () => clearInterval(t);
  }, [active?.id, active?.status]);

  // Load results when the active scan is done.
  useEffect(() => {
    setFindings([]); setGraph(null); setSelected(null); setUpgrades({}); setSim(null);
    if (!active || active.status !== "done") return;
    Promise.all([api.findings(active.id), api.graph(active.id)])
      .then(([f, g]) => { setFindings(f); setGraph(g); })
      .catch((e) => setError(e.message));
  }, [active?.id, active?.status]);

  const toggleUpgrade = (f: Finding) => {
    setSim(null);
    setUpgrades((cur) => {
      const next = { ...cur };
      if (f.package_key in next) { delete next[f.package_key]; return next; }
      // use the highest fix among all advisories on this package version
      const fixes = findings.filter((x) => x.package_key === f.package_key && x.recommended_fix).map((x) => x.recommended_fix!);
      next[f.package_key] = fixes.sort(cmpVersion).at(-1)!;
      return next;
    });
  };

  const preview = async () => {
    if (!active) return;
    setSimBusy(true);
    try {
      setSim(await api.simulate(active.id, Object.entries(upgrades).map(([key, version]) => ({ key, version }))));
    } catch (e) {
      setError(e instanceof Error ? e.message : "Preview failed");
    } finally {
      setSimBusy(false);
    }
  };

  const highlight = useMemo(() => selected?.path ?? [], [selected]);
  const upgradeCount = Object.keys(upgrades).length;

  return (
    <div className="flex min-h-full flex-col lg:flex-row">
      <aside className="shrink-0 space-y-8 border-b border-rule bg-panel p-5 lg:min-h-screen lg:w-80 lg:border-b-0 lg:border-r">
        <h1 className="text-xl font-bold tracking-tight">DepShield AI</h1>
        <ScanForm onCreated={(s) => { setScans((all) => [s, ...all]); setActiveId(s.id); }} />
        <nav aria-label="Scans">
          <h2 className="text-sm font-semibold">Your scans</h2>
          {scans.length === 0 && <p className="mt-2 text-sm text-muted">Nothing scanned yet.</p>}
          <ul className="mt-2 divide-y divide-rule">
            {scans.map((s) => (
              <li key={s.id}>
                <button onClick={() => setActiveId(s.id)} aria-current={s.id === activeId}
                  className={`flex w-full items-center justify-between gap-2 py-2 text-left text-sm ${s.id === activeId ? "font-semibold" : ""}`}>
                  <span className="truncate">{s.name}</span>
                  <span className="shrink-0 text-xs text-muted">
                    {s.status === "done" && s.summary ? `risk ${Math.round(s.summary.overall_score)}` : s.status}
                  </span>
                </button>
              </li>
            ))}
          </ul>
        </nav>
        <button onClick={onSignOut} className="text-sm text-muted underline underline-offset-2">Sign out</button>
      </aside>

      <main className="min-w-0 flex-1 p-6 pb-28 lg:p-10">
        {error && <p role="alert" className="mb-4 text-sm text-critical">{error}</p>}

        {!active && (
          <div className="max-w-xl pt-10">
            <h2 className="text-2xl font-semibold">Scan a project to see what to fix first</h2>
            <p className="mt-3 text-muted">
              Paste a GitHub repository or upload a lockfile. DepShield builds the dependency graph, checks it against
              OSV, and ranks every finding by how much it matters to your app.
            </p>
          </div>
        )}

        {active && active.status !== "done" && (
          <div className="max-w-xl pt-10">
            <h2 className="text-2xl font-semibold">{active.name}</h2>
            {active.status === "failed" ? (
              <p role="alert" className="mt-3 text-critical">The scan failed: {active.error}</p>
            ) : (
              <p className="mt-3 text-muted" aria-live="polite">Scanning dependencies. This usually takes under a minute.</p>
            )}
          </div>
        )}

        {active?.status === "done" && active.summary && (
          <>
            <p className="max-w-3xl text-2xl font-semibold leading-snug">{active.summary.headline}</p>
            <div className="mt-6 grid max-w-3xl gap-6 sm:grid-cols-[auto_1fr] sm:items-end">
              <div>
                <div className="text-5xl font-bold tabular-nums" style={{ color: active.summary.overall_score >= 80 ? LEVEL_COLOR.critical : active.summary.overall_score >= 60 ? LEVEL_COLOR.high : "inherit" }}>
                  {Math.round(active.summary.overall_score)}
                </div>
                <div className="text-sm text-muted">overall risk out of 100</div>
              </div>
              <div>
                <RiskBar counts={active.summary.counts} />
                <p className="mt-2 text-sm text-muted">
                  {active.summary.vulnerable_packages} of {active.summary.total_packages} packages have known vulnerabilities
                  {active.sensitive && ", in a service marked sensitive"}.
                </p>
              </div>
            </div>
            {active.summary.warnings?.length ? (
              <ul className="mt-4 max-w-3xl list-disc pl-5 text-sm text-muted">{active.summary.warnings.map((w) => <li key={w}>{w}</li>)}</ul>
            ) : null}

            <div className="mt-10 grid gap-8 xl:grid-cols-[minmax(0,1.2fr)_minmax(0,1fr)]">
              <section aria-labelledby="graph-h" className="xl:sticky xl:top-6 xl:self-start">
                <h2 id="graph-h" className="text-lg font-semibold">Paths from your app to vulnerable packages</h2>
                <p className="mb-3 text-sm text-muted">Select a finding, or click a package, to trace how it gets in.</p>
                <div className="h-[560px] border border-rule bg-panel">
                  {graph && graph.nodes.length > 0 ? (
                    <DependencyGraph data={graph} highlight={highlight}
                      onSelect={(key) => setSelected(findings.find((f) => f.package_key === key) ?? null)} />
                  ) : (
                    <p className="p-6 text-muted">No vulnerable paths to draw.</p>
                  )}
                </div>
              </section>

              <section aria-labelledby="fix-h">
                <h2 id="fix-h" className="mb-3 text-lg font-semibold">Fix in this order</h2>
                <FindingsList findings={findings} selectedId={selected?.id ?? null} upgrades={upgrades}
                  onSelect={(f) => setSelected(selected?.id === f.id ? null : f)} onToggleUpgrade={toggleUpgrade} />
              </section>
            </div>
          </>
        )}
      </main>

      {upgradeCount > 0 && active && (
        <div className="fixed inset-x-0 bottom-0 border-t border-rule bg-panel px-6 py-3 lg:left-80">
          <div className="flex flex-wrap items-center gap-x-6 gap-y-2">
            {sim ? (
              <p aria-live="polite" className="text-sm">
                Overall risk goes from <b className="tabular-nums">{Math.round(sim.before.overall_score)}</b> to{" "}
                <b className="tabular-nums">{Math.round(sim.after.overall_score)}</b>. {sim.resolved.length} finding{sim.resolved.length === 1 ? "" : "s"} resolved
                {sim.introduced.length ? `, ${sim.introduced.length} new` : ""}.
              </p>
            ) : (
              <p className="text-sm">{upgradeCount} upgrade{upgradeCount === 1 ? "" : "s"} selected</p>
            )}
            <div className="ml-auto flex gap-3">
              <button onClick={() => { setUpgrades({}); setSim(null); }} className="text-sm text-muted underline underline-offset-2">Clear</button>
              <button onClick={preview} disabled={simBusy} className="rounded bg-signal px-4 py-1.5 text-sm font-medium text-white disabled:opacity-60">
                {simBusy ? "Calculating" : "Preview updated risk"}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

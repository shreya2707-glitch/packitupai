import { FormEvent, useState } from "react";
import { api } from "../api";
import type { Scan } from "../types";

export default function ScanForm({ onCreated }: { onCreated: (scan: Scan) => void }) {
  const [mode, setMode] = useState<"github" | "upload">("github");
  const [url, setUrl] = useState("");
  const [files, setFiles] = useState<File[]>([]);
  const [name, setName] = useState("");
  const [sensitive, setSensitive] = useState(false);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError("");
    try {
      const scan = mode === "github" ? await api.createScan(url.trim(), sensitive) : await api.uploadScan(files, name, sensitive);
      onCreated(scan);
      setUrl("");
      setFiles([]);
      setName("");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Scan could not start");
    } finally {
      setBusy(false);
    }
  }

  const tab = (m: "github" | "upload", label: string) => (
    <button type="button" onClick={() => setMode(m)} aria-pressed={mode === m}
      className={`px-3 py-1.5 text-sm ${mode === m ? "border-b-2 border-signal font-semibold" : "text-muted"}`}>
      {label}
    </button>
  );

  return (
    <form onSubmit={submit} className="space-y-3">
      <div className="flex gap-1 border-b border-rule">{tab("github", "GitHub repo")}{tab("upload", "Upload files")}</div>

      {mode === "github" ? (
        <label className="block text-sm font-medium">
          Repository URL
          <input required value={url} onChange={(e) => setUrl(e.target.value)} placeholder="https://github.com/owner/repo"
            className="mt-1 w-full rounded border border-rule bg-panel px-3 py-2 font-normal" />
        </label>
      ) : (
        <>
          <label className="block text-sm font-medium">
            Project name
            <input value={name} onChange={(e) => setName(e.target.value)} placeholder="payments-api"
              className="mt-1 w-full rounded border border-rule bg-panel px-3 py-2 font-normal" />
          </label>
          <label className="block text-sm font-medium">
            Manifests
            <input type="file" multiple required accept=".json,.txt,.xml"
              onChange={(e) => setFiles(Array.from(e.target.files ?? []))}
              className="mt-1 block w-full text-sm font-normal file:mr-3 file:rounded file:border-0 file:bg-canvas file:px-3 file:py-2" />
            <span className="mt-1 block text-xs font-normal text-muted">package-lock.json, package.json, requirements.txt or pom.xml</span>
          </label>
        </>
      )}

      <label className="flex items-start gap-2 text-sm">
        <input type="checkbox" checked={sensitive} onChange={(e) => setSensitive(e.target.checked)} className="mt-1" />
        <span>Handles payments, auth or other sensitive data</span>
      </label>

      {error && <p role="alert" className="text-sm text-critical">{error}</p>}
      <button disabled={busy} className="w-full rounded bg-signal px-4 py-2 font-medium text-white disabled:opacity-60">
        {busy ? "Starting scan" : "Scan dependencies"}
      </button>
    </form>
  );
}

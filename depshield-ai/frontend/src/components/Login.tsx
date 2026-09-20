import { FormEvent, useState } from "react";
import { api, auth } from "../api";

export default function Login({ onAuthed }: { onAuthed: () => void }) {
  const [mode, setMode] = useState<"signin" | "register">("signin");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError("");
    try {
      const res = mode === "signin" ? await api.login(email, password) : await api.register(email, password);
      auth.set(res.access_token);
      onAuthed();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Something went wrong");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="min-h-full grid place-items-center p-6">
      <div className="w-full max-w-sm">
        <h1 className="text-3xl font-bold tracking-tight">DepShield AI</h1>
        <p className="mt-2 text-muted">See which vulnerable dependency to fix first, and the path it takes into your app.</p>

        <form onSubmit={submit} className="mt-8 space-y-4">
          <label className="block text-sm font-medium">
            Email
            <input type="email" required value={email} onChange={(e) => setEmail(e.target.value)} autoComplete="email"
              className="mt-1 w-full rounded border border-rule bg-panel px-3 py-2" />
          </label>
          <label className="block text-sm font-medium">
            Password
            <input type="password" required minLength={8} value={password} onChange={(e) => setPassword(e.target.value)}
              autoComplete={mode === "signin" ? "current-password" : "new-password"}
              className="mt-1 w-full rounded border border-rule bg-panel px-3 py-2" />
            {mode === "register" && <span className="mt-1 block text-xs font-normal text-muted">At least 8 characters.</span>}
          </label>
          {error && <p role="alert" className="text-sm text-critical">{error}</p>}
          <button disabled={busy} className="w-full rounded bg-signal px-4 py-2.5 font-medium text-white disabled:opacity-60">
            {busy ? "Working" : mode === "signin" ? "Sign in" : "Create account"}
          </button>
        </form>

        <button onClick={() => { setMode(mode === "signin" ? "register" : "signin"); setError(""); }}
          className="mt-4 text-sm text-signal underline underline-offset-2">
          {mode === "signin" ? "Create an account" : "I already have an account"}
        </button>
      </div>
    </div>
  );
}

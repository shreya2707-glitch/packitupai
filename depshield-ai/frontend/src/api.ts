import type { Finding, GraphData, Scan, Simulation } from "./types";

const BASE: string = import.meta.env.VITE_API_URL ?? "http://localhost:8000";
const TOKEN_KEY = "depshield_token";

export const auth = {
  get: () => localStorage.getItem(TOKEN_KEY),
  set: (t: string) => localStorage.setItem(TOKEN_KEY, t),
  clear: () => localStorage.removeItem(TOKEN_KEY),
};

export class ApiError extends Error {
  constructor(public status: number, message: string) {
    super(message);
  }
}

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const headers = new Headers(init.headers);
  const token = auth.get();
  if (token) headers.set("Authorization", `Bearer ${token}`);
  const res = await fetch(`${BASE}${path}`, { ...init, headers });
  if (res.status === 401 && token) {
    auth.clear();
    window.location.reload();
  }
  if (!res.ok) {
    let detail = res.statusText;
    try {
      const body = await res.json();
      detail = typeof body.detail === "string" ? body.detail : JSON.stringify(body.detail);
    } catch {
      /* keep statusText */
    }
    throw new ApiError(res.status, detail);
  }
  return res.status === 204 ? (undefined as T) : res.json();
}

const json = (body: unknown): RequestInit => ({
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify(body),
});

export const api = {
  register: (email: string, password: string) => request<{ access_token: string }>("/auth/register", json({ email, password })),
  login: (email: string, password: string) =>
    request<{ access_token: string }>("/auth/login", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ username: email, password }),
    }),
  scans: () => request<Scan[]>("/scans"),
  scan: (id: number) => request<Scan>(`/scans/${id}`),
  createScan: (repo_url: string, sensitive: boolean) => request<Scan>("/scans", json({ repo_url, sensitive })),
  uploadScan: (files: File[], name: string, sensitive: boolean) => {
    const form = new FormData();
    files.forEach((f) => form.append("files", f, f.name));
    form.append("name", name || "uploaded project");
    form.append("sensitive", String(sensitive));
    return request<Scan>("/scans/upload", { method: "POST", body: form });
  },
  findings: (id: number) => request<Finding[]>(`/scans/${id}/findings`),
  graph: (id: number) => request<GraphData>(`/scans/${id}/graph?focus=attack`),
  simulate: (id: number, upgrades: { key: string; version: string }[]) =>
    request<Simulation>(`/scans/${id}/simulate`, json({ upgrades })),
  remove: (id: number) => request<void>(`/scans/${id}`, { method: "DELETE" }),
};

import { useCallback, useEffect, useState, type FormEvent } from "react";
import { Activity, Plus, Server } from "lucide-react";
import { arbiterApi } from "../api/client";
import { EmptyState, ErrorPanel, LoadingPanel, PageHeader } from "../components/StatePanels";
import type {
  PlatformSettingsResponse,
  TargetHealthResponse,
  TargetModality,
  TargetSummary,
} from "../types/api";

export function SettingsPage() {
  const [settings, setSettings] = useState<PlatformSettingsResponse | null>(null);
  const [targets, setTargets] = useState<TargetSummary[]>([]);
  const [healthMap, setHealthMap] = useState<Record<string, TargetHealthResponse>>({});
  const [checkingId, setCheckingId] = useState<string | null>(null);

  const [adapterType, setAdapterType] = useState<
    "openai" | "anthropic" | "gemini" | "ollama" | "http"
  >("ollama");
  const [targetId, setTargetId] = useState("");
  const [targetType, setTargetType] = useState<TargetModality>("llm");
  const [model, setModel] = useState("llama3.2");
  const [baseUrl, setBaseUrl] = useState("http://localhost:11434");
  const [apiKeyEnvVar, setApiKeyEnvVar] = useState("");
  const [submitting, setSubmitting] = useState(false);

  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<unknown>(null);

  const loadAll = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [settingsRes, targetsRes] = await Promise.all([
        arbiterApi.getPlatformSettings(),
        arbiterApi.listTargets(),
      ]);
      setSettings(settingsRes);
      setTargets(targetsRes.items);
    } catch (err) {
      setError(err);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void loadAll();
  }, [loadAll]);

  const handleAdapterTypeChange = (
    nextType: "openai" | "anthropic" | "gemini" | "ollama" | "http",
  ) => {
    setAdapterType(nextType);
    if (nextType === "ollama") {
      setBaseUrl("http://localhost:11434");
      setModel("llama3.2");
      setApiKeyEnvVar("");
    } else if (nextType === "openai") {
      setBaseUrl("https://api.openai.com/v1");
      setModel("gpt-4o-mini");
      setApiKeyEnvVar("OPENAI_API_KEY");
    } else if (nextType === "anthropic") {
      setBaseUrl("https://api.anthropic.com");
      setModel("claude-3-5-sonnet-latest");
      setApiKeyEnvVar("ANTHROPIC_API_KEY");
    } else if (nextType === "gemini") {
      setBaseUrl("https://generativelanguage.googleapis.com");
      setModel("gemini-2.0-flash");
      setApiKeyEnvVar("GEMINI_API_KEY");
    } else {
      setBaseUrl("http://localhost:9000/chat");
      setModel("custom-http-app");
      setApiKeyEnvVar("");
    }
  };

  const handleRegister = async (e: FormEvent) => {
    e.preventDefault();
    if (!targetId.trim()) return;
    setSubmitting(true);
    setError(null);
    try {
      await arbiterApi.registerTarget({
        adapter_type: adapterType,
        target_id: targetId.trim(),
        target_type: targetType,
        model: model.trim() || undefined,
        ...(adapterType === "http"
          ? { endpoint_url: baseUrl.trim() }
          : { base_url: baseUrl.trim() }),
        ...(apiKeyEnvVar.trim() ? { api_key_env_var: apiKeyEnvVar.trim() } : {}),
      });
      setTargetId("");
      await loadAll();
    } catch (err) {
      setError(err);
    } finally {
      setSubmitting(false);
    }
  };

  const runHealthCheck = async (id: string) => {
    setCheckingId(id);
    try {
      const res = await arbiterApi.checkTargetHealth(id);
      setHealthMap((prev) => ({ ...prev, [id]: res }));
    } catch (err) {
      setError(err);
    } finally {
      setCheckingId(null);
    }
  };

  return (
    <div className="space-y-6">
      <PageHeader
        title="Platform Settings & Targets"
        subtitle="Inspect non-secret FastAPI runtime configuration and register environment-backed target adapters."
      />

      {error !== null && <ErrorPanel error={error} onRetry={loadAll} />}

      {loading ? (
        <LoadingPanel />
      ) : (
        <div className="grid grid-cols-1 gap-6 lg:grid-cols-12">
          <div className="space-y-6 lg:col-span-7">
            <div className="rounded-lg border border-slate-800/90 bg-[#0c1017] p-5">
              <div className="mb-4 flex items-center gap-2">
                <Server className="h-4 w-4 text-sky-400" />
                <h2 className="text-sm font-semibold text-slate-100">
                  Registered Target Adapters ({targets.length})
                </h2>
              </div>

              {targets.length === 0 ? (
                <EmptyState
                  title="No Target Adapters Registered"
                  description="Register an OpenAI-compatible, Anthropic, Gemini, Ollama, or HTTP target using the form to begin running benchmarks."
                />
              ) : (
                <div className="space-y-2.5">
                  {targets.map((target) => {
                    const health = healthMap[target.target_id];
                    return (
                      <div
                        key={target.target_id}
                        className="rounded-md border border-slate-800 bg-[#080b10] p-3.5 text-xs"
                      >
                        <div className="flex flex-wrap items-center justify-between gap-2">
                          <div>
                            <div className="font-mono font-semibold text-slate-100">
                              {target.target_id}
                            </div>
                            <div className="mt-0.5 text-slate-400">
                              {target.provider} / {target.model_name} ·{" "}
                              <span className="uppercase">{target.target_type}</span>
                              {target.endpoint && (
                                <span className="ml-2 font-mono text-[11px] text-slate-500">
                                  {target.endpoint}
                                </span>
                              )}
                            </div>
                          </div>

                          <button
                            type="button"
                            disabled={checkingId === target.target_id}
                            onClick={() => void runHealthCheck(target.target_id)}
                            className="inline-flex items-center gap-1.5 rounded border border-slate-700 bg-[#111620] px-2.5 py-1 text-[11px] font-medium text-slate-200 hover:bg-slate-800"
                          >
                            <Activity className="h-3 w-3 text-sky-400" />
                            {checkingId === target.target_id ? "Probing..." : "Check Health"}
                          </button>
                        </div>

                        {health && (
                          <div
                            className={`mt-2 rounded px-2.5 py-1.5 text-[11px] ${
                              health.healthy
                                ? "bg-emerald-500/10 text-emerald-300"
                                : "bg-rose-500/10 text-rose-300"
                            }`}
                          >
                            {health.detail}
                            {health.latency_ms !== null && ` (${health.latency_ms} ms)`}
                          </div>
                        )}
                      </div>
                    );
                  })}
                </div>
              )}
            </div>

            {settings && (
              <div className="rounded-lg border border-slate-800/90 bg-[#0c1017] p-5">
                <h2 className="mb-3 text-sm font-semibold text-slate-100">Runtime Environment</h2>
                <dl className="grid grid-cols-2 gap-3 text-xs">
                  <div>
                    <dt className="text-slate-400">Platform Version</dt>
                    <dd className="mt-0.5 font-mono text-slate-200">{settings.platform_version}</dd>
                  </div>
                  <div>
                    <dt className="text-slate-400">Persistence Backend</dt>
                    <dd className="mt-0.5 font-mono text-slate-200">{settings.storage_backend}</dd>
                  </div>
                  <div>
                    <dt className="text-slate-400">Default Per-Test Timeout</dt>
                    <dd className="mt-0.5 font-mono text-slate-200">
                      {settings.default_timeout_seconds ?? "Disabled"} s
                    </dd>
                  </div>
                  <div>
                    <dt className="text-slate-400">Built-In v1.0 Dataset</dt>
                    <dd className="mt-0.5 text-slate-200">
                      {settings.builtin_datasets_loaded ? "Preloaded" : "Manual Registration"}
                    </dd>
                  </div>
                  <div className="col-span-2">
                    <dt className="text-slate-400">Available Adapter Factories</dt>
                    <dd className="mt-1 flex flex-wrap gap-1.5">
                      {settings.available_adapter_types.map((a) => (
                        <span
                          key={a}
                          className="rounded border border-slate-800 bg-slate-900 px-2 py-0.5 font-mono text-[11px] text-slate-300"
                        >
                          {a}
                        </span>
                      ))}
                    </dd>
                  </div>
                </dl>
              </div>
            )}
          </div>

          <form
            onSubmit={handleRegister}
            className="h-fit space-y-4 rounded-lg border border-slate-800/90 bg-[#0c1017] p-5 lg:col-span-5"
          >
            <div className="flex items-center gap-2 border-b border-slate-800 pb-3">
              <Plus className="h-4 w-4 text-sky-400" />
              <h2 className="text-sm font-semibold text-slate-100">Register Target Adapter</h2>
            </div>

            <div className="grid grid-cols-2 gap-3">
              <div>
                <label
                  htmlFor="adapter-type-select"
                  className="block text-[11px] font-medium uppercase tracking-wider text-slate-400"
                >
                  Provider / Adapter
                </label>
                <select
                  id="adapter-type-select"
                  value={adapterType}
                  onChange={(e) =>
                    handleAdapterTypeChange(
                      e.target.value as "openai" | "anthropic" | "gemini" | "ollama" | "http",
                    )
                  }
                  className="mt-1.5 w-full rounded-md border border-slate-700 bg-[#111620] px-2.5 py-2 text-xs text-slate-100"
                >
                  <option value="ollama">Ollama (Local)</option>
                  <option value="openai">OpenAI Compatible</option>
                  <option value="anthropic">Anthropic</option>
                  <option value="gemini">Google Gemini</option>
                  <option value="http">Generic HTTP App</option>
                </select>
              </div>

              <div>
                <label
                  htmlFor="target-modality-select"
                  className="block text-[11px] font-medium uppercase tracking-wider text-slate-400"
                >
                  Modality
                </label>
                <select
                  id="target-modality-select"
                  value={targetType}
                  onChange={(e) => setTargetType(e.target.value as TargetModality)}
                  className="mt-1.5 w-full rounded-md border border-slate-700 bg-[#111620] px-2.5 py-2 text-xs text-slate-100"
                >
                  <option value="llm">LLM</option>
                  <option value="rag">RAG</option>
                  <option value="agent">Agent</option>
                </select>
              </div>
            </div>

            <div>
              <label
                htmlFor="target-id-input"
                className="block text-[11px] font-medium uppercase tracking-wider text-slate-400"
              >
                Target ID
              </label>
              <input
                id="target-id-input"
                type="text"
                required
                value={targetId}
                onChange={(e) => setTargetId(e.target.value)}
                placeholder="e.g. local-llama3-guardrail"
                className="mt-1.5 w-full rounded-md border border-slate-700 bg-[#111620] px-3 py-2 text-xs text-slate-100 placeholder:text-slate-500"
              />
            </div>

            <div>
              <label
                htmlFor="target-model-input"
                className="block text-[11px] font-medium uppercase tracking-wider text-slate-400"
              >
                Model Name
              </label>
              <input
                id="target-model-input"
                type="text"
                required={adapterType !== "http"}
                value={model}
                onChange={(e) => setModel(e.target.value)}
                className="mt-1.5 w-full rounded-md border border-slate-700 bg-[#111620] px-3 py-2 text-xs text-slate-100"
              />
            </div>

            <div>
              <label
                htmlFor="target-url-input"
                className="block text-[11px] font-medium uppercase tracking-wider text-slate-400"
              >
                {adapterType === "http" ? "Endpoint URL" : "Base URL"}
              </label>
              <input
                id="target-url-input"
                type="url"
                required
                value={baseUrl}
                onChange={(e) => setBaseUrl(e.target.value)}
                className="mt-1.5 w-full rounded-md border border-slate-700 bg-[#111620] px-3 py-2 font-mono text-xs text-slate-100"
              />
            </div>

            <div>
              <label
                htmlFor="target-env-var-input"
                className="block text-[11px] font-medium uppercase tracking-wider text-slate-400"
              >
                API Key Environment Variable Name
              </label>
              <input
                id="target-env-var-input"
                type="text"
                value={apiKeyEnvVar}
                onChange={(e) => setApiKeyEnvVar(e.target.value)}
                placeholder="Never enter raw secrets (e.g. OPENAI_API_KEY)"
                className="mt-1.5 w-full rounded-md border border-slate-700 bg-[#111620] px-3 py-2 font-mono text-xs text-slate-100 placeholder:text-slate-500"
              />
            </div>

            <button
              type="submit"
              disabled={submitting || !targetId.trim()}
              className="w-full rounded-md bg-sky-500 px-3.5 py-2 text-xs font-semibold text-slate-950 hover:bg-sky-400 disabled:opacity-40"
            >
              {submitting ? "Registering..." : "Register Target"}
            </button>
          </form>
        </div>
      )}
    </div>
  );
}

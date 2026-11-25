import { useEffect, useState } from "react";
import { NavLink, Outlet } from "react-router-dom";
import clsx from "clsx";
import {
  Activity,
  Award,
  BarChart3,
  Bug,
  Database,
  FileText,
  GitCompare,
  Layers,
  LayoutDashboard,
  Menu,
  Play,
  Settings,
  Shield,
  X,
} from "lucide-react";
import { arbiterApi } from "../api/client";
import type { HealthResponse } from "../types/api";

interface NavItem {
  to: string;
  label: string;
  icon: typeof LayoutDashboard;
  end?: boolean;
}

const NAV_GROUPS: Array<{ title: string; items: NavItem[] }> = [
  {
    title: "Overview",
    items: [
      { to: "/", label: "Dashboard Overview", icon: LayoutDashboard, end: true },
      { to: "/benchmarks", label: "Benchmark Explorer", icon: Layers },
      { to: "/runs/new", label: "New Benchmark Run", icon: Play },
    ],
  },
  {
    title: "Analysis",
    items: [
      { to: "/results", label: "Security Results", icon: BarChart3 },
      { to: "/vulnerabilities", label: "Vulnerability Explorer", icon: Bug },
      { to: "/compare", label: "Model Comparison", icon: GitCompare },
      { to: "/leaderboard", label: "Leaderboard", icon: Award },
    ],
  },
  {
    title: "Governance",
    items: [
      { to: "/reports", label: "Reports", icon: FileText },
      { to: "/datasets", label: "Dataset Explorer", icon: Database },
      { to: "/settings", label: "Settings", icon: Settings },
    ],
  },
];

export function Layout() {
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [healthError, setHealthError] = useState(false);

  useEffect(() => {
    let active = true;
    arbiterApi
      .getHealth()
      .then((res) => {
        if (active) {
          setHealth(res);
          setHealthError(false);
        }
      })
      .catch(() => {
        if (active) {
          setHealthError(true);
        }
      });
    return () => {
      active = false;
    };
  }, []);

  const navContent = (
    <div className="flex h-full flex-col justify-between bg-[#090c12] px-3 py-5">
      <div>
        <div className="mb-6 flex items-center justify-between px-2.5">
          <div className="flex items-center gap-2.5">
            <div className="flex h-8 w-8 items-center justify-center rounded-md border border-sky-500/30 bg-sky-500/10 text-sky-400">
              <Shield className="h-4 w-4" />
            </div>
            <div>
              <div className="text-sm font-semibold tracking-tight text-slate-100">Arbiter</div>
              <div className="text-[11px] font-medium tracking-wider text-slate-500 uppercase">
                SecurityBench
              </div>
            </div>
          </div>
          <button
            type="button"
            aria-label="Close navigation"
            onClick={() => setSidebarOpen(false)}
            className="rounded p-1 text-slate-400 hover:bg-slate-800 hover:text-slate-200 lg:hidden"
          >
            <X className="h-4 w-4" />
          </button>
        </div>

        <nav aria-label="Primary navigation" className="space-y-5">
          {NAV_GROUPS.map((group) => (
            <div key={group.title}>
              <div className="mb-1.5 px-2.5 text-[11px] font-semibold uppercase tracking-wider text-slate-500">
                {group.title}
              </div>
              <div className="space-y-0.5">
                {group.items.map((item) => {
                  const Icon = item.icon;
                  return (
                    <NavLink
                      key={item.to}
                      to={item.to}
                      end={item.end}
                      onClick={() => setSidebarOpen(false)}
                      className={({ isActive }) =>
                        clsx(
                          "flex items-center gap-2.5 rounded-md px-2.5 py-2 text-xs font-medium transition-colors",
                          isActive
                            ? "border border-slate-700/80 bg-[#141b27] text-slate-100"
                            : "border border-transparent text-slate-400 hover:bg-slate-900/70 hover:text-slate-200",
                        )
                      }
                    >
                      <Icon className="h-4 w-4 shrink-0 text-slate-400" />
                      <span>{item.label}</span>
                    </NavLink>
                  );
                })}
              </div>
            </div>
          ))}
        </nav>
      </div>

      <div className="rounded-lg border border-slate-800/80 bg-[#0d121c] p-3 text-xs">
        <div className="flex items-center justify-between">
          <span className="flex items-center gap-1.5 font-medium text-slate-300">
            <Activity className="h-3.5 w-3.5 text-slate-400" />
            FastAPI Backend
          </span>
          <span
            className={clsx(
              "inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-[10px] font-medium",
              health
                ? "bg-emerald-500/10 text-emerald-300"
                : healthError
                  ? "bg-rose-500/10 text-rose-300"
                  : "bg-slate-800 text-slate-400",
            )}
          >
            <span
              className={clsx(
                "h-1.5 w-1.5 rounded-full",
                health ? "bg-emerald-400" : healthError ? "bg-rose-400" : "bg-slate-500",
              )}
            />
            {health ? "Connected" : healthError ? "Offline" : "Checking"}
          </span>
        </div>
        <div className="mt-1.5 font-mono text-[11px] text-slate-500">
          {health ? `v${health.version}` : "http://127.0.0.1:8000"}
        </div>
      </div>
    </div>
  );

  return (
    <div className="flex min-h-screen bg-[#07090d] text-slate-100">
      <aside className="hidden w-64 shrink-0 border-r border-slate-800/80 lg:block">
        <div className="sticky top-0 h-screen">{navContent}</div>
      </aside>

      {sidebarOpen && (
        <div className="fixed inset-0 z-40 flex lg:hidden">
          <div
            className="fixed inset-0 bg-black/70"
            onClick={() => setSidebarOpen(false)}
          />
          <aside className="relative z-50 w-64 border-r border-slate-800 bg-[#090c12]">
            {navContent}
          </aside>
        </div>
      )}

      <div className="flex min-w-0 flex-1 flex-col">
        <header className="flex items-center justify-between border-b border-slate-800/80 bg-[#090c12] px-4 py-3 lg:hidden">
          <button
            type="button"
            aria-label="Open navigation"
            onClick={() => setSidebarOpen(true)}
            className="rounded-md border border-slate-800 p-1.5 text-slate-300 hover:bg-slate-800"
          >
            <Menu className="h-4 w-4" />
          </button>
          <span className="text-sm font-semibold text-slate-100">Arbiter SecurityBench</span>
          <span className="w-7" />
        </header>

        <main className="mx-auto w-full max-w-7xl flex-1 px-4 py-6 sm:px-6 lg:px-8">
          <Outlet />
        </main>
      </div>
    </div>
  );
}

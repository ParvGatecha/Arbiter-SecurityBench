import { Navigate, Route, Routes } from "react-router-dom";
import { Layout } from "./components/Layout";
import { BenchmarkExecutionDetailsPage } from "./pages/BenchmarkExecutionDetailsPage";
import { BenchmarkExplorerPage } from "./pages/BenchmarkExplorerPage";
import { DashboardOverviewPage } from "./pages/DashboardOverviewPage";
import { DatasetExplorerPage } from "./pages/DatasetExplorerPage";
import { LeaderboardPage } from "./pages/LeaderboardPage";
import { ModelComparisonPage } from "./pages/ModelComparisonPage";
import { NewBenchmarkRunPage } from "./pages/NewBenchmarkRunPage";
import { ReportsPage } from "./pages/ReportsPage";
import { SecurityResultsPage } from "./pages/SecurityResultsPage";
import { SettingsPage } from "./pages/SettingsPage";
import { VulnerabilityExplorerPage } from "./pages/VulnerabilityExplorerPage";

export function App() {
  return (
    <Routes>
      <Route element={<Layout />}>
        <Route path="/" element={<DashboardOverviewPage />} />
        <Route path="/benchmarks" element={<BenchmarkExplorerPage />} />
        <Route path="/runs/new" element={<NewBenchmarkRunPage />} />
        <Route path="/runs/:runId" element={<BenchmarkExecutionDetailsPage />} />
        <Route path="/results" element={<SecurityResultsPage />} />
        <Route path="/vulnerabilities" element={<VulnerabilityExplorerPage />} />
        <Route path="/compare" element={<ModelComparisonPage />} />
        <Route path="/leaderboard" element={<LeaderboardPage />} />
        <Route path="/reports" element={<ReportsPage />} />
        <Route path="/datasets" element={<DatasetExplorerPage />} />
        <Route path="/settings" element={<SettingsPage />} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Route>
    </Routes>
  );
}

export default App;

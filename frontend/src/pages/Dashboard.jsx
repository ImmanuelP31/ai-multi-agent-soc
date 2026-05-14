import AlertTable from "../components/AlertTable";
import SeverityChart from "../components/SeverityChart";
import SequencePredictions from "../components/SequencePredictions";
import LiveFeed from "../components/LiveFeed";
import StatsCards from "../components/StatsCards";

function Dashboard() {
  return (
    <main className="mx-auto flex min-h-screen w-full max-w-7xl flex-col gap-6 px-4 py-6 sm:px-6 lg:px-8">
      <header className="flex flex-col gap-2 border-b border-border pb-5 md:flex-row md:items-end md:justify-between">
        <div>
          <p className="text-xs font-semibold uppercase tracking-[0.18em] text-neon">
            Autonomous Security Operations
          </p>
          <h1 className="mt-2 text-3xl font-semibold tracking-normal text-white sm:text-4xl">
            AI Multi-Agent SOC Dashboard
          </h1>
        </div>
        <div className="rounded-lg border border-emerald-500/30 bg-emerald-500/10 px-3 py-2 text-sm text-emerald-200">
          Backend stream and alert APIs monitored live
        </div>
      </header>

      <StatsCards />

      <section className="grid gap-6 xl:grid-cols-[minmax(0,1.1fr)_minmax(360px,0.9fr)]">
        <div className="flex flex-col gap-6">
          <SeverityChart />
          <AlertTable />
        </div>
        <div className="flex flex-col gap-6">
          <SequencePredictions />
          <LiveFeed />
        </div>
      </section>
    </main>
  );
}

export default Dashboard;

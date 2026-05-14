import AlertTable from "../components/AlertTable";
import SeverityChart from "../components/SeverityChart";
import SequencePredictions from "../components/SequencePredictions";
import LiveFeed from "../components/LiveFeed";
// FIX 1: StatsCards was never imported or rendered — added below.
import StatsCards from "../components/StatsCards";

function Dashboard() {

  return (
    <div style={{ padding: "20px" }}>

      <h1>AI Multi-Agent SOC Dashboard</h1>

      {/* FIX 1: render StatsCards at the top of the dashboard */}
      <StatsCards />

      <SeverityChart />

      <SequencePredictions />

      <LiveFeed />

      <AlertTable />

    </div>
  );
}

export default Dashboard;
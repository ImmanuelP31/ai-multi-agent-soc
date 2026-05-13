import AlertTable from "../components/AlertTable";
import SeverityChart from "../components/SeverityChart";
import SequencePredictions from "../components/SequencePredictions";
import LiveFeed from "../components/LiveFeed";

function Dashboard() {

  return (
    <div style={{ padding: "20px" }}>

      <h1>AI Multi-Agent SOC Dashboard</h1>

      <SeverityChart />

      <SequencePredictions />

      <LiveFeed />

      <AlertTable />

    </div>
  );
}

export default Dashboard;
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  CartesianGrid
} from "recharts";

const data = [
  { severity: "LOW", count: 12 },
  { severity: "MEDIUM", count: 7 },
  { severity: "HIGH", count: 4 }
];

function SeverityChart() {

  return (

    <div>

      <h2>Severity Distribution</h2>

      <BarChart width={500} height={300} data={data}>

        <CartesianGrid strokeDasharray="3 3" />

        <XAxis dataKey="severity" />

        <YAxis />

        <Tooltip />

        <Bar dataKey="count" fill="#8884d8" />

      </BarChart>

    </div>
  );
}

export default SeverityChart;
import { motion } from "framer-motion";
import { FaShieldAlt, FaBug, FaExclamationTriangle } from "react-icons/fa";
import { useAlertStats } from "../hooks/useSocQueries";

const EMPTY_STATS = {
  total_alerts: 0,
  critical_count: 0,
  malware_count: 0,
};

export default function StatsCards() {
  const { data: stats = EMPTY_STATS, isPending: loading, isError: error } =
    useAlertStats();

  const cards = [
    {
      title: "Total Alerts",
      value: stats.total_alerts ?? 0,
      icon: <FaShieldAlt />,
      color: "text-info",
      bg: "bg-info/10",
    },
    {
      title: "Critical Threats",
      value: stats.critical_count ?? 0,
      icon: <FaExclamationTriangle />,
      color: "text-danger",
      bg: "bg-danger/10",
    },
    {
      title: "Malware Events",
      value: stats.malware_count ?? 0,
      icon: <FaBug />,
      color: "text-warning",
      bg: "bg-warning/10",
    },
  ];

  return (
    <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
      {cards.map((item) => (
        <motion.div key={item.title} whileHover={{ y: -2 }} className="card">
          <div className="flex items-center justify-between gap-4">
            <div>
              <p className="muted">{item.title}</p>
              <p className="mt-2 text-4xl font-semibold leading-none text-white">
                {loading ? "..." : item.value.toLocaleString()}
              </p>
              {error && <p className="mt-2 text-xs text-danger">API unavailable</p>}
            </div>
            <div
              className={`grid h-12 w-12 place-items-center rounded-lg ${item.bg} text-2xl ${item.color}`}
            >
              {item.icon}
            </div>
          </div>
        </motion.div>
      ))}
    </div>
  );
}

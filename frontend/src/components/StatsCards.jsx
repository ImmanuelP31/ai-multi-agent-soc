import { useEffect, useState } from "react";
import { motion } from "framer-motion";
import { FaShieldAlt, FaBug, FaExclamationTriangle } from "react-icons/fa";
import api from "../services/api";

export default function StatsCards() {
  const [stats, setStats] = useState({
    total_alerts: 0,
    critical_count: 0,
    malware_count: 0,
  });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(false);

  const fetchStats = () => {
    api
      .get("/alerts/stats")
      .then((res) => {
        setStats(res.data);
        setError(false);
        setLoading(false);
      })
      .catch((err) => {
        console.error(err);
        setError(true);
        setLoading(false);
      });
  };

  useEffect(() => {
    fetchStats();
    const interval = setInterval(fetchStats, 10000);
    return () => clearInterval(interval);
  }, []);

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

import { useEffect, useState } from "react";
import { motion } from "framer-motion";
import { FaShieldAlt, FaBug, FaExclamationTriangle } from "react-icons/fa";
import api from "../services/api";

export default function StatsCards() {
  const [stats,   setStats]   = useState({ total_alerts: 0, critical_count: 0, malware_count: 0 });
  const [loading, setLoading] = useState(true);

  const fetchStats = () => {
    api.get("/alerts/stats")
      .then((res) => {
        setStats(res.data);
        setLoading(false);
      })
      .catch((err) => {
        console.error(err);
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
      icon:  <FaShieldAlt />,
      color: "text-info",
    },
    {
      title: "Critical Threats",
      value: stats.critical_count ?? 0,
      icon:  <FaExclamationTriangle />,
      color: "text-danger",
    },
    {
      title: "Malware Events",
      value: stats.malware_count ?? 0,
      icon:  <FaBug />,
      color: "text-warning",
    },
  ];

  return (
    <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
      {cards.map((item, idx) => (
        <motion.div
          key={idx}
          whileHover={{ scale: 1.04 }}
          className="card shadow-neon"
        >
          <div className="flex justify-between items-center">
            <div>
              <p className="text-gray-400">{item.title}</p>
              <h1 className="text-3xl font-bold mt-2">
                {loading ? "—" : item.value.toLocaleString()}
              </h1>
            </div>
            <div className={`text-4xl ${item.color}`}>{item.icon}</div>
          </div>
        </motion.div>
      ))}
    </div>
  );
}
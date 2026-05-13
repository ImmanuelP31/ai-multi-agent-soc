import { motion } from "framer-motion";
import {
  FaShieldAlt,
  FaBug,
  FaExclamationTriangle,
} from "react-icons/fa";

export default function StatsCards() {
  const stats = [
    {
      title: "Total Alerts",
      value: 1542,
      icon: <FaShieldAlt />,
      color: "text-info",
    },
    {
      title: "Critical Threats",
      value: 29,
      icon: <FaExclamationTriangle />,
      color: "text-danger",
    },
    {
      title: "Malware Events",
      value: 83,
      icon: <FaBug />,
      color: "text-warning",
    },
  ];

  return (
    <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
      {stats.map((item, idx) => (
        <motion.div
          key={idx}
          whileHover={{ scale: 1.04 }}
          className="card shadow-neon"
        >
          <div className="flex justify-between items-center">
            <div>
              <p className="text-gray-400">
                {item.title}
              </p>

              <h1 className="text-3xl font-bold mt-2">
                {item.value}
              </h1>
            </div>

            <div className={`text-4xl ${item.color}`}>
              {item.icon}
            </div>
          </div>
        </motion.div>
      ))}
    </div>
  );
}
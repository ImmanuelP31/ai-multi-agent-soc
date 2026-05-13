import { useEffect, useState } from "react";
import api from "../services/api";

function AlertTable() {

  const [alerts, setAlerts] = useState([]);

  useEffect(() => {

    api.get("/alerts")
      .then((res) => {
        setAlerts(res.data);
      })
      .catch((err) => {
        console.error(err);
      });

  }, []);

  return (

    <div>

      <h2>Security Alerts</h2>

      <table border="1" cellPadding="10">

        <thead>
          <tr>
            <th>ID</th>
            <th>Event</th>
            <th>Severity</th>
            <th>IP</th>
            <th>Timestamp</th>
          </tr>
        </thead>

        <tbody>

          {alerts.map((alert) => (

            <tr key={alert.id}>

              <td>{alert.id}</td>
              <td>{alert.event}</td>
              <td>{alert.severity}</td>
              <td>{alert.ip}</td>
              <td>{alert.timestamp}</td>

            </tr>

          ))}

        </tbody>

      </table>

    </div>
  );
}

export default AlertTable;
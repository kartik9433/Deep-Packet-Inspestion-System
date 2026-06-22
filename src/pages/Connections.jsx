import { useEffect, useState } from "react";
import { getConnections } from "../api/connectionApi";

function Connections() {

  const [connections, setConnections] = useState([]);

  useEffect(() => {
    loadConnections();
  }, []);

  const loadConnections = async () => {
    const res = await getConnections();
    setConnections(res.data);
  };

  return (
    <div className="container mt-4">

      <h2>Connections</h2>

      <table className="table table-bordered">

        <thead>
          <tr>
            <th>Source IP</th>
            <th>Destination IP</th>
            <th>State</th>
            <th>Application</th>
          </tr>
        </thead>

        <tbody>
          {connections.map((c) => (
            <tr key={c.id}>
              <td>{c.srcIp}</td>
              <td>{c.dstIp}</td>
              <td>{c.state}</td>
              <td>{c.appType}</td>
            </tr>
          ))}
        </tbody>

      </table>
    </div>
  );
}

export default Connections;
import React, { useState } from "react";
import Landing from "./components/screens/Landing";
import Scanning from "./components/screens/Scanning";
import Dashboard from "./components/screens/Dashboard";
import { DEMO_DATA } from "./data/mockData";
import { runSecurityScan } from "./api/client";
import "./styles/sentinel.css";

export default function App() {
  const [screen, setScreen] = useState("landing");
  const [target, setTarget] = useState("");
  const [dataset, setDataset] = useState(DEMO_DATA);

  const handleStartScan = async (targetRepo, fallbackData) => {
    setTarget(targetRepo);
    setScreen("scanning");

    const scanResult = await runSecurityScan(targetRepo, fallbackData);
    setDataset(scanResult);
  };

  return (
    <div className="scs-root">
      {screen === "landing" && (
        <Landing onScan={handleStartScan} />
      )}
      {screen === "scanning" && (
        <Scanning
          target={target}
          dataset={dataset}
          onDone={() => setScreen("dashboard")}
          onCancel={() => setScreen("landing")}
        />
      )}
      {screen === "dashboard" && (
        <Dashboard
          target={target}
          dataset={dataset}
          onRescan={() => setScreen("landing")}
        />
      )}
    </div>
  );
}
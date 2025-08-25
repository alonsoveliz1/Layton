// App.tsx
import { useState } from "react";
import { AppHeader } from "./components/Header";
import { InterfaceModal } from "./components/InterfaceModal";
import { NetworkDashboard } from "./components/NetworkDashboard";
import { useInterfaces } from "./hooks/useInterfaces";
import { useCapture } from "./hooks/useCapture";

import "./styles/global.css";
import "./styles/components.css"; 
import "./styles/dashboard.css";

export default function App() {
  const { list, selected, loading, error, refresh, select, setError } = useInterfaces();
  const { isCapturing, toggle } = useCapture();
  const [showModal, setShowModal] = useState(false);

  const onToggleModal = () => setShowModal(prev => {
    const next = !prev;
    if (next) refresh(); // load on open
    return next;
  });

  return (
    <div className="container">
      <AppHeader
        selectedInterface={selected}
        showModal={showModal}
        isCapturing={isCapturing}
        loading={loading}
        onToggleModal={onToggleModal}
        onToggleCapture={() => toggle(selected, (m)=>setError(m))}
      />

      {showModal && (
        <InterfaceModal
          interfaces={list}
          selectedInterface={selected}
          onSelectInterface={select}
          isCapturing={isCapturing}
        />
      )}

      {error && <div className="error">{error}</div>}

      <NetworkDashboard isCapturing={isCapturing} />
    </div>
  );
}

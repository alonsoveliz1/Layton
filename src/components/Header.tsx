import { NetworkInterface } from "../types/network.types";

interface HeaderProps {
    selectedInterface: NetworkInterface | null;
    showModal: boolean;
    isCapturing: boolean;
    loading: boolean;
    onToggleModal: () => void;
    onToggleCapture: () => void;
    isExporting: boolean;
    onToggleExport: () => void;
}

export function AppHeader({
    selectedInterface,
    showModal,
    isCapturing,
    loading,
    onToggleModal,
    onToggleCapture,
    isExporting,
    onToggleExport,
}: HeaderProps){
    return (
    <header className="header">
        <div className="header-logo">
            <img src="/src/assets/icono1.png" alt="Layton Logo" />
            <h3>Layton ver: 1.0.0</h3>
        </div>
    
        <div className="header-controls">
            <button 
                className={`btn ${isExporting ? 'btn-danger' : 'btn-success'}`}
                disabled={!selectedInterface || isCapturing}
                onClick={onToggleExport}
                >
                {isExporting ? 'Stop traffic collection' : 'Export Traffic to CSV'}
            </button>
        </div>
        <div className="header-controls">
            <button 
                className={`btn ${showModal ? 'btn-selected' : 'btn-primary'}`}
                onClick={onToggleModal}
                disabled={loading}
                >
                {showModal ? 'Hide Interfaces' : 'Show Interfaces'}
            </button>
        
            <button 
                className={`btn ${isCapturing ? 'btn-danger' : 'btn-success'}`}
                disabled={!selectedInterface || isExporting}
                onClick={onToggleCapture}
            >
                {isCapturing ? 'Stop Capture' : 'Start Capture'}
                </button>
        </div>
    </header>
  );
}
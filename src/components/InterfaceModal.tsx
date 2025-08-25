import { NetworkInterface } from "../types/network.types";


interface InterfaceModalProps {
    interfaces: NetworkInterface[];
    selectedInterface: NetworkInterface | null;
    onSelectInterface: (interfaceName: string) => void;
    isCapturing: boolean;
}

export function InterfaceModal({ 
    interfaces, 
    selectedInterface, 
    onSelectInterface,
    isCapturing,
}: InterfaceModalProps) {
    return (
        <div className="modal">
            <h3 className="modal-title">Available Network Interfaces</h3>
            <hr className="modal-divider" />
  
            <div className="interface-list">
                {interfaces.map((iface) => (
                    <div key={iface.name} className="interface-card">
                        <span className="interface-name">{iface.name}</span>
                        <span className={`interface-status ${iface.is_up ? 'interface-status-up' : 'interface-status-down'}`}>
                            {iface.is_up ? 'UP' : 'DOWN'}
                        </span>
                        <span className="interface-desc">{iface.description}</span>
                        <button 
                            className={`btn ${selectedInterface?.name === iface.name ? 'btn-selected' : ''}`}
                            onClick={() => onSelectInterface(iface.name)}
                            disabled={isCapturing}
                        >
                            {selectedInterface?.name === iface.name ? 'Selected' : 'Select'}
                        </button>
                    </div>
                ))}
            </div>
        </div>
    );
}
// hooks/useCapture.ts
import { useState, useCallback } from "react";
import { startSystem, stopSystem } from "../api/network";
import type { NetworkInterface } from "../types/network.types";

export function useCapture() {
  const [isCapturing, setCapturing] = useState(false);

  const toggle = useCallback(async (iface: NetworkInterface | null, onError: (m: string)=>void) => {
    if (!iface) return onError("Please select a network interface first");
    try {
      if (isCapturing) { await stopSystem(); setCapturing(false); }
      else { await startSystem(iface.name); setCapturing(true); }
    } catch (e) {
      onError(`Failed to ${isCapturing ? "stop" : "start"} capture: ${e instanceof Error ? e.message : String(e)}`);
      setCapturing(false);
    }
  }, [isCapturing]);

  return { isCapturing, toggle };
}

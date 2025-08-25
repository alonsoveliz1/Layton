// hooks/useInterfaces.ts
import { useCallback, useRef, useState } from "react";
import { listNetworkDevices, getInterfaceInfo } from "../api/network";
import type { NetworkInterface } from "../types/network.types";

export function useInterfaces() {
  const [list, setList] = useState<NetworkInterface[]>([]);
  const [selected, setSelected] = useState<NetworkInterface | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const inFlight = useRef(false);

  const refresh = useCallback(async () => {
    if (inFlight.current) return;
    inFlight.current = true;
    setLoading(true);
    try {
      const next = await listNetworkDevices();
      setList(next);
      // keep selection valid
      if (selected && !next.some(i => i.name === selected.name)) setSelected(null);
      setError(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      inFlight.current = false;
      setLoading(false);
    }
  }, [selected]);

  const select = useCallback(async (name: string) => {
    try {
      const info = await getInterfaceInfo(name);
      setSelected(info);
      setError(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  }, []);

  return { list, selected, loading, error, refresh, select, setError };
}

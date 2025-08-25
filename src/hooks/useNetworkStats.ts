// hooks/useNetworkStats.ts
import { useEffect, useState } from "react";
import { listen, type Event, type UnlistenFn } from "@tauri-apps/api/event";
import type { NetworkStats } from "../types/network.types";

export function useNetworkStats(active: boolean) {
  const [stats, setStats] = useState<NetworkStats>({
    flow_count: 0, packets_per_second: 0, bytes_per_second: 0,
    total_packets: 0, total_bytes: 0, uptime_seconds: 0,
  });

  useEffect(() => {
    if (!active) { setStats({ flow_count:0, packets_per_second:0, bytes_per_second:0, total_packets:0, total_bytes:0, uptime_seconds:0 }); return; }
    let unlisten: UnlistenFn | undefined;
    const latest = { current: stats };
    let tick: number | undefined;

    (async () => {
      unlisten = await listen<NetworkStats>("network-stats", (e: Event<NetworkStats>) => {
        latest.current = e.payload;
      });
    })();

    const loop = () => { setStats(latest.current); tick = window.setTimeout(loop, 250); }; // 4Hz
    loop();
    return () => { if (unlisten) unlisten(); if (tick) clearTimeout(tick); };
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [active]);

  return stats;
}

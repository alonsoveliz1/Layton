// api/network.ts
import { invoke } from "@tauri-apps/api/core";
import type { NetworkInterface } from "../types/network.types";

function normalize(err: unknown): string {
  if (err instanceof Error) return err.message;
  try { return JSON.stringify(err); } catch { return String(err); }
}

export async function listNetworkDevices(): Promise<NetworkInterface[]> {
  try {
    return await invoke<NetworkInterface[]>("list_network_devices");
  } catch (e) {
    const msg = normalize(e).toLowerCase();
    if (msg.includes("permission")) throw new Error("Administrator privileges required to access raw interfaces.");
    if (msg.includes("pcap")) throw new Error("Pcap library not included; install it before using the app.");
    throw new Error(`Failed to list network interfaces: ${normalize(e)}`);
  }
}

export async function getInterfaceInfo(interfaceName: string): Promise<NetworkInterface> {
  return invoke<NetworkInterface>("get_selected_interface_info", { interfaceName });
}

export async function startSystem(iface: string) { return invoke("start_system", { interface: iface }); }
export async function stopSystem() { return invoke("stop_system"); }

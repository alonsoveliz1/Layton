import { invoke } from "@tauri-apps/api/core";
import { NetworkInterface } from "../types/network.types";

class NetworkService {
    async listInterfaces(): Promise<NetworkInterface[]>{
        try{
            const result = await invoke<NetworkInterface[]>("list_network_devices");
            return result;
        } catch (error) {
            console.error('Failed to list network devices:', error);
            
            if(error instanceof Error){
                if(error.message.includes("permission")){
                    throw new Error("Administrator priviledges required to access a raw network interface");
                }
                if(error.message.includes("pcap")){
                    throw new Error("Pcap library not include, install it before using the app");
                }
            }
        throw new Error(`Failed to list network interfaces: ${error}`);

        }
    }
}


export default new NetworkService();
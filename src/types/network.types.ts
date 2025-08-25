export interface NetworkInterface{
    name: string;
    description: string;
    addresses: string[];
    is_up: boolean;
}


export interface NetworkStats{
    flow_count: number,
    packets_per_second: number,
    bytes_per_second: number,
    total_packets: number,
    total_bytes: number,
    uptime_seconds: number,
}
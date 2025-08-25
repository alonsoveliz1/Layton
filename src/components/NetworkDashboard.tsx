import React, { useEffect, useState } from 'react';
import { listen } from '@tauri-apps/api/event';
import type { Event, UnlistenFn } from '@tauri-apps/api/event';
import type { NetworkStats } from '../types/network.types';
import { FlowStream } from "./FlowStream";

interface NetworkDashboardProps {
  isCapturing: boolean;
}

export function NetworkDashboard({ isCapturing }: NetworkDashboardProps) {
  const [stats, setStats] = useState<NetworkStats>({
    flow_count: 0,
    packets_per_second: 0,
    bytes_per_second: 0,
    total_packets: 0,
    total_bytes: 0,
    uptime_seconds: 0,
  });

  useEffect(() => {
    let unlisten: UnlistenFn | undefined;

    const setupListener = async () => {
      try {
        unlisten = await listen<NetworkStats>('network-stats', (event: Event<NetworkStats>) => {
          setStats(event.payload); // Update all stats at once
        });
      } catch (error) {
        console.error('Failed to setup listener:', error);
      }
    };

    if (isCapturing) {
      setupListener();
    } else {
      // Reset all stats when not capturing
      setStats({
        flow_count: 0,
        packets_per_second: 0,
        bytes_per_second: 0,
        total_packets: 0,
        total_bytes: 0,
        uptime_seconds: 0,
      });
    }

    return () => {
      if (unlisten) unlisten();
    };
  }, [isCapturing]);

  // Format uptime from seconds to MM:SS or HH:MM:SS
  const formatUptime = (seconds: number): string => {
    const hours = Math.floor(seconds / 3600);
    const minutes = Math.floor((seconds % 3600) / 60);
    const secs = seconds % 60;
    
    if (hours > 0) {
      return `${hours}:${minutes.toString().padStart(2, '0')}:${secs.toString().padStart(2, '0')}`;
    }
    return `${minutes.toString().padStart(2, '0')}:${secs.toString().padStart(2, '0')}`;
  };

  // Format bytes to human readable
  const formatBytes = (bytes: number): string => {
    if (bytes === 0) return '0';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return (bytes / Math.pow(k, i)).toFixed(1) + ' ' + sizes[i];
  };

  // Format bandwidth (bytes/sec to appropriate unit)
  const formatBandwidth = (bytesPerSec: number): { value: string; unit: string } => {
    if (bytesPerSec === 0) return { value: '0', unit: 'KB/s' };
    const k = 1024;
    
    if (bytesPerSec < k) {
      return { value: bytesPerSec.toFixed(0), unit: 'B/s' };
    } else if (bytesPerSec < k * k) {
      return { value: (bytesPerSec / k).toFixed(1), unit: 'KB/s' };
    } else {
      return { value: (bytesPerSec / (k * k)).toFixed(1), unit: 'MB/s' };
    }
  };

  const bandwidth = formatBandwidth(stats.bytes_per_second);

  // helper to swap card color when not capturing
  const kpiColor = (activeVar: string) =>
    (isCapturing ? activeVar : 'var(--kpi-off)');

  return (
    <div className={`dashboard-container ${isCapturing ? 'dashboard-container--compact' : ''}`}>
      <div className="kpi-grid">
        <div
          className={`kpi-card ${!isCapturing ? 'kpi-card--off' : ''}`}
          style={{ '--kpi-color': kpiColor('var(--color-accent)') } as React.CSSProperties}
        >
          <div className="kpi-header">
            <span className="kpi-label">Active Flows</span>
          </div>
          <div className="kpi-value-container">
            <span className="kpi-value">{stats.flow_count.toLocaleString()}</span>
          </div>
        </div>

        <div
          className={`kpi-card ${!isCapturing ? 'kpi-card--off' : ''}`}
          style={{ '--kpi-color': kpiColor('var(--color-secondary)') } as React.CSSProperties}
        >
          <div className="kpi-header">
            <span className="kpi-label">Packet Rate</span>
          </div>
          <div className="kpi-value-container">
            <span className="kpi-value">{stats.packets_per_second.toFixed(0)}</span>
            <span className="kpi-unit">pkt/s</span>
          </div>
        </div>

        <div
          className={`kpi-card ${!isCapturing ? 'kpi-card--off' : ''}`}
          style={{ '--kpi-color': kpiColor('var(--color-success)') } as React.CSSProperties}
        >
          <div className="kpi-header">
            <span className="kpi-label">Bandwidth</span>
          </div>
          <div className="kpi-value-container">
            <span className="kpi-value">{bandwidth.value}</span>
            <span className="kpi-unit">{bandwidth.unit}</span>
          </div>
        </div>

        <div
          className={`kpi-card ${!isCapturing ? 'kpi-card--off' : ''}`}
          style={{ '--kpi-color': kpiColor('var(--color-warning)') } as React.CSSProperties}
        >
          <div className="kpi-header">
            <span className="kpi-label">Total Packets</span>
          </div>
          <div className="kpi-value-container">
            <span className="kpi-value">{stats.total_packets.toLocaleString()}</span>
          </div>
        </div>

        <div
          className={`kpi-card ${!isCapturing ? 'kpi-card--off' : ''}`}
          style={{ '--kpi-color': kpiColor('var(--color-danger)') } as React.CSSProperties}
        >
          <div className="kpi-header">
            <span className="kpi-label">Total Data</span>
          </div>
          <div className="kpi-value-container">
            <span className="kpi-value">{formatBytes(stats.total_bytes)}</span>
          </div>
        </div>

        <div
          className={`kpi-card ${!isCapturing ? 'kpi-card--off' : ''}`}
          style={{ '--kpi-color': kpiColor('var(--color-secondary)') } as React.CSSProperties}
        >
          <div className="kpi-header">
            <span className="kpi-label">Uptime</span>
          </div>
          <div className="kpi-value-container">
            <span className="kpi-value">{formatUptime(stats.uptime_seconds)}</span>
          </div>
        </div>
      </div>
        <FlowStream active={isCapturing} />

    </div>
  );
}
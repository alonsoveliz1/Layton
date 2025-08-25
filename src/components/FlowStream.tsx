import { useEffect, useRef, useState } from "react";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";

type FlowKeyDTO = {
  ip_a: number; ip_b: number; port_a: number; port_b: number; protocol: number;
};

export type ClassifiedFlowEvent = {
  key: FlowKeyDTO;
  start_us: number;
  end_us: number;
  duration_us: number;
  total_packets: number;
  total_bytes: number;
  is_attack: boolean;
  p_attack: number;
  multi_class?: number;
  multi_label?: string;
  multi_probs?: number[];
};

function flowId(ev: ClassifiedFlowEvent) {
  const k = ev.key;
  return `${k.ip_a}:${k.port_a}->${k.ip_b}:${k.port_b}/${k.protocol}/${ev.start_us}`;
}

// IPv4 from u32 (network order)
function ipv4(u: number) {
  return [
    (u >>> 24) & 255,
    (u >>> 16) & 255,
    (u >>>  8) & 255,
    (u >>>  0) & 255
  ].join(".");
}

function fmtBytes(b: number) {
  if (b >= 1<<30) return (b/(1<<30)).toFixed(1) + " GB";
  if (b >= 1<<20) return (b/(1<<20)).toFixed(1) + " MB";
  if (b >= 1<<10) return (b/(1<<10)).toFixed(1) + " KB";
  return b + " B";
}

function fmtTimeUs(us: number) {
  if (us >= 1_000_000) return (us/1_000_000).toFixed(2) + " s";
  if (us >= 1_000) return (us/1_000).toFixed(1) + " ms";
  return us + " µs";
}

export function FlowStream({ active, maxRows = 2000 }: { active: boolean; maxRows?: number }) {
  const [rows, setRows] = useState<ClassifiedFlowEvent[]>([]);
  const [onlyAttacks, setOnlyAttacks] = useState(false);

  // internal buffers (no re-renders)
  const byIdRef = useRef<Map<string, ClassifiedFlowEvent>>(new Map());
  const orderRef = useRef<string[]>([]);
  const queueRef = useRef<ClassifiedFlowEvent[]>([]);
  const timerRef = useRef<number | null>(null);

  // flush batched events to state
  const flush = () => {
    timerRef.current = null as any;
    const batch = queueRef.current.splice(0, queueRef.current.length);
    if (!batch.length) return;
    const newRows = orderRef.current.map(id => byIdRef.current.get(id)!).filter(Boolean);
    setRows(newRows);
  };
  const scheduleFlush = () => {
    if (timerRef.current !== null) return;
    timerRef.current = window.setTimeout(flush, 200);
  };

  // reset when capture toggles off
  useEffect(() => {
    if (!active) {
      byIdRef.current.clear();
      orderRef.current = [];
      queueRef.current = [];
      setRows([]);
    }
  }, [active]);

  useEffect(() => {
    if (!active) return;

    let unlisten: UnlistenFn | undefined;

    (async () => {
      unlisten = await listen<ClassifiedFlowEvent>("flow_classified", (e) => {
        const ev = e.payload;
        const id = flowId(ev);
        if (byIdRef.current.has(id)) return;

        byIdRef.current.set(id, ev);
        orderRef.current.push(id);
        queueRef.current.push(ev);

        // ring buffer
        if (orderRef.current.length > maxRows) {
          const drop = orderRef.current.shift()!;
          byIdRef.current.delete(drop);
        }

        scheduleFlush();
      });
    })();

    return () => {
      if (unlisten) unlisten();
      if (timerRef.current !== null) {
        clearTimeout(timerRef.current);
        timerRef.current = null;
      }
    };
  }, [active, maxRows]);

  const filtered = onlyAttacks ? rows.filter(r => r.is_attack) : rows;

  return (
    <div className="panel" style={{ marginTop: "var(--spacing-lg)" }}>
      <div className="panel-header">
        <strong>Classified Flows</strong>
        <label style={{ marginLeft: "auto" }}>
          <input type="checkbox" checked={onlyAttacks} onChange={e => setOnlyAttacks(e.target.checked)} />
          &nbsp;Only attacks
        </label>
        <span style={{ marginLeft: 12, opacity: 0.75 }}>
          {filtered.length}/{rows.length}
        </span>
      </div>

      <div className="table">
        <div className="thead">
          <div>Class</div>
          <div>P(attack)</div>
          <div>Pkts</div>
          <div>Bytes</div>
          <div>Duration</div>
          <div>Flow</div>
        </div>
        <div className="tbody" style={{ maxHeight: 480, overflow: "auto" }}>
          {filtered.map((r) => {
            const id = flowId(r);
            return (
              <div className="trow" key={id}>
                <div className={`badge ${r.is_attack ? "danger" : "ok"}`}>
                  {r.multi_label ?? (r.is_attack ? "Attack" : "Benign")}
                </div>
                <div>{r.p_attack.toFixed(2)}</div>
                <div>{r.total_packets}</div>
                <div>{fmtBytes(r.total_bytes)}</div>
                <div>{fmtTimeUs(r.duration_us)}</div>
                <div className="flowtext">
                  {ipv4(r.key.ip_a)}:{r.key.port_a}
                  &nbsp;→&nbsp;
                  {ipv4(r.key.ip_b)}:{r.key.port_b}
                  &nbsp;(<span className="text-muted">proto {r.key.protocol}</span>)
                </div>
              </div>
            );
          })}
          {!filtered.length && (
            <div style={{ padding: 12, opacity: 0.6 }}>No flows yet…</div>
          )}
        </div>
      </div>
    </div>
  );
}

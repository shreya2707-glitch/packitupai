import { useMemo } from "react";
import ReactFlow, { Background, Controls, Edge, MarkerType, Node, Position } from "reactflow";
import "reactflow/dist/style.css";
import { colorForScore } from "../risk";
import type { GraphData } from "../types";

const COL_W = 250;
const ROW_H = 74;

interface Props {
  data: GraphData;
  /** Keys from the app down to the selected vulnerable package. */
  highlight: string[];
  onSelect: (key: string) => void;
}

export default function DependencyGraph({ data, highlight, onSelect }: Props) {
  const { nodes, edges } = useMemo(() => {
    const active = new Set(highlight);
    const activeEdges = new Set(highlight.slice(1).map((k, i) => `${highlight[i]}>${k}`));
    const dimming = highlight.length > 0;

    const columns = new Map<number, typeof data.nodes>();
    for (const n of data.nodes) {
      const col = Math.max(1, n.depth);
      columns.set(col, [...(columns.get(col) ?? []), n]);
    }

    const flowNodes: Node[] = [
      {
        id: "app",
        position: { x: 0, y: 0 },
        data: { label: <div className="font-semibold">Your app</div> },
        sourcePosition: Position.Right,
        style: { width: 130, background: "#0f1b2d", color: "#fff", border: "none", padding: 10 },
      },
    ];
    for (const [col, list] of columns) {
      list.sort((a, b) => b.risk - a.risk || a.name.localeCompare(b.name));
      list.forEach((n, i) => {
        const color = colorForScore(n.risk);
        flowNodes.push({
          id: n.key,
          position: { x: col * COL_W, y: (i - (list.length - 1) / 2) * ROW_H },
          sourcePosition: Position.Right,
          targetPosition: Position.Left,
          data: {
            label: (
              <div className="text-left leading-tight">
                <div className="truncate font-mono text-[12px] font-medium">{n.name}</div>
                <div className="font-mono text-[11px] text-muted">
                  {n.version}
                  {n.risk > 0 && <span style={{ color }} className="ml-2 font-semibold">risk {Math.round(n.risk)}</span>}
                </div>
              </div>
            ),
          },
          style: {
            width: 200,
            padding: 8,
            background: "#fff",
            border: "1px solid #d3d9e1",
            borderLeft: `6px solid ${color}`,
            opacity: dimming && !active.has(n.key) ? 0.3 : 1,
            boxShadow: active.has(n.key) ? "0 0 0 2px #2447f5" : "none",
          },
        });
      });
    }

    const flowEdges: Edge[] = data.edges.map((e) => {
      const on = activeEdges.has(`${e.source}>${e.target}`);
      return {
        id: `${e.source}>${e.target}`,
        source: e.source,
        target: e.target,
        animated: on,
        markerEnd: { type: MarkerType.ArrowClosed, color: on ? "#2447f5" : "#9aa6b6" },
        style: { stroke: on ? "#2447f5" : "#9aa6b6", strokeWidth: on ? 2.5 : 1.25, opacity: dimming && !on ? 0.35 : 1 },
      };
    });
    return { nodes: flowNodes, edges: flowEdges };
  }, [data, highlight]);

  return (
    <ReactFlow
      nodes={nodes}
      edges={edges}
      fitView
      fitViewOptions={{ padding: 0.15 }}
      nodesConnectable={false}
      minZoom={0.2}
      onNodeClick={(_, node) => node.id !== "app" && onSelect(node.id)}
    >
      <Background color="#d3d9e1" gap={24} />
      <Controls showInteractive={false} />
    </ReactFlow>
  );
}

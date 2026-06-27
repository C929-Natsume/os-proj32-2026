"use client";

import type { FC } from "react";
import type { TextMessagePartProps } from "@assistant-ui/react";
import { MarkdownText } from "@/components/assistant-ui/markdown-text";
import {
  Activity,
  FileSearch,
  MessageSquareText,
  ShieldAlert,
  Workflow,
} from "lucide-react";

type StepNode = {
  module?: string;
  title: string;
  lines: string[];
};

function normalizeModuleLabel(value: string) {
  const text = value.trim().toLowerCase();
  if (text.includes("intra")) return "INTRA-AGENT";
  if (text.includes("inter")) return "INTER-AGENT";
  if (text.includes("audit")) return "AUDIT";
  if (text.includes("showcase") || text.includes("frontend")) return "SHOWCASE";
  if (text.includes("redis")) return "REDIS";
  if (text.includes("ebpf")) return "eBPF";
  return value.trim().toUpperCase();
}

function splitModulePrefix(text: string) {
  const match = text.match(/^([A-Za-z][A-Za-z0-9_-]*)\s*[|｜]\s*(.+)$/);
  if (!match) return { module: undefined, title: text.trim() };
  return {
    module: normalizeModuleLabel(match[1]),
    title: match[2].trim(),
  };
}

function parseNodes(text: string): StepNode[] {
  const nodes: StepNode[] = [];
  const lines = (text || "").replace(/\r/g, "").split("\n");
  let current: StepNode | null = null;

  for (const raw of lines) {
    const line = raw.trim();
    if (!line) continue;

    const stepMatch =
      line.match(/^\d+\.\s*第?(\d+)步[:：]?\s*(.+)$/) ||
      line.match(/^第?(\d+)步[:：]?\s*(.+)$/);

    if (stepMatch) {
      if (current) nodes.push(current);
      const parsed = splitModulePrefix(stepMatch[2].trim());
      current = { module: parsed.module, title: parsed.title, lines: [] };
      continue;
    }

    const itemMatch = line.match(/^\d+\.\s*(.+)$/);
    if (!current) {
      current = { title: line, lines: [] };
    } else {
      current.lines.push(itemMatch ? itemMatch[1].trim() : line);
    }
  }

  if (current) nodes.push(current);
  return nodes;
}

function looksLikeStepFlow(text: string) {
  return /第?\d+步[:：]?/.test(text || "");
}

function getStepIcon(title: string, index: number) {
  const text = title.toLowerCase();
  if (text.includes("事件") || text.includes("检索")) {
    return <FileSearch className="size-4 text-slate-600" />;
  }
  if (text.includes("语义") || text.includes("根因")) {
    return <MessageSquareText className="size-4 text-slate-600" />;
  }
  if (text.includes("结论") || text.includes("审计")) {
    return <ShieldAlert className="size-4 text-slate-600" />;
  }
  if (index === 0) {
    return <Activity className="size-4 text-slate-600" />;
  }
  return <FileSearch className="size-4 text-slate-600" />;
}

function inferModule(node: StepNode) {
  if (node.module) return node.module;
  const joined = `${node.title}\n${node.lines.join("\n")}`.toLowerCase();
  if (joined.includes("intra-agent") || joined.includes("单体") || joined.includes("single")) return "INTRA-AGENT";
  if (joined.includes("inter-agent") || joined.includes("交互") || joined.includes("interactive")) return "INTER-AGENT";
  if (joined.includes("audit") || joined.includes("审计") || joined.includes("decision=")) return "AUDIT";
  if (joined.includes("showcase") || joined.includes("前端") || joined.includes("展示")) return "SHOWCASE";
  if (joined.includes("redis")) return "REDIS";
  if (joined.includes("ebpf")) return "eBPF";
  return "RUNTIME";
}

function getModuleBadgeClass(module: string) {
  if (module === "INTRA-AGENT") return "border-amber-200 bg-amber-50 text-amber-700";
  if (module === "INTER-AGENT") return "border-cyan-200 bg-cyan-50 text-cyan-700";
  if (module === "AUDIT") return "border-emerald-200 bg-emerald-50 text-emerald-700";
  if (module === "SHOWCASE") return "border-violet-200 bg-violet-50 text-violet-700";
  if (module === "REDIS") return "border-lime-200 bg-lime-50 text-lime-700";
  if (module === "eBPF") return "border-fuchsia-200 bg-fuchsia-50 text-fuchsia-700";
  return "border-slate-200 bg-slate-50 text-slate-600";
}

const StepArrow: FC = () => {
  return (
    <div className="flex h-10 items-center justify-center">
      <div className="relative h-full w-px bg-slate-300">
        <div className="absolute bottom-0 left-1/2 size-2 -translate-x-1/2 rotate-45 border-r-2 border-b-2 border-slate-400" />
      </div>
    </div>
  );
};

const StepCard: FC<{ node: StepNode; index: number; total: number }> = ({
  node,
  index,
  total,
}) => {
  const module = inferModule(node);
  return (
    <div className="relative">
      <div className="rounded-[24px] border border-slate-200 bg-white/95 p-4 shadow-[0_10px_32px_rgba(15,23,42,0.06)]">
        <div className="mb-3 flex items-center gap-3">
          <div className="flex size-10 items-center justify-center rounded-2xl bg-slate-100">
            {getStepIcon(node.title, index)}
          </div>
          <div className="min-w-0 flex-1">
            <div className="flex flex-wrap items-center gap-2">
              <div className="text-[11px] font-semibold tracking-[0.18em] text-slate-500 uppercase">
                Step {index + 1}
              </div>
              <div
                className={`inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-[10px] font-semibold tracking-[0.16em] uppercase ${getModuleBadgeClass(module)}`}
              >
                <Workflow className="size-3" />
                {module}
              </div>
            </div>
            <div className="text-[15px] font-semibold leading-6 text-slate-900">
              {node.title}
            </div>
          </div>
        </div>

        <div className="space-y-2">
          {node.lines.map((item, itemIndex) => (
            <div
              key={`${node.title}-${itemIndex}`}
              className="rounded-2xl border border-slate-200 bg-slate-50 px-3 py-2 text-sm leading-6 text-slate-700"
            >
              {item}
            </div>
          ))}
        </div>
      </div>

      {index < total - 1 ? <StepArrow /> : null}
    </div>
  );
};

const VerticalFlow: FC<{ nodes: StepNode[] }> = ({ nodes }) => {
  return (
    <div className="mx-auto w-full max-w-[42rem] space-y-0">
      {nodes.map((node, index) => (
        <StepCard
          key={`${node.title}-${index}`}
          node={node}
          index={index}
          total={nodes.length}
        />
      ))}
    </div>
  );
};

export const FlowMessage: FC<TextMessagePartProps> = ({ text }) => {
  const content =
    typeof text === "string"
      ? text
      : typeof (text as unknown as { text?: unknown })?.text === "string"
        ? ((text as unknown as { text?: string }).text ?? "")
        : "";
  const nodes = parseNodes(content);
  if (!looksLikeStepFlow(content) && nodes.length === 0) return <MarkdownText />;
  if (nodes.length === 0) {
    return (
      <div className="mx-auto w-full max-w-[42rem] rounded-[24px] border border-slate-200 bg-white/95 p-4 shadow-[0_10px_32px_rgba(15,23,42,0.06)]">
        <div className="text-[15px] font-semibold leading-6 text-slate-900">
          审计流程加载中
        </div>
        <div className="mt-3 rounded-2xl border border-slate-200 bg-slate-50 px-3 py-2 text-sm leading-6 text-slate-700">
          {content}
        </div>
      </div>
    );
  }
  return <VerticalFlow nodes={nodes} />;
};

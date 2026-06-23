"use client";

import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { type RunResult, stringifySafe, runCode } from "./sql-runner";
import { useEffect, useMemo, useState, useRef } from "react";
import { CirclePlay } from "lucide-react";

/**
 * 运行结果弹窗组件 Props
 */
export type RunDialogProps = {
    open: boolean;
    onOpenChange: (open: boolean) => void;
    language?: string;
    running: boolean;
    result: RunResult | null;
    /** 本次执行的原始代码（SQL 文本） */
    code?: string;
};

/**
 * 运行结果弹窗：显示语言与执行 SQL（可编辑）
 * 支持重新运行，并展示结果表格/错误信息。
 */
export function RunDialog({ open, onOpenChange, language, running, result, code }: RunDialogProps) {
    // 本地重新运行状态与结果（不改动父组件状态）
    const [localRunning, setLocalRunning] = useState(false);
    const [localResult, setLocalResult] = useState<RunResult | null>(null);

    const shownResult = localResult ?? result;
    const isRunning = running || localRunning;
    const rows = useMemo(
        () => (shownResult?.rows ? [...shownResult.rows] : []) as Array<Record<string, unknown>>,
        [shownResult?.rows]
    );
    const columns = useMemo(
        () => (rows.length > 0 ? Object.keys(rows[0] as Record<string, unknown>) : []),
        [rows]
    );
    // 从原始响应中提取运行耗时（秒）
    const costTime = useMemo(() => {
        const raw: unknown = shownResult?.raw;
        if (raw && typeof raw === "object" && typeof (raw as { cost_time?: unknown }).cost_time === "number") {
            return (raw as { cost_time: number }).cost_time;
        }
        return undefined;
    }, [shownResult?.raw]);

    // 可编辑的 SQL（初始值为传入 code），对话框关闭时重置
    const [editableSql, setEditableSql] = useState(code || "");
    useEffect(() => {
        if (open) {
            setEditableSql(code || "");
            // 打开时重置本地状态，避免上次运行的结果干扰
            setLocalRunning(false);
            setLocalResult(null);
        }
    }, [open, code]);

    const onReRun = async () => {
        if (!editableSql.trim()) return;
        setLocalRunning(true);
        setLocalResult(null);
        const res = await runCode(language || "sql", editableSql);
        setLocalResult(res);
        setLocalRunning(false);
    };

    // 动态计时：在 isRunning 期间实时显示耗时
    const [elapsed, setElapsed] = useState(0);
    const startRef = useRef<number | null>(null);
    useEffect(() => {
        if (isRunning) {
            // 启动计时
            startRef.current = performance.now();
            setElapsed(0);
            const id = setInterval(() => {
                if (startRef.current != null) {
                    setElapsed((performance.now() - startRef.current) / 1000);
                }
            }, 100); // 100ms 更新一次，兼顾流畅与性能
            return () => {
                clearInterval(id);
            };
        } else {
            // 停止计时并重置
            startRef.current = null;
        }
    }, [isRunning]);

    return (
        <Dialog open={open} onOpenChange={onOpenChange}>
            <DialogContent className="sm:max-w-4xl">
                <DialogHeader>
                    <DialogTitle>运行结果</DialogTitle>
                    <DialogDescription>
                        {language ? `语言：${language}` : "SQL"}
                    </DialogDescription>
                </DialogHeader>

                {/* 显示并可编辑本次执行的 SQL + 顶部运行按钮 */}
                <div className="space-y-2 mb-4">
                    <div className="flex items-center justify-between">
                        <div className="text-xs font-semibold text-muted-foreground">执行的 SQL（可编辑）</div>
                        <Button size="sm" onClick={onReRun} disabled={isRunning || !editableSql.trim()}>
                            <CirclePlay className="mr-1" /> 运行
                        </Button>
                    </div>
                    <textarea
                        className="w-full min-h-[100px] resize-none rounded-md border bg-muted/40 p-2 font-mono text-xs leading-relaxed focus:outline-none focus:ring-2 focus:ring-ring"
                        spellCheck={false}
                        aria-label="执行的 SQL"
                        value={editableSql}
                        onChange={(e) => setEditableSql(e.target.value)}
                    />
                </div>

                <div className="max-h-[60vh] space-y-4 overflow-auto" aria-busy={isRunning}>
                    <div className="text-sm text-muted-foreground">
                        {isRunning ? (
                            <>
                                运行中...
                                <span className="ml-2 tabular-nums">{elapsed.toFixed(2)}s</span>
                            </>
                        ) : (
                            <>运行结果</>
                        )}
                    </div>
                    {!isRunning && shownResult && (
                        <div className="space-y-3">
                            {shownResult.errorText && (
                                <div>
                                    <div className="mb-1 text-xs font-semibold text-red-500">error</div>
                                    <pre className="rounded-md bg-red-50 p-3 text-sm text-red-600 whitespace-pre-wrap break-words">
                                        {shownResult.errorText}
                                    </pre>
                                </div>
                            )}

                            {rows.length > 0 && (
                                <ResultTable rows={rows} columns={columns} costTime={costTime} />
                            )}

                            {!shownResult.errorText && rows.length === 0 && (
                                <div className="text-sm text-muted-foreground">无结果</div>
                            )}

                            {process.env.NODE_ENV !== "production" && !!shownResult?.raw && (
                                <details className="rounded-md border p-3">
                                    <summary className="cursor-pointer text-xs text-muted-foreground">原始响应(raw)</summary>
                                    <pre className="mt-2 text-xs whitespace-pre-wrap break-words">{stringifySafe(shownResult.raw)}</pre>
                                </details>
                            )}
                        </div>
                    )}
                </div>
            </DialogContent>
        </Dialog>
    );
}

function formatCell(v: unknown): string {
    if (v == null) return "";
    if (typeof v === "object") return stringifySafe(v);
    return String(v);
}

/**
 * 简单结果表格渲染
 */
function ResultTable({
    columns,
    rows,
    costTime,
}: {
    columns: string[];
    rows: Array<Record<string, unknown>>;
    costTime?: number;
}) {
    return (
        <div className="rounded-md border">
            <div className="flex items-center justify-between px-3 py-2 text-xs text-muted-foreground">
                <span>共 {rows.length} 行</span>
                {typeof costTime === "number" && (
                    <span className="ml-4 whitespace-nowrap">耗时 {costTime.toFixed(3)}s</span>
                )}
            </div>
            <div className="overflow-auto">
                <table className="w-full text-sm">
                    <thead className="sticky top-0 bg-muted">
                        <tr>
                            {columns.map((col) => (
                                <th key={col} className="border-b px-3 py-2 text-left font-semibold">
                                    {col}
                                </th>
                            ))}
                        </tr>
                    </thead>
                    <tbody>
                        {rows.map((r, i) => (
                            <tr key={i} className="border-b last:border-0">
                                {columns.map((col) => (
                                    <td key={col} className="px-3 py-2 align-top">
                                        {formatCell((r as Record<string, unknown>)[col])}
                                    </td>
                                ))}
                            </tr>
                        ))}
                    </tbody>
                </table>
            </div>
        </div>
    );
}

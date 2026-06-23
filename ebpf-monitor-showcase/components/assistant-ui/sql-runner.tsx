"use client";

const BASE_URL = process.env.NEXT_PUBLIC_SQLOPT_SERVICE_URL || "http://127.0.0.1:8000";

// 运行结果类型（仅 SQL）
export type RunResult = {
    ok: boolean;
    errorText?: string;
    rows?: Record<string, unknown>[]; // 后端返回的 result 数组
    raw?: unknown; // 原始响应（用于调试）
};

// 公共入口：后续可根据语言分发到不同后端执行
export async function runCode(language: string | undefined, code: string | undefined): Promise<RunResult> {
    if (!code) return { ok: false, errorText: "没有可运行的代码" };
    const lang = (language || "").toLowerCase();
    if (!lang.includes("sql")) return { ok: false, errorText: "仅支持运行 SQL" };
    return runSql(code);
}

async function runSql(sql: string): Promise<RunResult> {
    try {
        const resp = await fetch(`${BASE_URL}/api/sqls/run`, {
            method: "POST",
            headers: buildHeaders(true),
            body: JSON.stringify({ sql }),
        });
        const data = await resp.json().catch(() => null);
        if (!resp.ok) {
            return { ok: false, errorText: `HTTP ${resp.status}`, raw: data };
        }
        if (!data || typeof data !== "object") {
            return { ok: false, errorText: "响应格式不正确", raw: data };
        }
        const success = (data as { success?: boolean }).success !== false;
        const rows = Array.isArray((data as { result?: unknown }).result) ? (data as { result?: Record<string, unknown>[] }).result : [];
        const error = typeof (data as { error?: unknown }).error === "string" ? (data as { error?: string }).error : "";
        if (!success || error) {
            return { ok: false, errorText: error || "执行失败", rows, raw: data };
        }
        return { ok: true, rows, raw: data };
    } catch (e) {
        return { ok: false, errorText: e instanceof Error ? e.message : String(e) };
    }
}

// 安全 stringify
export function stringifySafe(v: unknown): string {
    if (typeof v === "string") return v;
    try { return JSON.stringify(v, null, 2); } catch { return String(v); }
}

// 构造 Headers（复用 serviceUtils 的逻辑，为避免循环依赖在此轻量实现）
function buildHeaders(json = true): HeadersInit {
    const headers: HeadersInit = {};
    if (json) headers["content-type"] = "application/json";
    headers["accept"] = "application/json";
    const token = (typeof window !== "undefined") ? window.localStorage.getItem("SQLOPT_SERVICE_TOKEN") : undefined;
    if (token) headers["authorization"] = `Bearer ${token}`;
    return headers;
}
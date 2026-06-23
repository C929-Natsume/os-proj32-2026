"use client";

import { useEffect } from "react";
import { clearAuth } from "@/lib/auth";

/**
 * 全局挂钩 window.fetch：
 * - 任何前端发起的请求若返回 401/403，则自动清理本地登录态（localStorage + 事件广播）。
 * - 与各 service 中的 fetchWithAuth 形成双保险，覆盖第三方库内部的 fetch（如 AssistantChatTransport）。
 */
export default function GlobalAuthFetch() {
    useEffect(() => {
        if (typeof window === "undefined" || typeof window.fetch !== "function") return;
        const origFetch = window.fetch.bind(window);
        window.fetch = async (input: RequestInfo | URL, init?: RequestInit) => {
            const res = await origFetch(input as RequestInfo, init);
            // 简单策略：统一对 401/403 进行登出处理
            if (res && (res.status === 401 || res.status === 403)) {
                try { clearAuth(); } catch { /* ignore */ }
            }
            return res;
        };
        return () => { window.fetch = origFetch as unknown as typeof window.fetch; };
    }, []);
    return null;
}

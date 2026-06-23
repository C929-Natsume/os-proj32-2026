"use client";

// 统一的 fetch 包装：当后端返回 401/403 时，自动清理登录态
// 注意：不在这里组装 Authorization 头，仍然沿用各处的 buildHeaders；
// 这里只负责在鉴权失效时触发登出。

import { clearAuth } from "./authService";

let hasLoggedOut = false; // 防抖：同一时刻仅触发一次登出

export type FetchWithAuthInit = RequestInit & {
    /** 默认 true。为 false 则不在 401/403 时自动登出。 */
    autoLogout?: boolean;
};

export async function fetchWithAuth(input: RequestInfo | URL, init?: FetchWithAuthInit): Promise<Response> {
    const { autoLogout = true, ...rest } = init || {};
    let resp: Response;
    try {
        resp = await fetch(input as RequestInfo, rest as RequestInit);
    } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        throw new Error(`网络请求失败: ${message}`);
    }
    if (autoLogout && (resp.status === 401 || resp.status === 403)) {
        // 清理本地登录态并广播事件
        if (!hasLoggedOut) {
            hasLoggedOut = true;
            try { clearAuth(); } catch { /* ignore */ }
            // 短暂延时后允许再次触发（避免永久锁定）
            setTimeout(() => { hasLoggedOut = false; }, 2000);
        }
    }
    return resp;
}

export default fetchWithAuth;

"use client";

// 读取 Token，使用浏览器 localStorage
export const TOKEN_STORAGE_KEY = "SQLOPT_SERVICE_TOKEN";

export function getToken(): string | undefined {
    if (typeof window !== "undefined") {
        return window.localStorage.getItem(TOKEN_STORAGE_KEY) || undefined;
    }
    return undefined;
}

// 公共：构造请求头（可选 JSON）
export function buildHeaders(json = true): HeadersInit {
    const headers: HeadersInit = {};
    if (json) headers["content-type"] = "application/json";
    headers["accept"] = "application/json";
    const token = getToken();
    if (token) headers["authorization"] = `Bearer ${token}`;
    return headers;
}

// 轻量可观察 Store 工厂
export type Unsubscribe = () => void;
export function createStore<S>(initial: S) {
    let state = initial;
    const subs = new Set<() => void>();
    const notify = () => subs.forEach(fn => { try { fn(); } catch { } });
    return {
        getState(): Readonly<S> { return state; },
        subscribe(fn: () => void): Unsubscribe { subs.add(fn); return () => subs.delete(fn); },
        setState(patch: Partial<S> | ((prev: S) => Partial<S>)) {
            const next = typeof patch === "function" ? (patch as (p: S) => Partial<S>)(state) : patch;
            state = Object.assign({}, state, next);
            notify();
        }
    };
}

// 通用：selectedId 本地持久化
export function createSelectedIdStorage(storageKey: string) {
    return {
        read(): string | null {
            if (typeof window === "undefined") return null;
            try { return window.localStorage.getItem(storageKey); } catch { return null; }
        },
        save(id: string | null) {
            if (typeof window === "undefined") return;
            try {
                if (id) window.localStorage.setItem(storageKey, id);
                else window.localStorage.removeItem(storageKey);
            } catch { }
        }
    };
}

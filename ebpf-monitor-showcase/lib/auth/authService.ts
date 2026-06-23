"use client";

import { TOKEN_STORAGE_KEY } from "../serviceUtils";

export const API_BASE = process.env.NEXT_PUBLIC_SQLOPT_SERVICE_URL || "";

// 默认账号（首次访问自动登录，不存在则自动注册）
const DEFAULT_EMAIL = process.env.NEXT_PUBLIC_DEFAULT_EMAIL;
const DEFAULT_PASSWORD = process.env.NEXT_PUBLIC_DEFAULT_PASSWORD;
const DEFAULT_NAME = process.env.NEXT_PUBLIC_DEFAULT_NAME || "Default";

export type AuthResponse = {
    access_token: string;
    refresh_token: string;
    token_type: string; // "bearer"
    user_id: number;
    user_name: string;
};

export type RegisterRequest = {
    name: string;
    email: string;
    password: string;
};

export type LoginRequest = {
    email: string;
    password: string;
};

const AUTH_STORAGE_KEY = "SQLopt.auth";

export type AuthState = {
    accessToken: string;
    refreshToken: string;
    tokenType: string;
    userId: number;
    userName: string;
    /** 标记是否为访客账号 */
    guest?: boolean;
};

export const AUTH_CHANGED_EVENT = "sqlopt:auth-changed";
type AuthChangedDetail = { kind: "login" | "logout" };
function emitAuthChanged(kind: AuthChangedDetail["kind"]) {
    if (typeof window === "undefined") return;
    try {
        window.dispatchEvent(new CustomEvent<AuthChangedDetail>(AUTH_CHANGED_EVENT as unknown as string, { detail: { kind } }));
    } catch { }
}

export function saveAuth(auth: AuthState) {
    if (typeof window === "undefined") return;
    try {
        window.localStorage.setItem(AUTH_STORAGE_KEY, JSON.stringify(auth));
        // 兼容现有 ModelPicker 等读取的 token key
        window.localStorage.setItem(TOKEN_STORAGE_KEY, auth.accessToken);
        emitAuthChanged("login");
    } catch { }
}

export function getAuth(): AuthState | null {
    if (typeof window === "undefined") return null;
    try {
        const raw = window.localStorage.getItem(AUTH_STORAGE_KEY);
        if (!raw) return null;
        return JSON.parse(raw) as AuthState;
    } catch {
        return null;
    }
}

export function isLoggedIn(): boolean {
    const a = getAuth();
    return !!(a && a.accessToken);
}

// ...访客令牌相关逻辑已移除

export function clearAuth() {
    if (typeof window === "undefined") return;
    try {
        window.localStorage.removeItem(AUTH_STORAGE_KEY);
        window.localStorage.removeItem(TOKEN_STORAGE_KEY);
        emitAuthChanged("logout");
    } catch { }
}

/**
 * 若本地无登录态且配置了默认账号环境变量，则自动尝试登录；
 * 登录失败（账号不存在）时自动注册后再登录。
 * 若用户已有登录态（包括手动登录或访客令牌），则保持现状不覆盖。
 */
export async function ensureDefaultAccount(): Promise<void> {
    if (typeof window === "undefined") return;
    if (getAuth()) return; // 已有登录态不覆盖
    if (!DEFAULT_EMAIL || !DEFAULT_PASSWORD) return; // 未配置默认账号
    try {
        await loginUser({ email: DEFAULT_EMAIL, password: DEFAULT_PASSWORD });
        console.info("[auth] default account logged in");
        return;
    } catch (e) {
        // 账号可能不存在，尝试注册
        try {
            await registerUser({ name: DEFAULT_NAME, email: DEFAULT_EMAIL, password: DEFAULT_PASSWORD });
            console.info("[auth] default account registered & logged in");
        } catch (e2) {
            console.warn("[auth] default account init failed", e, e2);
        }
    }
}

async function request<T>(path: string, body: unknown): Promise<T> {
    const res = await fetch(`${API_BASE}${path}`, {
        method: "POST",
        headers: {
            "content-type": "application/json",
            accept: "application/json",
        },
        body: JSON.stringify(body),
    });
    if (!res.ok) {
        const text = await res.text().catch(() => "");
        throw new Error(text || `HTTP ${res.status}`);
    }
    return (await res.json()) as T;
}

export async function registerUser(payload: RegisterRequest): Promise<AuthState> {
    const data = await request<AuthResponse>("/api/auth/register", payload);
    const auth: AuthState = {
        accessToken: data.access_token,
        refreshToken: data.refresh_token,
        tokenType: data.token_type,
        userId: data.user_id,
        userName: data.user_name,
    };
    saveAuth(auth);
    return auth;
}

export async function loginUser(payload: LoginRequest): Promise<AuthState> {
    const data = await request<AuthResponse>("/api/auth/login", payload);
    const auth: AuthState = {
        accessToken: data.access_token,
        refreshToken: data.refresh_token,
        tokenType: data.token_type,
        userId: data.user_id,
        userName: data.user_name,
    };
    saveAuth(auth);
    return auth;
}

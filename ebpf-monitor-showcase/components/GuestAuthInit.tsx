"use client";

import { useEffect } from "react";
import { ensureDefaultAccount } from "@/lib/auth";

/**
 * 初始化默认账号：
 * 若配置 NEXT_PUBLIC_DEFAULT_EMAIL / NEXT_PUBLIC_DEFAULT_PASSWORD 且本地无登录态 -> 自动登录/注册默认账号。
 * 用户后续手动登录后不会被覆盖。
 */
export default function GuestAuthInit() {
    useEffect(() => {
        (async () => {
            try {
                await ensureDefaultAccount();
            } catch { /* ignore default */ }
        })();
    }, []);
    return null;
}

"use client";
import * as React from "react";
import {
    Dialog,
    DialogContent,
    DialogHeader,
    DialogTitle,
    DialogDescription,
    DialogFooter,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { TypewriterEffectSmooth } from "@/components/ui/typewriter-effect";
import { loginUser, registerUser, isLoggedIn, getAuth, clearAuth } from "@/lib/auth";

export interface LoginModalProps {
    open: boolean;
    onOpenChange: (open: boolean) => void;
}

export function LoginModal({ open, onOpenChange }: LoginModalProps) {
    const [step, setStep] = React.useState<"intro" | "login" | "signup">("intro");
    const [loading, setLoading] = React.useState(false);
    const [error, setError] = React.useState<string | null>(null);
    const [authedName, setAuthedName] = React.useState<string | null>(null);
    const formRef = React.useRef<HTMLFormElement>(null);

    // 打开时回到引导页
    React.useEffect(() => {
        if (open) {
            setStep("intro");
            setError(null);
            const a = getAuth();
            setAuthedName(a?.userName || null);
        }
    }, [open]);

    const onLoginSubmit = async (e: React.FormEvent) => {
        e.preventDefault();
        setError(null);
        setLoading(true);
        try {
            const fd = new FormData(formRef.current || undefined);
            const email = String(fd.get("email") || "").trim();
            const password = String(fd.get("password") || "").trim();
            if (!email || !password) throw new Error("请输入邮箱和密码");
            const auth = await loginUser({ email, password });
            setAuthedName(auth.userName);
            onOpenChange(false);
        } catch (err) {
            const msg = err instanceof Error ? err.message : "登录失败";
            setError(msg);
        } finally {
            setLoading(false);
        }
    };

    const onSignupSubmit = async (e: React.FormEvent) => {
        e.preventDefault();
        setError(null);
        setLoading(true);
        try {
            const fd = new FormData(e.target as HTMLFormElement);
            const name = String(fd.get("name") || "").trim();
            const email = String(fd.get("email") || "").trim();
            const password = String(fd.get("password") || "").trim();
            const confirm = String(fd.get("confirm") || "").trim();
            if (!name) throw new Error("请输入用户名");
            if (!email) throw new Error("请输入邮箱");
            if (!password) throw new Error("请输入密码");
            if (password.length < 6) throw new Error("密码至少 6 位");
            if (password !== confirm) throw new Error("两次输入的密码不一致");
            const auth = await registerUser({ name, email, password });
            setAuthedName(auth.userName);
            onOpenChange(false);
        } catch (err) {
            const msg = err instanceof Error ? err.message : "注册失败";
            setError(msg);
        } finally {
            setLoading(false);
        }
    };

    return (
        <Dialog open={open} onOpenChange={onOpenChange}>
            {step === "intro" ? (
                <DialogContent className="max-w-lg">
                    <DialogHeader>
                        <DialogTitle>
                            <span className="sr-only">欢迎</span>
                        </DialogTitle>
                        <DialogDescription>
                            <span className="sr-only">请选择登录或注册以继续</span>
                        </DialogDescription>
                    </DialogHeader>
                    <div className="flex flex-col items-center justify-center py-6">
                        <p className="text-neutral-600 dark:text-neutral-200 text-xs sm:text-base mb-2">
                            {isLoggedIn() && authedName ? (
                                <span>已登录：{authedName}</span>
                            ) : (
                                <span>登录监控控制台</span>
                            )}
                        </p>
                        <TypewriterEffectSmooth
                            words={[
                                { text: "获取" },
                                { text: "审计模型" },
                                { text: "数据源" },
                                { text: "审计视图" },
                                { text: "配置。", className: "text-primary" },
                            ]}
                        />
                        {!isLoggedIn() ? (
                            <div className="mt-6 flex flex-col md:flex-row space-y-3 md:space-y-0 md:space-x-3">
                                <Button className="w-36" onClick={() => setStep("login")}>登录</Button>
                                <Button className="w-36" variant="outline" onClick={() => setStep("signup")}>
                                    注册
                                </Button>
                            </div>
                        ) : (
                            <div className="mt-6">
                                <Button
                                    variant="destructive"
                                    onClick={() => {
                                        clearAuth();
                                        setAuthedName(null);
                                    }}
                                >
                                    退出登录
                                </Button>
                            </div>
                        )}
                    </div>
                </DialogContent>
            ) : step === "login" ? (
                <DialogContent className="max-w-sm">
                    <DialogHeader className="text-center sm:text-center">
                        <DialogTitle>登录</DialogTitle>
                        <DialogDescription>登录以获取更多信息</DialogDescription>
                    </DialogHeader>
                    {error ? (
                        <div className="text-sm text-red-500 text-center">{error}</div>
                    ) : null}
                    <form ref={formRef} onSubmit={onLoginSubmit} className="space-y-3">
                        <div className="space-y-1.5">
                            <label className="text-sm font-medium text-foreground">邮箱</label>
                            <Input name="email" type="email" placeholder="请输入邮箱" required />
                        </div>
                        <div className="space-y-1.5">
                            <label className="text-sm font-medium text-foreground">密码</label>
                            <Input name="password" type="password" placeholder="请输入密码" required />
                        </div>
                        <DialogFooter className="gap-2">
                            <Button type="button" variant="ghost" onClick={() => setStep("intro")}>
                                返回
                            </Button>
                            <Button type="submit" disabled={loading}>
                                {loading ? "登录中…" : "登录"}
                            </Button>
                        </DialogFooter>
                    </form>
                </DialogContent>
            ) : (
                <DialogContent className="max-w-sm">
                    <DialogHeader className="text-center sm:text-center">
                        <DialogTitle>注册</DialogTitle>
                        <DialogDescription>创建新账号以开始使用</DialogDescription>
                    </DialogHeader>
                    {error ? (
                        <div className="text-sm text-red-500 text-center">{error}</div>
                    ) : null}
                    <form onSubmit={onSignupSubmit} className="space-y-3">
                        <div className="space-y-1.5">
                            <label className="text-sm font-medium text-foreground">用户名</label>
                            <Input name="name" placeholder="请输入用户名" required />
                        </div>
                        <div className="space-y-1.5">
                            <label className="text-sm font-medium text-foreground">邮箱</label>
                            <Input name="email" type="email" placeholder="请输入邮箱" required />
                        </div>
                        <div className="space-y-1.5">
                            <label className="text-sm font-medium text-foreground">密码</label>
                            <Input name="password" type="password" placeholder="请输入密码" required />
                        </div>
                        <div className="space-y-1.5">
                            <label className="text-sm font-medium text-foreground">确认密码</label>
                            <Input name="confirm" type="password" placeholder="请再次输入密码" required />
                        </div>
                        <DialogFooter className="gap-2">
                            <Button type="button" variant="ghost" onClick={() => setStep("intro")}>
                                返回
                            </Button>
                            <Button type="submit" disabled={loading}>
                                {loading ? "注册中…" : "注册"}
                            </Button>
                        </DialogFooter>
                    </form>
                </DialogContent>
            )}
        </Dialog>
    );
}

export default LoginModal;

"use client";

import Image from "next/image";
import { useEffect, useRef, useState, type FC } from "react";
import { databaseService, type DatabaseOption, type CreateDatabaseConnection } from "@/lib/database";
import { AUTH_CHANGED_EVENT } from "@/lib/auth";
import { NotFoundError, ValidationError } from "@/lib/errors";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "../ui/select";
import { Separator } from "../ui/separator";
import { Dialog, DialogContent, DialogFooter, DialogHeader, DialogTitle } from "../ui/dialog";
import { Button } from "../ui/button";
import { Input } from "../ui/input";
import { PlusIcon, Trash2Icon } from "lucide-react";
import editIcon from "../../assets/tools/edit.svg";
import dbIcon from "../../assets/providers/database.svg";

type IconType = string | import("next/image").StaticImageData;

export const DatabasePicker: FC = () => {
    const [options, setOptions] = useState<Array<{ name: string; value: string; icon: IconType }>>([]);
    const [val, setVal] = useState<string>("");
    const [loading, setLoading] = useState<boolean>(false);
    const ADD_VALUE = "__add__";
    const [menuOpen, setMenuOpen] = useState(false);
    // 拦截“删除”按钮导致的误选中
    const actionClickRef = useRef(false);
    const markActionClick = () => { actionClickRef.current = true; setTimeout(() => { actionClickRef.current = false; }, 100); };
    const stop = (e: Event | React.UIEvent | React.MouseEvent | React.PointerEvent | React.KeyboardEvent) => { e.preventDefault(); e.stopPropagation(); };
    const onActionPointerDownCapture = (e: React.PointerEvent) => { markActionClick(); e.stopPropagation(); };
    const onBtnMouseOrPointerDown = (e: React.MouseEvent | React.PointerEvent) => { markActionClick(); stop(e); };
    const onBtnMouseOrPointerUp = (e: React.MouseEvent | React.PointerEvent) => { markActionClick(); e.stopPropagation(); };
    const onBtnKeyDown = (e: React.KeyboardEvent) => { e.stopPropagation(); };

    // Add/Edit dialog state
    const [open, setOpen] = useState(false);
    const [dialogMode, setDialogMode] = useState<"add" | "edit">("add");
    const [editingId, setEditingId] = useState<string | null>(null);
    const [creating, setCreating] = useState(false);
    const [deletingId, setDeletingId] = useState<string | null>(null);
    const [form, setForm] = useState({
        database_name: "",
        database_uri: "",
        database_type: "opentenbase",
        database_description: "",
    });

    useEffect(() => {
        const syncFromService = () => {
            const opts: DatabaseOption[] = databaseService.getOptions();
            setOptions(opts.map(o => ({ name: o.name, value: o.value, icon: dbIcon })));
            setVal(databaseService.getSelectedId() ?? "");
        };
        const unsub = databaseService.subscribe(syncFromService);
        (async () => {
            setLoading(true);
            try {
                await databaseService.init();
                syncFromService();
            } finally {
                setLoading(false);
            }
        })();
        const onAuthChange = (e: CustomEvent<{ kind: "login" | "logout" }>) => {
            const kind = e?.detail?.kind;
            if (kind === "login") {
                setLoading(true);
                databaseService.refresh().finally(() => setLoading(false));
            } else if (kind === "logout") {
                setOptions([]);
                setVal("");
            }
        };
        window.addEventListener(AUTH_CHANGED_EVENT as unknown as string, onAuthChange as EventListener);
        return () => { unsub(); window.removeEventListener(AUTH_CHANGED_EVENT as unknown as string, onAuthChange as EventListener); };
    }, []);

    const handleSelectOpenChange = async (isOpen: boolean) => {
        setMenuOpen(isOpen);
        if (!isOpen) return;
        setLoading(true);
        try {
            await databaseService.refresh();
            const opts: DatabaseOption[] = databaseService.getOptions();
            setOptions(opts.map(o => ({ name: o.name, value: o.value, icon: dbIcon })));
        } finally {
            setLoading(false);
        }
    };

    const handleChange = async (v: string) => {
        if (v === ADD_VALUE) {
            setDialogMode("add");
            setEditingId(null);
            setForm({ database_name: "", database_uri: "", database_type: "opentenbase", database_description: "" });
            setOpen(true);
            return;
        }
        const prev = val;
        setVal(v);
        setLoading(true);
        try {
            await databaseService.select(v);
        } catch (e) {
            console.error(e);
            setVal(prev);
        } finally {
            setLoading(false);
        }
    };

    // 独立编辑入口
    const openEdit = async (id: string) => {
        setDialogMode("edit");
        setEditingId(id);
        setLoading(true);
        try {
            const info = await databaseService.get(id);
            setForm({
                database_name: info.database_name || "",
                database_uri: info.database_uri || "",
                database_type: info.database_type || "",
                database_description: info.database_description || "",
            });
            setOpen(true);
        } catch (e) {
            console.error(e);
        } finally {
            setLoading(false);
        }
    };

    const handleDelete = async (e: React.MouseEvent, id: string) => {
        e.preventDefault();
        e.stopPropagation();
        if (deletingId) return;
        const ok = typeof window !== "undefined" ? window.confirm("确认删除该数据库连接？") : true;
        if (!ok) return;
        try {
            setDeletingId(id);
            await databaseService.remove(id);
        } catch (err) {
            console.error(err);
            if (err instanceof NotFoundError) {
                if (typeof window !== "undefined") window.alert("删除失败：记录不存在（可能已被删除）。");
            } else if (err instanceof ValidationError) {
                if (typeof window !== "undefined") window.alert("删除失败：参数错误，请检查 connection_id。");
            } else if (err instanceof Error) {
                if (typeof window !== "undefined") window.alert(`删除失败：${err.message}`);
            }
        } finally {
            setDeletingId(null);
        }
    };

    const submitDialog = async () => {
        if (!form.database_name?.trim() || !form.database_uri?.trim()) {
            return; // 必填：名称与 URI
        }
        setCreating(true);
        try {
            if (dialogMode === "add") {
                const payload: CreateDatabaseConnection = {
                    database_name: form.database_name,
                    database_uri: form.database_uri,
                    database_type: form.database_type,
                    database_description: form.database_description,
                };
                const created = await databaseService.create(payload);
                console.log("Database created:", created);
            } else if (dialogMode === "edit" && editingId) {
                const updated = await databaseService.update(editingId, {
                    database_name: form.database_name,
                    database_uri: form.database_uri,
                    database_type: form.database_type,
                    database_description: form.database_description,
                }, "PUT");
                console.log("Database updated:", updated);
            }
            setOpen(false);
            setForm({ database_name: "", database_uri: "", database_type: "opentenbase", database_description: "" });
            setEditingId(null);
        } catch (err) {
            console.error(err);
        } finally {
            setCreating(false);
        }
    };

    return (
        <>
            <Select value={val} onValueChange={handleChange} disabled={loading} onOpenChange={handleSelectOpenChange}>
                <SelectTrigger className="min-w-[150px] max-w-[300px]" aria-busy={loading}>
                    {(() => {
                        const selected = options.find(o => o.value === val);
                        return selected ? (
                            <div className="flex flex-row items-center px-2 whitespace-nowrap space-x-3">
                                <span className="relative h-5 w-5 shrink-0">
                                    <Image src={selected.icon} alt={selected.name} fill className="object-contain" />
                                </span>
                                <span className="min-w-0 truncate">{selected.name}</span>
                            </div>
                        ) : <SelectValue placeholder="请选择数据源" />;
                    })()}
                </SelectTrigger>
                <SelectContent>
                    {options.map((db) => (
                        <SelectItem
                            key={db.value}
                            value={db.value}
                            onSelect={(e) => { if (actionClickRef.current) { e.preventDefault(); (e as unknown as { stopPropagation?: () => void }).stopPropagation?.(); } }}
                        >
                            <div className="flex w-full items-center justify-between">
                                <span className="flex flex-row items-center min-w-0 space-x-3">
                                    <span className="relative h-4 w-4 shrink-0">
                                        <Image src={db.icon} alt={db.name} fill className="object-contain" />
                                    </span>
                                    <span className="truncate">{db.name}</span>
                                </span>
                                {menuOpen && (
                                    <span className="flex items-center gap-2 pl-2" onPointerDownCapture={onActionPointerDownCapture}>
                                        <button
                                            title="编辑"
                                            className="rounded p-1 text-muted-foreground hover:bg-primary/10 hover:text-primary disabled:opacity-50"
                                            onMouseDown={onBtnMouseOrPointerDown}
                                            onPointerDown={onBtnMouseOrPointerDown}
                                            onPointerUp={onBtnMouseOrPointerUp}
                                            onMouseUp={onBtnMouseOrPointerUp}
                                            onKeyDown={onBtnKeyDown}
                                            onClick={(e) => { stop(e); openEdit(db.value); }}
                                            disabled={loading}
                                        >
                                            <span className="relative block h-4 w-4">
                                                <Image src={editIcon} alt="编辑" fill className="object-contain" />
                                            </span>
                                        </button>
                                        <button
                                            title="删除"
                                            className="rounded p-1 text-muted-foreground hover:bg-destructive/10 hover:text-destructive disabled:opacity-50"
                                            onMouseDown={onBtnMouseOrPointerDown}
                                            onPointerDown={onBtnMouseOrPointerDown}
                                            onPointerUp={onBtnMouseOrPointerUp}
                                            onMouseUp={onBtnMouseOrPointerUp}
                                            onKeyDown={onBtnKeyDown}
                                            onClick={(e) => handleDelete(e, db.value)}
                                            disabled={deletingId === db.value || loading}
                                        >
                                            <Trash2Icon className="size-4" />
                                        </button>
                                    </span>
                                )}
                            </div>
                        </SelectItem>
                    ))}
                    <Separator className="my-1" />
                    <SelectItem value={ADD_VALUE} disabled={loading}>
                        <span className="flex items-center gap-2 text-muted-foreground">
                            <PlusIcon className="size-4" />
                            <span>添加数据库连接…</span>
                        </span>
                    </SelectItem>
                </SelectContent>
            </Select>

            <Dialog open={open} onOpenChange={setOpen}>
                <DialogContent>
                    <DialogHeader>
                        <DialogTitle>{dialogMode === "add" ? "添加数据库连接" : "编辑数据库连接"}</DialogTitle>
                    </DialogHeader>
                    <div className="grid gap-3 py-2">
                        <div className="grid gap-1">
                            <label className="text-sm text-muted-foreground">显示名称（必填）</label>
                            <Input value={form.database_name} onChange={(e) => setForm((f) => ({ ...f, database_name: e.target.value }))} placeholder="例如：主库-线上" />
                        </div>
                        <div className="grid gap-1">
                            <label className="text-sm text-muted-foreground">连接 URI（必填）</label>
                            <Input value={form.database_uri} onChange={(e) => setForm((f) => ({ ...f, database_uri: e.target.value }))} placeholder="例如：mysql://user:pass@host:3306/db" />
                        </div>
                        <div className="grid gap-1">
                            <label className="text-sm text-muted-foreground">类型（可选）</label>
                            <Input value={form.database_type} onChange={(e) => setForm((f) => ({ ...f, database_type: e.target.value }))} placeholder="例如：opentenbase" />
                        </div>
                        <div className="grid gap-1">
                            <label className="text-sm text-muted-foreground">描述（可选）</label>
                            <Input value={form.database_description} onChange={(e) => setForm((f) => ({ ...f, database_description: e.target.value }))} placeholder="简短说明" />
                        </div>
                    </div>
                    <DialogFooter>
                        <Button variant="outline" onClick={() => setOpen(false)} disabled={creating}>取消</Button>
                        <Button onClick={submitDialog} disabled={creating || !form.database_name.trim() || !form.database_uri.trim()}>
                            {creating ? (dialogMode === "add" ? "创建中..." : "保存中...") : (dialogMode === "add" ? "创建" : "保存")}
                        </Button>
                    </DialogFooter>
                </DialogContent>
            </Dialog>
        </>
    );
};

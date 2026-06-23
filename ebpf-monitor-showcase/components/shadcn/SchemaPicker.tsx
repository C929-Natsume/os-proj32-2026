"use client";

import Image from "next/image";
import { useEffect, useRef, useState, type FC } from "react";
import { schemaService, type SchemaOption, type CreateDbSchema, type UpdateDbSchema } from "@/lib/schema";
import { AUTH_CHANGED_EVENT } from "@/lib/auth";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "../ui/select";
import { Separator } from "../ui/separator";
import { Dialog, DialogContent, DialogFooter, DialogHeader, DialogTitle } from "../ui/dialog";
import { Button } from "../ui/button";
import { Input } from "../ui/input";
import { PlusIcon, Trash2Icon } from "lucide-react";
import { NotFoundError, ValidationError } from "@/lib/errors";
import editIcon from "../../assets/tools/edit.svg";
import schemaIcon from "../../assets/providers/schema.svg";

export const SchemaPicker: FC = () => {
    const [options, setOptions] = useState<Array<{ name: string; value: string }>>([]);
    const [val, setVal] = useState<string>("");
    const [loading, setLoading] = useState<boolean>(false);
    const ADD_VALUE = "__add__";
    const [menuOpen, setMenuOpen] = useState(false);

    const [open, setOpen] = useState(false);
    const [dialogMode, setDialogMode] = useState<"add" | "edit">("add");
    const [editingId, setEditingId] = useState<string | null>(null);
    const [creating, setCreating] = useState(false);
    const [deletingId, setDeletingId] = useState<string | null>(null);
    const [form, setForm] = useState({
        schema_name: "",
        schema_content: "",
    });

    // 防止 SelectItem 被“编辑/删除”按钮误触发选中
    const actionClickRef = useRef(false);
    const markActionClick = () => { actionClickRef.current = true; setTimeout(() => { actionClickRef.current = false; }, 100); };
    const stop = (e: Event | React.UIEvent | React.MouseEvent | React.PointerEvent | React.KeyboardEvent) => { e.preventDefault(); e.stopPropagation(); };
    const onActionPointerDownCapture = (e: React.PointerEvent) => { markActionClick(); e.stopPropagation(); };
    const onBtnMouseOrPointerDown = (e: React.MouseEvent | React.PointerEvent) => { markActionClick(); stop(e); };
    const onBtnMouseOrPointerUp = (e: React.MouseEvent | React.PointerEvent) => { markActionClick(); e.stopPropagation(); };
    const onBtnKeyDown = (e: React.KeyboardEvent) => { e.stopPropagation(); };

    useEffect(() => {
        const syncFromService = () => {
            const opts: SchemaOption[] = schemaService.getOptions();
            setOptions(opts.map((o) => ({ name: o.name, value: o.value })));
            setVal(schemaService.getSelectedId() ?? "");
        };
        const unsub = schemaService.subscribe(syncFromService);
        (async () => {
            setLoading(true);
            try {
                await schemaService.init();
                syncFromService();
            } finally {
                setLoading(false);
            }
        })();
        const onAuthChange = (e: CustomEvent<{ kind: "login" | "logout" }>) => {
            const kind = e?.detail?.kind;
            if (kind === "login") {
                setLoading(true);
                schemaService.refresh().finally(() => setLoading(false));
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
            await schemaService.refresh();
            // 刷新后选项由订阅同步
        } finally {
            setLoading(false);
        }
    };

    const handleChange = async (v: string) => {
        if (v === ADD_VALUE) {
            setDialogMode("add");
            setEditingId(null);
            setForm({ schema_name: "", schema_content: "" });
            setOpen(true);
            return;
        }
        const prev = val;
        setVal(v);
        setLoading(true);
        try {
            await schemaService.select(v);
        } catch (e) {
            console.error(e);
            setVal(prev);
        } finally {
            setLoading(false);
        }
    };

    const handleDelete = async (e: React.MouseEvent, id: string) => {
        e.preventDefault();
        e.stopPropagation();
        if (deletingId) return;
        const ok = typeof window !== "undefined" ? window.confirm("确认删除该 Schema？") : true;
        if (!ok) return;
        try {
            setDeletingId(id);
            await schemaService.remove(id);
        } catch (err) {
            console.error(err);
            if (err instanceof NotFoundError) {
                if (typeof window !== "undefined") window.alert("删除失败：记录不存在（可能已被删除）。");
            } else if (err instanceof ValidationError) {
                if (typeof window !== "undefined") window.alert("删除失败：参数错误，请检查 schema_id。");
            } else if (err instanceof Error) {
                if (typeof window !== "undefined") window.alert(`删除失败：${err.message}`);
            }
        } finally {
            setDeletingId(null);
        }
    };

    // 独立编辑入口
    const openEdit = async (id: string) => {
        setDialogMode("edit");
        setEditingId(id);
        setLoading(true);
        try {
            const info = await schemaService.get(id);
            setForm({
                schema_name: info.schema_name || "",
                schema_content: info.schema_content || "",
            });
            setOpen(true);
        } catch (e) {
            console.error(e);
        } finally {
            setLoading(false);
        }
    };

    const submitDialog = async () => {
        if (!form.schema_content?.trim()) {
            return; // schema_content 为必填
        }
        setCreating(true);
        try {
            if (dialogMode === "add") {
                const payload: CreateDbSchema = {
                    schema_name: form.schema_name || undefined,
                    schema_content: form.schema_content,
                };
                const created = await schemaService.create(payload);
                console.log("Schema created:", created);
            } else if (dialogMode === "edit" && editingId) {
                const payload: UpdateDbSchema = {
                    schema_name: form.schema_name || undefined,
                    schema_content: form.schema_content,
                };
                const updated = await schemaService.update(editingId, payload, "PUT");
                console.log("Schema updated:", updated);
            }
            setOpen(false);
            setForm({ schema_name: "", schema_content: "" });
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
                <SelectTrigger className="min-w-[150px] max-w-[480px]" aria-busy={loading}>
                    {(() => {
                        const selected = options.find(o => o.value === val);
                        return selected ? (
                            <div className="flex flex-row items-center px-2 whitespace-nowrap space-x-3">
                                <span className="relative h-5 w-5 shrink-0">
                                    <Image src={schemaIcon} alt={selected.name} fill className="object-contain" />
                                </span>
                                <span className="min-w-0 truncate">{selected.name}</span>
                            </div>
                        ) : <SelectValue placeholder="请选择审计视图" />;
                    })()}
                </SelectTrigger>
                <SelectContent>
                    {options.map((s) => (
                        <SelectItem
                            key={s.value}
                            value={s.value}
                            onSelect={(e) => { if (actionClickRef.current) { e.preventDefault(); (e as unknown as { stopPropagation?: () => void }).stopPropagation?.(); } }}
                        >
                            <div className="flex w-full items-center justify-between">
                                <span className="flex items-center min-w-0 space-x-3">
                                    <span className="relative h-4 w-4 shrink-0">
                                        <Image src={schemaIcon} alt={s.name} fill className="object-contain" />
                                    </span>
                                    <span className="truncate">{s.name}</span>
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
                                            onClick={(e) => { stop(e); openEdit(s.value); }}
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
                                            onClick={(e) => handleDelete(e, s.value)}
                                            disabled={deletingId === s.value || loading}
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
                            <span>添加 Schema…</span>
                        </span>
                    </SelectItem>
                </SelectContent>
            </Select>

            <Dialog open={open} onOpenChange={setOpen}>
                <DialogContent>
                    <DialogHeader>
                        <DialogTitle>{dialogMode === "add" ? "添加 Schema" : "编辑 Schema"}</DialogTitle>
                    </DialogHeader>
                    <div className="grid gap-3 py-2">
                        <div className="grid gap-1">
                            <label className="text-sm text-muted-foreground">名称（可选）</label>
                            <Input value={form.schema_name} onChange={(e) => setForm((f) => ({ ...f, schema_name: e.target.value }))} placeholder="例如：线上库 Schema" />
                        </div>
                        <div className="grid gap-1">
                            <label className="text-sm text-muted-foreground">内容（JSON 或 DDL，必填）</label>
                            <Input value={form.schema_content} onChange={(e) => setForm((f) => ({ ...f, schema_content: e.target.value }))} placeholder="粘贴 Schema 内容" />
                        </div>
                    </div>
                    <DialogFooter>
                        <Button variant="outline" onClick={() => setOpen(false)} disabled={creating}>取消</Button>
                        <Button onClick={submitDialog} disabled={creating || !form.schema_content.trim()}>
                            {creating ? (dialogMode === "add" ? "创建中..." : "保存中...") : (dialogMode === "add" ? "创建" : "保存")}
                        </Button>
                    </DialogFooter>
                </DialogContent>
            </Dialog>
        </>
    );
};

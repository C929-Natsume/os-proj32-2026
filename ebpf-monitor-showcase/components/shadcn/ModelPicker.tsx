"use client";
import Image from "next/image";
import { useEffect, useRef, useState, type FC } from "react";
import { modelService, type ModelOption } from "@/lib/model";
import { NotFoundError, ValidationError } from "@/lib/errors";
import { AUTH_CHANGED_EVENT } from "@/lib/auth";
import anthropic from "../../assets/providers/anthropic.svg";
import fireworks from "../../assets/providers/fireworks.svg";
import google from "../../assets/providers/google.svg";
import deepseek from "../../assets/providers/deepseek.svg";
import meta from "../../assets/providers/meta.svg";
import mistral from "../../assets/providers/mistral.svg";
import openai from "../../assets/providers/openai.svg";
import qwen from "../../assets/providers/qwen.svg";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "../ui/select";
import { Separator } from "../ui/separator";
import { Dialog, DialogContent, DialogFooter, DialogHeader, DialogTitle } from "../ui/dialog";
import { Button } from "../ui/button";
import { Input } from "../ui/input";
import { PlusIcon, Trash2Icon } from "lucide-react";
import editIcon from "../../assets/tools/edit.svg";

// icon 映射，使用 modelService 计算的 iconKey
type IconType = string | import("next/image").StaticImageData;
const ICONS: Record<string, IconType> = {
  openai,
  deepseek,
  anthropic,
  google,
  meta,
  mistral,
  fireworks,
  qwen,
};
export const ModelPicker: FC = () => {
  // 选项与当前选中的 id
  const [options, setOptions] = useState<Array<{ name: string; value: string; icon: IconType }>>([]);
  const [selectedId, setSelectedId] = useState<string>("");
  const [loading, setLoading] = useState<boolean>(false);
  const ADD_VALUE = "__add__";

  // 事件拦截策略说明：
  // - Radix Select 在 pointerup/mouseup 阶段提交选中，子元素按钮点击容易“误选中”。
  // - 在按钮 pointerdown 阶段标记 actionClickRef，并阻止冒泡；在 mouseup 仅 stopPropagation，允许 onClick 正常触发。
  // - 在 SelectItem 的 onSelect 中，根据 actionClickRef 判定并 e.preventDefault()，最终阻止选中。
  // - 标记有效时间（100ms）覆盖 mouseup→click 序列，避免竞态。
  // 用于标记“当前是点击了操作按钮区域”，在 SelectItem 的 onSelect 中阻止选中
  const actionClickRef = useRef(false);
  const markActionClick = () => {
    actionClickRef.current = true;
    // 在事件循环结束后清除标记，避免影响下一次普通选择
    setTimeout(() => {
      actionClickRef.current = false;
    }, 100);
  };

  // 常用事件帮助函数，提升可读性
  const stop = (e: Event | React.UIEvent | React.MouseEvent | React.PointerEvent | React.KeyboardEvent) => { e.preventDefault(); e.stopPropagation(); };
  const onActionPointerDownCapture = (e: React.PointerEvent) => { markActionClick(); e.stopPropagation(); };
  const onBtnMouseOrPointerDown = (e: React.MouseEvent | React.PointerEvent) => { markActionClick(); stop(e); };
  const onBtnMouseOrPointerUp = (e: React.MouseEvent | React.PointerEvent) => { markActionClick(); e.stopPropagation(); };
  const onBtnKeyDown = (e: React.KeyboardEvent) => { e.stopPropagation(); };
  const onEditClick = (e: React.MouseEvent, id: string) => { stop(e); openEdit(id); };
  const onDeleteClick = (e: React.MouseEvent, id: string) => handleDelete(e, id);

  // 新增/编辑弹窗状态
  const [dialogOpen, setDialogOpen] = useState(false);
  const [dialogMode, setDialogMode] = useState<"add" | "edit">("add");
  const [editingId, setEditingId] = useState<string | null>(null);
  const [creating, setCreating] = useState(false);
  const [deletingId, setDeletingId] = useState<string | null>(null);
  const [form, setForm] = useState({
    model_name: "",
    model: "",
    base_url: "",
    api_key: "",
    model_description: "",
    model_avatar_url: "",
  });

  // 独立的编辑入口，避免通过 handleChange 触发 select
  const openEdit = async (id: string) => {
    setDialogMode("edit");
    setEditingId(id);
    setLoading(true);
    try {
      const info = await modelService.get(id);
      setForm({
        model_name: info.model_name || "",
        model: info.model || "",
        base_url: info.base_url || "",
        api_key: info.api_key || "",
        model_description: info.model_description || "",
        model_avatar_url: info.model_avatar_url || "",
      });
      setDialogOpen(true);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  // 把 UI 状态绑定到 modelService 的本地 store
  useEffect(() => {
    const syncFromService = () => {
      const opts: ModelOption[] = modelService.getOptions();
      const mapped = opts.map(o => ({ name: o.name, value: o.value, icon: ICONS[o.iconKey] || openai }));
      setOptions(mapped);
      setSelectedId(modelService.getSelectedId() ?? "");
    };
    const unsub = modelService.subscribe(syncFromService);
    // 首次初始化
    (async () => {
      setLoading(true);
      try {
        await modelService.init();
        syncFromService();
      } finally {
        setLoading(false);
      }
    })();
    const onAuthChange = (e: CustomEvent<{ kind: "login" | "logout" }>) => {
      // 登录后刷新模型列表；登出后清空 UI 并显示占位
      const kind = e?.detail?.kind as ("login" | "logout" | undefined);
      if (kind === "login") {
        setLoading(true);
        modelService.refresh().finally(() => setLoading(false));
      } else if (kind === "logout") {
        setOptions([]);
        setSelectedId("");
      }
    };
    window.addEventListener(AUTH_CHANGED_EVENT as unknown as string, onAuthChange as EventListener);
    return () => { unsub(); window.removeEventListener(AUTH_CHANGED_EVENT as unknown as string, onAuthChange as EventListener); };
  }, []);

  // 
  // 下拉框展开时，实时从后端刷新列表（以便展示刚创建的模型等最新数据）
  const handleSelectOpenChange = async (isOpen: boolean) => {
    if (!isOpen) return;
    setLoading(true);
    try {
      await modelService.refresh();
      // 刷新后同步本地选项
      const opts: ModelOption[] = modelService.getOptions();
      const mapped = opts.map(o => ({ name: o.name, value: o.value, icon: ICONS[o.iconKey] || openai }));
      setOptions(mapped);
    } catch {
      // 忽略错误，保留现有选项
    } finally {
      setLoading(false);
    }
  };

  // 选择模型：设置活跃模型，成功则持久化选择
  const handleSelectChange = async (v: string) => {
    if (v === ADD_VALUE) {
      setDialogMode("add");
      setForm({ model_name: "", model: "", base_url: "", api_key: "", model_description: "", model_avatar_url: "" });
      setDialogOpen(true);
      setEditingId(null);
      return;
    }
    const prev = selectedId;
    setSelectedId(v);
    setLoading(true);
    try {
      await modelService.select(v);
      // 成功后 service 会同步 selectedId，这里由订阅回填
    } catch (e) {
      console.error(e);
      setSelectedId(prev);
    } finally {
      setLoading(false);
    }
  };

  // 删除模型
  const handleDelete = async (e: React.MouseEvent, id: string) => {
    // 阻止触发 SelectItem 的选择行为
    e.preventDefault();
    e.stopPropagation();
    if (deletingId) return;
    // 简单确认，可替换为自定义对话框
    const ok = typeof window !== "undefined" ? window.confirm("确认删除该模型连接？") : true;
    if (!ok) return;
    try {
      setDeletingId(id);
      await modelService.remove(id);
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

  // 新增/编辑模型
  const submitDialog = async () => {
    if (!form.model?.trim()) {
      // 至少需要模型标识
      return;
    }
    setCreating(true);
    try {
      if (dialogMode === "add") {
        const created = await modelService.create({
          model_name: form.model_name || form.model,
          model: form.model,
          base_url: form.base_url,
          api_key: form.api_key,
          model_description: form.model_description,
          model_avatar_url: form.model_avatar_url,
        });
        console.log("Model created:", created);
      } else if (dialogMode === "edit" && editingId) {
        const updated = await modelService.update(editingId, {
          model_name: form.model_name || form.model,
          model: form.model,
          base_url: form.base_url,
          api_key: form.api_key,
          model_description: form.model_description,
          model_avatar_url: form.model_avatar_url,
        }, "PUT");
        console.log("Model updated:", updated);
      }
      setDialogOpen(false);
      setForm({ model_name: "", model: "", base_url: "", api_key: "", model_description: "", model_avatar_url: "" });
      setEditingId(null);
    } catch (err) {
      console.error(err);
    } finally {
      setCreating(false);
    }
  };

  return (
    <>
      <Select value={selectedId} onValueChange={handleSelectChange} disabled={loading} onOpenChange={handleSelectOpenChange}>
        <SelectTrigger className="w-auto flex-grow-0 flex-shrink-0 min-w-[150px] max-w-[480px]" aria-busy={loading}>
          {/* 只显示选中项的图标和名称，不显示操作按钮 */}
          {(() => {
            const selected = options.find(o => o.value === selectedId);
            return selected ? (
              <div className="flex flex-row items-center px-2 whitespace-nowrap space-x-3">
                <span className="relative h-5 w-5 shrink-0">
                  <Image src={selected.icon} alt={selected.name} fill className="object-contain" />
                </span>
                <span className="min-w-0 truncate flex-shrink">{selected.name}</span>
              </div>
            ) : <SelectValue placeholder="请选择审计模型" />;
          })()}
        </SelectTrigger>
        <SelectContent className="min-w-[150px] max-w-[480px]">
          {options.map((model) => (
            <SelectItem
              key={model.value}
              value={model.value}
              onSelect={(e) => {
                // 如果本次触发来自“操作按钮区域”，则阻止该项被选中
                if (actionClickRef.current) {
                  e.preventDefault();
                  (e as unknown as { stopPropagation?: () => void }).stopPropagation?.();
                }
              }}
            >
              <div className="flex w-full items-center justify-between">
                <span className="flex flex-row items-center min-w-0 space-x-3">
                  <span className="relative h-4 w-4 shrink-0">
                    <Image src={model.icon} alt={model.name} fill className="object-contain" />
                  </span>
                  <span className="truncate">{model.name}</span>
                </span>
                <span
                  className="flex items-center gap-2 pl-2"
                  onPointerDownCapture={onActionPointerDownCapture}
                >
                  <button
                    title="编辑"
                    className="rounded p-1 text-muted-foreground hover:bg-primary/10 hover:text-primary disabled:opacity-50"
                    onMouseDown={onBtnMouseOrPointerDown}
                    onPointerDown={onBtnMouseOrPointerDown}
                    onPointerUp={onBtnMouseOrPointerUp}
                    onMouseUp={onBtnMouseOrPointerUp}
                    onKeyDown={onBtnKeyDown}
                    onClick={(e) => onEditClick(e, model.value)}
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
                    onClick={(e) => onDeleteClick(e, model.value)}
                    disabled={deletingId === model.value || loading}
                  >
                    <Trash2Icon className="size-4" />
                  </button>
                </span>
              </div>
            </SelectItem>
          ))}
          <Separator className="my-1" />
          <SelectItem value={ADD_VALUE} disabled={loading}>
            <span className="flex items-center gap-2 text-muted-foreground">
              <PlusIcon className="size-4" />
              <span>添加自定义模型…</span>
            </span>
          </SelectItem>
        </SelectContent>
      </Select>

      <Dialog open={dialogOpen} onOpenChange={setDialogOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>{dialogMode === "add" ? "添加自定义模型" : "编辑模型"}</DialogTitle>
          </DialogHeader>
          <div className="grid gap-3 py-2">
            <div className="grid gap-1">
              <label className="text-sm text-muted-foreground">显示名称（可选）</label>
              <Input value={form.model_name} onChange={(e) => setForm((f) => ({ ...f, model_name: e.target.value }))} placeholder="例如：GPT-4o mini (内部)" />
            </div>
            <div className="grid gap-1">
              <label className="text-sm text-muted-foreground">模型标识（必填）</label>
              <Input value={form.model} onChange={(e) => setForm((f) => ({ ...f, model: e.target.value }))} placeholder="例如：gpt-4o-mini" />
            </div>
            <div className="grid gap-1">
              <label className="text-sm text-muted-foreground">Base URL（可选）</label>
              <Input value={form.base_url} onChange={(e) => setForm((f) => ({ ...f, base_url: e.target.value }))} placeholder="例如：https://api.openai.com/v1" />
            </div>
            <div className="grid gap-1">
              <label className="text-sm text-muted-foreground">API密匙（可选）</label>
              <Input value={form.api_key} onChange={(e) => setForm((f) => ({ ...f, api_key: e.target.value }))} placeholder="例如：sk-..." />
            </div>
            <div className="grid gap-1">
              <label className="text-sm text-muted-foreground">描述（可选）</label>
              <Input value={form.model_description} onChange={(e) => setForm((f) => ({ ...f, model_description: e.target.value }))} placeholder="简短说明" />
            </div>
            <div className="grid gap-1">
              <label className="text-sm text-muted-foreground">头像 URL（可选）</label>
              <Input value={form.model_avatar_url} onChange={(e) => setForm((f) => ({ ...f, model_avatar_url: e.target.value }))} placeholder="https://.../avatar.png" />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setDialogOpen(false)} disabled={creating}>取消</Button>
            <Button onClick={submitDialog} disabled={creating || !form.model.trim()}>{creating ? (dialogMode === "add" ? "创建中..." : "保存中...") : (dialogMode === "add" ? "创建" : "保存")}</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  );
};
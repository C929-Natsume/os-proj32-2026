import { openai } from "@ai-sdk/openai";
import { anthropic } from "@ai-sdk/anthropic";
import { google } from "@ai-sdk/google";
import { mistral } from "@ai-sdk/mistral";
import { deepseek } from "@ai-sdk/deepseek";
import { streamText, UIMessage, convertToModelMessages } from "ai";

// 将前端的模型列表映射到 provider 与具体模型名
// 注意：不同 provider 的模型名需与各自 SDK 对应
const REGISTRY: Record<string, { provider: "openai" | "deepseek" | "anthropic" | "google" | "meta" | "mistral" | "fireworks"; name: string }> = {
  // OpenAI
  "gpt-4o-mini": { provider: "openai", name: "gpt-4o-mini" },

  // DeepSeek（占位，需替换为实际 ai-sdk provider 或使用 OpenAI 兼容端点）
  "deepseek-r1": { provider: "deepseek", name: "deepseek-reasoner" },

  // Anthropic
  "claude-3.5-sonnet": { provider: "anthropic", name: "claude-3-5-sonnet-latest" },

  // Google Gemini
  "gemini-2.0-flash": { provider: "google", name: "gemini-2.0-flash" },

  // Meta（占位：若使用 open-source 模型需要你自行托管或接入推理服务）
  "llama-3-8b": { provider: "meta", name: "llama-3-8b" },

  // Fireworks（占位：同上，需对接 fireworks API 或兼容端点）
  "firefunction-v2": { provider: "fireworks", name: "firefunction-v2" },

  // Mistral
  "mistral-7b": { provider: "mistral", name: "mistral-small-latest" },
};

function getProviderModel(sel: { provider: string; name: string }) {
  switch (sel.provider) {
    case "openai":
      return openai(sel.name);
    case "anthropic":
      return anthropic(sel.name);
    case "google":
      return google(sel.name);
    case "mistral":
      return mistral(sel.name);
    case "deepseek":
      return deepseek(sel.name);
    case "meta":
    case "fireworks":
      return null; // 未接入
    default:
      return openai("gpt-4o-mini");
  }
}

export async function POST(req: Request) {
  const url = new URL(req.url);
  const modelParam = url.searchParams.get("model") ?? "deepseek-r1";
  const sel = REGISTRY[modelParam];

  const { messages }: { messages: UIMessage[] } = await req.json();
  console.log("收到的消息格式：", JSON.stringify(messages, null, 2));
  console.log("使用的模型：", modelParam);

  if (!sel) {
    return new Response(
      JSON.stringify({ error: `Unsupported model: ${modelParam}` }),
      { status: 400, headers: { "content-type": "application/json" } },
    );
  }

  const selectedModel = getProviderModel(sel);
  if (!selectedModel) {
    return new Response(
      JSON.stringify({
        error: `Provider ${sel.provider} 暂未接入，请对接其 SDK 或兼容端点后再试`,
      }),
      { status: 501, headers: { "content-type": "application/json" } },
    );
  }

  const result = streamText({
    model: selectedModel,
    messages: convertToModelMessages(messages),
  });

  const uiMessageStream = result.toUIMessageStreamResponse();
  console.log("返回的流式响应：", uiMessageStream);
  return uiMessageStream;
}

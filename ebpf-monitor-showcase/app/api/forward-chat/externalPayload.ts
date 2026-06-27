import type { UIMessage } from 'ai';

export interface ForwardBody {
  messages: UIMessage[];
  meta?: Record<string, unknown>;
  model?: string;
}

export interface OptimizeRequestPayload {
  sql: string;
  stream: boolean;
}

export type BackendEvent = {
  type?: string;
  content?: unknown;
  reasoning_content?: unknown;
  metadata?: { langgraph_step?: unknown; [k: string]: unknown } | undefined;
  [k: string]: unknown;
};

export const SSE_HEADERS: Record<string, string> = {
  'Content-Type': 'text/event-stream',
  'Cache-Control': 'no-cache',
  Connection: 'keep-alive',
  'x-accel-buffering': 'no',
  'x-vercel-ai-ui-message-stream': 'v1',
};

const encoder = new TextEncoder();
const decoder = new TextDecoder();

export function extractLastUserText(messages: UIMessage[]): string {
  const lastUser = [...messages].reverse().find((m) => m.role === 'user');
  if (!lastUser) return '';

  const chunks: string[] = [];
  const content = (lastUser as unknown as { content?: unknown }).content;
  if (typeof content === 'string') chunks.push(content);

  const parts = (lastUser as unknown as { parts?: unknown }).parts;
  if (Array.isArray(parts)) {
    for (const p of parts as unknown[]) {
      if (typeof p === 'string') chunks.push(p);
      else if (p && typeof p === 'object') {
        const text = (p as Record<string, unknown>).text;
        if (typeof text === 'string') chunks.push(text);
      }
    }
  }
  return chunks.map(String).join('\n').trim();
}

export function buildOptimizeRequestPayload(body: ForwardBody): OptimizeRequestPayload {
  const meta = (body.meta || {}) as Record<string, unknown>;
  const fromMessages = extractLastUserText(body.messages);
  const fromMeta = typeof meta.sql === 'string' ? meta.sql : '';
  const sql = (fromMessages || fromMeta || '').trim();
  const stream = typeof meta.stream === 'boolean' ? meta.stream : true;
  return { sql, stream: Boolean(stream) };
}

export function createAssistantUIErrorStream(error: string, details?: string) {
  const message = details ? `${error}: ${details}` : error;
  const stream = new ReadableStream<Uint8Array>({
    start(controller) {
      controller.enqueue(encoder.encode(`data: ${JSON.stringify({ type: 'start' })}\n\n`));
      controller.enqueue(encoder.encode(`data: ${JSON.stringify({ type: 'start-step' })}\n\n`));
      controller.enqueue(encoder.encode(`data: ${JSON.stringify({ type: 'text-start', id: 'text-error' })}\n\n`));
      controller.enqueue(encoder.encode(`data: ${JSON.stringify({ type: 'text-delta', id: 'text-error', delta: message })}\n\n`));
      controller.enqueue(encoder.encode(`data: ${JSON.stringify({ type: 'text-end', id: 'text-error' })}\n\n`));
      controller.enqueue(encoder.encode(`data: ${JSON.stringify({ type: 'finish-step' })}\n\n`));
      controller.enqueue(encoder.encode(`data: ${JSON.stringify({ type: 'finish', finishReason: 'stop' })}\n\n`));
      controller.enqueue(encoder.encode('data: [DONE]\n\n'));
      controller.close();
    },
  });
  return new Response(stream, { headers: SSE_HEADERS });
}

export function toAssistantUIResponse(backendStream: ReadableStream<Uint8Array>) {
  let buffer = '';
  let currentBackendStep: number | null = null;
  let currentStepIndex = -1;
  let reasoningStarted = false;
  let lastReasoning = '';

  function reasoningId() {
    return `reasoning-${currentStepIndex}`;
  }
  function textId() {
    return 'text-main';
  }

  function closeReasoning(controller: TransformStreamDefaultController<Uint8Array>) {
    if (reasoningStarted) controller.enqueue(encoder.encode(`data: ${JSON.stringify({ type: 'reasoning-end', id: reasoningId() })}\n\n`));
    reasoningStarted = false;
    lastReasoning = '';
  }

  function* extractPayloadLines(text: string): Generator<string> {
    const lines = text.split(/\r?\n/);
    for (const raw of lines) {
      const trimmed = raw.trim();
      if (!trimmed) continue;
      if (trimmed.startsWith('data:')) {
        const payload = trimmed.slice(5).trim();
        if (payload) yield payload;
      } else {
        yield trimmed;
      }
    }
  }

  function processObj(obj: BackendEvent, controller: TransformStreamDefaultController<Uint8Array>) {
    const backendStep = obj?.metadata && typeof obj.metadata.langgraph_step === 'number' ? (obj.metadata.langgraph_step as number) : null;
    if (backendStep !== null && backendStep !== currentBackendStep) {
      closeReasoning(controller);
      currentStepIndex += 1;
      currentBackendStep = backendStep;
    } else if (currentStepIndex < 0) {
      currentStepIndex = 0;
    }

    if (typeof obj?.reasoning_content === 'string') {
      const newText = obj.reasoning_content as string;
      const delta = newText.startsWith(lastReasoning) ? newText.slice(lastReasoning.length) : newText;
      if (delta) {
        if (!reasoningStarted) {
          controller.enqueue(encoder.encode(`data: ${JSON.stringify({ type: 'reasoning-start', id: reasoningId() })}\n\n`));
          reasoningStarted = true;
        }
        controller.enqueue(encoder.encode(`data: ${JSON.stringify({ type: 'reasoning-delta', id: reasoningId(), delta })}\n\n`));
        lastReasoning = newText;
      }
    } else if (obj?.type === 'ReasoningChunk' && typeof obj?.content === 'string' && obj.content) {
      if (!reasoningStarted) {
        controller.enqueue(encoder.encode(`data: ${JSON.stringify({ type: 'reasoning-start', id: reasoningId() })}\n\n`));
        reasoningStarted = true;
      }
      controller.enqueue(encoder.encode(`data: ${JSON.stringify({ type: 'reasoning-delta', id: reasoningId(), delta: obj.content })}\n\n`));
    }

    if (obj?.type === 'AIMessageChunk' && typeof obj?.content === 'string' && obj.content) {
      controller.enqueue(encoder.encode(`data: ${JSON.stringify({ type: 'text-delta', id: textId(), delta: obj.content })}\n\n`));
    }
  }

  const uiTransform = new TransformStream<Uint8Array, Uint8Array>({
    start(controller) {
      controller.enqueue(encoder.encode(`data: ${JSON.stringify({ type: 'start' })}\n\n`));
      controller.enqueue(encoder.encode(`data: ${JSON.stringify({ type: 'start-step' })}\n\n`));
      controller.enqueue(encoder.encode(`data: ${JSON.stringify({ type: 'text-start', id: textId() })}\n\n`));
    },
    transform(chunk, controller) {
      buffer += decoder.decode(chunk, { stream: true });
      const lastNewlineIdx = Math.max(buffer.lastIndexOf('\n'), buffer.lastIndexOf('\r'));
      if (lastNewlineIdx === -1) return;
      const completePart = buffer.slice(0, lastNewlineIdx + 1);
      buffer = buffer.slice(lastNewlineIdx + 1);
      for (const line of extractPayloadLines(completePart)) {
        if (line === '[DONE]') continue;
        try {
          processObj(JSON.parse(line), controller);
        } catch {
          // ignore malformed chunk
        }
      }
    },
    flush(controller) {
      if (buffer.trim()) {
        for (const line of extractPayloadLines(buffer)) {
          if (line === '[DONE]') continue;
          try {
            processObj(JSON.parse(line), controller);
          } catch {
            // ignore malformed chunk
          }
        }
      }
      closeReasoning(controller);
      controller.enqueue(encoder.encode(`data: ${JSON.stringify({ type: 'text-end', id: textId() })}\n\n`));
      controller.enqueue(encoder.encode(`data: ${JSON.stringify({ type: 'finish-step' })}\n\n`));
      controller.enqueue(encoder.encode(`data: ${JSON.stringify({ type: 'finish', finishReason: 'stop' })}\n\n`));
      controller.enqueue(encoder.encode('data: [DONE]\n\n'));
    },
  });

  return new Response(backendStream.pipeThrough(uiTransform), { headers: SSE_HEADERS });
}

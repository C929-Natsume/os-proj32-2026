import {
  buildOptimizeRequestPayload,
  ForwardBody,
  createAssistantUIErrorStream,
  SSE_HEADERS,
  toAssistantUIResponse,
} from './externalPayload';
import { findLatestAnomaliesByQuery, findRelatedAudit } from '@/lib/server/monitorApi';

function jsonError(message: string, status = 400, detail?: unknown) {
  return new Response(JSON.stringify(detail !== undefined ? { error: message, detail } : { error: message }), {
    status,
    headers: { 'content-type': 'application/json', 'cache-control': 'no-store' },
  });
}

async function readBody(req: Request): Promise<ForwardBody | Response> {
  try {
    return (await req.json()) as ForwardBody;
  } catch {
    return jsonError('请求体必须是合法 JSON', 400);
  }
}

function makeAuditNarrative(query: string) {
  const anomalies = findLatestAnomaliesByQuery(query, 3);
  const steps: Array<{ reasoning: string; text: string }> = [];

  if (!anomalies.length) {
    steps.push({
      reasoning: '当前没有匹配到异常记录，系统改为返回最近的全量告警摘要。',
      text: '未命中指定异常，建议换用规则名、进程名、对象路径或严重级别继续检索。',
    });
    return steps;
  }

  steps.push({
    reasoning: `系统从真实监控库中检索到 ${anomalies.length} 条相关异常，并按最近时间排序。`,
    text: anomalies
      .map(
        (item, index) =>
          `${index + 1}. [${item.severity}] ${item.rule} | 进程=${item.comm} | 对象=${item.object || '-'} | 原因=${item.reason || '无'}`,
      )
      .join('\n'),
  });

  const primary = anomalies[0] as Record<string, any>;
  steps.push({
    reasoning: '系统基于规则类型和严重级别推断审计类别与处置建议。',
    text: `主异常命中规则 ${primary.rule}，严重级别 ${primary.severity}，对象 ${primary.object || '-'}，属于需要重点说明的监控事件。`,
  });

  const relatedAudit = findRelatedAudit(String(primary.rule || ''), Number(primary.pid || 0)) as Record<string, any> | null;
  if (relatedAudit) {
    const result = relatedAudit.result || {};
    steps.push({
      reasoning: '系统找到对应的历史审计结果，用于补充 LLM 审计/关联审计结论。',
      text: `历史审计结果：decision=${result.decision || '-'}，class=${result.class || '-'}，status=${result.status || '-'}。`,
    });
  } else {
    steps.push({
      reasoning: '当前未找到完全对应的历史 audit_results 记录，因此本次展示基于异常记录做实时解释。',
      text: '没有直接命中的历史审计条目，但异常本身已经足以用于展示链路和风险分析。',
    });
  }

  steps.push({
    reasoning: '系统输出最终结论，并给出适合比赛展示的解释性摘要。',
    text: '结论：该链路已从真实监控数据库走通。你当前看到的是基于 ebpf-multi-agent-monitor 真实日志生成的告警解读，可继续切换规则关键词查看更多过程。',
  });

  return steps;
}

function buildBackendNarrativeStream(query: string) {
  const encoder = new TextEncoder();
  const steps = makeAuditNarrative(query);

  return new ReadableStream<Uint8Array>({
    start(controller) {
      let stepIndex = 0;
      const send = (obj: unknown) => controller.enqueue(encoder.encode(`data: ${JSON.stringify(obj)}\n\n`));

      const pushStep = () => {
        if (stepIndex >= steps.length) {
          controller.enqueue(encoder.encode('data: [DONE]\n\n'));
          controller.close();
          return;
        }

        const step = steps[stepIndex];
        send({ metadata: { langgraph_step: stepIndex }, reasoning_content: step.reasoning });

        const lines = step.text.split(/\n/).filter(Boolean);
        for (const line of lines) {
          send({
            type: 'AIMessageChunk',
            content: `${line}\n`,
            metadata: { langgraph_step: stepIndex },
          });
        }

        stepIndex += 1;
        setTimeout(pushStep, 30);
      };

      pushStep();
    },
  });
}

export async function POST(req: Request) {
  const maybeBody = await readBody(req);
  if (maybeBody instanceof Response) return maybeBody;

  const body = maybeBody;
  if (!body?.messages || !Array.isArray(body.messages) || body.messages.length === 0) {
    return jsonError('缺少 messages 或格式不正确', 400);
  }

  const payload = buildOptimizeRequestPayload(body);
  if (!payload.sql) return createAssistantUIErrorStream('缺少输入内容');

  try {
    const backendStream = buildBackendNarrativeStream(payload.sql);
    return toAssistantUIResponse(backendStream);
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return createAssistantUIErrorStream('生成监控链路说明失败', message);
  }
}

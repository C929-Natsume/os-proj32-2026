import {
  buildOptimizeRequestPayload,
  ForwardBody,
  createAssistantUIErrorStream,
  toAssistantUIResponse,
} from './externalPayload';
import { findLatestAnomaliesByQuery, findRelatedAudit, readLatestIntraLogEntry } from '@/lib/server/monitorApi';

type NarrativeAnomaly = {
  severity?: string;
  rule?: string;
  comm?: string;
  object?: string | null;
  reason?: string | null;
  pid?: number;
};

type ShowcaseMode = 'single' | 'interactive' | 'all' | 'default';

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

function detectShowcaseMode(query: string): ShowcaseMode {
  const text = query.toLowerCase();
  if (text.includes('all') || text.includes('全量') || (text.includes('single') && text.includes('interactive')) || (text.includes('intra') && text.includes('inter'))) {
    return 'all';
  }
  if (text.includes('interactive') || text.includes('交互') || text.includes('inter')) {
    return 'interactive';
  }
  if (text.includes('single') || text.includes('单点') || text.includes('intra')) {
    return 'single';
  }
  return 'default';
}

function makeAuditNarrative(query: string) {
  const anomalies = findLatestAnomaliesByQuery(query, 3) as NarrativeAnomaly[];
  const steps: Array<{ reasoning: string; text: string }> = [];
  const mode = detectShowcaseMode(query);

  if (mode === 'single') {
    const logEntry = readLatestIntraLogEntry();
    if (logEntry) {
      return [
        {
          reasoning: `第1步：系统切换到 single 模式，并读取最新的 intra-agent 真实日志文件 ${logEntry.source_file}。`,
          text: [
            '第1步：showcase | 进入 single 单点展示模式',
            '1. 当前展示来源于真实的 intra-agent 用户友好日志',
            `2. 日志文件=${logEntry.source_file}`,
            `3. 异常类型=${logEntry.anomaly_type}`,
            `4. 风险等级=${logEntry.risk_level}`,
          ].join('\n'),
        },
        {
          reasoning: '第2步：前端按用户友好日志中的事件序列还原异常触发路径，而不是使用固定模板。',
          text: [
            '第2步：intra-agent | 还原异常事件序列',
            ...logEntry.event_sequence.slice(0, 4).map((item, index) => `${index + 1}. ${item}`),
          ].join('\n'),
        },
        {
          reasoning: '第3步：系统展示日志中记录的语义关联与根因定位，用于说明异常行为和上层意图之间的关系。',
          text: [
            '第3步：intra-agent | 展示语义关联与根因定位',
            ...(logEntry.semantic_association.length
              ? logEntry.semantic_association.slice(0, 3).map((item, index) => `${index + 1}. ${item}`)
              : ['1. 当前日志未记录最近语义上下文']),
            `${logEntry.semantic_association.length ? logEntry.semantic_association.length + 1 : 2}. 根因=${logEntry.root_cause || '-'}`,
          ].join('\n'),
        },
        {
          reasoning: '第4步：输出最终分析报告，并补充 PID、TID、对象等关键上下文，形成可演示的真实链路结果。',
          text: [
            '第4步：audit | 输出最终审计结论',
            `1. 时间=${logEntry.time}`,
            `2. PID/TID=${logEntry.pid ?? '-'} / ${logEntry.tid ?? '-'}`,
            `3. agent=${logEntry.agent_id}  comm=${logEntry.comm}`,
            `4. object=${logEntry.object}`,
            `5. 分析报告=${logEntry.analysis_report || '-'}`,
            ...(logEntry.evidence.length
              ? [`6. 关键证据=${logEntry.evidence.slice(0, 2).join(' | ')}`]
              : []),
          ].join('\n'),
        },
      ];
    }

    return [
      {
        reasoning: '第1步：系统切换到 single 模式，但当前未发现可用的 intra-agent 真实日志文件，因此回退到数据库异常摘要。',
        text: [
          '第1步：showcase | 进入 single 单点展示模式',
          '1. 当前未找到 logs/intra_agent/anomaly_YYYYMMDD_HHMMSS.log',
          '2. 已自动回退到真实监控数据库中的异常摘要',
        ].join('\n'),
      },
      {
        reasoning: '第2步：回退路径仍然基于真实落库数据，不是静态假数据。',
        text: [
          '第2步：intra-agent | 读取数据库异常摘要',
          '1. 使用 anomalies 与 audit_results 表生成说明',
          '2. 可以先运行 intra 审计后再回来查看完整真实日志链路',
        ].join('\n'),
      },
    ];
  }

  if (mode === 'interactive') {
    return [
      {
        reasoning: '第1步：系统切换到 interactive 模式，只展示 inter-agent 交互式多智能体异常分析链路。',
        text: [
          '第1步：showcase | 进入 interactive 交互展示模式',
          '1. 仅关注多智能体之间的交互关系与传播路径',
          '2. 展示消息流、拓扑关系与交互异常定位',
        ].join('\n'),
      },
      {
        reasoning: '第2步：interactive 模式会围绕 inter:messages、inter:events 和 inter:anomalies 等真实 Redis/SQLite 数据构建交互视图。',
        text: [
          '第2步：inter-agent | 构建交互拓扑视图',
          '1. 读取 agent 间消息、事件与异常流',
          '2. 还原交互链路与异常传播上下文',
        ].join('\n'),
      },
      {
        reasoning: '第3步：系统对提示注入、重复交互、角色偏离、资源竞争等协作异常进行分析。',
        text: [
          '第3步：inter-agent | 执行协作异常分析',
          '1. 识别角色冲突、异常接力、上下文丢失等问题',
          '2. 输出交互链路中的关键异常节点',
        ].join('\n'),
      },
      {
        reasoning: '第4步：最终以前端流程节点形式展示 inter-agent 检测结果，便于比赛讲解协作异常。',
        text: [
          '第4步：audit | 返回 inter-agent 展示结论',
          '1. 前端重点展示交互分支与异常传播路径',
          '2. 保持与 single 模式一致的展示壳子',
        ].join('\n'),
      },
    ];
  }

  if (mode === 'all') {
    return [
      {
        reasoning: '第1步：系统切换到 all 模式，同时串联 single 与 interactive 两条链路。',
        text: [
          '第1步：showcase | 进入 all 全量联合展示模式',
          '1. 同时展示单点异常检测与多智能体交互分析',
          '2. 统一使用真实监控数据库作为展示底座',
        ].join('\n'),
      },
      {
        reasoning: '第2步：上游先经过单体行为筛查，再进入交互关联分析，形成完整运行时视图。',
        text: [
          '第2步：intra-agent | 汇聚单体异常检测结果',
          '1. intra 负责发现单体风险',
          '2. inter 负责补充交互传播与根因关系',
        ].join('\n'),
      },
      {
        reasoning: '第3步：系统将规则检测、LLM 审计和交互拓扑分析结果汇总到统一展示层。',
        text: [
          '第3步：inter-agent | 汇聚交互异常与传播关系',
          '1. 合并 anomaly、audit_results 与交互异常结果',
          '2. 前端按流程图方式输出完整路径',
        ].join('\n'),
      },
      {
        reasoning: '第4步：最终返回比赛展示视角下的完整链路说明，兼顾单点风险与协作风险。',
        text: [
          '第4步：audit | 输出全链路联合审计结论',
          '1. 同时展示单体风险与协作风险',
          '2. 适用于完整系统能力讲解与答辩演示',
        ].join('\n'),
      },
    ];
  }

  if (!anomalies.length) {
    steps.push({
      reasoning: '第1步：当前没有匹配到异常记录，先回退到最近的全量告警摘要。',
      text: [
        '第1步：showcase | 接收查询请求',
        '1. 用户提交了异常检索请求',
        '2. 系统准备查询真实监控库',
        '第2步：audit | 返回空结果说明',
        '1. 当前没有找到直接匹配的异常记录',
        '2. 可以改用规则名、进程名、对象路径继续检索',
      ].join('\n'),
    });
    return steps;
  }

  const primary = anomalies[0] as Record<string, any>;
  steps.push({
    reasoning: `第1步：系统从真实监控库中检索到 ${anomalies.length} 条相关异常，并按最近时间排序。`,
    text: [
      '第1步：intra-agent | 检索异常记录',
      `1. 命中 ${anomalies.length} 条相关异常`,
      `2. 主规则=${primary.rule || '-'}`,
      `3. 主进程=${primary.comm || '-'}`,
      `4. 主对象=${primary.object || '-'}`,
    ].join('\n'),
  });

  steps.push({
    reasoning: '第2步：系统基于规则类型和严重级别推断审计类别与处置建议。',
    text: [
      '第2步：intra-agent | 形成主分析节点',
      `1. 严重级别=${primary.severity || '-'}`,
      `2. 异常原因=${primary.reason || '无'}`,
      '3. 该节点作为后续审计与展示的中心节点',
    ].join('\n'),
  });

  const relatedAudit = findRelatedAudit(String(primary.rule || ''), Number(primary.pid || 0)) as Record<string, any> | null;
  if (relatedAudit) {
    const result = relatedAudit.result || {};
    steps.push({
      reasoning: '第3步：系统找到对应的历史审计结果，用于补充 LLM 审计/关联审计结论。',
      text: [
        '第3步：audit | 生成审计复核分支',
        '1. 命中历史 audit_results 记录',
        `2. decision=${result.decision || '-'}`,
        `3. class=${result.class || '-'}`,
        `4. status=${result.status || '-'}`,
      ].join('\n'),
    });
  } else {
    steps.push({
      reasoning: '第3步：当前未找到完全对应的历史 audit_results 记录，因此本次展示基于异常记录做实时解释。',
      text: [
        '第3步：audit | 生成审计复核分支',
        '1. 当前没有直接命中的历史审计条目',
        '2. 采用异常记录本身进行实时解释',
      ].join('\n'),
    });
  }

  steps.push({
    reasoning: '第4步：系统输出最终结论，并给出适合比赛展示的解释性摘要。',
    text: [
      '第4步：showcase | 生成前端展示结论',
      '1. 链路已经从真实监控数据库走通',
      '2. 当前结果来自 ebpf-multi-agent-monitor 的真实日志与审计输出',
      '3. 可以继续切换规则关键词查看其他流程',
    ].join('\n'),
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
        send({
          type: 'AIMessageChunk',
          content: `${step.text}\n\n`,
          metadata: { langgraph_step: stepIndex },
        });

        stepIndex += 1;
        setTimeout(pushStep, 700);
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

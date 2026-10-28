<script setup lang="ts">
import type { EChartsOption } from 'echarts'
import { computed, ref, watch } from 'vue'
import { api } from '@/api/client'
import BaseChart from '@/components/BaseChart.vue'
import CloudBadge from '@/components/CloudBadge.vue'
import CodeBlock from '@/components/CodeBlock.vue'
import DataTable from '@/components/DataTable.vue'
import Icon from '@/components/Icon.vue'
import JsonView from '@/components/JsonView.vue'
import LoadState from '@/components/LoadState.vue'
import PermissionPath from '@/components/PermissionPath.vue'
import PolicyViewer from '@/components/PolicyViewer.vue'
import Tabs from '@/components/Tabs.vue'
import VerdictBadge from '@/components/VerdictBadge.vue'
import type { Column } from '@/components/table'
import { useFetch } from '@/composables/useFetch'
import { usePalette } from '@/composables/useTheme'
import { useAnalysis } from '@/stores/analysis'
import type { GraphFinding, RawPrivilegeFinding, Verdict } from '@/types'
import { chartBase } from '@/utils/chart'
import { formatNumber, percent } from '@/utils/format'
import { attachmentMeta, decisionMeta, findingMeta, reasonMeta, remediationMeta, verdictMeta } from '@/utils/labels'

const props = defineProps<{ name: string }>()
const store = useAnalysis()
const palette = usePalette()

const { data, loading, error, status, reload } = useFetch(() => api.identity(props.name))
watch(() => [props.name, store.version], reload, { immediate: true })

const tab = ref('policy')
watch(
  () => props.name,
  () => (tab.value = 'policy'),
)

const id = computed(() => data.value?.identity)
const model = computed(() => store.model)

// ── 판정 경로: hybrid.py 의 MergeModule.decide 와 같은 순서로 따라가 본다 ──────
interface Step {
  key: string
  title: string
  expr: string
  value?: number
  threshold?: number
  met: boolean
  outcome: Verdict
  state: 'decided' | 'skipped' | 'unmet'
}

const steps = computed<Step[]>(() => {
  const m = model.value
  const row = id.value
  if (!m || !row) return []
  const R = row.rule_score
  const A = row.anomaly_score
  const G = row.graph_score
  const weighted = Math.round((m.weights.rule * R + m.weights.ai * A + m.weights.graph * G) * 1000) / 1000
  const list: Omit<Step, 'state'>[] = [
    { key: 'rule', title: '규칙 위반', expr: 'R ≥ 1.0', value: R, threshold: 1, met: R >= 1, outcome: 'BLOCK' },
    {
      key: 'hybrid',
      title: '종합 점수',
      expr: `${m.weights.rule}·R + ${m.weights.ai}·A + ${m.weights.graph}·G ≥ ${m.threshold}`,
      value: weighted,
      threshold: m.threshold,
      met: weighted >= m.threshold,
      outcome: 'ALERT',
    },
    { key: 'ai', title: '행동 이상 단독', expr: `A ≥ ${m.ai_alert}`, value: A, threshold: m.ai_alert, met: A >= m.ai_alert, outcome: 'ALERT' },
    { key: 'graph', title: '권한 그래프 단독', expr: `G ≥ ${m.graph_alert}`, value: G, threshold: m.graph_alert, met: G >= m.graph_alert, outcome: 'ALERT' },
    { key: 'allow', title: '위 조건에 모두 해당 없음', expr: '', met: true, outcome: 'ALLOW' },
  ]
  const decidedAt = list.findIndex((s) => s.met)
  return list.map((s, i) => ({ ...s, state: i === decidedAt ? 'decided' : i > decidedAt ? 'skipped' : 'unmet' }))
})

// ── 점수 구성(레이더) ────────────────────────────────────────────────────────
const radar = computed<EChartsOption>(() => {
  const p = palette.value
  const row = id.value
  const color = row ? { BLOCK: p.block, ALERT: p.alert, ALLOW: p.allow }[row.verdict] : p.accent
  return {
    ...chartBase(p),
    tooltip: { ...chartBase(p).tooltip, trigger: 'item' },
    radar: {
      radius: '66%',
      indicator: [
        { name: '규칙 R', max: 1 },
        { name: '행동 이상 A', max: 1 },
        { name: '권한 그래프 G', max: 1 },
      ],
      axisName: { color: p.text, fontSize: 12, fontWeight: 600 },
      splitNumber: 4,
      splitLine: { lineStyle: { color: p.border } },
      splitArea: { show: false },
      axisLine: { lineStyle: { color: p.border } },
    },
    series: [
      {
        type: 'radar',
        symbolSize: 6,
        lineStyle: { color, width: 2 },
        itemStyle: { color },
        areaStyle: { color, opacity: 0.18 },
        data: [{ name: '점수', value: row ? [row.rule_score, row.anomaly_score, row.graph_score] : [0, 0, 0] }],
      },
    ],
  }
})

// ── 표 정의 ──────────────────────────────────────────────────────────────────
const graphColumns: Column<GraphFinding>[] = [
  { key: 'finding_type', label: '유형' },
  { key: 'operation', label: '작업' },
  { key: 'target', label: '대상 리소스' },
  { key: 'effect', label: 'Effect' },
  { key: 'description', label: '설명' },
]
const rawColumns: Column<RawPrivilegeFinding>[] = [
  { key: 'raw_action', label: '작업' },
  { key: 'scope', label: '범위' },
  { key: 'severity', label: '심각도' },
  { key: 'finding_type', label: '유형' },
  { key: 'description', label: '설명' },
]

const triggeredRules = computed(() => {
  const names = data.value?.rules?.triggered_rule_names ?? []
  return names.map((n) => ({ name: n, severity: model.value?.rules.find((r) => r.name === n)?.severity ?? null }))
})

// 행동 지표를 같은 클라우드의 중앙값과 비교한다.
const behaviorTiles = computed(() => {
  const d = data.value
  if (!d?.behavior) return []
  const ratio = (v: number, base: number) => (base > 0 ? v / base : null)
  const api = ratio(d.behavior.api_call_count, d.population.api_call_median)
  const fail = ratio(d.behavior.failed_login_count, d.population.failed_login_median)
  const night = d.behavior.login_hour < 6 || d.behavior.login_hour >= 22
  return [
    { label: '로그인 시간', value: `${d.behavior.login_hour}시`, note: night ? '야간 시간대' : '일과 시간대', warn: night },
    {
      label: 'API 호출 수',
      value: formatNumber(d.behavior.api_call_count),
      note: `${d.population.cloud} 중앙값 ${formatNumber(d.population.api_call_median)}${api ? ` · ${api.toFixed(1)}배` : ''}`,
      warn: !!api && api >= 3,
    },
    {
      label: '로그인 실패',
      value: `${d.behavior.failed_login_count}회`,
      note: `${d.population.cloud} 중앙값 ${d.population.failed_login_median}회${fail && Number.isFinite(fail) ? ` · ${fail.toFixed(1)}배` : ''}`,
      warn: d.behavior.failed_login_count >= d.population.failed_login_median * 3 && d.behavior.failed_login_count >= 5,
    },
  ]
})

const tabs = computed(() => [
  { key: 'policy', label: '권한·정책', count: data.value ? data.value.aws_policy_items.length || data.value.policies.length : undefined },
  { key: 'evidence', label: '분석 근거' },
  { key: 'input', label: '원본 입력' },
  { key: 'fix', label: '개선 권고' },
])

const metaRows = computed(() => {
  const m = data.value?.metadata
  if (!m) return []
  const yn = (v: boolean) => (v ? '예' : '아니오')
  return [
    ['역할', m.role],
    ['관리자 권한', yn(m.is_admin)],
    ['MFA 사용', yn(m.mfa_enabled)],
    ['API 키 보유', yn(m.has_api_key)],
    ['권한 수준', `${m.privilege_level} (${m.privilege_level_numeric})`],
    ['Mock 정답 라벨', m.is_true_risk ? `위험${m.risk_scenario ? ` · ${m.risk_scenario}` : ''}` : '정상'],
  ]
})

const isAws = computed(() => id.value?.cloud === 'AWS')

// 점수 옆에 두는 계정 속성. 위험한 조합(관리자·API 키가 MFA 없이 쓰이는 경우)만 강조한다.
const attrs = computed(() => {
  const m = data.value?.metadata
  if (!m) return []
  return [
    { label: m.is_admin ? '관리자 권한' : '일반 권한', warn: m.is_admin && !m.mfa_enabled },
    { label: m.mfa_enabled ? 'MFA 사용' : 'MFA 꺼짐', warn: !m.mfa_enabled && (m.is_admin || m.has_api_key) },
    ...(m.has_api_key ? [{ label: 'API 키 보유', warn: !m.mfa_enabled }] : []),
  ]
})
</script>

<template>
  <div>
    <RouterLink to="/identities" class="mb-4 inline-flex items-center gap-1.5 text-[13px] font-semibold text-muted hover:text-ink">
      <Icon name="back" :size="15" />대상 목록
    </RouterLink>

    <LoadState :loading="loading" :error="status === 404 ? `‘${name}’ 대상을 찾을 수 없어요.` : error" @retry="reload">
      <template v-if="data && id">
        <header class="mb-6 flex flex-wrap items-start justify-between gap-4">
          <div>
            <div class="flex flex-wrap items-center gap-3">
              <h1 class="text-[28px] leading-tight font-bold tracking-tight break-all">{{ id.name }}</h1>
              <VerdictBadge :verdict="id.verdict" size="lg" show-ko />
            </div>
            <div class="mt-2 flex flex-wrap items-center gap-x-4 gap-y-1 text-[13.5px] text-muted">
              <CloudBadge :cloud="id.cloud" />
              <span>위험 점수 <b class="num text-ink">{{ id.risk_score.toFixed(3) }}</b></span>
              <span class="num">{{ data.total }}개 중 <b class="text-ink">{{ id.rank }}위</b> (상위 {{ percent(id.rank, data.total) }})</span>
              <span v-if="id.decision_by">결정 신호 <b class="text-ink">{{ decisionMeta[id.decision_by].label }}</b></span>
            </div>
          </div>
        </header>

        <section class="grid gap-4 lg:grid-cols-3">
          <div class="card card-pad lg:col-span-2">
            <h2 class="h-card">왜 {{ id.verdict }} 인가요?</h2>

            <ul v-if="id.reasons.length" class="mt-3 space-y-2.5">
              <li v-for="code in id.reasons" :key="code" class="flex gap-3 rounded-xl bg-surface-2 px-3.5 py-3">
                <Icon name="warn" :size="16" class="mt-0.5 shrink-0" :style="{ color: verdictMeta[id.verdict].var }" />
                <div class="min-w-0">
                  <div class="text-[13.5px] font-semibold">{{ reasonMeta[code]?.label ?? code }}</div>
                  <div class="mt-0.5 text-[12.5px] text-muted">{{ reasonMeta[code]?.detail ?? '' }}</div>
                </div>
              </li>
            </ul>
            <p v-else class="mt-3 rounded-xl bg-surface-2 px-3.5 py-3 text-[13px] text-muted">
              규칙 위반, 행동 이상, 권한 그래프 위험 신호가 임계값을 넘지 않았어요.
            </p>

            <h3 class="eyebrow mt-6 mb-2.5">판정 경로 — 위에서부터 차례로 확인하고, 처음 해당하는 단계에서 결정돼요</h3>
            <ol class="space-y-2">
              <li
                v-for="(s, i) in steps"
                :key="s.key"
                class="flex items-center gap-3 rounded-xl border px-3.5 py-2.5 transition-colors"
                :class="s.state === 'skipped' ? 'opacity-60' : ''"
                :style="
                  s.state === 'decided'
                    ? {
                        borderColor: `color-mix(in srgb, ${verdictMeta[s.outcome].var} 45%, transparent)`,
                        background: `color-mix(in srgb, ${verdictMeta[s.outcome].var} 8%, transparent)`,
                      }
                    : { borderColor: 'var(--border)' }
                "
              >
                <span
                  class="grid size-6 shrink-0 place-items-center rounded-full text-[11.5px] font-bold"
                  :style="
                    s.state === 'decided'
                      ? { background: verdictMeta[s.outcome].var, color: '#fff' }
                      : { background: 'var(--surface-3)', color: 'var(--muted)' }
                  "
                >
                  <Icon v-if="s.state === 'decided'" name="check" :size="13" />
                  <template v-else>{{ i + 1 }}</template>
                </span>
                <div class="min-w-0 flex-1">
                  <div class="flex flex-wrap items-baseline gap-x-2.5">
                    <span class="text-[13.5px] font-semibold">{{ s.title }}</span>
                    <span v-if="s.expr" class="code text-muted !text-[12px]">{{ s.expr }}</span>
                  </div>
                  <div v-if="s.value !== undefined && s.state !== 'skipped'" class="mt-1 flex items-center gap-2.5">
                    <span class="h-1 w-24 overflow-hidden rounded-full bg-surface-3">
                      <span
                        class="block h-full rounded-full"
                        :style="{ width: `${Math.min(s.value / (s.threshold ?? 1), 1) * 100}%`, background: s.met ? verdictMeta[s.outcome].var : 'var(--faint)' }"
                      />
                    </span>
                    <span class="num text-[12px] text-muted">{{ s.value.toFixed(3) }} / {{ s.threshold }} · {{ s.met ? '해당' : '해당 없음' }}</span>
                  </div>
                  <div v-else-if="s.state === 'skipped'" class="mt-0.5 text-[12px] text-muted">앞 단계에서 이미 결정돼 확인하지 않아요</div>
                </div>
                <VerdictBadge :verdict="s.outcome" />
              </li>
            </ol>
          </div>

          <div class="card card-pad">
            <h2 class="h-card">점수 구성</h2>
            <BaseChart :option="radar" height="210px" />
            <dl class="mt-1 space-y-2.5 text-[13px]">
              <div class="flex items-center justify-between">
                <dt class="text-muted">규칙 R <span class="text-faint">× {{ model?.weights.rule }}</span></dt>
                <dd class="num font-semibold">{{ id.rule_score.toFixed(3) }}</dd>
              </div>
              <div class="flex items-center justify-between">
                <dt class="text-muted">행동 이상 A <span class="text-faint">× {{ model?.weights.ai }}</span></dt>
                <dd class="num font-semibold">{{ id.anomaly_score.toFixed(3) }}</dd>
              </div>
              <div class="flex items-center justify-between">
                <dt class="text-muted">권한 그래프 G <span class="text-faint">× {{ model?.weights.graph }}</span></dt>
                <dd class="num font-semibold">{{ id.graph_score.toFixed(3) }}</dd>
              </div>
              <div class="flex items-center justify-between border-t border-line pt-2.5">
                <dt class="font-semibold">위험 점수</dt>
                <dd class="num text-lg font-bold" :style="{ color: verdictMeta[id.verdict].var }">{{ id.risk_score.toFixed(3) }}</dd>
              </div>
            </dl>

            <div v-if="attrs.length" class="mt-5 border-t border-line pt-4">
              <div class="eyebrow mb-2.5">계정 속성</div>
              <div class="flex flex-wrap gap-1.5">
                <span
                  v-for="a in attrs"
                  :key="a.label"
                  class="chip"
                  :style="a.warn ? { color: 'var(--alert)', borderColor: 'color-mix(in srgb, var(--alert) 40%, transparent)', background: 'color-mix(in srgb, var(--alert) 10%, transparent)' } : undefined"
                  >{{ a.label }}</span
                >
              </div>
            </div>
          </div>
        </section>

        <section class="card mt-4">
          <div class="px-5 pt-3"><Tabs v-model="tab" :items="tabs" /></div>

          <!-- 권한·정책 -->
          <div v-if="tab === 'policy'" class="space-y-5 p-5">
            <div v-if="isAws" class="grid gap-3 sm:grid-cols-2">
              <div class="rounded-xl bg-surface-2 p-3.5">
                <div class="eyebrow mb-2">소속 그룹</div>
                <div v-if="id.groups.length" class="flex flex-wrap gap-1.5"><span v-for="g in id.groups" :key="g" class="chip">{{ g }}</span></div>
                <span v-else class="text-[13px] text-faint">없음</span>
              </div>
              <div class="rounded-xl bg-surface-2 p-3.5">
                <div class="eyebrow mb-2">전환 가능한 역할</div>
                <div v-if="id.role_assignments.length" class="flex flex-wrap gap-1.5"><span v-for="r in id.role_assignments" :key="r" class="chip">{{ r }}</span></div>
                <span v-else class="text-[13px] text-faint">없음</span>
                <p v-if="id.role_assignments.length" class="mt-2 text-[12px] text-muted">역할의 권한은 이 대상의 점수에 합산하지 않고 별도로 검사해요.</p>
              </div>
            </div>

            <template v-if="isAws && data.aws_policy_items.length">
              <article v-for="item in data.aws_policy_items" :key="`${item.policy_id}-${item.attachment_type}`" class="rounded-xl border border-line p-4">
                <div class="flex flex-wrap items-center justify-between gap-3">
                  <PermissionPath :path="item.permission_path" />
                  <div class="flex items-center gap-1.5">
                    <span class="chip">{{ attachmentMeta[item.attachment_type] }}</span>
                    <span class="chip">{{ item.policy_type === 'inline' ? '인라인' : '관리형' }}</span>
                  </div>
                </div>
                <div class="mt-3"><PolicyViewer :document="item.raw_policy_document" /></div>
              </article>
            </template>

            <template v-else-if="data.policies.length">
              <article v-for="(p, i) in data.policies" :key="i" class="rounded-xl border border-line p-4">
                <div class="mb-3 text-[13px] font-semibold">{{ p.csp }} 정책</div>
                <PolicyViewer :document="p.raw_policy_document" />
              </article>
            </template>
            <p v-else class="py-8 text-center text-[13px] text-muted">표시할 정책이 없습니다.</p>
          </div>

          <!-- 분석 근거 -->
          <div v-else-if="tab === 'evidence'" class="space-y-8 p-5">
            <section>
              <h3 class="h-card mb-3">규칙 검사</h3>
              <div v-if="triggeredRules.length" class="flex flex-wrap gap-2">
                <span v-for="r in triggeredRules" :key="r.name" class="chip !h-auto py-1.5" style="color: var(--block); border-color: color-mix(in srgb, var(--block) 35%, transparent); background: color-mix(in srgb, var(--block) 9%, transparent)">
                  <b>{{ reasonMeta[r.name]?.label ?? r.name }}</b>
                  <span v-if="r.severity !== null" class="num opacity-80">심각도 {{ r.severity }}</span>
                </span>
              </div>
              <p v-else class="text-[13px] text-muted">발동한 규칙이 없습니다.</p>
              <p v-if="data.rules" class="mt-2 text-[12px] text-faint">위반이 확인된 정책 레코드 {{ data.rules.violation_record_count }}건 · 최대 규칙 점수 {{ data.rules.max_rule_score.toFixed(2) }}</p>
            </section>

            <section>
              <h3 class="h-card mb-3">행동 이상 <span class="ml-1 text-[12.5px] font-normal text-muted">같은 클라우드 {{ data.population.size }}개와 비교</span></h3>
              <div class="grid gap-3 sm:grid-cols-3">
                <div v-for="t in behaviorTiles" :key="t.label" class="rounded-xl bg-surface-2 p-3.5">
                  <div class="eyebrow">{{ t.label }}</div>
                  <div class="num mt-1 text-xl font-bold" :style="t.warn ? { color: 'var(--alert)' } : undefined">{{ t.value }}</div>
                  <div class="mt-0.5 text-[12px] text-muted">{{ t.note }}</div>
                </div>
              </div>
              <p v-if="data.ai" class="mt-2.5 text-[12.5px] text-muted">
                행동 이상 점수 <b class="num text-ink">{{ data.ai.ai_score.toFixed(3) }}</b> · 이상 순위 <b class="num text-ink">{{ data.ai.anomaly_rank }}위</b> / {{ data.total }}
                <template v-if="data.ai.is_detected_anomaly"> · <span style="color: var(--alert)" class="font-semibold">이상치로 탐지됨</span></template>
              </p>
            </section>

            <section>
              <h3 class="h-card mb-3">권한 그래프</h3>
              <div v-if="data.graph_summary" class="mb-3 grid grid-cols-2 gap-3 sm:grid-cols-4">
                <div v-for="[label, value] in [['권한 연결', data.graph_summary.permission_edge_count], ['와일드카드', data.graph_summary.wildcard_edge_count], ['분류되지 않은 작업', data.graph_summary.unknown_operation_count], ['대상 리소스', data.graph_summary.target_count]]" :key="label" class="rounded-xl bg-surface-2 p-3.5">
                  <div class="eyebrow">{{ label }}</div>
                  <div class="num mt-1 text-xl font-bold">{{ value }}</div>
                </div>
              </div>
              <div v-if="data.graph_findings.length" class="overflow-hidden rounded-xl border border-line">
                <DataTable :columns="graphColumns" :rows="data.graph_findings" :row-key="(r) => `${r.finding_type}-${r.operation}-${r.target}`" :page-size="50">
                  <template #cell-finding_type="{ row }"><span class="font-semibold">{{ findingMeta[(row as GraphFinding).finding_type] ?? (row as GraphFinding).finding_type }}</span></template>
                  <template #cell-target="{ row }"><span class="code">{{ (row as GraphFinding).target }}</span></template>
                </DataTable>
              </div>
              <p v-else class="text-[13px] text-muted">그래프에서 발견된 위험 신호가 없습니다.</p>
            </section>

            <section>
              <h3 class="h-card mb-3">원본 정책의 권한 상승 신호</h3>
              <div v-if="data.raw_privilege_findings.length" class="overflow-hidden rounded-xl border border-line">
                <DataTable :columns="rawColumns" :rows="data.raw_privilege_findings" :row-key="(r) => `${r.raw_action}-${r.scope}`" :page-size="50">
                  <template #cell-raw_action="{ row }"><span class="code font-semibold">{{ (row as RawPrivilegeFinding).raw_action }}</span></template>
                  <template #cell-finding_type="{ row }">{{ findingMeta[(row as RawPrivilegeFinding).finding_type] ?? (row as RawPrivilegeFinding).finding_type }}</template>
                </DataTable>
              </div>
              <p v-else class="text-[13px] text-muted">발견된 신호가 없습니다.</p>
            </section>
          </div>

          <!-- 원본 입력 -->
          <div v-else-if="tab === 'input'" class="space-y-5 p-5">
            <dl class="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
              <div v-for="[k, v] in metaRows" :key="k" class="rounded-xl bg-surface-2 p-3.5">
                <dt class="eyebrow">{{ k }}</dt>
                <dd class="mt-1 text-[14px] font-semibold">{{ v }}</dd>
              </div>
            </dl>
            <p class="text-[12px] text-muted">‘Mock 정답 라벨’은 Mock 데이터를 만들 때 미리 정해 둔 값이며, 분석에는 쓰이지 않아요.</p>
            <JsonView :value="{ metadata: data.metadata, behavior: data.behavior, policies: data.policies.map((p) => p.raw_policy_document) }" max-height="420px" />
          </div>

          <!-- 개선 권고 -->
          <div v-else class="p-5">
            <p v-if="!data.remediation_plan" class="py-8 text-center text-[13px] text-muted">개선 권고 대상이 아니에요. 현재 판정이 ALLOW 입니다.</p>
            <div v-else class="space-y-6">
              <div class="flex flex-wrap items-center gap-2">
                <span class="chip">우선순위 <b class="num ml-1 text-ink">#{{ data.remediation_plan.remediation_priority }}</b></span>
                <span class="chip">{{ remediationMeta[data.remediation_plan.remediation_type] ?? data.remediation_plan.remediation_type }}</span>
              </div>

              <section v-if="data.remediation_effect">
                <h3 class="h-card mb-3">적용 시 예상 효과 <span class="text-[12.5px] font-normal text-muted">시뮬레이션</span></h3>
                <div class="flex flex-wrap items-center gap-4 rounded-xl bg-surface-2 p-4">
                  <div>
                    <div class="eyebrow mb-1.5">조치 전</div>
                    <div class="flex items-center gap-2.5"><VerdictBadge :verdict="data.remediation_effect.before_action" /><span class="num font-bold">{{ data.remediation_effect.before_risk_score.toFixed(3) }}</span></div>
                  </div>
                  <Icon name="arrow" :size="18" class="text-faint" />
                  <div>
                    <div class="eyebrow mb-1.5">조치 후</div>
                    <div class="flex items-center gap-2.5"><VerdictBadge :verdict="data.remediation_effect.after_action" /><span class="num font-bold">{{ data.remediation_effect.after_risk_score.toFixed(3) }}</span></div>
                  </div>
                  <div class="num ml-auto text-[13px] text-muted">
                    위험도 <b style="color: var(--allow)">−{{ data.remediation_effect.risk_reduction.toFixed(3) }}</b>
                    · 그래프 신호 {{ data.remediation_effect.before_graph_findings }}→{{ data.remediation_effect.after_graph_findings }}
                  </div>
                </div>
              </section>

              <section>
                <h3 class="h-card mb-3">권고 사항</h3>
                <ol class="space-y-2">
                  <li v-for="(r, i) in data.remediation_plan.recommendation" :key="i" class="flex gap-3 text-[13.5px]">
                    <span class="num grid size-5 shrink-0 place-items-center rounded-full bg-accent-soft text-[11.5px] font-bold text-accent">{{ i + 1 }}</span>
                    <span>{{ r }}</span>
                  </li>
                </ol>
              </section>

              <section v-if="data.remediation_plan.manual_steps.length">
                <h3 class="h-card mb-3">사람이 직접 확인할 일</h3>
                <ul class="space-y-2 text-[13.5px] text-muted">
                  <li v-for="(s, i) in data.remediation_plan.manual_steps" :key="i" class="flex gap-2.5"><span class="mt-2 size-1 shrink-0 rounded-full bg-faint" />{{ s }}</li>
                </ul>
              </section>

              <section v-if="data.remediation_plan.terraform_supported && data.remediation_plan.terraform_code">
                <h3 class="h-card mb-3">Terraform 초안</h3>
                <CodeBlock :code="data.remediation_plan.terraform_code" />
              </section>

              <p class="text-[12px] text-muted">권고와 정책 초안일 뿐이에요. 실제 AWS 권한을 변경하지 않습니다.</p>
            </div>
          </div>
        </section>
      </template>
    </LoadState>
  </div>
</template>

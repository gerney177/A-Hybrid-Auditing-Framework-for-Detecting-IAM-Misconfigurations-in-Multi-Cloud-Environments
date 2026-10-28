<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { downloads } from '@/api/client'
import CloudBadge from '@/components/CloudBadge.vue'
import DataTable from '@/components/DataTable.vue'
import Icon from '@/components/Icon.vue'
import LoadState from '@/components/LoadState.vue'
import PageHeader from '@/components/PageHeader.vue'
import RunButton from '@/components/RunButton.vue'
import ScoreBar from '@/components/ScoreBar.vue'
import Segmented from '@/components/Segmented.vue'
import VerdictBadge from '@/components/VerdictBadge.vue'
import type { Column } from '@/components/table'
import { useAnalysis } from '@/stores/analysis'
import type { IdentityRow } from '@/types'
import { CLOUDS, reasonLabel, verdictMeta, VERDICTS } from '@/utils/labels'

const store = useAnalysis()
const route = useRoute()
const router = useRouter()

// 필터는 주소(?cloud=AWS&verdict=ALERT&q=...)에 담아 두어 새로고침·공유해도 유지된다.
const cloud = ref(String(route.query.cloud ?? 'all'))
const verdict = ref(String(route.query.verdict ?? 'all'))
const q = ref(String(route.query.q ?? ''))

watch([cloud, verdict, q], () => {
  const query: Record<string, string> = {}
  if (cloud.value !== 'all') query.cloud = cloud.value
  if (verdict.value !== 'all') query.verdict = verdict.value
  if (q.value.trim()) query.q = q.value.trim()
  router.replace({ query })
})

function matches(r: IdentityRow, skip?: 'cloud' | 'verdict') {
  const needle = q.value.trim().toLowerCase()
  return (
    (skip === 'cloud' || cloud.value === 'all' || r.cloud === cloud.value) &&
    (skip === 'verdict' || verdict.value === 'all' || r.verdict === verdict.value) &&
    (!needle || r.name.toLowerCase().includes(needle) || r.reasons.some((c) => reasonLabel(c).toLowerCase().includes(needle)))
  )
}

const rows = computed(() => store.identities.filter((r) => matches(r)))

// 각 선택지 옆 숫자는 '다른 필터를 적용한 상태에서' 그 선택지를 고르면 몇 개인지를 보여준다.
const cloudOptions = computed(() => [
  { value: 'all', label: '전체', count: store.identities.filter((r) => matches(r, 'cloud')).length },
  ...CLOUDS.map((c) => ({ value: c, label: c, count: store.identities.filter((r) => matches(r, 'cloud') && r.cloud === c).length })),
])
const verdictOptions = computed(() => [
  { value: 'all', label: '전체', count: store.identities.filter((r) => matches(r, 'verdict')).length },
  ...VERDICTS.map((v) => ({
    value: v,
    label: v,
    color: verdictMeta[v].var,
    count: store.identities.filter((r) => matches(r, 'verdict') && r.verdict === v).length,
  })),
])

const model = computed(() => store.model)
const hot = (kind: 'rule' | 'ai' | 'graph', value: number) =>
  !!model.value && value >= (kind === 'rule' ? 1 : kind === 'ai' ? model.value.ai_alert : model.value.graph_alert)

const columns: Column<IdentityRow>[] = [
  { key: 'rank', label: '순위', sortable: true, width: '64px' },
  { key: 'name', label: '대상', sortable: true },
  { key: 'cloud', label: '클라우드', sortable: true },
  { key: 'verdict', label: '판정', sortable: true, sortValue: (r) => VERDICTS.indexOf(r.verdict) },
  { key: 'risk_score', label: '위험 점수', sortable: true },
  { key: 'rule_score', label: '규칙 R', sortable: true, align: 'right' },
  { key: 'anomaly_score', label: '행동 A', sortable: true, align: 'right' },
  { key: 'graph_score', label: '그래프 G', sortable: true, align: 'right' },
  { key: 'reasons', label: '판정 근거' },
  { key: 'groups', label: '그룹' },
]

function reset() {
  cloud.value = 'all'
  verdict.value = 'all'
  q.value = ''
}
const filtered = computed(() => cloud.value !== 'all' || verdict.value !== 'all' || q.value.trim() !== '')
</script>

<template>
  <div>
  <LoadState :loading="store.loading && !store.identities.length" :error="store.error" :empty="store.missing" empty-text="저장된 분석 결과가 아직 없습니다." @retry="store.load()">
    <template #empty><RunButton /></template>

    <PageHeader title="대상 목록" subtitle="사용자·서비스 계정 단위의 분석 결과예요. 행을 누르면 판정 근거와 정책을 볼 수 있습니다.">
      <template #actions>
        <a class="btn" :href="downloads.csv" download><Icon name="download" :size="15" />전체 CSV</a>
      </template>
    </PageHeader>

    <div class="card">
      <div class="flex flex-wrap items-center gap-3 border-b border-line p-4">
        <div class="relative w-full sm:w-[260px]">
          <Icon name="search" :size="16" class="pointer-events-none absolute top-1/2 left-3 -translate-y-1/2 text-faint" />
          <input v-model="q" class="input !pl-9" type="search" placeholder="이름·근거로 검색" aria-label="검색" />
        </div>
        <Segmented v-model="cloud" :options="cloudOptions" label="클라우드" />
        <Segmented v-model="verdict" :options="verdictOptions" label="판정" />
        <button v-if="filtered" class="btn btn-sm btn-ghost" @click="reset"><Icon name="x" :size="14" />초기화</button>
        <span class="num ml-auto text-[12.5px] text-muted">{{ rows.length }}개 표시 중</span>
      </div>

      <DataTable
        :columns="columns"
        :rows="rows"
        :row-key="(r) => r.name"
        :page-size="15"
        clickable
        :initial-sort="{ key: 'rank', dir: 'asc' }"
        @row-click="(r) => router.push(`/identities/${encodeURIComponent(r.name)}`)"
      >
        <template #cell-rank="{ row }"><span class="num text-faint">{{ row.rank }}</span></template>
        <template #cell-name="{ row }"><span class="font-semibold">{{ row.name }}</span></template>
        <template #cell-cloud="{ row }"><CloudBadge :cloud="row.cloud" /></template>
        <template #cell-verdict="{ row }"><VerdictBadge :verdict="row.verdict" /></template>
        <template #cell-risk_score="{ row }"><ScoreBar :value="row.risk_score" :verdict="row.verdict" /></template>
        <template #cell-rule_score="{ row }">
          <span class="num" :class="hot('rule', row.rule_score) ? 'font-bold' : 'text-muted'" :style="hot('rule', row.rule_score) ? { color: 'var(--block)' } : undefined">{{ row.rule_score.toFixed(2) }}</span>
        </template>
        <template #cell-anomaly_score="{ row }">
          <span class="num" :class="hot('ai', row.anomaly_score) ? 'font-bold' : 'text-muted'" :style="hot('ai', row.anomaly_score) ? { color: 'var(--alert)' } : undefined">{{ row.anomaly_score.toFixed(2) }}</span>
        </template>
        <template #cell-graph_score="{ row }">
          <span class="num" :class="hot('graph', row.graph_score) ? 'font-bold' : 'text-muted'" :style="hot('graph', row.graph_score) ? { color: 'var(--alert)' } : undefined">{{ row.graph_score.toFixed(2) }}</span>
        </template>
        <template #cell-reasons="{ row }">
          <span v-if="row.reasons.length === 0" class="text-faint">–</span>
          <span v-else class="flex items-center gap-1.5" :title="row.reasons.map(reasonLabel).join(' · ')">
            <span class="chip">{{ reasonLabel(row.reasons[0]) }}</span>
            <span v-if="row.reasons.length > 1" class="num text-[12px] text-muted">+{{ row.reasons.length - 1 }}</span>
          </span>
        </template>
        <template #cell-groups="{ row }">
          <span v-if="row.groups.length === 0" class="text-faint">–</span>
          <span v-else class="text-[12.5px] text-muted">{{ row.groups.join(', ') }}</span>
        </template>
      </DataTable>
    </div>

    <p v-if="model" class="mt-3 text-[12px] text-faint">
      R·A·G는 규칙·행동 이상·권한 그래프 점수(0~1)입니다. 단독으로 판정을 바꾸는 임계값(R ≥ 1.0 · A ≥ {{ model.ai_alert }} · G ≥
      {{ model.graph_alert }})을 넘으면 색으로 강조돼요.
    </p>
  </LoadState>
  </div>
</template>

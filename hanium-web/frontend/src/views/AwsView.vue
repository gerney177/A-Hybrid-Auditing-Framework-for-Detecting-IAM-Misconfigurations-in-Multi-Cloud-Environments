<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { api } from '@/api/client'
import DataTable from '@/components/DataTable.vue'
import Icon from '@/components/Icon.vue'
import KpiCard from '@/components/KpiCard.vue'
import LoadState from '@/components/LoadState.vue'
import Notice from '@/components/Notice.vue'
import PageHeader from '@/components/PageHeader.vue'
import PermissionPath from '@/components/PermissionPath.vue'
import Segmented from '@/components/Segmented.vue'
import Tabs from '@/components/Tabs.vue'
import type { Column } from '@/components/table'
import { useFetch } from '@/composables/useFetch'
import { useAnalysis } from '@/stores/analysis'
import type { AwsFinding, AwsPolicyItem } from '@/types'
import { analysisScopeMeta, attachmentMeta, identityTypeMeta } from '@/utils/labels'

const store = useAnalysis()
const { data, loading, error, reload } = useFetch(() => api.aws())
watch(() => store.version, reload, { immediate: true })

const tab = ref('policies')
const type = ref('all')
const connection = ref('all')
const q = ref('')

type Scoped = Pick<AwsPolicyItem, 'identity_type' | 'attachment_type' | 'identity_name' | 'policy_name'>
function inScope(r: Scoped) {
  const needle = q.value.trim().toLowerCase()
  return (
    (type.value === 'all' || r.identity_type === type.value) &&
    (connection.value === 'all' ||
      (connection.value === 'group' ? r.attachment_type === 'group' : r.attachment_type !== 'group')) &&
    (!needle || r.identity_name.toLowerCase().includes(needle) || r.policy_name.toLowerCase().includes(needle))
  )
}

const policies = computed(() => (data.value?.policy_items ?? []).filter(inScope))
const wildcards = computed(() => (data.value?.wildcard_findings ?? []).filter(inScope))
const passroles = computed(() => (data.value?.passrole_findings ?? []).filter(inScope))

const tabs = computed(() => [
  { key: 'policies', label: '분석한 정책', count: policies.value.length },
  { key: 'wildcard', label: '와일드카드 검토 후보', count: wildcards.value.length },
  { key: 'passrole', label: 'PassRole 검토 후보', count: passroles.value.length },
])

const typeOptions = [
  { value: 'all', label: '전체' },
  { value: 'user', label: '사용자' },
  { value: 'role', label: '역할' },
]
const connectionOptions = [
  { value: 'all', label: '전체' },
  { value: 'direct', label: '직접 연결' },
  { value: 'group', label: '그룹 경유' },
]

const policyColumns: Column<AwsPolicyItem>[] = [
  { key: 'identity_name', label: '대상', sortable: true },
  { key: 'identity_type', label: '유형', sortable: true, width: '72px' },
  { key: 'policy_name', label: '정책', sortable: true },
  { key: 'attachment_type', label: '연결 방식', sortable: true },
  { key: 'permission_path', label: '권한 연결 경로' },
]
const findingColumns: Column<AwsFinding>[] = [
  { key: 'identity_name', label: '대상', sortable: true },
  { key: 'identity_type', label: '유형', sortable: true, width: '72px' },
  { key: 'policy_name', label: '정책', sortable: true },
  { key: 'original_action', label: '작업', sortable: true },
  { key: 'original_resources', label: '리소스' },
  { key: 'attachment_type', label: '연결 방식', sortable: true },
  { key: 'permission_path', label: '권한 연결 경로' },
]

const counts = computed(() => data.value?.counts)
</script>

<template>
  <div>
  <LoadState :loading="loading" :error="error" @retry="reload">
    <template v-if="data && counts">
      <PageHeader title="AWS 정책 분석">
        <template #subtitle>{{ analysisScopeMeta[data.analysis_scope] ?? data.analysis_scope }}</template>
      </PageHeader>

      <Notice class="mb-5">
        <b>검토 후보</b>는 위험이 확정됐다는 뜻이 아니에요. Resource·Condition 같은 제한 조건과 함께 확인해 주세요.
        {{ data.source === 'mock300' ? ' 이 데이터는 300개 Mock 중 AWS 100개이며 실제 AWS 계정에서 수집한 것이 아닙니다.' : '' }}
      </Notice>

      <section class="grid grid-cols-2 gap-4 xl:grid-cols-4" aria-label="요약">
        <KpiCard label="AWS 사용자" :value="counts.users" :sub="`역할 ${counts.roles}개 · 그룹 ${counts.groups}개`" />
        <KpiCard label="분석한 정책 본문" :value="counts.policy_bodies" :sub="`역할 정책 ${counts.role_policy_bodies}개 · 그룹 정책 연결 ${counts.group_policy_links}건`" />
        <KpiCard label="와일드카드 후보" :value="counts.wildcard" tone="ALERT" sub="서비스 전체 Action (예: s3:*)" />
        <KpiCard label="PassRole 후보" :value="counts.passrole" tone="ALERT" sub="iam:PassRole 을 허용하는 정책" />
      </section>

      <section class="card mt-4">
        <div class="flex flex-wrap items-center gap-3 border-b border-line p-4">
          <div class="relative w-full sm:w-[240px]">
            <Icon name="search" :size="16" class="pointer-events-none absolute top-1/2 left-3 -translate-y-1/2 text-faint" />
            <input v-model="q" class="input !pl-9" type="search" placeholder="대상·정책 이름 검색" aria-label="검색" />
          </div>
          <div class="flex items-center gap-2"><span class="eyebrow">대상 유형</span><Segmented v-model="type" :options="typeOptions" label="대상 유형" /></div>
          <div class="flex items-center gap-2"><span class="eyebrow">연결 방식</span><Segmented v-model="connection" :options="connectionOptions" label="연결 방식" /></div>
        </div>
        <div class="px-5 pt-2"><Tabs v-model="tab" :items="tabs" /></div>

        <DataTable v-if="tab === 'policies'" :columns="policyColumns" :rows="policies" :row-key="(r) => `${r.identity}|${r.policy_id}|${r.attachment_type}`" :page-size="12">
          <template #cell-identity_name="{ row }">
            <RouterLink v-if="(row as AwsPolicyItem).identity_type === 'user'" :to="`/identities/${(row as AwsPolicyItem).identity_name}`" class="font-semibold hover:text-accent hover:underline">{{ (row as AwsPolicyItem).identity_name }}</RouterLink>
            <span v-else class="font-semibold">{{ (row as AwsPolicyItem).identity_name }}</span>
          </template>
          <template #cell-identity_type="{ row }"><span class="chip">{{ identityTypeMeta[(row as AwsPolicyItem).identity_type] }}</span></template>
          <template #cell-attachment_type="{ row }">{{ attachmentMeta[(row as AwsPolicyItem).attachment_type] }}</template>
          <template #cell-permission_path="{ row }"><PermissionPath :path="(row as AwsPolicyItem).permission_path" /></template>
        </DataTable>

        <DataTable v-else-if="tab === 'wildcard'" :columns="findingColumns" :rows="wildcards" :row-key="(r) => `${r.identity}|${r.policy_id}|${r.original_action}|${r.attachment_type}`" :page-size="12" empty-text="현재 검사에서 와일드카드 후보가 없습니다.">
          <template #cell-identity_name="{ row }">
            <RouterLink v-if="(row as AwsFinding).identity_type === 'user'" :to="`/identities/${(row as AwsFinding).identity_name}`" class="font-semibold hover:text-accent hover:underline">{{ (row as AwsFinding).identity_name }}</RouterLink>
            <span v-else class="font-semibold">{{ (row as AwsFinding).identity_name }}</span>
          </template>
          <template #cell-identity_type="{ row }"><span class="chip">{{ identityTypeMeta[(row as AwsFinding).identity_type] }}</span></template>
          <template #cell-original_action="{ row }"><span class="code font-semibold" style="color: var(--alert)">{{ (row as AwsFinding).original_action }}</span></template>
          <template #cell-original_resources="{ row }"><span class="code">{{ (row as AwsFinding).original_resources.join(', ') }}</span></template>
          <template #cell-attachment_type="{ row }">{{ attachmentMeta[(row as AwsFinding).attachment_type] }}</template>
          <template #cell-permission_path="{ row }"><PermissionPath :path="(row as AwsFinding).permission_path" /></template>
        </DataTable>

        <DataTable v-else :columns="findingColumns" :rows="passroles" :row-key="(r) => `${r.identity}|${r.policy_id}|${r.original_action}|${r.attachment_type}`" :page-size="12" empty-text="현재 검사에서 PassRole 후보가 없습니다.">
          <template #cell-identity_name="{ row }">
            <RouterLink v-if="(row as AwsFinding).identity_type === 'user'" :to="`/identities/${(row as AwsFinding).identity_name}`" class="font-semibold hover:text-accent hover:underline">{{ (row as AwsFinding).identity_name }}</RouterLink>
            <span v-else class="font-semibold">{{ (row as AwsFinding).identity_name }}</span>
          </template>
          <template #cell-identity_type="{ row }"><span class="chip">{{ identityTypeMeta[(row as AwsFinding).identity_type] }}</span></template>
          <template #cell-original_action="{ row }"><span class="code font-semibold" style="color: var(--block)">{{ (row as AwsFinding).original_action }}</span></template>
          <template #cell-original_resources="{ row }"><span class="code">{{ (row as AwsFinding).original_resources.join(', ') }}</span></template>
          <template #cell-attachment_type="{ row }">{{ attachmentMeta[(row as AwsFinding).attachment_type] }}</template>
          <template #cell-permission_path="{ row }"><PermissionPath :path="(row as AwsFinding).permission_path" /></template>
        </DataTable>
      </section>

      <p class="mt-3 text-[12px] text-faint">역할 신뢰 관계와 실제 행동 로그 분석은 아직 지원하지 않습니다.</p>
    </template>
  </LoadState>
  </div>
</template>

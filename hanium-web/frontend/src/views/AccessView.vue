<script setup lang="ts">
import { ref, watch } from 'vue'
import { api } from '@/api/client'
import Icon from '@/components/Icon.vue'
import LoadState from '@/components/LoadState.vue'
import Notice from '@/components/Notice.vue'
import PageHeader from '@/components/PageHeader.vue'
import PolicyViewer from '@/components/PolicyViewer.vue'
import { useFetch } from '@/composables/useFetch'
import { useAnalysis } from '@/stores/analysis'
import { shortArn } from '@/utils/format'

const store = useAnalysis()
const { data, loading, error, reload } = useFetch(() => api.access())
watch(() => store.version, reload, { immediate: true })

// 카드마다 펼침 상태를 따로 기억한다.
const expanded = ref(new Set<string>())
function toggle(key: string) {
  const next = new Set(expanded.value)
  if (next.has(key)) next.delete(key)
  else next.add(key)
  expanded.value = next
}
const open = (key: string) => expanded.value.has(key)
const PREVIEW = 12
</script>

<template>
  <div>
  <LoadState :loading="loading" :error="error" @retry="reload">
    <template v-if="data">
      <PageHeader title="역할 · 그룹" subtitle="AWS 사용자가 그룹으로 받는 권한과, 전환할 수 있는 역할을 보여줘요." />

      <Notice class="mb-6">
        역할 정책은 사용자 점수에 <b>자동으로 합산하지 않고</b> 별도로 검사합니다. 사용자가 역할로 전환할 수 있다는 설정({{ data.assignment_count }}건)만 연결돼 있어요.
      </Notice>

      <h2 class="mb-3 flex items-center gap-2 text-[15px] font-bold"><Icon name="group" :size="17" class="text-muted" />그룹 <span class="num text-muted">{{ data.groups.length }}</span></h2>
      <div class="grid gap-4 lg:grid-cols-3">
        <article v-for="g in data.groups" :key="g.arn" class="card card-pad flex flex-col">
          <div class="flex items-start justify-between gap-3">
            <div class="min-w-0">
              <h3 class="truncate text-[15px] font-bold">{{ g.name }}</h3>
              <div class="mt-0.5 truncate text-[12px] text-faint" :title="g.arn">{{ shortArn(g.arn) }}</div>
            </div>
            <div class="text-right">
              <div class="num text-2xl leading-none font-bold">{{ g.members.length }}</div>
              <div class="mt-1 text-[11.5px] text-muted">소속 사용자</div>
            </div>
          </div>

          <div class="mt-4 flex flex-wrap gap-1.5">
            <RouterLink
              v-for="m in open(`gm-${g.name}`) ? g.members : g.members.slice(0, PREVIEW)"
              :key="m"
              :to="`/identities/${m}`"
              class="chip transition-colors hover:border-accent hover:text-accent"
              >{{ m }}</RouterLink
            >
            <button v-if="g.members.length > PREVIEW" class="chip !border-dashed hover:text-ink" @click="toggle(`gm-${g.name}`)">
              {{ open(`gm-${g.name}`) ? '접기' : `+${g.members.length - PREVIEW}명 더 보기` }}
            </button>
          </div>

          <div class="mt-auto pt-4">
            <div class="eyebrow mb-2">연결된 정책</div>
            <div v-for="p in g.policies" :key="p.name" class="rounded-xl border border-line">
              <button class="flex w-full items-center justify-between gap-2 px-3.5 py-2.5 text-left" :aria-expanded="open(`gp-${g.name}-${p.name}`)" @click="toggle(`gp-${g.name}-${p.name}`)">
                <span class="flex items-center gap-2 text-[13px] font-semibold"><Icon name="policy" :size="14" class="text-faint" />{{ p.name }}</span>
                <Icon :name="open(`gp-${g.name}-${p.name}`) ? 'up' : 'down'" :size="15" class="text-faint" />
              </button>
              <div v-if="open(`gp-${g.name}-${p.name}`)" class="border-t border-line p-3"><PolicyViewer :document="p.document" /></div>
            </div>
          </div>
        </article>
      </div>

      <h2 class="mt-9 mb-3 flex items-center gap-2 text-[15px] font-bold"><Icon name="role" :size="17" class="text-muted" />역할 <span class="num text-muted">{{ data.roles.length }}</span></h2>
      <div class="grid gap-4 lg:grid-cols-3">
        <article v-for="r in data.roles" :key="r.arn" class="card card-pad flex flex-col">
          <div class="flex items-start justify-between gap-3">
            <div class="min-w-0">
              <h3 class="truncate text-[15px] font-bold">{{ r.name }}</h3>
              <div class="mt-0.5 truncate text-[12px] text-faint" :title="r.arn">{{ shortArn(r.arn) }}</div>
            </div>
            <div class="text-right">
              <div class="num text-2xl leading-none font-bold">{{ r.assumable_by.length }}</div>
              <div class="mt-1 text-[11.5px] text-muted">전환 가능 사용자</div>
            </div>
          </div>

          <div class="mt-4 grid grid-cols-2 gap-2.5">
            <div class="rounded-xl bg-surface-2 p-3">
              <div class="eyebrow">와일드카드 후보</div>
              <div class="num mt-0.5 text-lg font-bold" :style="r.wildcard_count ? { color: 'var(--alert)' } : undefined">{{ r.wildcard_count }}</div>
            </div>
            <div class="rounded-xl bg-surface-2 p-3">
              <div class="eyebrow">PassRole 후보</div>
              <div class="num mt-0.5 text-lg font-bold" :style="r.passrole_count ? { color: 'var(--block)' } : undefined">{{ r.passrole_count }}</div>
            </div>
          </div>

          <div class="mt-4">
            <div class="eyebrow mb-2">전환할 수 있는 사용자</div>
            <div class="flex flex-wrap gap-1.5">
              <RouterLink
                v-for="m in open(`rm-${r.name}`) ? r.assumable_by : r.assumable_by.slice(0, 8)"
                :key="m"
                :to="`/identities/${m}`"
                class="chip transition-colors hover:border-accent hover:text-accent"
                >{{ m }}</RouterLink
              >
              <button v-if="r.assumable_by.length > 8" class="chip !border-dashed hover:text-ink" @click="toggle(`rm-${r.name}`)">
                {{ open(`rm-${r.name}`) ? '접기' : `+${r.assumable_by.length - 8}명 더 보기` }}
              </button>
            </div>
          </div>

          <div class="mt-auto pt-4">
            <div class="eyebrow mb-2">역할 정책</div>
            <div v-for="p in r.policies" :key="p.name" class="rounded-xl border border-line">
              <button class="flex w-full items-center justify-between gap-2 px-3.5 py-2.5 text-left" :aria-expanded="open(`rp-${r.name}-${p.name}`)" @click="toggle(`rp-${r.name}-${p.name}`)">
                <span class="flex items-center gap-2 text-[13px] font-semibold"><Icon name="policy" :size="14" class="text-faint" />{{ p.name }}</span>
                <Icon :name="open(`rp-${r.name}-${p.name}`) ? 'up' : 'down'" :size="15" class="text-faint" />
              </button>
              <div v-if="open(`rp-${r.name}-${p.name}`)" class="border-t border-line p-3"><PolicyViewer :document="p.document" /></div>
            </div>
          </div>
        </article>
      </div>
    </template>
  </LoadState>
  </div>
</template>

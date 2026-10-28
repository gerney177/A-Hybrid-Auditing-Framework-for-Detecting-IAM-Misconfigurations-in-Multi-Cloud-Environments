<script setup lang="ts">
import { computed, ref } from 'vue'
import type { PolicyDocument } from '@/types'
import Icon from './Icon.vue'
import JsonView from './JsonView.vue'

const props = defineProps<{ document: PolicyDocument | null | undefined }>()

interface Block {
  title: string
  effect?: string
  actions: string[]
  resources: string[]
  members: string[]
}

const asList = (value: unknown): string[] =>
  value == null ? [] : (Array.isArray(value) ? value : [value]).map((v) => String(v))

/** AWS(Statement) · Azure(role+actions) · GCP(binding) 세 가지 모양을 같은 블록으로 맞춘다. */
const blocks = computed<Block[] | null>(() => {
  const doc = props.document as Record<string, any> | null | undefined
  if (!doc) return null

  if (doc.Statement) {
    const statements: Array<Record<string, any>> = Array.isArray(doc.Statement) ? doc.Statement : [doc.Statement]
    return statements.map((s, i) => ({
      title: s.Sid ?? `Statement ${i + 1}`,
      effect: s.Effect,
      actions: asList(s.Action ?? s.NotAction),
      resources: asList(s.Resource),
      members: asList(s.Principal?.AWS ?? s.Principal),
    }))
  }
  if (doc.actions) {
    return [{ title: `역할 ${doc.role ?? ''}`.trim(), actions: asList(doc.actions), resources: [], members: asList(doc.principal) }]
  }
  if (doc.binding) {
    return [
      {
        title: `역할 ${doc.binding.role ?? ''}`.trim(),
        actions: asList(doc.binding.permissions),
        resources: [],
        members: asList(doc.binding.members),
      },
    ]
  }
  return null
})

// 눈에 띄어야 하는 권한: 와일드카드, 권한 상승에 쓰이는 작업
const ESCALATION = /(^|:)passrole$|roleassignments\/write|setiampolicy/i
function tone(action: string): 'wild' | 'escalate' | 'plain' {
  if (action.includes('*')) return 'wild'
  if (ESCALATION.test(action)) return 'escalate'
  return 'plain'
}

const showJson = ref(false)
</script>

<template>
  <div class="space-y-3">
    <template v-if="blocks && blocks.length">
      <div v-for="(b, i) in blocks" :key="i" class="rounded-xl border border-line bg-surface-2/50 p-3.5">
        <div class="mb-2.5 flex flex-wrap items-center gap-2">
          <span
            v-if="b.effect"
            class="rounded-md px-2 py-0.5 text-[11.5px] font-bold tracking-wide"
            :style="{
              color: b.effect === 'Allow' ? 'var(--allow)' : 'var(--block)',
              background: `color-mix(in srgb, ${b.effect === 'Allow' ? 'var(--allow)' : 'var(--block)'} 13%, transparent)`,
            }"
            >{{ b.effect }}</span
          >
          <span class="text-[13px] font-semibold">{{ b.title }}</span>
        </div>

        <dl class="grid grid-cols-[64px_minmax(0,1fr)] gap-x-3 gap-y-2.5 text-[12.5px]">
          <dt class="pt-0.5 text-faint">작업</dt>
          <dd class="flex flex-wrap gap-1.5">
            <span
              v-for="a in b.actions"
              :key="a"
              class="code rounded-md border px-1.5 py-px !text-[12px] break-all"
              :class="tone(a) === 'plain' ? 'border-line bg-surface text-ink' : ''"
              :style="
                tone(a) === 'plain'
                  ? undefined
                  : {
                      color: tone(a) === 'wild' ? 'var(--alert)' : 'var(--block)',
                      borderColor: `color-mix(in srgb, ${tone(a) === 'wild' ? 'var(--alert)' : 'var(--block)'} 40%, transparent)`,
                      background: `color-mix(in srgb, ${tone(a) === 'wild' ? 'var(--alert)' : 'var(--block)'} 10%, transparent)`,
                    }
              "
              :title="tone(a) === 'wild' ? '와일드카드' : tone(a) === 'escalate' ? '권한 상승에 쓰일 수 있는 작업' : undefined"
              >{{ a }}</span
            >
          </dd>

          <template v-if="b.resources.length">
            <dt class="pt-0.5 text-faint">리소스</dt>
            <dd class="flex flex-wrap gap-1.5">
              <span
                v-for="r in b.resources"
                :key="r"
                class="code rounded-md border px-1.5 py-px !text-[12px] break-all"
                :class="r === '*' ? '' : 'border-line bg-surface'"
                :style="
                  r === '*'
                    ? {
                        color: 'var(--alert)',
                        borderColor: 'color-mix(in srgb, var(--alert) 40%, transparent)',
                        background: 'color-mix(in srgb, var(--alert) 10%, transparent)',
                      }
                    : undefined
                "
                >{{ r }}</span
              >
            </dd>
          </template>

          <template v-if="b.members.length">
            <dt class="pt-0.5 text-faint">대상</dt>
            <dd class="code break-all text-muted !text-[12px]">{{ b.members.join(', ') }}</dd>
          </template>
        </dl>
      </div>
    </template>

    <button class="btn btn-sm btn-ghost !px-1" @click="showJson = !showJson">
      <Icon :name="showJson ? 'down' : 'right'" :size="14" />
      원본 JSON {{ showJson ? '접기' : '보기' }}
    </button>
    <JsonView v-if="showJson" :value="document" max-height="280px" />
  </div>
</template>

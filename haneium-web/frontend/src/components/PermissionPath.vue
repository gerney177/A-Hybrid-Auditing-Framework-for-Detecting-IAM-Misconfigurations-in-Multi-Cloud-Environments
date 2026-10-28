<script setup lang="ts">
import { computed } from 'vue'
import Icon from './Icon.vue'

const props = defineProps<{ path: string[] }>()

// "arn:aws:iam::123:group/Team:policy/Name" 같은 ID 를 종류와 이름으로 나눈다.
function describe(arn: string) {
  const policy = arn.match(/:policy\/(.+)$/)
  if (policy) return { kind: 'policy', name: policy[1] }
  const principal = arn.match(/:(user|group|role)\/(.+)$/)
  if (principal) return { kind: principal[1], name: principal[2] }
  return { kind: 'policy', name: arn }
}

const kindLabel: Record<string, string> = { user: '사용자', group: '그룹', role: '역할', policy: '정책' }
const kindIcon: Record<string, string> = { user: 'user', group: 'group', role: 'role', policy: 'policy' }

const nodes = computed(() => props.path.map((arn) => ({ arn, ...describe(arn) })))
</script>

<template>
  <div class="flex flex-wrap items-center gap-1.5">
    <template v-for="(node, i) in nodes" :key="i">
      <Icon v-if="i > 0" name="arrow" :size="13" class="text-faint" />
      <span
        class="inline-flex items-center gap-1.5 rounded-lg border border-line bg-surface-2 py-1 pr-2.5 pl-2 text-[12.5px]"
        :title="node.arn"
      >
        <Icon :name="kindIcon[node.kind]" :size="13" class="text-faint" />
        <span class="text-faint">{{ kindLabel[node.kind] }}</span>
        <span class="font-semibold">{{ node.name }}</span>
      </span>
    </template>
  </div>
</template>

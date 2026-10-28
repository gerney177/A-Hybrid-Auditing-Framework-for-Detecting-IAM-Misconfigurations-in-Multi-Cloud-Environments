import { defineStore } from 'pinia'
import { ref, shallowRef } from 'vue'
import { api, ApiError } from '@/api/client'
import { useToast } from '@/composables/useToast'
import type { IdentityRow, ModelInfo, Overview, RunRecord } from '@/types'

/** 여러 화면이 함께 쓰는 분석 결과(개요·대상 목록)와 '분석 실행' 상태. */
export const useAnalysis = defineStore('analysis', () => {
  const overview = shallowRef<Overview | null>(null)
  const identities = shallowRef<IdentityRow[]>([])
  const model = shallowRef<ModelInfo | null>(null)
  const runs = shallowRef<RunRecord[]>([])
  const loading = ref(true)
  const error = ref<string | null>(null)
  const missing = ref(false) // 아직 분석 결과가 한 번도 없는 상태
  const running = ref(false)
  // 분석을 다시 실행하면 올라간다. 다른 화면들이 이 값을 보고 다시 불러온다.
  const version = ref(0)

  async function load() {
    loading.value = true
    error.value = null
    missing.value = false
    try {
      const [o, i, m, r] = await Promise.all([api.overview(), api.identities(), api.model(), api.runs()])
      overview.value = o
      identities.value = i
      model.value = m
      runs.value = r
    } catch (cause) {
      if (cause instanceof ApiError && cause.status === 404) missing.value = true
      else error.value = cause instanceof Error ? cause.message : String(cause)
    } finally {
      loading.value = false
    }
  }

  async function run() {
    if (running.value) return
    const toast = useToast()
    running.value = true
    try {
      const result = await api.runAnalysis()
      await load()
      version.value++
      const v = result.verdicts
      toast.push(
        'success',
        `분석을 마치고 저장했어요 · 실행 ID ${result.run_id ?? '–'} (BLOCK ${v.BLOCK ?? 0} · ALERT ${v.ALERT ?? 0} · ALLOW ${v.ALLOW ?? 0})`,
      )
    } catch (cause) {
      toast.push('error', cause instanceof Error ? cause.message : String(cause), 8000)
    } finally {
      running.value = false
    }
  }

  return { overview, identities, model, runs, loading, error, missing, running, version, load, run }
})

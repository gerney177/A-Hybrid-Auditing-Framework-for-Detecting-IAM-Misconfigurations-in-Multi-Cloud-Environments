import { ref, shallowRef } from 'vue'
import { ApiError } from '@/api/client'

/** 로딩·오류 상태를 함께 관리하는 단순한 조회 도구. 늦게 도착한 이전 응답은 버린다. */
export function useFetch<T>(loader: () => Promise<T>) {
  const data = shallowRef<T | null>(null)
  const error = ref<string | null>(null)
  const status = ref<number | null>(null)
  const loading = ref(true)
  let ticket = 0

  async function reload() {
    const mine = ++ticket
    loading.value = true
    error.value = null
    status.value = null
    try {
      const result = await loader()
      if (mine === ticket) data.value = result
    } catch (cause) {
      if (mine !== ticket) return
      data.value = null
      error.value = cause instanceof Error ? cause.message : String(cause)
      status.value = cause instanceof ApiError ? cause.status : null
    } finally {
      if (mine === ticket) loading.value = false
    }
  }

  return { data, error, status, loading, reload }
}

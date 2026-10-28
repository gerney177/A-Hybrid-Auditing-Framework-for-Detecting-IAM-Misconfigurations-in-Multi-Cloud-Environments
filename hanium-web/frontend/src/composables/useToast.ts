import { ref } from 'vue'

export interface Toast {
  id: number
  tone: 'success' | 'error' | 'info'
  message: string
}

const toasts = ref<Toast[]>([])
let seq = 0

export function useToast() {
  function push(tone: Toast['tone'], message: string, ms = 4500) {
    const id = ++seq
    toasts.value.push({ id, tone, message })
    setTimeout(() => dismiss(id), ms)
  }
  function dismiss(id: number) {
    toasts.value = toasts.value.filter((t) => t.id !== id)
  }
  return { toasts, push, dismiss }
}

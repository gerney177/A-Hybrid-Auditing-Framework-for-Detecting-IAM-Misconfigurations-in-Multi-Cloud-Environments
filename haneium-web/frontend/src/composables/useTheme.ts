import { nextTick, ref, watch } from 'vue'

export type Theme = 'light' | 'dark'

// index.html 의 인라인 스크립트가 이미 data-theme 을 정해 둔다.
const theme = ref<Theme>(document.documentElement.dataset.theme === 'dark' ? 'dark' : 'light')

watch(
  theme,
  (value) => {
    document.documentElement.dataset.theme = value
    try {
      localStorage.setItem('theme', value)
    } catch {
      /* 저장소를 못 쓰는 환경이면 이번 접속에만 적용된다 */
    }
  },
  { flush: 'sync' },
)

export function useTheme() {
  return {
    theme,
    toggle: () => {
      theme.value = theme.value === 'dark' ? 'light' : 'dark'
    },
  }
}

/** 차트(canvas)는 CSS 변수를 못 읽으므로 값을 꺼내 와서 테마가 바뀔 때마다 갱신한다. */
export interface Palette {
  text: string
  muted: string
  faint: string
  border: string
  surface: string
  surface2: string
  accent: string
  block: string
  alert: string
  allow: string
  info: string
  font: string
}

function read(): Palette {
  const style = getComputedStyle(document.documentElement)
  const get = (name: string) => style.getPropertyValue(name).trim()
  return {
    text: get('--text'),
    muted: get('--muted'),
    faint: get('--faint'),
    border: get('--border'),
    surface: get('--surface'),
    surface2: get('--surface-2'),
    accent: get('--accent'),
    block: get('--block'),
    alert: get('--alert'),
    allow: get('--allow'),
    info: get('--info'),
    font: get('--font-sans'),
  }
}

let palette: ReturnType<typeof ref<Palette>> | null = null

export function usePalette() {
  if (!palette) {
    palette = ref<Palette>(read())
    watch(theme, () => nextTick(() => (palette!.value = read())))
  }
  return palette as { value: Palette }
}

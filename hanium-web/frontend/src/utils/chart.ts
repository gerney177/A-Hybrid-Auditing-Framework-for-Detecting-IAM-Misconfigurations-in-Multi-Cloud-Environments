import type { EChartsOption } from 'echarts'
import type { Palette } from '@/composables/useTheme'

/** 모든 차트가 공유하는 글꼴·툴팁·애니메이션 설정 */
export function chartBase(p: Palette): Pick<EChartsOption, 'textStyle' | 'tooltip' | 'animationDuration'> {
  return {
    textStyle: { fontFamily: p.font, color: p.muted },
    tooltip: {
      confine: true,
      backgroundColor: p.surface,
      borderColor: p.border,
      borderWidth: 1,
      padding: [8, 12],
      textStyle: { color: p.text, fontSize: 12.5, fontFamily: p.font },
      extraCssText: 'box-shadow:0 10px 28px rgba(0,0,0,.18);border-radius:10px;',
    },
    animationDuration: 600,
  }
}

export function verdictColors(p: Palette) {
  return { BLOCK: p.block, ALERT: p.alert, ALLOW: p.allow } as const
}

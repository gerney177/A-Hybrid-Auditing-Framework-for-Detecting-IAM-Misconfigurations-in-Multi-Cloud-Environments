// 쓰는 차트 종류만 등록해서 번들 크기를 줄인다.
import { BarChart, PieChart, RadarChart } from 'echarts/charts'
import { GridComponent, LegendComponent, RadarComponent, TooltipComponent } from 'echarts/components'
import { use } from 'echarts/core'
import { CanvasRenderer } from 'echarts/renderers'

use([BarChart, PieChart, RadarChart, GridComponent, LegendComponent, RadarComponent, TooltipComponent, CanvasRenderer])

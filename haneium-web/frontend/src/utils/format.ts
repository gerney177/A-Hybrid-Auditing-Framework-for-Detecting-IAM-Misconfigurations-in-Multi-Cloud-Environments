const KST = 'Asia/Seoul'

export function score(value: number | null | undefined, digits = 3): string {
  return value == null ? '–' : value.toFixed(digits)
}

export function percent(part: number, whole: number, digits = 1): string {
  return whole === 0 ? '0%' : `${((part / whole) * 100).toFixed(digits)}%`
}

/** 서버는 UTC ISO 문자열을 주므로 한국 시간으로 보여준다. */
export function kst(iso: string | null | undefined): string {
  if (!iso) return '–'
  // DB 의 created_at 은 "2026-10-27 06:44:29"(UTC) 형식이라 T/Z 를 보정한다.
  const normalized = /[zZ]|[+-]\d\d:?\d\d$/.test(iso) ? iso : `${iso.replace(' ', 'T')}Z`
  const date = new Date(normalized)
  if (Number.isNaN(date.getTime())) return iso
  const parts = new Intl.DateTimeFormat('ko-KR', {
    timeZone: KST,
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: false,
  }).formatToParts(date)
  const get = (type: string) => parts.find((p) => p.type === type)?.value ?? ''
  return `${get('year')}-${get('month')}-${get('day')} ${get('hour')}:${get('minute')}:${get('second')}`
}

/** ARN 은 길어서 마지막 부분만 보여주고 전체는 title 로 남긴다. */
export function shortArn(arn: string | null | undefined): string {
  if (!arn) return '–'
  const tail = arn.split(':').slice(5).join(':') || arn
  return tail
}

export function formatNumber(value: number): string {
  return value.toLocaleString('ko-KR')
}

import type { AttachmentType, Cloud, DecisionBy, Verdict } from '@/types'

export const VERDICTS: Verdict[] = ['BLOCK', 'ALERT', 'ALLOW']
export const CLOUDS: Cloud[] = ['AWS', 'Azure', 'GCP']

export const verdictMeta: Record<Verdict, { ko: string; hint: string; var: string }> = {
  BLOCK: { ko: '차단', hint: '명확한 규칙 위반으로 즉시 조치가 필요합니다.', var: 'var(--block)' },
  ALERT: { ko: '경고', hint: '위험 신호가 있어 검토가 필요합니다.', var: 'var(--alert)' },
  ALLOW: { ko: '허용', hint: '현재 기준에서 위험 신호가 없습니다.', var: 'var(--allow)' },
}

export const cloudDot: Record<Cloud, string> = {
  AWS: '#6f7df5',
  Azure: '#2fa8e8',
  GCP: '#b36bf0',
}

/** 판정 근거 코드 → 사람이 읽는 설명 */
export const reasonMeta: Record<string, { label: string; detail: string }> = {
  NO_WILDCARD: {
    label: '와일드카드 권한',
    detail: 'Action 또는 Resource 에 * 가 들어 있어 필요 이상으로 넓은 권한이 부여돼 있습니다.',
  },
  MFA_REQUIRED: {
    label: '관리자 MFA 미설정',
    detail: '관리자 권한을 가진 계정인데 다중 인증(MFA)이 꺼져 있습니다.',
  },
  API_KEY_NO_MFA: {
    label: 'API 키 보유 · MFA 없음',
    detail: 'API 키가 발급돼 있는데 MFA 가 꺼져 있어 키가 유출되면 바로 악용될 수 있습니다.',
  },
  NO_ROOT_KEY: {
    label: 'root 계정 API 키',
    detail: 'root 계정에 API 키가 발급돼 있습니다.',
  },
  AI_ANOMALY_DETECTED: {
    label: '행동 이상 탐지',
    detail: '로그인 시간·API 호출·로그인 실패 패턴이 다른 계정과 눈에 띄게 다릅니다.',
  },
  AI_ONLY_ANOMALY_ALERT: {
    label: '행동 이상 단독 경고',
    detail: '정책 위반은 없지만 행동 이상 점수가 매우 높아 단독으로 경고로 올렸습니다.',
  },
  GRAPH_RISK_SIGNAL: {
    label: '권한 그래프 위험 신호',
    detail: '권한 그래프에서 와일드카드나 알 수 없는 작업 같은 위험 신호가 발견됐습니다.',
  },
  GRAPH_ONLY_RISK_ALERT: {
    label: '권한 그래프 단독 경고',
    detail: '규칙 위반·행동 이상은 없지만 권한 상승 가능성 같은 정책상 위험 신호만으로 경고로 올렸습니다.',
  },
}

export function reasonLabel(code: string): string {
  return reasonMeta[code]?.label ?? code
}

export const findingMeta: Record<string, string> = {
  WILDCARD_PERMISSION: '와일드카드 권한',
  UNKNOWN_OPERATION: '분류되지 않은 작업',
  PRIVILEGE_ESCALATION_VECTOR: '권한 상승 가능',
}

export const decisionMeta: Record<DecisionBy, { label: string; detail: string }> = {
  rule: { label: '규칙', detail: '규칙 점수가 1.0 이상이라 즉시 차단' },
  hybrid: { label: '종합 점수', detail: '규칙·행동·그래프의 가중합으로 판정' },
  ai: { label: '행동 이상', detail: '행동 이상 점수 단독으로 경고 승격' },
  graph: { label: '권한 그래프', detail: '그래프 점수 단독으로 경고 승격' },
}

export const remediationMeta: Record<string, string> = {
  POLICY_DRAFT: '정책 초안 제안',
  MANUAL_REVIEW: '수동 검토',
  POLICY_DRAFT_AND_MANUAL_MFA: '정책 초안 + MFA 설정',
}

export const attachmentMeta: Record<AttachmentType, string> = {
  user_direct: '사용자 직접',
  role_direct: '역할 직접',
  group: '그룹 경유',
}

export const identityTypeMeta: Record<string, string> = { user: '사용자', role: '역할' }

export const analysisScopeMeta: Record<string, string> = {
  user_role_and_group_v2: '사용자 직접 정책 + 그룹 경유 정책 + 역할 직접 정책',
  user_and_role_direct_v1: '사용자·역할 직접 정책 (그룹 경유 제외)',
  user_direct_legacy: '사용자 직접 정책',
}

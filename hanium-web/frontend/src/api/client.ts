import type {
  AccessInfo,
  AwsAnalysis,
  IdentityDetail,
  IdentityRow,
  ModelInfo,
  Overview,
  RemediationPlan,
  RemediationEffect,
  RunRecord,
  RunResult,
} from '@/types'

export class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
  ) {
    super(message)
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  let response: Response
  try {
    response = await fetch(`/api${path}`, init)
  } catch {
    throw new ApiError(0, 'API 서버에 연결할 수 없습니다. 백엔드(8010)가 켜져 있는지 확인해 주세요.')
  }
  if (!response.ok) {
    let detail = response.statusText
    try {
      detail = (await response.json()).detail ?? detail
    } catch {
      /* 본문이 JSON 이 아니면 상태 문구를 그대로 쓴다 */
    }
    throw new ApiError(response.status, detail)
  }
  return response.json() as Promise<T>
}

export const api = {
  overview: () => request<Overview>('/overview'),
  model: () => request<ModelInfo>('/model'),
  identities: () => request<IdentityRow[]>('/identities'),
  identity: (name: string) => request<IdentityDetail>(`/identities/${encodeURIComponent(name)}`),
  aws: () => request<AwsAnalysis>('/aws'),
  access: () => request<AccessInfo>('/access'),
  remediations: () => request<Array<RemediationPlan & { effect: RemediationEffect | null }>>('/remediations'),
  runs: () => request<RunRecord[]>('/runs'),
  runAnalysis: () => request<RunResult>('/runs', { method: 'POST' }),
}

export const downloads = {
  report: '/api/export/report.json',
  csv: '/api/export/identities.csv',
}

export type Verdict = 'BLOCK' | 'ALERT' | 'ALLOW'
export type Cloud = 'AWS' | 'Azure' | 'GCP'
export type DecisionBy = 'rule' | 'ai' | 'graph' | 'hybrid'

export interface IdentityRow {
  name: string
  cloud: Cloud
  verdict: Verdict
  risk_score: number
  rule_score: number
  anomaly_score: number
  graph_score: number
  groups: string[]
  role_assignments: string[]
  reasons: string[]
  decision_by: DecisionBy | null
  is_anomaly: boolean
  graph_finding_count: number
  raw_privilege_finding_count: number
  rank: number
}

export interface RemediationSummary {
  planned: number
  applied: number
  action_changed: number
  risk_improved: number
  avg_before: number | null
  avg_after: number | null
  by_type: Record<string, number>
  after_verdicts: Partial<Record<Verdict, number>>
}

export interface Overview {
  executed_at: string
  dataset_version: string
  source: string
  run_id: number | null
  dataset_id: number | null
  seed: number | null
  summary: {
    total: number
    users: number
    groups: number
    roles: number
    clouds: Record<Cloud, number>
    verdicts: Partial<Record<Verdict, number>>
  }
  verdict_by_cloud: Record<Cloud, Record<Verdict, number>>
  score_bins: Array<{ from: number; to: number } & Record<Verdict, number>>
  reasons: Array<{ code: string; count: number }>
  decision_by: Partial<Record<DecisionBy, number>>
  top_risk: IdentityRow[]
  remediation: RemediationSummary
  notes: string[]
}

export interface ModelInfo {
  weights: { rule: number; ai: number; graph: number }
  threshold: number
  ai_alert: number
  graph_alert: number
  rules: Array<{ name: string; severity: number }>
}

export interface IdentityMetadata {
  identity: string
  cloud_provider: Cloud
  role: string
  is_admin: boolean
  mfa_enabled: boolean
  has_api_key: boolean
  privilege_level: string
  privilege_level_numeric: number
  is_true_risk: boolean
  risk_scenario: string | null
}

export interface IdentityBehavior {
  identity: string
  cloud_provider: Cloud
  login_hour: number
  api_call_count: number
  failed_login_count: number
}

/** 클라우드마다 모양이 다른 원본 정책 문서 */
export type PolicyDocument = Record<string, unknown>

export interface RawPolicy {
  identity: string
  csp: Cloud
  raw_policy_document: PolicyDocument
}

export type AttachmentType = 'user_direct' | 'role_direct' | 'group'

export interface AwsPolicyItem {
  identity: string
  identity_name: string
  identity_type: 'user' | 'role'
  csp: Cloud
  attachment_type: AttachmentType
  policy_name: string
  policy_arn: string | null
  policy_id: string | null
  policy_type: string
  policy_source_identity: string
  group_name?: string
  permission_path: string[]
  raw_policy_document?: PolicyDocument | null
}

export interface AwsFinding {
  identity: string
  identity_name: string
  identity_type: 'user' | 'role'
  attachment_type: AttachmentType
  policy_source_identity: string
  policy_type: string
  policy_name: string
  policy_id: string | null
  permission_path: string[]
  original_action: string
  original_resources: string[]
  condition: unknown
  status: string
  wildcard_type?: string
  matched_action?: string
}

export interface AwsAnalysis {
  analysis_scope: string
  collected_at: string | null
  source: string | null
  counts: {
    users: number
    roles: number
    groups: number
    policy_bodies: number
    role_policy_bodies: number
    group_policy_links: number
    wildcard: number
    passrole: number
  }
  policy_items: AwsPolicyItem[]
  wildcard_findings: AwsFinding[]
  passrole_findings: AwsFinding[]
}

export interface NamedPolicy {
  name: string
  document: PolicyDocument
}

export interface AccessRole {
  name: string
  arn: string
  assumable_by: string[]
  trusted_principals: string[]
  policies: NamedPolicy[]
  wildcard_count: number
  passrole_count: number
}

export interface AccessGroup {
  name: string
  arn: string
  members: string[]
  policies: NamedPolicy[]
}

export interface AccessInfo {
  roles: AccessRole[]
  groups: AccessGroup[]
  assignment_count: number
}

export interface GraphFinding {
  identity: string
  finding_type: string
  operation: string
  target: string
  effect: string
  source_csp: Cloud
  description: string
}

export interface RawPrivilegeFinding {
  identity: string
  source_csp: Cloud
  raw_action: string
  scope: string
  effect: string
  finding_type: string
  severity: string
  description: string
}

export interface RemediationPlan {
  remediation_priority: number
  identity: string
  source_csp: Cloud
  final_action: Verdict
  hybrid_risk_score: number
  triggered_rules: string[]
  graph_evidence: string[]
  raw_policy_evidence: string[]
  remediation_type: string
  recommendation: string[]
  manual_steps: string[]
  terraform_supported: boolean
  terraform_code: string | null
}

export interface RemediationEffect {
  identity: string
  before_risk_score: number
  before_action: Verdict
  after_risk_score: number
  after_action: Verdict
  before_rule_score: number
  after_rule_score: number
  before_graph_findings: number
  after_graph_findings: number
  remediation_applied: boolean
  risk_reduction: number
  action_changed: boolean
}

export interface IdentityDetail {
  identity: IdentityRow
  total: number
  metadata: IdentityMetadata | null
  behavior: IdentityBehavior | null
  population: { api_call_median: number; failed_login_median: number; cloud: Cloud; size: number }
  policies: RawPolicy[]
  aws_policy_items: AwsPolicyItem[]
  rules: { max_rule_score: number; violation_record_count: number; triggered_rule_names: string[] } | null
  ai: {
    raw_isolation_score: number
    ai_score: number
    isolation_prediction: number
    is_detected_anomaly: boolean
    anomaly_rank: number
  } | null
  graph_summary: {
    permission_edge_count: number
    wildcard_edge_count: number
    unknown_operation_count: number
    target_count: number
  } | null
  graph_findings: GraphFinding[]
  raw_privilege_findings: RawPrivilegeFinding[]
  integrated: { hybrid_risk_score: number; decision_by: DecisionBy } | null
  remediation_plan: RemediationPlan | null
  remediation_effect: RemediationEffect | null
}

export interface RunRecord {
  run_id: number
  dataset_id: number
  created_at: string
  source: string
}

export interface RunResult {
  executed_at: string
  run_id: number | null
  dataset_id: number | null
  verdicts: Partial<Record<Verdict, number>>
}

export type Verdict = 'malicious' | 'suspicious' | 'clean_no_findings' | 'inconclusive';

export type ModuleType = 'url' | 'apk' | 'sms' | 'screenshot';

export type Severity = 'info' | 'low' | 'medium' | 'high';

export type CheckStatus = 'completed' | 'failed' | 'unavailable' | 'skipped';

export interface EvidenceItem {
  id: string;
  category: string;
  severity: Severity;
  title: string;
  detail: string;
  source: 'model' | 'rule' | 'reputation' | 'parser' | 'ocr';
}

export interface CheckPerformed {
  name: string;
  status: CheckStatus;
  detail?: string | null;
}

export interface AnalysisResult {
  investigation_id: string;
  type: ModuleType;
  created_at: string;
  verdict: Verdict;
  display_label: string;
  summary: string;
  evidence: EvidenceItem[];
  checks_performed: CheckPerformed[];
  limitations: string[];
  recommendations: string[];
  analysis_version: string;
  model_version?: string | null;
  input_summary: string;
  saved?: boolean;
}

export interface HealthStatus {
  status: string;
  db: string;
  model_loaded: boolean;
  model_version?: string | null;
  model_error?: string | null;
  ocr_available: boolean;
  ocr_engine?: string | null;
  ocr_detail: string;
  external_lookups_enabled: boolean;
  reputation_sources: Record<string, string>;
  version: string;
}

export interface DashboardStats {
  total: number;
  by_type: Record<string, number>;
  by_verdict: Record<string, number>;
  last_7d: number;
  last_30d: number;
  recent: Array<{
    id: string;
    type: string;
    created_at: string;
    verdict: string;
    display_label: string;
    input_display: string;
  }>;
}

export interface HistoryItem {
  id: string;
  type: string;
  created_at: string;
  verdict: string;
  display_label: string;
  summary: string;
  input_display: string;
  status: string;
  duration_ms?: number | null;
}

export interface HistoryResponse {
  items: HistoryItem[];
  total: number;
  page: number;
  page_size: number;
  has_more: boolean;
}

export interface InvestigationDetail {
  id: string;
  type: string;
  created_at: string;
  verdict: string;
  display_label: string;
  summary: string;
  input_display: string;
  status: string;
  duration_ms?: number | null;
  model_version?: string | null;
  analysis_version: string;
  result_json: AnalysisResult;
}

export type InitiativeStatus =
  | "pending"
  | "running"
  | "paused"
  | "completed"
  | "cancelled"
  | "failed";

export type InitiativePriority = "low" | "normal" | "high" | "urgent";
export type InitiativeRiskClass = "low" | "medium" | "high" | "critical";
export type InitiativeTaskStatus = "queued" | "running" | "retry" | "completed" | "failed" | "cancelled";

export interface InitiativeRecord {
  id: string;
  source: string;
  external_ref: string | null;
  title: string;
  description: string;
  priority: InitiativePriority;
  risk_class: InitiativeRiskClass;
  status: InitiativeStatus;
  requested_by: string;
  metadata: Record<string, unknown>;
  created_at: string;
  updated_at: string;
  started_at: string | null;
  finished_at: string | null;
  last_error: string | null;
}

export interface InitiativeTaskRecord {
  id: string;
  initiative_id: string;
  sequence: number;
  task_type: string;
  payload: Record<string, unknown>;
  status: InitiativeTaskStatus;
  retry_count: number;
  max_retries: number;
  next_run_at: string;
  created_at: string;
  updated_at: string;
  started_at: string | null;
  finished_at: string | null;
  last_error: string | null;
}

export interface InitiativeEventRecord {
  id: number;
  initiative_id: string;
  task_id: string | null;
  event_type: string;
  actor: string;
  payload: Record<string, unknown>;
  timestamp: string;
  previous_hash: string;
  current_hash: string;
}

export interface CreateInitiativeTaskInput {
  task_type: string;
  payload?: Record<string, unknown>;
  max_retries?: number;
}

export interface CreateInitiativeInput {
  source: string;
  external_ref?: string;
  title: string;
  description?: string;
  priority?: InitiativePriority;
  risk_class?: InitiativeRiskClass;
  requested_by?: string;
  metadata?: Record<string, unknown>;
  tasks?: CreateInitiativeTaskInput[];
}

export interface ListInitiativeFilters {
  status?: InitiativeStatus;
  source?: string;
  priority?: InitiativePriority;
  limit?: number;
}

export interface InitiativeStats {
  enabled: boolean;
  total: number;
  pending: number;
  running: number;
  paused: number;
  completed: number;
  cancelled: number;
  failed: number;
  task_queued: number;
  task_running: number;
  task_retry: number;
  task_failed: number;
}

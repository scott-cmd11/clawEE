import type { AuditLedger } from "./audit-ledger";
import type { ChannelHub, ChannelKind } from "./channel-hub";
import type { InteractionStore } from "./interaction-store";
import type {
  CreateInitiativeInput,
  InitiativeEventRecord,
  InitiativeRecord,
  InitiativeStats,
  InitiativeTaskRecord,
  ListInitiativeFilters,
} from "./initiative-types";
import type { InitiativeStore } from "./initiative-store";
import type { VdiService } from "./vdi-service";

const MAX_BACKOFF_SECONDS = 300;

export interface InitiativeEngineOptions {
  enabled: boolean;
  pollSeconds: number;
  maxTaskRetries: number;
  nodeId: string;
}

export interface InitiativeControlService {
  isEnabled(): boolean;
  getStats(): InitiativeStats;
  createInitiative(input: CreateInitiativeInput): {
    created: boolean;
    initiative: InitiativeRecord;
    tasks: InitiativeTaskRecord[];
  };
  listInitiatives(filters?: ListInitiativeFilters): InitiativeRecord[];
  getInitiative(id: string): InitiativeRecord | null;
  listInitiativeTasks(id: string): InitiativeTaskRecord[];
  listInitiativeEvents(id: string, limit?: number): InitiativeEventRecord[];
  startInitiative(id: string, actor: string): InitiativeRecord;
  pauseInitiative(id: string, actor: string, reason?: string): InitiativeRecord;
  cancelInitiative(id: string, actor: string, reason?: string): InitiativeRecord;
  interruptInitiative(id: string, actor: string, reason?: string): InitiativeRecord;
}

export class InitiativeEngine implements InitiativeControlService {
  private options: InitiativeEngineOptions;
  private store: InitiativeStore;
  private channelHub: ChannelHub;
  private interactionStore: InteractionStore;
  private ledger: AuditLedger;
  private vdiService: VdiService | null;
  private vdiSessionAliases = new Map<string, string>();
  private timer: NodeJS.Timeout | null = null;
  private tickInFlight = false;

  constructor(
    options: InitiativeEngineOptions,
    store: InitiativeStore,
    channelHub: ChannelHub,
    interactionStore: InteractionStore,
    ledger: AuditLedger,
    vdiService?: VdiService,
  ) {
    this.options = {
      enabled: options.enabled,
      pollSeconds: Math.max(5, Math.floor(options.pollSeconds || 30)),
      maxTaskRetries: Math.max(0, Math.floor(options.maxTaskRetries || 3)),
      nodeId: String(options.nodeId || "local-node").trim() || "local-node",
    };
    this.store = store;
    this.channelHub = channelHub;
    this.interactionStore = interactionStore;
    this.ledger = ledger;
    this.vdiService = vdiService || null;
  }

  isEnabled(): boolean {
    return this.options.enabled;
  }

  async start(): Promise<void> {
    if (!this.options.enabled) {
      return;
    }
    const intervalMs = this.options.pollSeconds * 1000;
    this.timer = setInterval(() => {
      void this.runNow();
    }, intervalMs);
    await this.runNow();
  }

  async stop(): Promise<void> {
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = null;
    }
  }

  async runNow(): Promise<void> {
    if (!this.options.enabled || this.tickInFlight) {
      return;
    }
    this.tickInFlight = true;
    try {
      const claim = this.store.claimNextDueTask(this.options.nodeId);
      if (!claim) {
        return;
      }
      const task = claim.task;
      const initiative = claim.initiative;
      this.ledger.logAndSignAction("INITIATIVE_TASK_STARTED", {
        initiative_id: initiative.id,
        task_id: task.id,
        task_type: task.task_type,
        node_id: this.options.nodeId,
      });
      await this.executeTask(initiative, task);
    } catch (error) {
      this.ledger.logAndSignAction("SYSTEM_ERROR", {
        module: "initiative-engine",
        stage: "runNow",
        message: error instanceof Error ? error.message : String(error),
      });
    } finally {
      this.tickInFlight = false;
    }
  }

  createInitiative(input: CreateInitiativeInput): {
    created: boolean;
    initiative: InitiativeRecord;
    tasks: InitiativeTaskRecord[];
  } {
    const created = this.store.createInitiative(input);
    if (created.created) {
      this.store.appendEvent(
        created.initiative.id,
        null,
        "initiative.created",
        created.initiative.requested_by || "manual-operator",
        {
          source: created.initiative.source,
          priority: created.initiative.priority,
          risk_class: created.initiative.risk_class,
          task_count: created.tasks.length,
        },
      );
      this.ledger.logAndSignAction("INITIATIVE_CREATED", {
        initiative_id: created.initiative.id,
        source: created.initiative.source,
        title: created.initiative.title,
        priority: created.initiative.priority,
        risk_class: created.initiative.risk_class,
        task_count: created.tasks.length,
      });
      for (const task of created.tasks) {
        this.store.appendEvent(
          created.initiative.id,
          task.id,
          "task.scheduled",
          created.initiative.requested_by || "manual-operator",
          {
            sequence: task.sequence,
            task_type: task.task_type,
            next_run_at: task.next_run_at,
          },
        );
        this.ledger.logAndSignAction("INITIATIVE_TASK_SCHEDULED", {
          initiative_id: created.initiative.id,
          task_id: task.id,
          sequence: task.sequence,
          task_type: task.task_type,
        });
      }
    } else {
      this.ledger.logAndSignAction("INITIATIVE_DEDUPED", {
        initiative_id: created.initiative.id,
        source: created.initiative.source,
        external_ref: created.initiative.external_ref,
      });
    }
    return created;
  }

  listInitiatives(filters: ListInitiativeFilters = {}): InitiativeRecord[] {
    return this.store.listInitiatives(filters);
  }

  getInitiative(id: string): InitiativeRecord | null {
    return this.store.getInitiativeById(id);
  }

  listInitiativeTasks(id: string): InitiativeTaskRecord[] {
    return this.store.listInitiativeTasks(id);
  }

  listInitiativeEvents(id: string, limit = 200): InitiativeEventRecord[] {
    return this.store.listInitiativeEvents(id, limit);
  }

  startInitiative(id: string, actor: string): InitiativeRecord {
    const updated = this.store.setInitiativeStatus(id, "running", actor);
    this.ledger.logAndSignAction("INITIATIVE_STATUS_CHANGED", {
      initiative_id: id,
      status: "running",
      actor,
    });
    return updated;
  }

  pauseInitiative(id: string, actor: string, reason = ""): InitiativeRecord {
    const updated = this.store.setInitiativeStatus(id, "paused", actor, reason);
    this.ledger.logAndSignAction("INITIATIVE_STATUS_CHANGED", {
      initiative_id: id,
      status: "paused",
      actor,
      reason: reason || null,
    });
    return updated;
  }

  cancelInitiative(id: string, actor: string, reason = ""): InitiativeRecord {
    const updated = this.store.setInitiativeStatus(id, "cancelled", actor, reason);
    this.ledger.logAndSignAction("INITIATIVE_STATUS_CHANGED", {
      initiative_id: id,
      status: "cancelled",
      actor,
      reason: reason || null,
    });
    return updated;
  }

  interruptInitiative(id: string, actor: string, reason = "manual-interrupt"): InitiativeRecord {
    const updated = this.store.setInitiativeStatus(id, "paused", actor, reason);
    this.store.appendEvent(id, null, "initiative.interrupted", actor, {
      reason,
    });
    this.ledger.logAndSignAction("INITIATIVE_INTERRUPTED", {
      initiative_id: id,
      actor,
      reason,
    });
    return updated;
  }

  getStats(): InitiativeStats {
    if (!this.options.enabled) {
      return {
        enabled: false,
        total: 0,
        pending: 0,
        running: 0,
        paused: 0,
        completed: 0,
        cancelled: 0,
        failed: 0,
        task_queued: 0,
        task_running: 0,
        task_retry: 0,
        task_failed: 0,
      };
    }
    return this.store.getStats();
  }

  private async executeTask(initiative: InitiativeRecord, task: InitiativeTaskRecord): Promise<void> {
    try {
      switch (task.task_type) {
        case "noop":
          this.store.completeTask(initiative.id, task.id, "initiative-engine", {
            action: "noop",
          });
          this.ledger.logAndSignAction("INITIATIVE_TASK_COMPLETED", {
            initiative_id: initiative.id,
            task_id: task.id,
            task_type: task.task_type,
            action: "noop",
          });
          break;
        case "channel.send":
          this.executeChannelSendTask(initiative.id, task);
          break;
        case "vdi.session.start":
          await this.executeVdiSessionStartTask(initiative.id, task);
          break;
        case "vdi.browser.step":
          await this.executeVdiBrowserStepTask(initiative.id, task);
          break;
        case "vdi.session.stop":
          await this.executeVdiSessionStopTask(initiative.id, task);
          break;
        default:
          throw new Error(`Unsupported initiative task type: ${task.task_type}`);
      }
    } catch (error) {
      const retryCount = task.retry_count + 1;
      const maxRetries = Math.max(task.max_retries, this.options.maxTaskRetries);
      const backoffSeconds = Math.min(Math.max(5, 30 * retryCount), MAX_BACKOFF_SECONDS);
      const nextRunAt = new Date(Date.now() + backoffSeconds * 1000).toISOString();
      const message = error instanceof Error ? error.message : String(error);
      this.store.failTaskWithRetry({
        initiativeId: initiative.id,
        taskId: task.id,
        actor: "initiative-engine",
        retryCount,
        maxRetries,
        errorMessage: message,
        nextRunAt,
      });
      this.ledger.logAndSignAction("INITIATIVE_TASK_FAILED", {
        initiative_id: initiative.id,
        task_id: task.id,
        task_type: task.task_type,
        retry_count: retryCount,
        max_retries: maxRetries,
        next_run_at: nextRunAt,
        exhausted: retryCount > maxRetries,
        error: message,
      });
    }
  }

  private executeChannelSendTask(initiativeId: string, task: InitiativeTaskRecord): void {
    const payload = task.payload || {};
    const channelRaw = String(payload.channel || "").trim().toLowerCase();
    const destination = String(payload.destination || "").trim();
    const text = String(payload.text || "").trim();
    const metadata =
      payload.metadata && typeof payload.metadata === "object" && !Array.isArray(payload.metadata)
        ? (payload.metadata as Record<string, unknown>)
        : {};
    if (!channelRaw || !destination || !text) {
      throw new Error("channel.send task payload requires channel, destination, and text.");
    }
    const channelKind = channelRaw as ChannelKind;
    if (!["slack", "teams", "discord", "email", "webhook"].includes(channelKind)) {
      throw new Error(`Unsupported channel kind in task payload: ${channelRaw}`);
    }

    const message = this.channelHub.queueOutbound({
      channel: channelKind,
      destination,
      text,
      metadata: {
        ...metadata,
        initiative_id: initiativeId,
        initiative_task_id: task.id,
      },
    });
    this.interactionStore.recordChannelOutbound(message);
    this.store.completeTask(initiativeId, task.id, "initiative-engine", {
      action: "channel.send",
      message_id: message.id,
      channel: message.channel,
      destination: message.destination,
    });
    this.ledger.logAndSignAction("INITIATIVE_TASK_COMPLETED", {
      initiative_id: initiativeId,
      task_id: task.id,
      task_type: task.task_type,
      action: "channel.send",
      channel: message.channel,
      destination: message.destination,
      message_id: message.id,
    });
  }

  private getVdiServiceOrThrow(): VdiService {
    if (!this.vdiService || !this.vdiService.isEnabled()) {
      throw new Error("VDI runtime is not available for initiative task execution.");
    }
    return this.vdiService;
  }

  private resolveSessionId(payload: Record<string, unknown>): string {
    const directId = String(payload.session_id || "").trim();
    if (directId) {
      return directId;
    }
    const alias = String(payload.session_alias || "").trim();
    if (alias && this.vdiSessionAliases.has(alias)) {
      return String(this.vdiSessionAliases.get(alias) || "").trim();
    }
    throw new Error("VDI task payload requires session_id or resolvable session_alias.");
  }

  private async executeVdiSessionStartTask(
    initiativeId: string,
    task: InitiativeTaskRecord,
  ): Promise<void> {
    const vdi = this.getVdiServiceOrThrow();
    const payload = task.payload || {};
    const session = await vdi.startSession(payload);
    const alias = String(payload.session_alias || payload.session_key || "").trim();
    if (alias) {
      this.vdiSessionAliases.set(alias, session.id);
    }
    this.store.completeTask(initiativeId, task.id, "initiative-engine", {
      action: "vdi.session.start",
      session_id: session.id,
      session_alias: alias || null,
      status: session.status,
      current_url: session.current_url,
    });
    this.ledger.logAndSignAction("INITIATIVE_TASK_COMPLETED", {
      initiative_id: initiativeId,
      task_id: task.id,
      task_type: task.task_type,
      action: "vdi.session.start",
      session_id: session.id,
      session_alias: alias || null,
    });
  }

  private async executeVdiBrowserStepTask(
    initiativeId: string,
    task: InitiativeTaskRecord,
  ): Promise<void> {
    const vdi = this.getVdiServiceOrThrow();
    const payload = task.payload || {};
    const sessionId = this.resolveSessionId(payload);
    const stepInput =
      payload.step && typeof payload.step === "object" && !Array.isArray(payload.step)
        ? (payload.step as Record<string, unknown>)
        : payload;
    const result = await vdi.executeStep(sessionId, stepInput);
    this.store.completeTask(initiativeId, task.id, "initiative-engine", {
      action: "vdi.browser.step",
      session_id: sessionId,
      step_action: result.action,
      screenshot_path: result.screenshot_path || null,
      current_url: result.current_url || null,
      text: result.text || null,
    });
    this.ledger.logAndSignAction("INITIATIVE_TASK_COMPLETED", {
      initiative_id: initiativeId,
      task_id: task.id,
      task_type: task.task_type,
      action: "vdi.browser.step",
      session_id: sessionId,
      step_action: result.action,
      screenshot_path: result.screenshot_path || null,
    });
  }

  private async executeVdiSessionStopTask(
    initiativeId: string,
    task: InitiativeTaskRecord,
  ): Promise<void> {
    const vdi = this.getVdiServiceOrThrow();
    const payload = task.payload || {};
    const sessionId = this.resolveSessionId(payload);
    const reason = String(payload.reason || "").trim();
    const session = await vdi.stopSession(sessionId, reason);
    const alias = String(payload.session_alias || payload.session_key || "").trim();
    if (alias) {
      this.vdiSessionAliases.delete(alias);
    }
    this.store.completeTask(initiativeId, task.id, "initiative-engine", {
      action: "vdi.session.stop",
      session_id: session.id,
      stopped_at: session.stopped_at,
      status: session.status,
    });
    this.ledger.logAndSignAction("INITIATIVE_TASK_COMPLETED", {
      initiative_id: initiativeId,
      task_id: task.id,
      task_type: task.task_type,
      action: "vdi.session.stop",
      session_id: session.id,
      status: session.status,
    });
  }
}

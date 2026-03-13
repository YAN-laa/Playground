package store

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/yan/ndr-platform/internal/shared"
)

type PostgresStore struct {
	pool *pgxpool.Pool
}

func NewPostgresStore(ctx context.Context, databaseURL string) (*PostgresStore, error) {
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		return nil, err
	}
	store := &PostgresStore{pool: pool}
	if err := store.migrate(ctx); err != nil {
		pool.Close()
		return nil, err
	}
	return store, nil
}

func (s *PostgresStore) Close() {
	s.pool.Close()
}

func nullableTime(value time.Time) any {
	if value.IsZero() {
		return nil
	}
	return value
}

func (s *PostgresStore) migrate(ctx context.Context) error {
	ddl := []string{
		`create table if not exists probes (
			id text primary key,
			tenant_id text not null,
			probe_code text not null,
			name text not null,
			status text not null,
			version text not null,
			rule_version text not null,
			applied_config_id text not null default '',
			applied_rule_id text not null default '',
			last_deploy_status text not null default '',
			last_deploy_message text not null default '',
			last_deploy_at timestamptz,
			cpu_usage double precision not null default 0,
			mem_usage double precision not null default 0,
			drop_rate double precision not null default 0,
			last_heartbeat_at timestamptz not null,
			created_at timestamptz not null
		)`,
		`create table if not exists probe_configs (
			id text primary key,
			tenant_id text not null,
			name text not null,
			description text not null,
			filters jsonb not null,
			output_types jsonb not null,
			created_at timestamptz not null
		)`,
		`create table if not exists rule_bundles (
			id text primary key,
			tenant_id text not null,
			version text not null,
			description text not null,
			enabled boolean not null,
			created_at timestamptz not null
		)`,
		`create table if not exists probe_bindings (
			id text primary key,
			tenant_id text not null,
			probe_id text not null unique,
			probe_name text not null,
			probe_config_id text not null,
			rule_bundle_id text not null,
			updated_at timestamptz not null
		)`,
		`create table if not exists deployment_records (
			id text primary key,
			tenant_id text not null,
			probe_id text not null,
			probe_name text not null,
			probe_config_id text not null,
			rule_bundle_id text not null,
			status text not null,
			message text not null,
			created_at timestamptz not null
		)`,
		`create table if not exists upgrade_packages (
			id text primary key,
			tenant_id text not null,
			version text not null,
			package_url text not null,
			file_name text not null default '',
			file_size bigint not null default 0,
			checksum text not null,
			notes text not null,
			enabled boolean not null,
			created_at timestamptz not null
		)`,
		`create table if not exists probe_upgrade_tasks (
			id text primary key,
			tenant_id text not null,
			probe_id text not null,
			probe_name text not null,
			package_id text not null default '',
			action text not null,
			previous_version text not null,
			target_version text not null,
			status text not null,
			retry_count integer not null default 0,
			max_retries integer not null default 0,
			message text not null,
			created_at timestamptz not null,
			completed_at timestamptz
		)`,
		`create table if not exists probe_version_history (
			id text primary key,
			tenant_id text not null,
			probe_id text not null,
			probe_name text not null,
			action text not null,
			from_version text not null,
			to_version text not null,
			result text not null,
			message text not null,
			created_at timestamptz not null
		)`,
		`create table if not exists probe_metrics (
			id text primary key,
			tenant_id text not null,
			probe_id text not null,
			cpu_usage double precision not null,
			mem_usage double precision not null,
			drop_rate double precision not null,
			created_at timestamptz not null
		)`,
		`create table if not exists raw_events (
			id text primary key,
			tenant_id text not null,
			probe_id text not null,
			event_type text not null,
			event_time timestamptz not null,
			ingest_time timestamptz not null,
			payload jsonb not null
		)`,
		`create table if not exists flows (
			id text primary key,
			tenant_id text not null,
			probe_id text not null,
			flow_id text not null unique,
			src_ip text not null,
			src_port integer not null,
			dst_ip text not null,
			dst_port integer not null,
			proto text not null,
			app_proto text not null,
			seen_at timestamptz not null
		)`,
		`create table if not exists assets (
			id text primary key,
			tenant_id text not null,
			name text not null,
			ip text not null,
			org_id text not null default '',
			org_name text not null default '',
			asset_type text not null,
			importance_level text not null,
			owner text not null,
			tags jsonb not null,
			created_at timestamptz not null
		)`,
		`create table if not exists organizations (
			id text primary key,
			tenant_id text not null,
			name text not null,
			code text not null,
			parent_id text not null default '',
			level integer not null default 1,
			path jsonb not null,
			created_at timestamptz not null
		)`,
		`create table if not exists threat_intel (
			id text primary key,
			tenant_id text not null,
			type text not null,
			value text not null,
			severity text not null,
			source text not null,
			tags jsonb not null,
			created_at timestamptz not null
		)`,
		`create table if not exists suppression_rules (
			id text primary key,
			tenant_id text not null,
			name text not null,
			src_ip text not null,
			dst_ip text not null,
			signature_id integer not null,
			signature text not null,
			enabled boolean not null,
			created_at timestamptz not null
		)`,
		`create table if not exists risk_policies (
			id text primary key,
			tenant_id text not null,
			name text not null,
			severity1_score integer not null,
			severity2_score integer not null,
			severity3_score integer not null,
			default_score integer not null,
			intel_hit_bonus integer not null,
			critical_asset_bonus integer not null,
			enabled boolean not null,
			created_at timestamptz not null
		)`,
		`create table if not exists ticket_automation_policies (
			id text primary key,
			tenant_id text not null,
			name text not null,
			reminder_before_mins integer not null,
			escalation_after_mins integer not null,
			escalation_assignee text not null,
			escalation_status text not null,
			enabled boolean not null,
			created_at timestamptz not null
		)`,
		`create table if not exists alerts (
			id text primary key,
			tenant_id text not null,
			fingerprint text not null unique,
			first_seen_at timestamptz not null,
			last_seen_at timestamptz not null,
			event_count integer not null,
			probe_ids jsonb not null,
			probe_count integer not null default 1,
			src_ip text not null,
			dst_ip text not null,
			dst_port integer not null,
			proto text not null,
			signature_id integer not null,
			signature text not null,
			category text not null,
			severity integer not null,
			risk_score integer not null,
			attack_result text not null default 'unknown',
			window_minutes integer not null default 0,
			status text not null,
			assignee text not null,
			source_asset_id text not null default '',
			source_asset_name text not null default '',
			target_asset_id text not null default '',
			target_asset_name text not null default '',
			threat_intel_tags jsonb not null default '[]',
			threat_intel_hits jsonb not null default '[]'
		)`,
		`create table if not exists tickets (
			id text primary key,
			tenant_id text not null,
			alert_id text not null,
			title text not null,
			description text not null,
			priority text not null,
			status text not null,
			assignee text not null,
			sla_deadline timestamptz,
			sla_status text not null default 'active',
			reminded_at timestamptz,
			escalated_at timestamptz,
			created_at timestamptz not null
		)`,
		`create table if not exists users (
			id text primary key,
			tenant_id text not null,
			username text not null,
			display_name text not null,
			password text not null,
			status text not null,
			roles jsonb not null,
			allowed_tenants jsonb not null default '[]',
			allowed_probe_ids jsonb not null default '[]',
			allowed_asset_ids jsonb not null default '[]',
			allowed_org_ids jsonb not null default '[]',
			created_at timestamptz not null,
			unique(tenant_id, username)
		)`,
		`create table if not exists roles (
			id text primary key,
			tenant_id text not null,
			name text not null,
			description text not null,
			permissions jsonb not null,
			created_at timestamptz not null,
			unique(tenant_id, name)
		)`,
		`create table if not exists auth_tokens (
			token text primary key,
			user_id text not null
		)`,
		`create table if not exists audit_logs (
			id text primary key,
			tenant_id text not null,
			user_id text not null,
			action text not null,
			resource_type text not null,
			resource_id text not null,
			result text not null,
			created_at timestamptz not null
		)`,
		`create table if not exists activities (
			id text primary key,
			tenant_id text not null,
			resource_type text not null,
			resource_id text not null,
			action text not null,
			operator text not null,
			detail text not null,
			created_at timestamptz not null
		)`,
		`create table if not exists export_tasks (
			id text primary key,
			tenant_id text not null,
			user_id text not null,
			resource_type text not null,
			format text not null,
			status text not null,
			query_summary text not null,
			file_path text not null,
			error_message text not null,
			created_at timestamptz not null,
			completed_at timestamptz,
			expires_at timestamptz
		)`,
		`create table if not exists notification_channels (
			id text primary key,
			tenant_id text not null,
			name text not null,
			type text not null,
			target text not null,
			enabled boolean not null,
			events jsonb not null,
			created_at timestamptz not null
		)`,
		`create table if not exists notification_templates (
			id text primary key,
			tenant_id text not null,
			name text not null,
			event_type text not null,
			title_template text not null,
			body_template text not null,
			created_at timestamptz not null
		)`,
		`create table if not exists notification_records (
			id text primary key,
			tenant_id text not null,
			channel_id text not null,
			channel_name text not null,
			channel_type text not null,
			target text not null,
			event_type text not null,
			resource_type text not null,
			resource_id text not null,
			status text not null,
			summary text not null,
			error_message text not null,
			retry_count integer not null default 0,
			next_retry_at timestamptz,
			created_at timestamptz not null,
			delivered_at timestamptz
		)`,
		`alter table if exists probes add column if not exists applied_config_id text not null default ''`,
		`alter table if exists probes add column if not exists applied_rule_id text not null default ''`,
		`alter table if exists probes add column if not exists last_deploy_status text not null default ''`,
		`alter table if exists probes add column if not exists last_deploy_message text not null default ''`,
		`alter table if exists probes add column if not exists last_deploy_at timestamptz`,
		`alter table if exists probes add column if not exists cpu_usage double precision not null default 0`,
		`alter table if exists probes add column if not exists mem_usage double precision not null default 0`,
		`alter table if exists probes add column if not exists drop_rate double precision not null default 0`,
		`alter table if exists export_tasks add column if not exists expires_at timestamptz`,
		`alter table if exists tickets add column if not exists sla_deadline timestamptz`,
		`alter table if exists tickets add column if not exists sla_status text not null default 'active'`,
		`alter table if exists tickets add column if not exists reminded_at timestamptz`,
		`alter table if exists tickets add column if not exists escalated_at timestamptz`,
		`alter table if exists probe_upgrade_tasks add column if not exists previous_version text not null default ''`,
		`alter table if exists probe_upgrade_tasks add column if not exists retry_count integer not null default 0`,
		`alter table if exists probe_upgrade_tasks add column if not exists max_retries integer not null default 0`,
		`alter table if exists probe_upgrade_tasks add column if not exists package_id text not null default ''`,
		`alter table if exists upgrade_packages add column if not exists file_name text not null default ''`,
		`alter table if exists upgrade_packages add column if not exists file_size bigint not null default 0`,
		`alter table if exists users add column if not exists allowed_tenants jsonb not null default '[]'`,
		`alter table if exists users add column if not exists allowed_probe_ids jsonb not null default '[]'`,
		`alter table if exists users add column if not exists allowed_asset_ids jsonb not null default '[]'`,
		`alter table if exists users add column if not exists allowed_org_ids jsonb not null default '[]'`,
		`alter table if exists assets add column if not exists org_id text not null default ''`,
		`alter table if exists assets add column if not exists org_name text not null default ''`,
		`alter table if exists alerts add column if not exists source_asset_id text not null default ''`,
		`alter table if exists alerts add column if not exists source_asset_name text not null default ''`,
		`alter table if exists alerts add column if not exists target_asset_id text not null default ''`,
		`alter table if exists alerts add column if not exists target_asset_name text not null default ''`,
		`alter table if exists alerts add column if not exists threat_intel_tags jsonb not null default '[]'`,
		`alter table if exists alerts add column if not exists threat_intel_hits jsonb not null default '[]'`,
		`alter table if exists alerts add column if not exists attack_result text not null default 'unknown'`,
		`alter table if exists alerts add column if not exists probe_count integer not null default 1`,
		`alter table if exists alerts add column if not exists window_minutes integer not null default 0`,
		`alter table if exists notification_records add column if not exists retry_count integer not null default 0`,
		`alter table if exists notification_records add column if not exists next_retry_at timestamptz`,
		`create index if not exists idx_probes_tenant_status on probes (tenant_id, status)`,
		`create index if not exists idx_probe_bindings_tenant_probe on probe_bindings (tenant_id, probe_id)`,
		`create index if not exists idx_deployment_records_tenant_probe_created on deployment_records (tenant_id, probe_id, created_at desc)`,
		`create index if not exists idx_upgrade_packages_tenant_version on upgrade_packages (tenant_id, version, created_at desc)`,
		`create index if not exists idx_probe_upgrade_tasks_tenant_probe_created on probe_upgrade_tasks (tenant_id, probe_id, created_at desc)`,
		`create index if not exists idx_probe_version_history_tenant_probe_created on probe_version_history (tenant_id, probe_id, created_at desc)`,
		`create index if not exists idx_probe_metrics_tenant_probe_created on probe_metrics (tenant_id, probe_id, created_at desc)`,
		`create index if not exists idx_assets_tenant_ip on assets (tenant_id, ip)`,
		`create index if not exists idx_assets_tenant_org on assets (tenant_id, org_id, created_at desc)`,
		`create index if not exists idx_organizations_tenant_parent on organizations (tenant_id, parent_id, created_at asc)`,
		`create index if not exists idx_threat_intel_tenant_value on threat_intel (tenant_id, value)`,
		`create index if not exists idx_suppression_rules_tenant_created on suppression_rules (tenant_id, created_at desc)`,
		`create index if not exists idx_risk_policies_tenant_created on risk_policies (tenant_id, created_at desc)`,
		`create index if not exists idx_ticket_automation_policies_tenant_created on ticket_automation_policies (tenant_id, created_at desc)`,
		`create index if not exists idx_alerts_tenant_last_seen on alerts (tenant_id, last_seen_at desc)`,
		`create index if not exists idx_tickets_tenant_created on tickets (tenant_id, created_at desc)`,
		`create index if not exists idx_tickets_tenant_sla on tickets (tenant_id, status, sla_deadline)`,
		`create index if not exists idx_export_tasks_tenant_created on export_tasks (tenant_id, created_at desc)`,
		`create index if not exists idx_notification_channels_tenant_created on notification_channels (tenant_id, created_at desc)`,
		`create index if not exists idx_notification_templates_tenant_event on notification_templates (tenant_id, event_type, created_at desc)`,
		`create index if not exists idx_notification_records_tenant_created on notification_records (tenant_id, created_at desc)`,
		`create index if not exists idx_notification_records_retry on notification_records (status, next_retry_at)`,
		`update alerts set probe_count = greatest(1, coalesce(jsonb_array_length(probe_ids), 1))`,
		`update alerts set window_minutes = case when last_seen_at > first_seen_at then greatest(1, ceil(extract(epoch from (last_seen_at - first_seen_at)) / 60.0)::int) else 0 end`,
	}
	for _, stmt := range ddl {
		if _, err := s.pool.Exec(ctx, stmt); err != nil {
			return err
		}
	}
	return nil
}

func (s *PostgresStore) UpsertProbe(ctx context.Context, probe shared.Probe) (shared.Probe, error) {
	_, err := s.pool.Exec(ctx, `
		insert into probes (id, tenant_id, probe_code, name, status, version, rule_version, applied_config_id, applied_rule_id, last_deploy_status, last_deploy_message, last_deploy_at, cpu_usage, mem_usage, drop_rate, last_heartbeat_at, created_at)
		values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)
		on conflict (id) do update set
			status = excluded.status,
			version = excluded.version,
			rule_version = excluded.rule_version,
			applied_config_id = excluded.applied_config_id,
			applied_rule_id = excluded.applied_rule_id,
			last_deploy_status = excluded.last_deploy_status,
			last_deploy_message = excluded.last_deploy_message,
			last_deploy_at = excluded.last_deploy_at,
			cpu_usage = excluded.cpu_usage,
			mem_usage = excluded.mem_usage,
			drop_rate = excluded.drop_rate,
			last_heartbeat_at = excluded.last_heartbeat_at,
			name = excluded.name
	`, probe.ID, probe.TenantID, probe.ProbeCode, probe.Name, probe.Status, probe.Version, probe.RuleVersion, probe.AppliedConfigID, probe.AppliedRuleID, probe.LastDeployStatus, probe.LastDeployMessage, nullableTime(probe.LastDeployAt), probe.CPUUsage, probe.MemUsage, probe.DropRate, probe.LastHeartbeatAt, probe.CreatedAt)
	return probe, err
}

func (s *PostgresStore) GetProbe(ctx context.Context, id string) (shared.Probe, bool, error) {
	row := s.pool.QueryRow(ctx, `select id, tenant_id, probe_code, name, status, version, rule_version, applied_config_id, applied_rule_id, last_deploy_status, last_deploy_message, last_deploy_at, cpu_usage, mem_usage, drop_rate, last_heartbeat_at, created_at from probes where id=$1`, id)
	var probe shared.Probe
	var lastDeployAt *time.Time
	err := row.Scan(&probe.ID, &probe.TenantID, &probe.ProbeCode, &probe.Name, &probe.Status, &probe.Version, &probe.RuleVersion, &probe.AppliedConfigID, &probe.AppliedRuleID, &probe.LastDeployStatus, &probe.LastDeployMessage, &lastDeployAt, &probe.CPUUsage, &probe.MemUsage, &probe.DropRate, &probe.LastHeartbeatAt, &probe.CreatedAt)
	if err == pgx.ErrNoRows {
		return shared.Probe{}, false, nil
	}
	if lastDeployAt != nil {
		probe.LastDeployAt = *lastDeployAt
	}
	return probe, err == nil, err
}

func (s *PostgresStore) FindProbeByCode(ctx context.Context, tenantID, probeCode string) (shared.Probe, bool, error) {
	row := s.pool.QueryRow(ctx, `select id, tenant_id, probe_code, name, status, version, rule_version, applied_config_id, applied_rule_id, last_deploy_status, last_deploy_message, last_deploy_at, cpu_usage, mem_usage, drop_rate, last_heartbeat_at, created_at from probes where tenant_id=$1 and probe_code=$2 order by last_heartbeat_at desc, created_at desc limit 1`, tenantID, probeCode)
	var probe shared.Probe
	var lastDeployAt *time.Time
	err := row.Scan(&probe.ID, &probe.TenantID, &probe.ProbeCode, &probe.Name, &probe.Status, &probe.Version, &probe.RuleVersion, &probe.AppliedConfigID, &probe.AppliedRuleID, &probe.LastDeployStatus, &probe.LastDeployMessage, &lastDeployAt, &probe.CPUUsage, &probe.MemUsage, &probe.DropRate, &probe.LastHeartbeatAt, &probe.CreatedAt)
	if err == pgx.ErrNoRows {
		return shared.Probe{}, false, nil
	}
	if err != nil {
		return shared.Probe{}, false, err
	}
	if lastDeployAt != nil {
		probe.LastDeployAt = *lastDeployAt
	}
	return probe, true, nil
}

func (s *PostgresStore) ListProbes(ctx context.Context, tenantID string) ([]shared.Probe, error) {
	query := `select distinct on (tenant_id, probe_code) id, tenant_id, probe_code, name, status, version, rule_version, applied_config_id, applied_rule_id, last_deploy_status, last_deploy_message, last_deploy_at, cpu_usage, mem_usage, drop_rate, last_heartbeat_at, created_at from probes`
	args := []any{}
	if tenantID != "" {
		query += ` where tenant_id=$1`
		args = append(args, tenantID)
	}
	query += ` order by tenant_id, probe_code, last_heartbeat_at desc, created_at desc`
	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []shared.Probe
	for rows.Next() {
		var probe shared.Probe
		var lastDeployAt *time.Time
		if err := rows.Scan(&probe.ID, &probe.TenantID, &probe.ProbeCode, &probe.Name, &probe.Status, &probe.Version, &probe.RuleVersion, &probe.AppliedConfigID, &probe.AppliedRuleID, &probe.LastDeployStatus, &probe.LastDeployMessage, &lastDeployAt, &probe.CPUUsage, &probe.MemUsage, &probe.DropRate, &probe.LastHeartbeatAt, &probe.CreatedAt); err != nil {
			return nil, err
		}
		if lastDeployAt != nil {
			probe.LastDeployAt = *lastDeployAt
		}
		out = append(out, probe)
	}
	return out, rows.Err()
}

func (s *PostgresStore) CreateProbeConfig(ctx context.Context, config shared.ProbeConfig) (shared.ProbeConfig, error) {
	filters, err := json.Marshal(config.Filters)
	if err != nil {
		return shared.ProbeConfig{}, err
	}
	outputTypes, err := json.Marshal(config.OutputTypes)
	if err != nil {
		return shared.ProbeConfig{}, err
	}
	_, err = s.pool.Exec(ctx, `insert into probe_configs (id, tenant_id, name, description, filters, output_types, created_at) values ($1,$2,$3,$4,$5,$6,$7)`,
		config.ID, config.TenantID, config.Name, config.Description, filters, outputTypes, config.CreatedAt)
	return config, err
}

func (s *PostgresStore) GetProbeConfig(ctx context.Context, id string) (shared.ProbeConfig, bool, error) {
	row := s.pool.QueryRow(ctx, `select id, tenant_id, name, description, filters, output_types, created_at from probe_configs where id=$1`, id)
	var cfg shared.ProbeConfig
	var filtersRaw, outputsRaw []byte
	err := row.Scan(&cfg.ID, &cfg.TenantID, &cfg.Name, &cfg.Description, &filtersRaw, &outputsRaw, &cfg.CreatedAt)
	if err == pgx.ErrNoRows {
		return shared.ProbeConfig{}, false, nil
	}
	if err != nil {
		return shared.ProbeConfig{}, false, err
	}
	if err := json.Unmarshal(filtersRaw, &cfg.Filters); err != nil {
		return shared.ProbeConfig{}, false, err
	}
	if err := json.Unmarshal(outputsRaw, &cfg.OutputTypes); err != nil {
		return shared.ProbeConfig{}, false, err
	}
	return cfg, true, nil
}

func (s *PostgresStore) ListProbeConfigs(ctx context.Context, tenantID string) ([]shared.ProbeConfig, error) {
	rows, err := s.pool.Query(ctx, `select id, tenant_id, name, description, filters, output_types, created_at from probe_configs where ($1='' or tenant_id=$1) order by created_at desc`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]shared.ProbeConfig, 0)
	for rows.Next() {
		var cfg shared.ProbeConfig
		var filtersRaw, outputsRaw []byte
		if err := rows.Scan(&cfg.ID, &cfg.TenantID, &cfg.Name, &cfg.Description, &filtersRaw, &outputsRaw, &cfg.CreatedAt); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(filtersRaw, &cfg.Filters); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(outputsRaw, &cfg.OutputTypes); err != nil {
			return nil, err
		}
		out = append(out, cfg)
	}
	return out, rows.Err()
}

func (s *PostgresStore) CreateRuleBundle(ctx context.Context, bundle shared.RuleBundle) (shared.RuleBundle, error) {
	_, err := s.pool.Exec(ctx, `insert into rule_bundles (id, tenant_id, version, description, enabled, created_at) values ($1,$2,$3,$4,$5,$6)`,
		bundle.ID, bundle.TenantID, bundle.Version, bundle.Description, bundle.Enabled, bundle.CreatedAt)
	return bundle, err
}

func (s *PostgresStore) GetRuleBundle(ctx context.Context, id string) (shared.RuleBundle, bool, error) {
	row := s.pool.QueryRow(ctx, `select id, tenant_id, version, description, enabled, created_at from rule_bundles where id=$1`, id)
	var bundle shared.RuleBundle
	err := row.Scan(&bundle.ID, &bundle.TenantID, &bundle.Version, &bundle.Description, &bundle.Enabled, &bundle.CreatedAt)
	if err == pgx.ErrNoRows {
		return shared.RuleBundle{}, false, nil
	}
	return bundle, err == nil, err
}

func (s *PostgresStore) ListRuleBundles(ctx context.Context, tenantID string) ([]shared.RuleBundle, error) {
	rows, err := s.pool.Query(ctx, `select id, tenant_id, version, description, enabled, created_at from rule_bundles where ($1='' or tenant_id=$1) order by created_at desc`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]shared.RuleBundle, 0)
	for rows.Next() {
		var bundle shared.RuleBundle
		if err := rows.Scan(&bundle.ID, &bundle.TenantID, &bundle.Version, &bundle.Description, &bundle.Enabled, &bundle.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, bundle)
	}
	return out, rows.Err()
}

func (s *PostgresStore) UpsertProbeBinding(ctx context.Context, binding shared.ProbeBinding) (shared.ProbeBinding, error) {
	_, err := s.pool.Exec(ctx, `
		insert into probe_bindings (id, tenant_id, probe_id, probe_name, probe_config_id, rule_bundle_id, updated_at)
		values ($1,$2,$3,$4,$5,$6,$7)
		on conflict (probe_id) do update set
			probe_name=excluded.probe_name,
			probe_config_id=excluded.probe_config_id,
			rule_bundle_id=excluded.rule_bundle_id,
			updated_at=excluded.updated_at
	`, binding.ID, binding.TenantID, binding.ProbeID, binding.ProbeName, binding.ProbeConfigID, binding.RuleBundleID, binding.UpdatedAt)
	return binding, err
}

func (s *PostgresStore) GetProbeBindingByProbeID(ctx context.Context, probeID string) (shared.ProbeBinding, bool, error) {
	row := s.pool.QueryRow(ctx, `select id, tenant_id, probe_id, probe_name, probe_config_id, rule_bundle_id, updated_at from probe_bindings where probe_id=$1`, probeID)
	var item shared.ProbeBinding
	err := row.Scan(&item.ID, &item.TenantID, &item.ProbeID, &item.ProbeName, &item.ProbeConfigID, &item.RuleBundleID, &item.UpdatedAt)
	if err == pgx.ErrNoRows {
		return shared.ProbeBinding{}, false, nil
	}
	return item, err == nil, err
}

func (s *PostgresStore) ListProbeBindings(ctx context.Context, tenantID string) ([]shared.ProbeBinding, error) {
	rows, err := s.pool.Query(ctx, `select id, tenant_id, probe_id, probe_name, probe_config_id, rule_bundle_id, updated_at from probe_bindings where ($1='' or tenant_id=$1) order by updated_at desc`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []shared.ProbeBinding
	for rows.Next() {
		var item shared.ProbeBinding
		if err := rows.Scan(&item.ID, &item.TenantID, &item.ProbeID, &item.ProbeName, &item.ProbeConfigID, &item.RuleBundleID, &item.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *PostgresStore) CreateDeploymentRecord(ctx context.Context, record shared.DeploymentRecord) (shared.DeploymentRecord, error) {
	_, err := s.pool.Exec(ctx, `insert into deployment_records (id, tenant_id, probe_id, probe_name, probe_config_id, rule_bundle_id, status, message, created_at) values ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
		record.ID, record.TenantID, record.ProbeID, record.ProbeName, record.ProbeConfigID, record.RuleBundleID, record.Status, record.Message, record.CreatedAt)
	return record, err
}

func (s *PostgresStore) ListDeploymentRecords(ctx context.Context, tenantID string) ([]shared.DeploymentRecord, error) {
	rows, err := s.pool.Query(ctx, `select id, tenant_id, probe_id, probe_name, probe_config_id, rule_bundle_id, status, message, created_at from deployment_records where ($1='' or tenant_id=$1) order by created_at desc`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []shared.DeploymentRecord
	for rows.Next() {
		var item shared.DeploymentRecord
		if err := rows.Scan(&item.ID, &item.TenantID, &item.ProbeID, &item.ProbeName, &item.ProbeConfigID, &item.RuleBundleID, &item.Status, &item.Message, &item.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *PostgresStore) CreateProbeUpgradeTask(ctx context.Context, task shared.ProbeUpgradeTask) (shared.ProbeUpgradeTask, error) {
	_, err := s.pool.Exec(ctx, `insert into probe_upgrade_tasks (id, tenant_id, probe_id, probe_name, package_id, action, previous_version, target_version, status, retry_count, max_retries, message, created_at, completed_at) values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`,
		task.ID, task.TenantID, task.ProbeID, task.ProbeName, task.PackageID, task.Action, task.PreviousVersion, task.TargetVersion, task.Status, task.RetryCount, task.MaxRetries, task.Message, task.CreatedAt, nullableTime(task.CompletedAt))
	return task, err
}

func (s *PostgresStore) ListProbeUpgradeTasks(ctx context.Context, tenantID string) ([]shared.ProbeUpgradeTask, error) {
	rows, err := s.pool.Query(ctx, `select id, tenant_id, probe_id, probe_name, package_id, action, previous_version, target_version, status, retry_count, max_retries, message, created_at, completed_at from probe_upgrade_tasks where ($1='' or tenant_id=$1) order by created_at desc`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]shared.ProbeUpgradeTask, 0)
	for rows.Next() {
		var item shared.ProbeUpgradeTask
		var completedAt *time.Time
		if err := rows.Scan(&item.ID, &item.TenantID, &item.ProbeID, &item.ProbeName, &item.PackageID, &item.Action, &item.PreviousVersion, &item.TargetVersion, &item.Status, &item.RetryCount, &item.MaxRetries, &item.Message, &item.CreatedAt, &completedAt); err != nil {
			return nil, err
		}
		if completedAt != nil {
			item.CompletedAt = *completedAt
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *PostgresStore) GetPendingProbeUpgradeTask(ctx context.Context, probeID string) (shared.ProbeUpgradeTask, bool, error) {
	row := s.pool.QueryRow(ctx, `select id, tenant_id, probe_id, probe_name, package_id, action, previous_version, target_version, status, retry_count, max_retries, message, created_at, completed_at from probe_upgrade_tasks where probe_id=$1 and status='pending' order by created_at desc limit 1`, probeID)
	var item shared.ProbeUpgradeTask
	var completedAt *time.Time
	err := row.Scan(&item.ID, &item.TenantID, &item.ProbeID, &item.ProbeName, &item.PackageID, &item.Action, &item.PreviousVersion, &item.TargetVersion, &item.Status, &item.RetryCount, &item.MaxRetries, &item.Message, &item.CreatedAt, &completedAt)
	if err == pgx.ErrNoRows {
		return shared.ProbeUpgradeTask{}, false, nil
	}
	if completedAt != nil {
		item.CompletedAt = *completedAt
	}
	return item, err == nil, err
}

func (s *PostgresStore) UpdateProbeUpgradeTask(ctx context.Context, task shared.ProbeUpgradeTask) (shared.ProbeUpgradeTask, error) {
	_, err := s.pool.Exec(ctx, `update probe_upgrade_tasks set package_id=$2, status=$3, retry_count=$4, message=$5, completed_at=$6 where id=$1`,
		task.ID, task.PackageID, task.Status, task.RetryCount, task.Message, nullableTime(task.CompletedAt))
	return task, err
}

func (s *PostgresStore) CreateUpgradePackage(ctx context.Context, pkg shared.UpgradePackage) (shared.UpgradePackage, error) {
	_, err := s.pool.Exec(ctx, `insert into upgrade_packages (id, tenant_id, version, package_url, file_name, file_size, checksum, notes, enabled, created_at) values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
		pkg.ID, pkg.TenantID, pkg.Version, pkg.PackageURL, pkg.FileName, pkg.FileSize, pkg.Checksum, pkg.Notes, pkg.Enabled, pkg.CreatedAt)
	return pkg, err
}

func (s *PostgresStore) ListUpgradePackages(ctx context.Context, tenantID string) ([]shared.UpgradePackage, error) {
	rows, err := s.pool.Query(ctx, `select id, tenant_id, version, package_url, file_name, file_size, checksum, notes, enabled, created_at from upgrade_packages where ($1='' or tenant_id=$1) order by created_at desc`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]shared.UpgradePackage, 0)
	for rows.Next() {
		var item shared.UpgradePackage
		if err := rows.Scan(&item.ID, &item.TenantID, &item.Version, &item.PackageURL, &item.FileName, &item.FileSize, &item.Checksum, &item.Notes, &item.Enabled, &item.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *PostgresStore) FindUpgradePackageByID(ctx context.Context, tenantID, id string) (shared.UpgradePackage, bool, error) {
	row := s.pool.QueryRow(ctx, `select id, tenant_id, version, package_url, file_name, file_size, checksum, notes, enabled, created_at from upgrade_packages where tenant_id=$1 and id=$2`, tenantID, id)
	var item shared.UpgradePackage
	err := row.Scan(&item.ID, &item.TenantID, &item.Version, &item.PackageURL, &item.FileName, &item.FileSize, &item.Checksum, &item.Notes, &item.Enabled, &item.CreatedAt)
	if err == pgx.ErrNoRows {
		return shared.UpgradePackage{}, false, nil
	}
	return item, err == nil, err
}

func (s *PostgresStore) FindUpgradePackageByVersion(ctx context.Context, tenantID, version string) (shared.UpgradePackage, bool, error) {
	row := s.pool.QueryRow(ctx, `select id, tenant_id, version, package_url, file_name, file_size, checksum, notes, enabled, created_at from upgrade_packages where tenant_id=$1 and version=$2 order by created_at desc limit 1`, tenantID, version)
	var item shared.UpgradePackage
	err := row.Scan(&item.ID, &item.TenantID, &item.Version, &item.PackageURL, &item.FileName, &item.FileSize, &item.Checksum, &item.Notes, &item.Enabled, &item.CreatedAt)
	if err == pgx.ErrNoRows {
		return shared.UpgradePackage{}, false, nil
	}
	return item, err == nil, err
}

func (s *PostgresStore) AddProbeVersionHistory(ctx context.Context, item shared.ProbeVersionHistory) error {
	_, err := s.pool.Exec(ctx, `insert into probe_version_history (id, tenant_id, probe_id, probe_name, action, from_version, to_version, result, message, created_at) values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
		item.ID, item.TenantID, item.ProbeID, item.ProbeName, item.Action, item.FromVersion, item.ToVersion, item.Result, item.Message, item.CreatedAt)
	return err
}

func (s *PostgresStore) ListProbeVersionHistory(ctx context.Context, tenantID, probeID string) ([]shared.ProbeVersionHistory, error) {
	rows, err := s.pool.Query(ctx, `select id, tenant_id, probe_id, probe_name, action, from_version, to_version, result, message, created_at from probe_version_history where ($1='' or tenant_id=$1) and ($2='' or probe_id=$2) order by created_at desc`, tenantID, probeID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]shared.ProbeVersionHistory, 0)
	for rows.Next() {
		var item shared.ProbeVersionHistory
		if err := rows.Scan(&item.ID, &item.TenantID, &item.ProbeID, &item.ProbeName, &item.Action, &item.FromVersion, &item.ToVersion, &item.Result, &item.Message, &item.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *PostgresStore) AddProbeMetric(ctx context.Context, metric shared.ProbeMetric) error {
	_, err := s.pool.Exec(ctx, `insert into probe_metrics (id, tenant_id, probe_id, cpu_usage, mem_usage, drop_rate, created_at) values ($1,$2,$3,$4,$5,$6,$7)`,
		metric.ID, metric.TenantID, metric.ProbeID, metric.CPUUsage, metric.MemUsage, metric.DropRate, metric.CreatedAt)
	return err
}

func (s *PostgresStore) ListProbeMetrics(ctx context.Context, query shared.ProbeMetricQuery) ([]shared.ProbeMetric, error) {
	if query.Limit <= 0 {
		query.Limit = 20
	}
	rows, err := s.pool.Query(ctx, `select id, tenant_id, probe_id, cpu_usage, mem_usage, drop_rate, created_at from probe_metrics where ($1='' or tenant_id=$1) and ($2='' or probe_id=$2) and ($3::timestamptz is null or created_at >= $3) order by created_at desc limit $4`, query.TenantID, query.ProbeID, nullableTime(query.Since), query.Limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]shared.ProbeMetric, 0)
	for rows.Next() {
		var metric shared.ProbeMetric
		if err := rows.Scan(&metric.ID, &metric.TenantID, &metric.ProbeID, &metric.CPUUsage, &metric.MemUsage, &metric.DropRate, &metric.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, metric)
	}
	return out, rows.Err()
}

func (s *PostgresStore) AddRawEvent(ctx context.Context, event shared.RawEvent) error {
	sanitized := sanitizeRawEventForJSONB(event)
	payload, err := json.Marshal(sanitized.Payload)
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx, `insert into raw_events (id, tenant_id, probe_id, event_type, event_time, ingest_time, payload) values ($1,$2,$3,$4,$5,$6,$7)`,
		sanitized.ID, sanitized.TenantID, sanitized.ProbeID, sanitized.EventType, sanitized.EventTime, sanitized.IngestTime, payload)
	return err
}

func sanitizeRawEventForJSONB(event shared.RawEvent) shared.RawEvent {
	event.ID = sanitizeJSONString(event.ID)
	event.TenantID = sanitizeJSONString(event.TenantID)
	event.ProbeID = sanitizeJSONString(event.ProbeID)
	event.EventType = sanitizeJSONString(event.EventType)
	event.Payload = sanitizeSuricataEventForJSONB(event.Payload)
	return event
}

func sanitizeSuricataEventForJSONB(event shared.SuricataEvent) shared.SuricataEvent {
	event.Timestamp = sanitizeJSONString(event.Timestamp)
	event.EventType = sanitizeJSONString(event.EventType)
	event.SrcIP = sanitizeJSONString(event.SrcIP)
	event.DstIP = sanitizeJSONString(event.DstIP)
	event.Proto = sanitizeJSONString(event.Proto)
	event.AppProto = sanitizeJSONString(event.AppProto)
	event.FlowID = sanitizeJSONString(event.FlowID)
	if event.Alert != nil {
		event.Alert = &shared.SuricataAlert{
			SignatureID: event.Alert.SignatureID,
			Signature:   sanitizeJSONString(event.Alert.Signature),
			Category:    sanitizeJSONString(event.Alert.Category),
			Severity:    event.Alert.Severity,
		}
	}
	event.Payload = sanitizeJSONValueForJSONB(event.Payload)
	return event
}

func sanitizeJSONValueForJSONB(value any) map[string]any {
	out, _ := sanitizeJSONAnyForJSONB(value).(map[string]any)
	if out == nil {
		return map[string]any{}
	}
	return out
}

func sanitizeJSONAnyForJSONB(value any) any {
	switch typed := value.(type) {
	case nil:
		return nil
	case string:
		return sanitizeJSONString(typed)
	case []byte:
		return sanitizeJSONString(string(typed))
	case map[string]any:
		out := make(map[string]any, len(typed))
		for key, item := range typed {
			out[sanitizeJSONString(key)] = sanitizeJSONAnyForJSONB(item)
		}
		return out
	case []any:
		out := make([]any, 0, len(typed))
		for _, item := range typed {
			out = append(out, sanitizeJSONAnyForJSONB(item))
		}
		return out
	case map[string]string:
		out := make(map[string]any, len(typed))
		for key, item := range typed {
			out[sanitizeJSONString(key)] = sanitizeJSONString(item)
		}
		return out
	case []string:
		out := make([]any, 0, len(typed))
		for _, item := range typed {
			out = append(out, sanitizeJSONString(item))
		}
		return out
	default:
		return value
	}
}

func sanitizeJSONString(value string) string {
	if value == "" {
		return ""
	}
	if !utf8.ValidString(value) {
		value = strings.ToValidUTF8(value, "")
	}
	return strings.Map(func(r rune) rune {
		switch {
		case r == 0:
			return -1
		case r >= 0xD800 && r <= 0xDFFF:
			return -1
		default:
			return r
		}
	}, value)
}

func (s *PostgresStore) ListRawEvents(ctx context.Context, tenantID string, since, until time.Time, probeIDs []string) ([]shared.RawEvent, error) {
	query := `select id, tenant_id, probe_id, event_type, event_time, ingest_time, payload from raw_events where 1=1`
	args := []any{}
	idx := 1
	if tenantID != "" {
		query += fmt.Sprintf(" and tenant_id=$%d", idx)
		args = append(args, tenantID)
		idx++
	}
	if !since.IsZero() {
		query += fmt.Sprintf(" and event_time >= $%d", idx)
		args = append(args, since)
		idx++
	}
	if !until.IsZero() {
		query += fmt.Sprintf(" and event_time <= $%d", idx)
		args = append(args, until)
		idx++
	}
	if len(probeIDs) > 0 {
		query += fmt.Sprintf(" and probe_id = any($%d)", idx)
		args = append(args, probeIDs)
		idx++
	}
	query += ` order by event_time desc`
	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]shared.RawEvent, 0)
	for rows.Next() {
		var event shared.RawEvent
		var payloadRaw []byte
		if err := rows.Scan(&event.ID, &event.TenantID, &event.ProbeID, &event.EventType, &event.EventTime, &event.IngestTime, &payloadRaw); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(payloadRaw, &event.Payload); err != nil {
			return nil, err
		}
		out = append(out, event)
	}
	return out, rows.Err()
}

func (s *PostgresStore) UpsertFlow(ctx context.Context, flow shared.Flow) (shared.Flow, error) {
	_, err := s.pool.Exec(ctx, `
		insert into flows (id, tenant_id, probe_id, flow_id, src_ip, src_port, dst_ip, dst_port, proto, app_proto, seen_at)
		values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
		on conflict (flow_id) do update set
			seen_at=excluded.seen_at,
			src_ip=excluded.src_ip,
			src_port=excluded.src_port,
			dst_ip=excluded.dst_ip,
			dst_port=excluded.dst_port,
			proto=excluded.proto,
			app_proto=excluded.app_proto
	`, flow.ID, flow.TenantID, flow.ProbeID, flow.FlowID, flow.SrcIP, flow.SrcPort, flow.DstIP, flow.DstPort, flow.Proto, flow.AppProto, flow.SeenAt)
	return flow, err
}

func (s *PostgresStore) ListFlowsByIDs(ctx context.Context, tenantID string, flowIDs []string) ([]shared.Flow, error) {
	if len(flowIDs) == 0 {
		return []shared.Flow{}, nil
	}
	rows, err := s.pool.Query(ctx, `select id, tenant_id, probe_id, flow_id, src_ip, src_port, dst_ip, dst_port, proto, app_proto, seen_at from flows where tenant_id=$1 and flow_id = any($2) order by seen_at desc`, tenantID, flowIDs)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]shared.Flow, 0)
	for rows.Next() {
		var flow shared.Flow
		if err := rows.Scan(&flow.ID, &flow.TenantID, &flow.ProbeID, &flow.FlowID, &flow.SrcIP, &flow.SrcPort, &flow.DstIP, &flow.DstPort, &flow.Proto, &flow.AppProto, &flow.SeenAt); err != nil {
			return nil, err
		}
		out = append(out, flow)
	}
	return out, rows.Err()
}

func (s *PostgresStore) ListFlows(ctx context.Context, query shared.FlowQuery) ([]shared.Flow, error) {
	sql := `select id, tenant_id, probe_id, flow_id, src_ip, src_port, dst_ip, dst_port, proto, app_proto, seen_at from flows where 1=1`
	args := []any{}
	idx := 1
	if query.TenantID != "" {
		sql += fmt.Sprintf(" and tenant_id=$%d", idx)
		args = append(args, query.TenantID)
		idx++
	}
	if query.SrcIP != "" {
		sql += fmt.Sprintf(" and src_ip=$%d", idx)
		args = append(args, query.SrcIP)
		idx++
	}
	if query.DstIP != "" {
		sql += fmt.Sprintf(" and dst_ip=$%d", idx)
		args = append(args, query.DstIP)
		idx++
	}
	if query.AppProto != "" {
		sql += fmt.Sprintf(" and app_proto=$%d", idx)
		args = append(args, query.AppProto)
		idx++
	}
	if !query.Since.IsZero() {
		sql += fmt.Sprintf(" and seen_at >= $%d", idx)
		args = append(args, query.Since)
		idx++
	}
	sql += ` order by seen_at desc`
	rows, err := s.pool.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []shared.Flow
	for rows.Next() {
		var flow shared.Flow
		if err := rows.Scan(&flow.ID, &flow.TenantID, &flow.ProbeID, &flow.FlowID, &flow.SrcIP, &flow.SrcPort, &flow.DstIP, &flow.DstPort, &flow.Proto, &flow.AppProto, &flow.SeenAt); err != nil {
			return nil, err
		}
		out = append(out, flow)
	}
	return out, rows.Err()
}

func (s *PostgresStore) CreateAsset(ctx context.Context, asset shared.Asset) (shared.Asset, error) {
	tags, err := json.Marshal(asset.Tags)
	if err != nil {
		return shared.Asset{}, err
	}
	_, err = s.pool.Exec(ctx, `insert into assets (id, tenant_id, name, ip, org_id, org_name, asset_type, importance_level, owner, tags, created_at) values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
		asset.ID, asset.TenantID, asset.Name, asset.IP, asset.OrgID, asset.OrgName, asset.AssetType, asset.ImportanceLevel, asset.Owner, tags, asset.CreatedAt)
	return asset, err
}

func (s *PostgresStore) ListAssets(ctx context.Context, tenantID string) ([]shared.Asset, error) {
	rows, err := s.pool.Query(ctx, `select id, tenant_id, name, ip, org_id, org_name, asset_type, importance_level, owner, tags, created_at from assets where ($1='' or tenant_id=$1) order by created_at desc`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]shared.Asset, 0)
	for rows.Next() {
		asset, ok, err := scanAsset(rows)
		if err != nil {
			return nil, err
		}
		if ok {
			out = append(out, asset)
		}
	}
	return out, rows.Err()
}

func (s *PostgresStore) FindAssetByIP(ctx context.Context, tenantID, ip string) (shared.Asset, bool, error) {
	row := s.pool.QueryRow(ctx, `select id, tenant_id, name, ip, org_id, org_name, asset_type, importance_level, owner, tags, created_at from assets where tenant_id=$1 and ip=$2 limit 1`, tenantID, ip)
	return scanAsset(row)
}

func (s *PostgresStore) CreateOrganization(ctx context.Context, org shared.Organization) (shared.Organization, error) {
	pathRaw, err := json.Marshal(org.Path)
	if err != nil {
		return shared.Organization{}, err
	}
	_, err = s.pool.Exec(ctx, `insert into organizations (id, tenant_id, name, code, parent_id, level, path, created_at) values ($1,$2,$3,$4,$5,$6,$7,$8)`,
		org.ID, org.TenantID, org.Name, org.Code, org.ParentID, org.Level, pathRaw, org.CreatedAt)
	return org, err
}

func (s *PostgresStore) ListOrganizations(ctx context.Context, tenantID string) ([]shared.Organization, error) {
	rows, err := s.pool.Query(ctx, `select id, tenant_id, name, code, parent_id, level, path, created_at from organizations where ($1='' or tenant_id=$1) order by level asc, created_at asc`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]shared.Organization, 0)
	for rows.Next() {
		item, ok, err := scanOrganization(rows)
		if err != nil {
			return nil, err
		}
		if ok {
			out = append(out, item)
		}
	}
	return out, rows.Err()
}

func (s *PostgresStore) GetOrganization(ctx context.Context, id string) (shared.Organization, bool, error) {
	row := s.pool.QueryRow(ctx, `select id, tenant_id, name, code, parent_id, level, path, created_at from organizations where id=$1`, id)
	return scanOrganization(row)
}

func (s *PostgresStore) CreateThreatIntel(ctx context.Context, intel shared.ThreatIntel) (shared.ThreatIntel, error) {
	tags, err := json.Marshal(intel.Tags)
	if err != nil {
		return shared.ThreatIntel{}, err
	}
	_, err = s.pool.Exec(ctx, `insert into threat_intel (id, tenant_id, type, value, severity, source, tags, created_at) values ($1,$2,$3,$4,$5,$6,$7,$8)`,
		intel.ID, intel.TenantID, intel.Type, intel.Value, intel.Severity, intel.Source, tags, intel.CreatedAt)
	return intel, err
}

func (s *PostgresStore) ListThreatIntel(ctx context.Context, tenantID string) ([]shared.ThreatIntel, error) {
	rows, err := s.pool.Query(ctx, `select id, tenant_id, type, value, severity, source, tags, created_at from threat_intel where ($1='' or tenant_id=$1) order by created_at desc`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]shared.ThreatIntel, 0)
	for rows.Next() {
		intel, ok, err := scanThreatIntel(rows)
		if err != nil {
			return nil, err
		}
		if ok {
			out = append(out, intel)
		}
	}
	return out, rows.Err()
}

func (s *PostgresStore) FindThreatIntelByValue(ctx context.Context, tenantID, value string) ([]shared.ThreatIntel, error) {
	rows, err := s.pool.Query(ctx, `select id, tenant_id, type, value, severity, source, tags, created_at from threat_intel where tenant_id=$1 and value=$2 order by created_at desc`, tenantID, value)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]shared.ThreatIntel, 0)
	for rows.Next() {
		intel, ok, err := scanThreatIntel(rows)
		if err != nil {
			return nil, err
		}
		if ok {
			out = append(out, intel)
		}
	}
	return out, rows.Err()
}

func (s *PostgresStore) CreateSuppressionRule(ctx context.Context, rule shared.SuppressionRule) (shared.SuppressionRule, error) {
	_, err := s.pool.Exec(ctx, `insert into suppression_rules (id, tenant_id, name, src_ip, dst_ip, signature_id, signature, enabled, created_at) values ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
		rule.ID, rule.TenantID, rule.Name, rule.SrcIP, rule.DstIP, rule.SignatureID, rule.Signature, rule.Enabled, rule.CreatedAt)
	return rule, err
}

func (s *PostgresStore) ListSuppressionRules(ctx context.Context, tenantID string) ([]shared.SuppressionRule, error) {
	rows, err := s.pool.Query(ctx, `select id, tenant_id, name, src_ip, dst_ip, signature_id, signature, enabled, created_at from suppression_rules where ($1='' or tenant_id=$1) order by created_at desc`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]shared.SuppressionRule, 0)
	for rows.Next() {
		var rule shared.SuppressionRule
		if err := rows.Scan(&rule.ID, &rule.TenantID, &rule.Name, &rule.SrcIP, &rule.DstIP, &rule.SignatureID, &rule.Signature, &rule.Enabled, &rule.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, rule)
	}
	return out, rows.Err()
}

func (s *PostgresStore) CreateRiskPolicy(ctx context.Context, policy shared.RiskPolicy) (shared.RiskPolicy, error) {
	_, err := s.pool.Exec(ctx, `insert into risk_policies (id, tenant_id, name, severity1_score, severity2_score, severity3_score, default_score, intel_hit_bonus, critical_asset_bonus, enabled, created_at) values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
		policy.ID, policy.TenantID, policy.Name, policy.Severity1Score, policy.Severity2Score, policy.Severity3Score, policy.DefaultScore, policy.IntelHitBonus, policy.CriticalAssetBonus, policy.Enabled, policy.CreatedAt)
	return policy, err
}

func (s *PostgresStore) ListRiskPolicies(ctx context.Context, tenantID string) ([]shared.RiskPolicy, error) {
	rows, err := s.pool.Query(ctx, `select id, tenant_id, name, severity1_score, severity2_score, severity3_score, default_score, intel_hit_bonus, critical_asset_bonus, enabled, created_at from risk_policies where ($1='' or tenant_id=$1) order by created_at desc`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]shared.RiskPolicy, 0)
	for rows.Next() {
		var policy shared.RiskPolicy
		if err := rows.Scan(&policy.ID, &policy.TenantID, &policy.Name, &policy.Severity1Score, &policy.Severity2Score, &policy.Severity3Score, &policy.DefaultScore, &policy.IntelHitBonus, &policy.CriticalAssetBonus, &policy.Enabled, &policy.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, policy)
	}
	return out, rows.Err()
}

func (s *PostgresStore) CreateTicketAutomationPolicy(ctx context.Context, policy shared.TicketAutomationPolicy) (shared.TicketAutomationPolicy, error) {
	_, err := s.pool.Exec(ctx, `insert into ticket_automation_policies (id, tenant_id, name, reminder_before_mins, escalation_after_mins, escalation_assignee, escalation_status, enabled, created_at) values ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
		policy.ID, policy.TenantID, policy.Name, policy.ReminderBeforeMins, policy.EscalationAfterMins, policy.EscalationAssignee, policy.EscalationStatus, policy.Enabled, policy.CreatedAt)
	return policy, err
}

func (s *PostgresStore) ListTicketAutomationPolicies(ctx context.Context, tenantID string) ([]shared.TicketAutomationPolicy, error) {
	rows, err := s.pool.Query(ctx, `select id, tenant_id, name, reminder_before_mins, escalation_after_mins, escalation_assignee, escalation_status, enabled, created_at from ticket_automation_policies where ($1='' or tenant_id=$1) order by created_at desc`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]shared.TicketAutomationPolicy, 0)
	for rows.Next() {
		var policy shared.TicketAutomationPolicy
		if err := rows.Scan(&policy.ID, &policy.TenantID, &policy.Name, &policy.ReminderBeforeMins, &policy.EscalationAfterMins, &policy.EscalationAssignee, &policy.EscalationStatus, &policy.Enabled, &policy.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, policy)
	}
	return out, rows.Err()
}

func (s *PostgresStore) UpsertAlertByFingerprint(ctx context.Context, fp string, build func(existing *shared.Alert) shared.Alert) (shared.Alert, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return shared.Alert{}, err
	}
	defer tx.Rollback(ctx)

	row := tx.QueryRow(ctx, `select id, tenant_id, fingerprint, first_seen_at, last_seen_at, event_count, probe_ids, probe_count, src_ip, dst_ip, dst_port, proto, signature_id, signature, category, severity, risk_score, attack_result, window_minutes, status, assignee, source_asset_id, source_asset_name, target_asset_id, target_asset_name, threat_intel_tags, threat_intel_hits from alerts where fingerprint=$1`, fp)
	current, ok, err := scanAlert(row)
	if err != nil {
		return shared.Alert{}, err
	}
	var next shared.Alert
	if !ok {
		next = build(nil)
	} else {
		next = build(&current)
	}
	probeIDs, err := json.Marshal(next.ProbeIDs)
	if err != nil {
		return shared.Alert{}, err
	}
	tags, err := json.Marshal(next.ThreatIntelTags)
	if err != nil {
		return shared.Alert{}, err
	}
	hits, err := json.Marshal(next.ThreatIntelHits)
	if err != nil {
		return shared.Alert{}, err
	}
	_, err = tx.Exec(ctx, `
		insert into alerts (id, tenant_id, fingerprint, first_seen_at, last_seen_at, event_count, probe_ids, probe_count, src_ip, dst_ip, dst_port, proto, signature_id, signature, category, severity, risk_score, attack_result, window_minutes, status, assignee, source_asset_id, source_asset_name, target_asset_id, target_asset_name, threat_intel_tags, threat_intel_hits)
		values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26,$27)
		on conflict (id) do update set
			last_seen_at=excluded.last_seen_at,
			event_count=excluded.event_count,
			probe_ids=excluded.probe_ids,
			probe_count=excluded.probe_count,
			risk_score=excluded.risk_score,
			attack_result=excluded.attack_result,
			window_minutes=excluded.window_minutes,
			status=excluded.status,
			assignee=excluded.assignee,
			source_asset_id=excluded.source_asset_id,
			source_asset_name=excluded.source_asset_name,
			target_asset_id=excluded.target_asset_id,
			target_asset_name=excluded.target_asset_name,
			threat_intel_tags=excluded.threat_intel_tags,
			threat_intel_hits=excluded.threat_intel_hits
	`, next.ID, next.TenantID, next.Fingerprint, next.FirstSeenAt, next.LastSeenAt, next.EventCount, probeIDs, next.ProbeCount, next.SrcIP, next.DstIP, next.DstPort, next.Proto, next.SignatureID, next.Signature, next.Category, next.Severity, next.RiskScore, next.AttackResult, next.WindowMinutes, next.Status, next.Assignee, next.SourceAssetID, next.SourceAssetName, next.TargetAssetID, next.TargetAssetName, tags, hits)
	if err != nil {
		return shared.Alert{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return shared.Alert{}, err
	}
	return next, nil
}

func (s *PostgresStore) GetAlert(ctx context.Context, id string) (shared.Alert, bool, error) {
	row := s.pool.QueryRow(ctx, `select id, tenant_id, fingerprint, first_seen_at, last_seen_at, event_count, probe_ids, probe_count, src_ip, dst_ip, dst_port, proto, signature_id, signature, category, severity, risk_score, attack_result, window_minutes, status, assignee, source_asset_id, source_asset_name, target_asset_id, target_asset_name, threat_intel_tags, threat_intel_hits from alerts where id=$1`, id)
	return scanAlert(row)
}

func (s *PostgresStore) UpdateAlertStatus(ctx context.Context, id string, mutate func(alert shared.Alert) shared.Alert) (shared.Alert, bool, error) {
	current, ok, err := s.GetAlert(ctx, id)
	if err != nil || !ok {
		return current, ok, err
	}
	next := mutate(current)
	probeIDs, err := json.Marshal(next.ProbeIDs)
	if err != nil {
		return shared.Alert{}, false, err
	}
	_, err = s.pool.Exec(ctx, `update alerts set last_seen_at=$2, event_count=$3, probe_ids=$4, risk_score=$5, status=$6, assignee=$7 where id=$1`,
		next.ID, next.LastSeenAt, next.EventCount, probeIDs, next.RiskScore, next.Status, next.Assignee)
	if err != nil {
		return shared.Alert{}, false, err
	}
	return next, true, nil
}

func (s *PostgresStore) ListAlerts(ctx context.Context, query shared.AlertQuery) ([]shared.Alert, error) {
	sql := `select id, tenant_id, fingerprint, first_seen_at, last_seen_at, event_count, probe_ids, probe_count, src_ip, dst_ip, dst_port, proto, signature_id, signature, category, severity, risk_score, attack_result, window_minutes, status, assignee, source_asset_id, source_asset_name, target_asset_id, target_asset_name, threat_intel_tags, threat_intel_hits from alerts where 1=1`
	args := []any{}
	idx := 1
	if query.TenantID != "" {
		sql += fmt.Sprintf(" and tenant_id=$%d", idx)
		args = append(args, query.TenantID)
		idx++
	}
	if !query.Since.IsZero() {
		sql += fmt.Sprintf(" and last_seen_at >= $%d", idx)
		args = append(args, query.Since)
		idx++
	}
	predicates := make([]string, 0, 12)
	if query.Status != "" {
		predicates = append(predicates, fmt.Sprintf("status=$%d", idx))
		args = append(args, query.Status)
		idx++
	}
	if query.SrcIP != "" {
		predicates = append(predicates, fmt.Sprintf("src_ip=$%d", idx))
		args = append(args, query.SrcIP)
		idx++
	}
	if query.DstIP != "" {
		predicates = append(predicates, fmt.Sprintf("dst_ip=$%d", idx))
		args = append(args, query.DstIP)
		idx++
	}
	if query.Signature != "" {
		predicates = append(predicates, fmt.Sprintf("lower(signature) like lower($%d)", idx))
		args = append(args, "%"+query.Signature+"%")
		idx++
	}
	if query.Category != "" {
		predicates = append(predicates, fmt.Sprintf("lower(category) like lower($%d)", idx))
		args = append(args, "%"+query.Category+"%")
		idx++
	}
	if query.Probe != "" {
		predicates = append(predicates, fmt.Sprintf("array_to_string(probe_ids, ',') ilike $%d", idx))
		args = append(args, "%"+query.Probe+"%")
		idx++
	}
	if query.Severity != 0 {
		predicates = append(predicates, fmt.Sprintf("severity=$%d", idx))
		args = append(args, query.Severity)
		idx++
	}
	if query.Assignee != "" {
		predicates = append(predicates, fmt.Sprintf("assignee=$%d", idx))
		args = append(args, query.Assignee)
		idx++
	}
	if query.AttackResult != "" {
		predicates = append(predicates, fmt.Sprintf("attack_result=$%d", idx))
		args = append(args, query.AttackResult)
		idx++
	}
	if query.MinProbeCount > 0 {
		predicates = append(predicates, fmt.Sprintf("probe_count >= $%d", idx))
		args = append(args, query.MinProbeCount)
		idx++
	}
	if query.MaxProbeCount > 0 {
		predicates = append(predicates, fmt.Sprintf("probe_count <= $%d", idx))
		args = append(args, query.MaxProbeCount)
		idx++
	}
	if query.MinWindowMins > 0 {
		predicates = append(predicates, fmt.Sprintf("window_minutes >= $%d", idx))
		args = append(args, query.MinWindowMins)
		idx++
	}
	if query.MaxWindowMins > 0 {
		predicates = append(predicates, fmt.Sprintf("window_minutes <= $%d", idx))
		args = append(args, query.MaxWindowMins)
		idx++
	}
	if len(predicates) > 0 {
		joiner := " and "
		if strings.EqualFold(query.MatchMode, "any") {
			joiner = " or "
		}
		sql += " and (" + strings.Join(predicates, joiner) + ")"
	}
	sql += ` order by last_seen_at desc`
	rows, err := s.pool.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []shared.Alert
	for rows.Next() {
		alert, ok, err := scanAlert(rows)
		if err != nil {
			return nil, err
		}
		if ok {
			out = append(out, alert)
		}
	}
	return out, rows.Err()
}

func (s *PostgresStore) CreateTicket(ctx context.Context, ticket shared.Ticket) (shared.Ticket, error) {
	_, err := s.pool.Exec(ctx, `insert into tickets (id, tenant_id, alert_id, title, description, priority, status, assignee, sla_deadline, sla_status, reminded_at, escalated_at, created_at) values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`,
		ticket.ID, ticket.TenantID, ticket.AlertID, ticket.Title, ticket.Description, ticket.Priority, ticket.Status, ticket.Assignee, nullableTime(ticket.SLADeadline), ticket.SLAStatus, nullableTime(ticket.RemindedAt), nullableTime(ticket.EscalatedAt), ticket.CreatedAt)
	return ticket, err
}

func (s *PostgresStore) ListTickets(ctx context.Context, tenantID string) ([]shared.Ticket, error) {
	query := `select id, tenant_id, alert_id, title, description, priority, status, assignee, sla_deadline, sla_status, reminded_at, escalated_at, created_at from tickets`
	args := []any{}
	if tenantID != "" {
		query += ` where tenant_id=$1`
		args = append(args, tenantID)
	}
	query += ` order by created_at desc`
	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []shared.Ticket
	for rows.Next() {
		var t shared.Ticket
		var slaDeadline *time.Time
		var remindedAt *time.Time
		var escalatedAt *time.Time
		if err := rows.Scan(&t.ID, &t.TenantID, &t.AlertID, &t.Title, &t.Description, &t.Priority, &t.Status, &t.Assignee, &slaDeadline, &t.SLAStatus, &remindedAt, &escalatedAt, &t.CreatedAt); err != nil {
			return nil, err
		}
		if slaDeadline != nil {
			t.SLADeadline = *slaDeadline
		}
		if remindedAt != nil {
			t.RemindedAt = *remindedAt
		}
		if escalatedAt != nil {
			t.EscalatedAt = *escalatedAt
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

func (s *PostgresStore) ListTicketsByAlert(ctx context.Context, tenantID, alertID string) ([]shared.Ticket, error) {
	rows, err := s.pool.Query(ctx, `select id, tenant_id, alert_id, title, description, priority, status, assignee, sla_deadline, sla_status, reminded_at, escalated_at, created_at from tickets where tenant_id=$1 and alert_id=$2 order by created_at desc`, tenantID, alertID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []shared.Ticket
	for rows.Next() {
		var t shared.Ticket
		var slaDeadline *time.Time
		var remindedAt *time.Time
		var escalatedAt *time.Time
		if err := rows.Scan(&t.ID, &t.TenantID, &t.AlertID, &t.Title, &t.Description, &t.Priority, &t.Status, &t.Assignee, &slaDeadline, &t.SLAStatus, &remindedAt, &escalatedAt, &t.CreatedAt); err != nil {
			return nil, err
		}
		if slaDeadline != nil {
			t.SLADeadline = *slaDeadline
		}
		if remindedAt != nil {
			t.RemindedAt = *remindedAt
		}
		if escalatedAt != nil {
			t.EscalatedAt = *escalatedAt
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

func (s *PostgresStore) GetTicket(ctx context.Context, id string) (shared.Ticket, bool, error) {
	row := s.pool.QueryRow(ctx, `select id, tenant_id, alert_id, title, description, priority, status, assignee, sla_deadline, sla_status, reminded_at, escalated_at, created_at from tickets where id=$1`, id)
	var t shared.Ticket
	var slaDeadline *time.Time
	var remindedAt *time.Time
	var escalatedAt *time.Time
	err := row.Scan(&t.ID, &t.TenantID, &t.AlertID, &t.Title, &t.Description, &t.Priority, &t.Status, &t.Assignee, &slaDeadline, &t.SLAStatus, &remindedAt, &escalatedAt, &t.CreatedAt)
	if err == pgx.ErrNoRows {
		return shared.Ticket{}, false, nil
	}
	if slaDeadline != nil {
		t.SLADeadline = *slaDeadline
	}
	if remindedAt != nil {
		t.RemindedAt = *remindedAt
	}
	if escalatedAt != nil {
		t.EscalatedAt = *escalatedAt
	}
	return t, err == nil, err
}

func (s *PostgresStore) UpdateTicketStatus(ctx context.Context, id string, mutate func(ticket shared.Ticket) shared.Ticket) (shared.Ticket, bool, error) {
	current, ok, err := s.GetTicket(ctx, id)
	if err != nil || !ok {
		return current, ok, err
	}
	next := mutate(current)
	_, err = s.pool.Exec(ctx, `update tickets set status=$2, assignee=$3, sla_deadline=$4, sla_status=$5, reminded_at=$6, escalated_at=$7 where id=$1`, next.ID, next.Status, next.Assignee, nullableTime(next.SLADeadline), next.SLAStatus, nullableTime(next.RemindedAt), nullableTime(next.EscalatedAt))
	if err != nil {
		return shared.Ticket{}, false, err
	}
	return next, true, nil
}

func (s *PostgresStore) CreateUser(ctx context.Context, user shared.User) (shared.User, error) {
	roles, err := json.Marshal(user.Roles)
	if err != nil {
		return shared.User{}, err
	}
	allowedTenants, err := json.Marshal(user.AllowedTenants)
	if err != nil {
		return shared.User{}, err
	}
	allowedProbeIDs, err := json.Marshal(user.AllowedProbeIDs)
	if err != nil {
		return shared.User{}, err
	}
	allowedAssetIDs, err := json.Marshal(user.AllowedAssetIDs)
	if err != nil {
		return shared.User{}, err
	}
	allowedOrgIDs, err := json.Marshal(user.AllowedOrgIDs)
	if err != nil {
		return shared.User{}, err
	}
	_, err = s.pool.Exec(ctx, `insert into users (id, tenant_id, username, display_name, password, status, roles, allowed_tenants, allowed_probe_ids, allowed_asset_ids, allowed_org_ids, created_at) values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
		user.ID, user.TenantID, user.Username, user.DisplayName, user.Password, user.Status, roles, allowedTenants, allowedProbeIDs, allowedAssetIDs, allowedOrgIDs, user.CreatedAt)
	return user, err
}

func (s *PostgresStore) ListUsers(ctx context.Context, tenantID string) ([]shared.User, error) {
	query := `select id, tenant_id, username, display_name, password, status, roles, allowed_tenants, allowed_probe_ids, allowed_asset_ids, allowed_org_ids, created_at from users`
	args := []any{}
	if tenantID != "" {
		query += ` where tenant_id=$1`
		args = append(args, tenantID)
	}
	query += ` order by created_at desc`
	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []shared.User
	for rows.Next() {
		user, ok, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		if ok {
			out = append(out, user)
		}
	}
	return out, rows.Err()
}

func (s *PostgresStore) FindUser(ctx context.Context, tenantID, username string) (shared.User, bool, error) {
	row := s.pool.QueryRow(ctx, `select id, tenant_id, username, display_name, password, status, roles, allowed_tenants, allowed_probe_ids, allowed_asset_ids, allowed_org_ids, created_at from users where tenant_id=$1 and username=$2`, tenantID, username)
	return scanUser(row)
}

func (s *PostgresStore) GetUser(ctx context.Context, id string) (shared.User, bool, error) {
	row := s.pool.QueryRow(ctx, `select id, tenant_id, username, display_name, password, status, roles, allowed_tenants, allowed_probe_ids, allowed_asset_ids, allowed_org_ids, created_at from users where id=$1`, id)
	return scanUser(row)
}

func (s *PostgresStore) CreateRole(ctx context.Context, role shared.Role) (shared.Role, error) {
	perms, err := json.Marshal(role.Permissions)
	if err != nil {
		return shared.Role{}, err
	}
	_, err = s.pool.Exec(ctx, `insert into roles (id, tenant_id, name, description, permissions, created_at) values ($1,$2,$3,$4,$5,$6)`,
		role.ID, role.TenantID, role.Name, role.Description, perms, role.CreatedAt)
	return role, err
}

func (s *PostgresStore) ListRoles(ctx context.Context, tenantID string) ([]shared.Role, error) {
	query := `select id, tenant_id, name, description, permissions, created_at from roles`
	args := []any{}
	if tenantID != "" {
		query += ` where tenant_id=$1`
		args = append(args, tenantID)
	}
	query += ` order by created_at desc`
	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []shared.Role
	for rows.Next() {
		role, ok, err := scanRole(rows)
		if err != nil {
			return nil, err
		}
		if ok {
			out = append(out, role)
		}
	}
	return out, rows.Err()
}

func (s *PostgresStore) SaveToken(ctx context.Context, token, userID string) error {
	_, err := s.pool.Exec(ctx, `insert into auth_tokens (token, user_id) values ($1,$2) on conflict (token) do update set user_id=excluded.user_id`, token, userID)
	return err
}

func (s *PostgresStore) LookupToken(ctx context.Context, token string) (shared.User, bool, error) {
	row := s.pool.QueryRow(ctx, `select u.id, u.tenant_id, u.username, u.display_name, u.password, u.status, u.roles, u.allowed_tenants, u.allowed_probe_ids, u.allowed_asset_ids, u.allowed_org_ids, u.created_at
		from auth_tokens t join users u on u.id=t.user_id where t.token=$1`, token)
	return scanUser(row)
}

func (s *PostgresStore) AddAuditLog(ctx context.Context, log shared.AuditLog) error {
	_, err := s.pool.Exec(ctx, `insert into audit_logs (id, tenant_id, user_id, action, resource_type, resource_id, result, created_at) values ($1,$2,$3,$4,$5,$6,$7,$8)`,
		log.ID, log.TenantID, log.UserID, log.Action, log.ResourceType, log.ResourceID, log.Result, log.CreatedAt)
	return err
}

func (s *PostgresStore) ListAuditLogs(ctx context.Context, tenantID string) ([]shared.AuditLog, error) {
	query := `select id, tenant_id, user_id, action, resource_type, resource_id, result, created_at from audit_logs`
	args := []any{}
	if tenantID != "" {
		query += ` where tenant_id=$1`
		args = append(args, tenantID)
	}
	query += ` order by created_at desc`
	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []shared.AuditLog
	for rows.Next() {
		var log shared.AuditLog
		if err := rows.Scan(&log.ID, &log.TenantID, &log.UserID, &log.Action, &log.ResourceType, &log.ResourceID, &log.Result, &log.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, log)
	}
	return out, rows.Err()
}

func (s *PostgresStore) AddActivity(ctx context.Context, activity shared.Activity) error {
	_, err := s.pool.Exec(ctx, `insert into activities (id, tenant_id, resource_type, resource_id, action, operator, detail, created_at) values ($1,$2,$3,$4,$5,$6,$7,$8)`,
		activity.ID, activity.TenantID, activity.ResourceType, activity.ResourceID, activity.Action, activity.Operator, activity.Detail, activity.CreatedAt)
	return err
}

func (s *PostgresStore) ListActivities(ctx context.Context, tenantID, resourceType, resourceID string) ([]shared.Activity, error) {
	rows, err := s.pool.Query(ctx, `select id, tenant_id, resource_type, resource_id, action, operator, detail, created_at
		from activities
		where ($1='' or tenant_id=$1) and ($2='' or resource_type=$2) and ($3='' or resource_id=$3)
		order by created_at desc`, tenantID, resourceType, resourceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]shared.Activity, 0)
	for rows.Next() {
		var activity shared.Activity
		if err := rows.Scan(&activity.ID, &activity.TenantID, &activity.ResourceType, &activity.ResourceID, &activity.Action, &activity.Operator, &activity.Detail, &activity.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, activity)
	}
	return out, rows.Err()
}

func (s *PostgresStore) CreateExportTask(ctx context.Context, task shared.ExportTask) (shared.ExportTask, error) {
	_, err := s.pool.Exec(ctx, `insert into export_tasks (id, tenant_id, user_id, resource_type, format, status, query_summary, file_path, error_message, created_at, completed_at, expires_at)
		values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
		task.ID, task.TenantID, task.UserID, task.ResourceType, task.Format, task.Status, task.QuerySummary, task.FilePath, task.ErrorMessage, task.CreatedAt, nullableTime(task.CompletedAt), nullableTime(task.ExpiresAt))
	return task, err
}

func (s *PostgresStore) UpdateExportTask(ctx context.Context, task shared.ExportTask) (shared.ExportTask, error) {
	_, err := s.pool.Exec(ctx, `update export_tasks set status=$2, query_summary=$3, file_path=$4, error_message=$5, completed_at=$6, expires_at=$7 where id=$1`,
		task.ID, task.Status, task.QuerySummary, task.FilePath, task.ErrorMessage, nullableTime(task.CompletedAt), nullableTime(task.ExpiresAt))
	return task, err
}

func (s *PostgresStore) GetExportTask(ctx context.Context, id string) (shared.ExportTask, bool, error) {
	row := s.pool.QueryRow(ctx, `select id, tenant_id, user_id, resource_type, format, status, query_summary, file_path, error_message, created_at, completed_at, expires_at from export_tasks where id=$1`, id)
	return scanExportTask(row)
}

func (s *PostgresStore) ListExportTasks(ctx context.Context, tenantID string) ([]shared.ExportTask, error) {
	rows, err := s.pool.Query(ctx, `select id, tenant_id, user_id, resource_type, format, status, query_summary, file_path, error_message, created_at, completed_at, expires_at
		from export_tasks where ($1='' or tenant_id=$1) order by created_at desc`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]shared.ExportTask, 0)
	for rows.Next() {
		task, ok, err := scanExportTask(rows)
		if err != nil {
			return nil, err
		}
		if ok {
			out = append(out, task)
		}
	}
	return out, rows.Err()
}

type scanner interface {
	Scan(dest ...any) error
}

func (s *PostgresStore) CreateNotificationChannel(ctx context.Context, channel shared.NotificationChannel) (shared.NotificationChannel, error) {
	events, err := json.Marshal(channel.Events)
	if err != nil {
		return shared.NotificationChannel{}, err
	}
	_, err = s.pool.Exec(ctx, `insert into notification_channels (id, tenant_id, name, type, target, enabled, events, created_at) values ($1,$2,$3,$4,$5,$6,$7,$8)`,
		channel.ID, channel.TenantID, channel.Name, channel.Type, channel.Target, channel.Enabled, events, channel.CreatedAt)
	return channel, err
}

func (s *PostgresStore) ListNotificationChannels(ctx context.Context, tenantID string) ([]shared.NotificationChannel, error) {
	rows, err := s.pool.Query(ctx, `select id, tenant_id, name, type, target, enabled, events, created_at from notification_channels where ($1='' or tenant_id=$1) order by created_at desc`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]shared.NotificationChannel, 0)
	for rows.Next() {
		channel, ok, err := scanNotificationChannel(rows)
		if err != nil {
			return nil, err
		}
		if ok {
			out = append(out, channel)
		}
	}
	return out, rows.Err()
}

func (s *PostgresStore) CreateNotificationTemplate(ctx context.Context, template shared.NotificationTemplate) (shared.NotificationTemplate, error) {
	_, err := s.pool.Exec(ctx, `insert into notification_templates (id, tenant_id, name, event_type, title_template, body_template, created_at) values ($1,$2,$3,$4,$5,$6,$7)`,
		template.ID, template.TenantID, template.Name, template.EventType, template.TitleTemplate, template.BodyTemplate, template.CreatedAt)
	return template, err
}

func (s *PostgresStore) ListNotificationTemplates(ctx context.Context, tenantID string) ([]shared.NotificationTemplate, error) {
	rows, err := s.pool.Query(ctx, `select id, tenant_id, name, event_type, title_template, body_template, created_at from notification_templates where ($1='' or tenant_id=$1) order by created_at desc`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]shared.NotificationTemplate, 0)
	for rows.Next() {
		template, ok, err := scanNotificationTemplate(rows)
		if err != nil {
			return nil, err
		}
		if ok {
			out = append(out, template)
		}
	}
	return out, rows.Err()
}

func (s *PostgresStore) CreateNotificationRecord(ctx context.Context, record shared.NotificationRecord) (shared.NotificationRecord, error) {
	_, err := s.pool.Exec(ctx, `insert into notification_records (id, tenant_id, channel_id, channel_name, channel_type, target, event_type, resource_type, resource_id, status, summary, error_message, retry_count, next_retry_at, created_at, delivered_at)
		values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)`,
		record.ID, record.TenantID, record.ChannelID, record.ChannelName, record.ChannelType, record.Target, record.EventType, record.ResourceType, record.ResourceID, record.Status, record.Summary, record.ErrorMessage, record.RetryCount, nullableTime(record.NextRetryAt), record.CreatedAt, nullableTime(record.DeliveredAt))
	return record, err
}

func (s *PostgresStore) UpdateNotificationRecord(ctx context.Context, record shared.NotificationRecord) (shared.NotificationRecord, error) {
	_, err := s.pool.Exec(ctx, `update notification_records set status=$2, summary=$3, error_message=$4, retry_count=$5, next_retry_at=$6, delivered_at=$7 where id=$1`,
		record.ID, record.Status, record.Summary, record.ErrorMessage, record.RetryCount, nullableTime(record.NextRetryAt), nullableTime(record.DeliveredAt))
	return record, err
}

func (s *PostgresStore) ListNotificationRecords(ctx context.Context, tenantID string) ([]shared.NotificationRecord, error) {
	rows, err := s.pool.Query(ctx, `select id, tenant_id, channel_id, channel_name, channel_type, target, event_type, resource_type, resource_id, status, summary, error_message, retry_count, next_retry_at, created_at, delivered_at from notification_records where ($1='' or tenant_id=$1) order by created_at desc`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]shared.NotificationRecord, 0)
	for rows.Next() {
		record, ok, err := scanNotificationRecord(rows)
		if err != nil {
			return nil, err
		}
		if ok {
			out = append(out, record)
		}
	}
	return out, rows.Err()
}

func scanExportTask(s scanner) (shared.ExportTask, bool, error) {
	var task shared.ExportTask
	var completedAt *time.Time
	var expiresAt *time.Time
	err := s.Scan(&task.ID, &task.TenantID, &task.UserID, &task.ResourceType, &task.Format, &task.Status, &task.QuerySummary, &task.FilePath, &task.ErrorMessage, &task.CreatedAt, &completedAt, &expiresAt)
	if err == pgx.ErrNoRows {
		return shared.ExportTask{}, false, nil
	}
	if err != nil {
		return shared.ExportTask{}, false, err
	}
	if completedAt != nil {
		task.CompletedAt = *completedAt
	}
	if expiresAt != nil {
		task.ExpiresAt = *expiresAt
	}
	return task, true, nil
}

func scanAlert(s scanner) (shared.Alert, bool, error) {
	var alert shared.Alert
	var probeIDsRaw []byte
	var tagsRaw []byte
	var hitsRaw []byte
	err := s.Scan(&alert.ID, &alert.TenantID, &alert.Fingerprint, &alert.FirstSeenAt, &alert.LastSeenAt, &alert.EventCount, &probeIDsRaw, &alert.ProbeCount, &alert.SrcIP, &alert.DstIP, &alert.DstPort, &alert.Proto, &alert.SignatureID, &alert.Signature, &alert.Category, &alert.Severity, &alert.RiskScore, &alert.AttackResult, &alert.WindowMinutes, &alert.Status, &alert.Assignee, &alert.SourceAssetID, &alert.SourceAssetName, &alert.TargetAssetID, &alert.TargetAssetName, &tagsRaw, &hitsRaw)
	if err == pgx.ErrNoRows {
		return shared.Alert{}, false, nil
	}
	if err != nil {
		return shared.Alert{}, false, err
	}
	if err := json.Unmarshal(probeIDsRaw, &alert.ProbeIDs); err != nil {
		return shared.Alert{}, false, err
	}
	if len(tagsRaw) > 0 {
		_ = json.Unmarshal(tagsRaw, &alert.ThreatIntelTags)
	}
	if len(hitsRaw) > 0 {
		_ = json.Unmarshal(hitsRaw, &alert.ThreatIntelHits)
	}
	return alert, true, nil
}

func scanUser(s scanner) (shared.User, bool, error) {
	var user shared.User
	var rolesRaw []byte
	var allowedTenantsRaw []byte
	var allowedProbeIDsRaw []byte
	var allowedAssetIDsRaw []byte
	var allowedOrgIDsRaw []byte
	err := s.Scan(&user.ID, &user.TenantID, &user.Username, &user.DisplayName, &user.Password, &user.Status, &rolesRaw, &allowedTenantsRaw, &allowedProbeIDsRaw, &allowedAssetIDsRaw, &allowedOrgIDsRaw, &user.CreatedAt)
	if err == pgx.ErrNoRows {
		return shared.User{}, false, nil
	}
	if err != nil {
		return shared.User{}, false, err
	}
	if err := json.Unmarshal(rolesRaw, &user.Roles); err != nil {
		return shared.User{}, false, err
	}
	if err := json.Unmarshal(allowedTenantsRaw, &user.AllowedTenants); err != nil {
		return shared.User{}, false, err
	}
	if err := json.Unmarshal(allowedProbeIDsRaw, &user.AllowedProbeIDs); err != nil {
		return shared.User{}, false, err
	}
	if len(allowedAssetIDsRaw) > 0 {
		if err := json.Unmarshal(allowedAssetIDsRaw, &user.AllowedAssetIDs); err != nil {
			return shared.User{}, false, err
		}
	}
	if len(allowedOrgIDsRaw) > 0 {
		if err := json.Unmarshal(allowedOrgIDsRaw, &user.AllowedOrgIDs); err != nil {
			return shared.User{}, false, err
		}
	}
	return user, true, nil
}

func scanRole(s scanner) (shared.Role, bool, error) {
	var role shared.Role
	var permsRaw []byte
	err := s.Scan(&role.ID, &role.TenantID, &role.Name, &role.Description, &permsRaw, &role.CreatedAt)
	if err == pgx.ErrNoRows {
		return shared.Role{}, false, nil
	}
	if err != nil {
		return shared.Role{}, false, err
	}
	if err := json.Unmarshal(permsRaw, &role.Permissions); err != nil {
		return shared.Role{}, false, err
	}
	return role, true, nil
}

func scanNotificationChannel(s scanner) (shared.NotificationChannel, bool, error) {
	var channel shared.NotificationChannel
	var eventsRaw []byte
	err := s.Scan(&channel.ID, &channel.TenantID, &channel.Name, &channel.Type, &channel.Target, &channel.Enabled, &eventsRaw, &channel.CreatedAt)
	if err == pgx.ErrNoRows {
		return shared.NotificationChannel{}, false, nil
	}
	if err != nil {
		return shared.NotificationChannel{}, false, err
	}
	if err := json.Unmarshal(eventsRaw, &channel.Events); err != nil {
		return shared.NotificationChannel{}, false, err
	}
	return channel, true, nil
}

func scanNotificationRecord(s scanner) (shared.NotificationRecord, bool, error) {
	var record shared.NotificationRecord
	var nextRetryAt *time.Time
	var deliveredAt *time.Time
	err := s.Scan(&record.ID, &record.TenantID, &record.ChannelID, &record.ChannelName, &record.ChannelType, &record.Target, &record.EventType, &record.ResourceType, &record.ResourceID, &record.Status, &record.Summary, &record.ErrorMessage, &record.RetryCount, &nextRetryAt, &record.CreatedAt, &deliveredAt)
	if err == pgx.ErrNoRows {
		return shared.NotificationRecord{}, false, nil
	}
	if err != nil {
		return shared.NotificationRecord{}, false, err
	}
	if nextRetryAt != nil {
		record.NextRetryAt = *nextRetryAt
	}
	if deliveredAt != nil {
		record.DeliveredAt = *deliveredAt
	}
	return record, true, nil
}

func scanNotificationTemplate(s scanner) (shared.NotificationTemplate, bool, error) {
	var template shared.NotificationTemplate
	err := s.Scan(&template.ID, &template.TenantID, &template.Name, &template.EventType, &template.TitleTemplate, &template.BodyTemplate, &template.CreatedAt)
	if err == pgx.ErrNoRows {
		return shared.NotificationTemplate{}, false, nil
	}
	if err != nil {
		return shared.NotificationTemplate{}, false, err
	}
	return template, true, nil
}

func scanAsset(s scanner) (shared.Asset, bool, error) {
	var asset shared.Asset
	var tagsRaw []byte
	err := s.Scan(&asset.ID, &asset.TenantID, &asset.Name, &asset.IP, &asset.OrgID, &asset.OrgName, &asset.AssetType, &asset.ImportanceLevel, &asset.Owner, &tagsRaw, &asset.CreatedAt)
	if err == pgx.ErrNoRows {
		return shared.Asset{}, false, nil
	}
	if err != nil {
		return shared.Asset{}, false, err
	}
	if err := json.Unmarshal(tagsRaw, &asset.Tags); err != nil {
		return shared.Asset{}, false, err
	}
	return asset, true, nil
}

func scanOrganization(s scanner) (shared.Organization, bool, error) {
	var item shared.Organization
	var pathRaw []byte
	err := s.Scan(&item.ID, &item.TenantID, &item.Name, &item.Code, &item.ParentID, &item.Level, &pathRaw, &item.CreatedAt)
	if err == pgx.ErrNoRows {
		return shared.Organization{}, false, nil
	}
	if err != nil {
		return shared.Organization{}, false, err
	}
	if len(pathRaw) > 0 {
		if err := json.Unmarshal(pathRaw, &item.Path); err != nil {
			return shared.Organization{}, false, err
		}
	}
	return item, true, nil
}

func scanThreatIntel(s scanner) (shared.ThreatIntel, bool, error) {
	var intel shared.ThreatIntel
	var tagsRaw []byte
	err := s.Scan(&intel.ID, &intel.TenantID, &intel.Type, &intel.Value, &intel.Severity, &intel.Source, &tagsRaw, &intel.CreatedAt)
	if err == pgx.ErrNoRows {
		return shared.ThreatIntel{}, false, nil
	}
	if err != nil {
		return shared.ThreatIntel{}, false, err
	}
	if err := json.Unmarshal(tagsRaw, &intel.Tags); err != nil {
		return shared.ThreatIntel{}, false, err
	}
	return intel, true, nil
}

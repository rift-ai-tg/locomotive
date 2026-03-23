package config

import (
	"net/url"
	"time"

	"github.com/brody192/locomotive/internal/railway/subscribe/environment_logs"
	"github.com/brody192/locomotive/internal/railway/subscribe/http_logs"
	"github.com/flexstack/uuid"
)

type SeverityLevel string

const (
	SeverityDebug SeverityLevel = "debug"
	SeverityInfo  SeverityLevel = "info"
	SeverityWarn  SeverityLevel = "warn"
	SeverityError SeverityLevel = "error"
	SeverityFatal SeverityLevel = "fatal"
)

var severityRank = map[SeverityLevel]int{
	SeverityDebug: 0,
	SeverityInfo:  1,
	SeverityWarn:  2,
	SeverityError: 3,
	SeverityFatal: 4,
}

func (s SeverityLevel) IsValid() bool {
	_, ok := severityRank[s]
	return ok
}
func (s SeverityLevel) Rank() int {
	switch s {
	case SeverityDebug:
		return 0
	case SeverityInfo:
		return 1
	case SeverityWarn:
		return 2
	case SeverityError:
		return 3
	default:
		return 0 // fallback to debug
	}
}

type (
	AdditionalHeaders map[string]string

	WebhookMode string
)

type WebhookConfig struct {
	ExpectedHostContains []string
	ExpectedHeaders      []string

	Headers AdditionalHeaders

	EnvironmentLogReconstructorFunc func([]environment_logs.EnvironmentLogWithMetadata) ([]byte, error)
	HTTPLogReconstructorFunc        func([]http_logs.DeploymentHttpLogWithMetadata) ([]byte, error)
}

type config struct {
	RailwayApiKey uuid.UUID   `env:"RAILWAY_API_KEY,required,notEmpty"`
	EnvironmentId uuid.UUID   `env:"ENVIRONMENT_ID,required,notEmpty"`
	ServiceIds    []uuid.UUID `env:"SERVICE_IDS,required,notEmpty"`

	WebhookUrl        url.URL           `env:"WEBHOOK_URL,required,notEmpty"`
	AdditionalHeaders AdditionalHeaders `env:"ADDITIONAL_HEADERS"`
	WebhookMode       WebhookMode       `env:"WEBHOOK_MODE" envDefault:"json"`

	MinSeverity SeverityLevel `env:"MIN_SEVERITY" envDefault:"debug"`

	Whitelist []string `env:"WHITELIST" envSeparator:"," envDefault:""`
	Blacklist []string `env:"BLACKLIST" envSeparator:"," envDefault:""`
	
	ReportStatusEvery time.Duration `env:"REPORT_STATUS_EVERY" envDefault:"1m"`

	// SentryDedupWindow suppresses repeated identical logs (message+source) within this window.
	// Only applies when WebhookMode is sentry. Default 1m reduces tick-cycle spam.
	SentryDedupWindow time.Duration `env:"SENTRY_DEDUP_WINDOW" envDefault:"1m"`

	EnableHttpLogs   bool `env:"ENABLE_HTTP_LOGS" envDefault:"false"`
	EnableDeployLogs bool `env:"ENABLE_DEPLOY_LOGS" envDefault:"true"`
}

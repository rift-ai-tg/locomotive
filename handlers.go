package main

import (
	"context"
	"fmt"
	"log/slog"
	"regexp"
	"strings"
	"sync/atomic"
	"time"

	"github.com/brody192/locomotive/internal/config"
	"github.com/brody192/locomotive/internal/deduplicator"
	"github.com/brody192/locomotive/internal/logger"
	"github.com/brody192/locomotive/internal/railway/subscribe/environment_logs"
	"github.com/brody192/locomotive/internal/railway/subscribe/http_logs"
	"github.com/brody192/locomotive/internal/util"
	"github.com/brody192/locomotive/internal/webhook"
)

var (
	serializeRegex = regexp.MustCompile(`\x1b\[[0-9;]*m`)
)

func matchesAny(msg string, patterns []*regexp.Regexp) bool {
	for _, re := range patterns {
		if re.MatchString(msg) {
			return true
		}
	}
	return false
}

func severityFromToken(token string) (config.SeverityLevel, bool) {
	switch strings.ToUpper(strings.Trim(token, "[]:")) {
	case "DBG", "DEBUG":
		return config.SeverityDebug, true
	case "INF", "INFO":
		return config.SeverityInfo, true
	case "WRN", "WARN", "WARNING":
		return config.SeverityWarn, true
	case "ERR", "ERROR":
		return config.SeverityError, true
	case "FATAL", "FTL":
		return config.SeverityFatal, true
	default:
		return "", false
	}
}

func detectLeadingSeverity(msg string) (config.SeverityLevel, bool) {
	fields := strings.Fields(msg)
	if len(fields) == 0 {
		return "", false
	}

	if severity, ok := severityFromToken(fields[0]); ok {
		return severity, true
	}

	if len(fields) < 2 {
		return "", false
	}

	if _, err := time.Parse(time.RFC3339Nano, fields[0]); err != nil {
		return "", false
	}

	return severityFromToken(fields[1])
}

func classifySeverity(msg string, filter FilterSettings) (config.SeverityLevel, bool) {
	severity, ok := detectLeadingSeverity(msg)
	if !ok {
		return "", false
	}

	switch {
	case matchesAny(msg, filter.InfoWhitelist):
		severity = config.SeverityInfo
	case matchesAny(msg, filter.WarnWhitelist):
		severity = config.SeverityWarn
	case matchesAny(msg, filter.ErrorWhitelist):
		severity = config.SeverityError
	}

	switch severity {
	case config.SeverityDebug, config.SeverityInfo:
		if matchesAny(msg, filter.InfoBlacklist) {
			return "", false
		}
	case config.SeverityWarn:
		if matchesAny(msg, filter.WarnBlacklist) {
			return "", false
		}
	case config.SeverityError, config.SeverityFatal:
		if matchesAny(msg, filter.ErrorBlacklist) {
			return "", false
		}
	}

	return severity, true
}

type FilterSettings struct {
	MinSeverity    config.SeverityLevel
	InfoWhitelist  []*regexp.Regexp
	InfoBlacklist  []*regexp.Regexp
	WarnWhitelist  []*regexp.Regexp
	WarnBlacklist  []*regexp.Regexp
	ErrorWhitelist []*regexp.Regexp
	ErrorBlacklist []*regexp.Regexp
}

func NewFilterSettings(
	minSeverity config.SeverityLevel,
	infoWhitelistPatterns []string,
	infoBlacklistPatterns []string,
	warnWhitelistPatterns []string,
	warnBlacklistPatterns []string,
	errorWhitelistPatterns []string,
	errorBlacklistPatterns []string,
) (FilterSettings, error) {

	compile := func(patterns []string) ([]*regexp.Regexp, error) {
		result := make([]*regexp.Regexp, 0, len(patterns))

		for _, pattern := range patterns {
			pattern = strings.TrimSpace(pattern)
			if pattern == "" {
				continue
			}

			re, err := regexp.Compile(pattern)
			if err != nil {
				return nil, fmt.Errorf("invalid regex '%s': %w", pattern, err)
			}

			result = append(result, re)
		}

		return result, nil
	}

	infoWhitelist, err := compile(infoWhitelistPatterns)
	if err != nil {
		return FilterSettings{}, fmt.Errorf("info whitelist error: %w", err)
	}

	infoBlacklist, err := compile(infoBlacklistPatterns)
	if err != nil {
		return FilterSettings{}, fmt.Errorf("info blacklist error: %w", err)
	}

	warnWhitelist, err := compile(warnWhitelistPatterns)
	if err != nil {
		return FilterSettings{}, fmt.Errorf("warn whitelist error: %w", err)
	}

	warnBlacklist, err := compile(warnBlacklistPatterns)
	if err != nil {
		return FilterSettings{}, fmt.Errorf("warn blacklist error: %w", err)
	}

	errorWhitelist, err := compile(errorWhitelistPatterns)
	if err != nil {
		return FilterSettings{}, fmt.Errorf("error whitelist error: %w", err)
	}

	errorBlacklist, err := compile(errorBlacklistPatterns)
	if err != nil {
		return FilterSettings{}, fmt.Errorf("error blacklist error: %w", err)
	}

	return FilterSettings{
		MinSeverity:    minSeverity,
		InfoWhitelist:  infoWhitelist,
		InfoBlacklist:  infoBlacklist,
		WarnWhitelist:  warnWhitelist,
		WarnBlacklist:  warnBlacklist,
		ErrorWhitelist: errorWhitelist,
		ErrorBlacklist: errorBlacklist,
	}, nil
}

func handleDeployLogsAsync(
	ctx context.Context,
	deployLogsProcessed *atomic.Int64,
	serviceLogTrack chan []environment_logs.EnvironmentLogWithMetadata,
	filter FilterSettings,
	sentryDedup *deduplicator.Deduplicator,
) {
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case logs := <-serviceLogTrack:
				filteredLogs := make([]environment_logs.EnvironmentLogWithMetadata, 0, len(logs))

				for _, logEntry := range logs {
					logMsg := serializeRegex.ReplaceAllString(logEntry.Log.Message, "")
					if len(logMsg) <= util.MinEventTextLength {
						continue
					}

					detectedSeverity, ok := classifySeverity(logMsg, filter)
					if !ok {
						continue
					}

					logEntry.Log.Severity = string(detectedSeverity)

					if detectedSeverity.Rank() < filter.MinSeverity.Rank() {
						continue
					}

					filteredLogs = append(filteredLogs, logEntry)
				}

				if len(filteredLogs) == 0 {
					continue
				}

				for _, log := range filteredLogs {
					if sentryDedup != nil {
						msg := util.StripAnsi(log.Log.Message)
						sig := deduplicator.SignatureForDeployLog(
							msg,
							log.Metadata["service_id"],
							log.Metadata["deployment_id"],
							log.Log.Severity,
						)
						if !sentryDedup.RecordAndShouldSend(sig) {
							continue
						}
					}

					if serializedLog, err := webhook.SendDeployLogsWebhook([]environment_logs.EnvironmentLogWithMetadata{log}); err != nil {
						attrs := []any{logger.ErrAttr(err)}

						if serializedLog != nil {
							attrs = append(attrs, slog.String("serialized_log", string(serializedLog)))
						}

						logger.Stderr.Error("error sending deploy log webhook", attrs...)
						continue
					}

					deployLogsProcessed.Add(1)
				}
			}
		}
	}()
}

func handleHttpLogsAsync(ctx context.Context, httpLogsProcessed *atomic.Int64, httpLogTrack chan []http_logs.DeploymentHttpLogWithMetadata) {
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case logs := <-httpLogTrack:
				if serializedLogs, err := webhook.SendHttpLogsWebhook(logs); err != nil {
					attrs := []any{logger.ErrAttr(err)}

					if serializedLogs != nil {
						attrs = append(attrs, slog.String("serialized_logs", string(serializedLogs)))
					}

					logger.Stderr.Error("error sending http logs webhook(s)", attrs...)

					continue
				}

				httpLogsProcessed.Add(int64(len(logs)))
			}
		}
	}()
}

package main

import (
	"context"
	"fmt"
	"log/slog"
	"regexp"
	"strings"
	"sync/atomic"

	"github.com/brody192/locomotive/internal/config"
	"github.com/brody192/locomotive/internal/deduplicator"
	"github.com/brody192/locomotive/internal/logger"
	"github.com/brody192/locomotive/internal/railway/subscribe/environment_logs"
	"github.com/brody192/locomotive/internal/railway/subscribe/http_logs"
	"github.com/brody192/locomotive/internal/util"
	"github.com/brody192/locomotive/internal/webhook"
)

var (
	errorRegex = regexp.MustCompile(`(?i)\b(ERR|ERROR|FATAL|PANIC)\b`)
	warnRegex  = regexp.MustCompile(`(?i)\b(WRN|WARN|WARNING)\b`)
	infoRegex  = regexp.MustCompile(`(?i)\b(INF|INFO)\b`)
	debugRegex = regexp.MustCompile(`(?i)\b(DBG|DEBUG)\b`)

	serializeRegex = regexp.MustCompile(`\x1b\[[0-9;]*m`)
)

func detectSeverityFromMessage(msg string) config.SeverityLevel {
	switch {
		case errorRegex.MatchString(msg):
			return config.SeverityLevel("error")
		case warnRegex.MatchString(msg):
			return config.SeverityLevel("warn")
		case infoRegex.MatchString(msg):
			return config.SeverityLevel("info")
		case debugRegex.MatchString(msg):
			return config.SeverityLevel("debug")
		default:
			return config.SeverityLevel("error")
	}
}

type FilterSettings struct {
	MinSeverity config.SeverityLevel
	Whitelist   []*regexp.Regexp
	Blacklist   []*regexp.Regexp
}
func NewFilterSettings(
	minSeverity config.SeverityLevel,
	whitelistPatterns []string,
	blacklistPatterns []string,
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

	whitelist, err := compile(whitelistPatterns)
	if err != nil {
		return FilterSettings{}, fmt.Errorf("whitelist error: %w", err)
	}

	blacklist, err := compile(blacklistPatterns)
	if err != nil {
		return FilterSettings{}, fmt.Errorf("blacklist error: %w", err)
	}

	return FilterSettings{
		MinSeverity: minSeverity,
		Whitelist:   whitelist,
		Blacklist:   blacklist,
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
					var logMsg string = serializeRegex.ReplaceAllString(logEntry.Log.Message, "")
					detectedSeverity := detectSeverityFromMessage(logMsg)

					logEntry.Log.Severity = string(detectedSeverity)

					if detectedSeverity.Rank() < filter.MinSeverity.Rank() {
						continue
					}


					if len(filter.Whitelist) > 0 {
						matched := false
						for _, re := range filter.Whitelist {
							if re.MatchString(logMsg) {
								matched = true
								break
							}
						}
						if !matched {
							continue
						}
					}

					if len(filter.Blacklist) > 0 {
						blocked := false
						for _, re := range filter.Blacklist {
							if re.MatchString(logMsg) {
								blocked = true
								break
							}
						}
						if blocked {
							continue // blocked by blacklist
						}
					}

					filteredLogs = append(filteredLogs, logEntry)
				}

				if len(filteredLogs) == 0 {
					continue
				}

				// fmt.Printfs("Payload: %s\n", filteredLogs)

				for _, log := range filteredLogs {
					// Sentry dedup: suppress repeated identical errors within window
					if sentryDedup != nil {
						msg := util.StripAnsi(log.Log.Message)
						sig := deduplicator.SignatureForDeployLog(
							msg,
							log.Metadata["service_id"],
							log.Metadata["deployment_id"],
							log.Log.Severity,
						)
						if !sentryDedup.RecordAndShouldSend(sig) {
							continue // suppress duplicate
						}
					}

					// Send each log individually
					if serializedLog, err := webhook.SendDeployLogsWebhook([]environment_logs.EnvironmentLogWithMetadata{log}); err != nil {
						attrs := []any{logger.ErrAttr(err)}

						if serializedLog != nil {
							attrs = append(attrs, slog.String("serialized_log", string(serializedLog)))
						}

						logger.Stderr.Error("error sending deploy log webhook", attrs...)
						continue
					}

					// Increment processed count by 1 for each log
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

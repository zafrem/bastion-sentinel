package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/zafrem/bastion-sentinel/config"
	"github.com/zafrem/bastion-sentinel/types"
)

// Notifier fires out-of-band security alerts (Slack, PagerDuty) asynchronously
// when a request is blocked with a risk score at or above the configured threshold.
type Notifier struct {
	cfg    config.NotificationsConfig
	log    *slog.Logger
	client *http.Client
}

func NewNotifier(cfg config.NotificationsConfig, log *slog.Logger) *Notifier {
	return &Notifier{
		cfg:    cfg,
		log:    log,
		client: &http.Client{Timeout: 5 * time.Second},
	}
}

// Notify fires alerts in a background goroutine so it never blocks the request path.
func (n *Notifier) Notify(resp types.ValidateResponse) {
	if resp.Status != types.StatusBlocked {
		return
	}
	if resp.PromptCheck.RiskScore < n.cfg.CriticalThreshold {
		return
	}
	go n.fire(resp)
}

func (n *Notifier) fire(resp types.ValidateResponse) {
	if n.cfg.SlackWebhookURL != "" {
		n.sendSlack(resp)
	}
	if n.cfg.PagerDutyRoutingKey != "" {
		n.sendPagerDuty(resp)
	}
}

func (n *Notifier) sendSlack(resp types.ValidateResponse) {
	msg := map[string]any{
		"text": fmt.Sprintf(
			":rotating_light: *Bastion-Sentinel* — Critical injection blocked\n"+
				"*Request:* `%s` | *Score:* `%.2f` | *Patterns:* `%v`",
			resp.RequestID, resp.PromptCheck.RiskScore, resp.PromptCheck.MatchedPatterns,
		),
	}
	n.post(n.cfg.SlackWebhookURL, msg)
}

func (n *Notifier) sendPagerDuty(resp types.ValidateResponse) {
	payload := map[string]any{
		"routing_key":  n.cfg.PagerDutyRoutingKey,
		"event_action": "trigger",
		"payload": map[string]any{
			"summary":   fmt.Sprintf("Prompt injection blocked (score %.2f): %s", resp.PromptCheck.RiskScore, resp.RequestID),
			"severity":  "critical",
			"source":    "bastion-sentinel",
			"timestamp": resp.Timestamp.UTC().Format(time.RFC3339),
			"custom_details": map[string]any{
				"matched_patterns": resp.PromptCheck.MatchedPatterns,
				"risk_score":       resp.PromptCheck.RiskScore,
			},
		},
	}
	n.post("https://events.pagerduty.com/v2/enqueue", payload)
}

func (n *Notifier) post(url string, body any) {
	data, err := json.Marshal(body)
	if err != nil {
		return
	}
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(data))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := n.client.Do(req)
	if err != nil {
		n.log.Warn("notification failed", "url", url, "err", err)
		return
	}
	resp.Body.Close()
	if resp.StatusCode >= 300 {
		n.log.Warn("notification rejected", "url", url, "status", resp.StatusCode)
	}
}

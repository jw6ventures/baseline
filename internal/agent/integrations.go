package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	jw6_utils "github.com/jw6ventures/jw6-go-utils"

	agentv1 "github.com/jw6ventures/baseline/api/agent/v1"
	"github.com/jw6ventures/baseline/internal/model"
	"github.com/jw6ventures/baseline/internal/unifi"
)

// pollUniFi reads a UniFi console; tests replace it.
var pollUniFi = unifi.Poll

// PollFunc answers one kind of poll from the server with what it read,
// which is sent as JSON.
type PollFunc func(ctx context.Context, config []byte) (any, error)

// maxPollTime bounds an integration poll whatever the server asks.
const maxPollTime = 5 * time.Minute

// capabilities are the host's, plus the integrations this agent polls
// for the server.
func (a *Agent) capabilities() []string {
	caps := a.Env.Capabilities()
	if a.Integrations {
		caps = append(caps, model.CapUniFi)
	}
	return caps
}

// pollIntegration runs one IntegrationPoll. The secret lives only as long
// as the poll.
func (a *Agent) pollIntegration(ctx context.Context, p *agentv1.IntegrationPoll) *agentv1.IntegrationResult {
	res := &agentv1.IntegrationResult{RequestId: p.GetRequestId()}
	poll := a.Polls[p.GetKind()]
	if poll == nil && !a.Integrations {
		res.Error = "integrations are off in this host's agent.conf (integrations = off)"
		return res
	}
	timeout := min(time.Duration(p.GetTimeoutSeconds())*time.Second, maxPollTime)
	if timeout <= 0 {
		timeout = maxPollTime
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var out any
	var err error
	switch {
	case poll != nil:
		out, err = poll(ctx, p.GetConfigJson())
	case p.GetKind() == "unifi":
		var cfg unifi.Config
		if err = json.Unmarshal(p.GetConfigJson(), &cfg); err == nil {
			out, err = pollUniFi(ctx, cfg, p.GetSecret())
		}
	default:
		err = fmt.Errorf("this agent doesn't know the %q integration", p.GetKind())
	}
	if err == nil {
		res.PayloadJson, err = json.Marshal(out)
	}
	if err != nil {
		a.logf(jw6_utils.Warn, "%s poll for the server: %v", p.GetKind(), err)
		res.Error = err.Error()
	}
	return res
}

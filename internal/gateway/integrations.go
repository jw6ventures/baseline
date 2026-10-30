package gateway

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"slices"
	"time"

	jw6_utils "github.com/jw6ventures/jw6-go-utils"

	agentv1 "github.com/jw6ventures/baseline/api/agent/v1"
)

// ErrAgentOffline is a poll for a host whose agent isn't connected.
var ErrAgentOffline = errors.New("the host's agent isn't connected")

// ErrNoCapability is a poll for an agent that can't run it: too old, or
// turned off in its agent.conf.
var ErrNoCapability = errors.New("the host's agent can't poll this (update it, or check integrations in its agent.conf)")

type pendingPoll struct {
	agentID string
	done    chan *agentv1.IntegrationResult
}

// PollIntegration has a host's agent poll a system on its network (kind
// "unifi") and waits for what it found, as JSON. The secret goes over the
// agent's mTLS stream and is never stored by the agent.
func (g *Gateway) PollIntegration(ctx context.Context, hostID, kind, capability string, config []byte, secret string, timeout time.Duration) ([]byte, error) {
	g.mu.Lock()
	var sess *session
	for _, s := range g.sessions {
		if s.hostID == hostID {
			sess = s
		}
	}
	if sess == nil {
		g.mu.Unlock()
		return nil, ErrAgentOffline
	}
	if !slices.Contains(sess.caps, capability) {
		g.mu.Unlock()
		return nil, ErrNoCapability
	}
	id := rand.Text()
	p := &pendingPoll{agentID: sess.agentID, done: make(chan *agentv1.IntegrationResult, 1)}
	g.polls[id] = p
	g.mu.Unlock()
	defer func() {
		g.mu.Lock()
		delete(g.polls, id)
		g.mu.Unlock()
	}()

	msg := &agentv1.ServerMessage{Msg: &agentv1.ServerMessage_IntegrationPoll{IntegrationPoll: &agentv1.IntegrationPoll{
		RequestId: id, Kind: kind, ConfigJson: config, Secret: secret, TimeoutSeconds: uint32(timeout / time.Second)}}}
	if !g.Send(sess.agentID, msg) {
		return nil, ErrAgentOffline
	}
	// A little longer than the agent's own limit, so its error arrives.
	t := time.NewTimer(timeout + 10*time.Second)
	defer t.Stop()
	select {
	case res := <-p.done:
		if e := res.GetError(); e != "" {
			return nil, errors.New(e)
		}
		return res.GetPayloadJson(), nil
	case <-sess.ctx.Done():
		return nil, fmt.Errorf("%w (it disconnected during the poll)", ErrAgentOffline)
	case <-t.C:
		return nil, errors.New("the host's agent didn't answer in time")
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// pollResult hands a result to the poll waiting for it. Results for polls
// that weren't sent to this agent are dropped.
func (g *Gateway) pollResult(sess *session, res *agentv1.IntegrationResult) {
	g.mu.Lock()
	p := g.polls[res.GetRequestId()]
	g.mu.Unlock()
	if p == nil || p.agentID != sess.agentID {
		g.logf(jw6_utils.Debug, "agent %s sent a result for an unknown poll", sess.agentID)
		return
	}
	select {
	case p.done <- res:
	default:
	}
}

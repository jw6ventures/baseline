package agent

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"os"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	agentv1 "github.com/jw6ventures/baseline/api/agent/v1"
	"github.com/jw6ventures/baseline/internal/pki"
)

// Enroll trades a token for a client cert and writes the state directory.
// The server is authenticated by the CA fingerprint inside the token, so no
// CA file has to be copied to the host first.
func Enroll(ctx context.Context, server, token, stateDir, version string, env Host) (string, error) {
	_, fingerprint, err := pki.ParseToken(token)
	if err != nil {
		return "", err
	}
	host, _, err := net.SplitHostPort(server)
	if err != nil {
		return "", fmt.Errorf("server %q must be host:port: %w", server, err)
	}
	tlsCfg := &tls.Config{
		ServerName: host,
		MinVersion: tls.VersionTLS13,
		// Standard verification can't work yet (the CA isn't trusted
		// anywhere); VerifyConnection does it against the pinned CA.
		InsecureSkipVerify: true,
		VerifyConnection: func(cs tls.ConnectionState) error {
			raw := make([][]byte, len(cs.PeerCertificates))
			for i, c := range cs.PeerCertificates {
				raw[i] = c.Raw
			}
			return pki.VerifyPinned(raw, fingerprint, host)
		},
	}
	conn, err := grpc.NewClient(server, grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)))
	if err != nil {
		return "", err
	}
	defer conn.Close()

	key, csr, err := pki.GenerateKey()
	if err != nil {
		return "", err
	}
	id := env.Identity()
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	resp, err := agentv1.NewAgentGatewayClient(conn).Enroll(ctx, &agentv1.EnrollRequest{
		Token:        token,
		CsrDer:       csr,
		Identity:     &agentv1.HostIdentity{MachineId: id.MachineID, DmiUuid: id.DMIUUID, Hostname: id.Hostname},
		AgentVersion: version,
	})
	if err != nil {
		return "", err
	}

	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return "", err
	}
	st := &State{Dir: stateDir}
	if err := writeAtomic(st.path("ca.crt"), pki.EncodeCert(resp.GetCaCertDer()), 0o644); err != nil {
		return "", err
	}
	// resp.ReleasePublicKey, the server's own release key, is ignored:
	// updates must be signed by a key built into the agent (update.go).
	if err := st.SaveCert(key, resp.GetClientCertDer()); err != nil {
		return "", err
	}
	// agent-id last: its presence is what marks the agent as enrolled.
	if err := writeAtomic(st.path("agent-id"), []byte(resp.GetAgentId()+"\n"), 0o644); err != nil {
		return "", err
	}
	return resp.GetAgentId(), nil
}

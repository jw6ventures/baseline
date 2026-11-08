package model

// CapContainerLogs is the capability an agent reports when it reads
// container logs for the server (agent.conf container_logs, on by default).
const CapContainerLogs = "container-logs"

// ContainerLogLine is a line of a container's log as the server passes it
// on: its stream (stdout or stderr) and the text, which starts with the
// engine's RFC 3339 timestamp. Logs are never stored.
type ContainerLogLine struct {
	Stream string `json:"s"`
	Text   string `json:"t"`
}

// ContainerLogsRequest asks a host's agent for a container's log.
type ContainerLogsRequest struct {
	Engine    string // docker, podman or podman:<user>
	Container string // name or ID
	Tail      int    // lines from the end
	Follow    bool   // keep sending new lines
	// MaxSeconds bounds a followed log; the agent caps it at an hour.
	MaxSeconds int
}

// ContainerLogEvent is lines of a container's log as they reach the
// server. The last event of a log has Done set, and Error when the log
// couldn't be read.
type ContainerLogEvent struct {
	Lines []ContainerLogLine
	// Dropped counts lines left out before these: the container wrote
	// faster than they could be passed on.
	Dropped uint64
	Done    bool
	Error   string
}

const (
	DefaultContainerLogLines = 200
	MaxContainerLogLines     = 5000
)

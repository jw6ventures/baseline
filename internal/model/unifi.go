package model

// CapUniFi is the capability an agent reports when it can poll a UniFi
// controller for the server (agent.conf integrations, on by default).
const CapUniFi = "unifi"

// UniFi is what one poll of a UniFi console found: the Network
// application's sites with their adopted devices and wired clients, and
// UniFi Protect's devices. It is read by the server or, for a console only
// a host's network reaches, by that host's agent, and is the same either
// way. Like a section it holds state, not readings: no uptimes or traffic.
type UniFi struct {
	NetworkVersion string        `json:"network_version,omitempty"`
	Sites          []UniFiSite   `json:"sites"`
	ProtectVersion string        `json:"protect_version,omitempty"`
	Protect        []UniFiCamera `json:"protect,omitempty"`
	// ProtectError says why Protect couldn't be read (not installed, the
	// key has no access to it); the Network part still counts.
	ProtectError string `json:"protect_error,omitempty"`
}

type UniFiSite struct {
	ID   string `json:"id"`
	Ref  string `json:"ref,omitempty"` // internalReference: "default", the classic API's site name
	Name string `json:"name"`
	// Devices are the adopted UniFi devices: gateways, switches, APs.
	Devices []UniFiDevice `json:"devices"`
	// Clients are the wired clients only.
	Clients []UniFiClient `json:"clients"`
	// PortsError says why the switch ports of wired clients couldn't be
	// read (they come from the classic API); the clients still count.
	PortsError string `json:"ports_error,omitempty"`
}

type UniFiDevice struct {
	ID                string   `json:"id"`
	Name              string   `json:"name"`
	Model             string   `json:"model,omitempty"`
	MAC               string   `json:"mac"` // lower case, colon separated
	IP                string   `json:"ip,omitempty"`
	State             string   `json:"state"` // ONLINE, OFFLINE, UPDATING...
	Firmware          string   `json:"firmware,omitempty"`
	FirmwareUpdatable bool     `json:"firmware_updatable,omitempty"`
	Features          []string `json:"features,omitempty"`  // switching, accessPoint, gateway...
	UplinkID          string   `json:"uplink_id,omitempty"` // the device it hangs off
}

type UniFiClient struct {
	ID   string `json:"id"`
	Name string `json:"name,omitempty"`
	MAC  string `json:"mac"`
	IP   string `json:"ip,omitempty"`
	// UplinkID is the device the client is plugged into, Port its port
	// number there (0: unknown).
	UplinkID string `json:"uplink_id,omitempty"`
	Port     int    `json:"port,omitempty"`
}

// UniFiCamera is a UniFi Protect device: a camera or doorbell, or a light,
// sensor, chime or viewer (Kind).
type UniFiCamera struct {
	Kind  string `json:"kind"` // camera | light | sensor | chime | viewer
	ID    string `json:"id"`
	Name  string `json:"name"`
	Model string `json:"model,omitempty"`
	MAC   string `json:"mac,omitempty"`
	State string `json:"state"` // CONNECTED, DISCONNECTED...
}

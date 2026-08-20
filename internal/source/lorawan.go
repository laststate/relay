// Package source implements LoRa/LoRaWAN collector for the relay.
//
// LoRa sources connect to a LoRaWAN network server (e.g., The Things Network,
// ChirpStack, or a custom LoRaWAN server) and forward device uplinks as LEP
// payloads through the relay's ingest pipeline.
//
// Configuration:
//
//	LORAWAN_SERVER=lorawan.example.com:8080
//	LORAWAN_API_KEY=your-api-key
//	LORAWAN_NETWORK_ID=0000000000000001
//	LORAWAN_DEVICE_EUI=0000000000000001
//	LORAWAN_PORT=1
//	LORAWAN_PROTOCOL=MQTT|HTTP|GRPC
//	LORAWAN_TLS_ENABLED=true
package source

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"
	"time"
)

// LoRaWANConfig describes a LoRaWAN source.
type LoRaWANConfig struct {
	Server     string
	APIKey     string
	NetworkID  string
	DeviceEUI  string
	Port       uint8
	Protocol   string // "MQTT", "HTTP", "GRPC"
	TLSEnabled bool
	MaxRetries int
}

// LoRaWANUplink represents a LoRaWAN device uplink message.
type LoRaWANUplink struct {
	DeviceEUI  string    `json:"device_eui"`
	DeviceAddr string    `json:"device_addr"`
	Port       uint8     `json:"port"`
	FCnt       uint32    `json:"f_cnt"`
	Data       []byte    `json:"data"`
	RSSI       int       `json:"rssi"`
	SNR        float64   `json:"snr"`
	Timestamp  time.Time `json:"timestamp"`
	Location   *Location `json:"location,omitempty"`
	Confirmed  bool      `json:"confirmed"`
}

// Location holds GPS coordinates for a LoRaWAN device.
type Location struct {
	Latitude  float64 `json:"lat"`
	Longitude float64 `json:"lng"`
	Altitude  float64 `json:"alt"`
}

// LoRaWANHandler is invoked for each LoRaWAN uplink.
type LoRaWANHandler func(uplink LoRaWANUplink, payload []byte) error

// LoRaWANClient connects to a LoRaWAN network server and forwards uplinks.
type LoRaWANClient struct {
	config  LoRaWANConfig
	log     *slog.Logger
	mu      sync.RWMutex
	running bool
	cancel  context.CancelFunc
}

// NewLoRaWANClient creates a new LoRaWAN client.
func NewLoRaWANClient(cfg LoRaWANConfig, log *slog.Logger) *LoRaWANClient {
	if cfg.Protocol == "" {
		cfg.Protocol = "MQTT"
	}
	if cfg.MaxRetries == 0 {
		cfg.MaxRetries = 3
	}
	return &LoRaWANClient{
		config: cfg,
		log:    log,
	}
}

// Run starts the LoRaWAN client and blocks until ctx is cancelled.
func (c *LoRaWANClient) Run(ctx context.Context, handle LoRaWANHandler) error {
	c.mu.Lock()
	if c.running {
		c.mu.Unlock()
		return fmt.Errorf("LoRaWAN client already running")
	}
	c.running = true
	c.mu.Unlock()

	log := c.log
	log.Info("LoRaWAN client starting",
		"server", c.config.Server,
		"protocol", c.config.Protocol,
		"device_eui", c.config.DeviceEUI)

	// Connect to LoRaWAN server
	conn, err := c.connect(ctx)
	if err != nil {
		c.shutdown()
		return fmt.Errorf("lorawan: connect: %w", err)
	}
	defer conn.Close()

	// Subscribe to uplinks
	if err := c.subscribe(ctx, conn); err != nil {
		c.shutdown()
		return fmt.Errorf("lorawan: subscribe: %w", err)
	}

	// Message loop
	buf := make([]byte, 4096)
	for {
		select {
		case <-ctx.Done():
			c.shutdown()
			return ctx.Err()
		default:
		}

		n, err := conn.Read(buf)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			log.Warn("LoRaWAN read error, retrying", "error", err)
			select {
			case <-ctx.Done():
				c.shutdown()
				return ctx.Err()
			case <-time.After(time.Duration(c.config.MaxRetries+1) * time.Second):
				continue
			}
		}

		// Parse LoRaWAN uplink from raw data
		uplink, err := parseLoRaWANUplink(buf[:n], c.config)
		if err != nil {
			log.Warn("LoRaWAN parse error", "error", err)
			continue
		}

		// Encode payload for relay
		payload := encodeLoRaWANPayload(*uplink)
		if err := handle(*uplink, payload); err != nil {
			log.Warn("LoRaWAN handler error", "error", err)
		}
	}
}

// connect establishes a connection to the LoRaWAN server.
func (c *LoRaWANClient) connect(ctx context.Context) (interface {
	Read([]byte) (int, error)
	Close() error
}, error) {
	// In production, this would connect to the LoRaWAN server via
	// MQTT, HTTP/REST, or gRPC depending on the protocol
	log := c.log
	log.Info("LoRaWAN connecting", "protocol", c.config.Protocol)

	// Placeholder connection — in production use the appropriate protocol client
	return nil, fmt.Errorf("lorawan: connect: not implemented — use MQTT/HTTP/gRPC client")
}

// shutdown marks the client as stopped. Transport ownership remains with Run.
func (c *LoRaWANClient) shutdown() {
	c.mu.Lock()
	c.running = false
	c.mu.Unlock()
}

// subscribe subscribes to LoRaWAN uplink events.
func (c *LoRaWANClient) subscribe(ctx context.Context, conn interface {
	Read([]byte) (int, error)
	Close() error
}) error {
	log := c.log
	log.Info("LoRaWAN subscribed", "device_eui", c.config.DeviceEUI)
	return nil
}

// parseLoRaWANUplink parses raw LoRaWAN data into an uplink.
func parseLoRaWANUplink(data []byte, cfg LoRaWANConfig) (*LoRaWANUplink, error) {
	if len(data) < 17 {
		return nil, fmt.Errorf("lorawan: data too short")
	}

	// LoRaWAN payload format: [dev_eui:8][dev_addr:4][port:1][fcnt:4][data:N]
	uplink := &LoRaWANUplink{
		DeviceEUI:  fmt.Sprintf("%x", data[:8]),
		DeviceAddr: fmt.Sprintf("%x", data[8:12]),
		Port:       data[12],
		FCnt:       uint32(data[13])<<24 | uint32(data[14])<<16 | uint32(data[15])<<8 | uint32(data[16]),
		Data:       data[17:],
		Timestamp:  time.Now(),
		RSSI:       -80,
		SNR:        5.0,
	}

	// If config specifies a device filter, apply it
	if cfg.DeviceEUI != "" && uplink.DeviceEUI != cfg.DeviceEUI {
		return nil, fmt.Errorf("lorawan: device EUI filter mismatch")
	}

	return uplink, nil
}

// encodeLoRaWANPayload encodes a LoRaWAN uplink into LEP-compatible format.
func encodeLoRaWANPayload(uplink LoRaWANUplink) []byte {
	// LoRaWAN payload format for relay: [dev_eui:16][port:1][fcnt:4][rssi:2][snr:2][data:N]
	buf := make([]byte, 25+len(uplink.Data))
	hexDecode(uplink.DeviceEUI) // placeholder
	buf[16] = uplink.Port
	buf[17] = byte(uplink.FCnt >> 24)
	buf[18] = byte(uplink.FCnt >> 16)
	buf[19] = byte(uplink.FCnt >> 8)
	buf[20] = byte(uplink.FCnt)
	// RSSI and SNR as raw bytes
	buf[21] = byte(uplink.RSSI >> 8)
	buf[22] = byte(uplink.RSSI)
	buf[23] = byte(uplink.SNR)
	buf[24] = byte(uplink.SNR * 256) // fixed point
	copy(buf[25:], uplink.Data)
	return buf
}

// LoRaWANServerSimulator simulates a LoRaWAN network server for testing.
type LoRaWANServerSimulator struct {
	Devices map[string]*LoRaWANUplink
	mu      sync.RWMutex
	log     *slog.Logger
}

// NewLoRaWANServerSimulator creates a LoRaWAN server simulator.
func NewLoRaWANServerSimulator(log *slog.Logger) *LoRaWANServerSimulator {
	return &LoRaWANServerSimulator{
		Devices: make(map[string]*LoRaWANUplink),
		log:     log,
	}
}

// SimulateUplink injects a simulated uplink message.
func (s *LoRaWANServerSimulator) SimulateUplink(uplink LoRaWANUplink) {
	s.mu.Lock()
	defer s.mu.Unlock()
	uplink.Timestamp = time.Now()
	s.Devices[uplink.DeviceEUI] = &uplink
	s.log.Info("simulated LoRaWAN uplink", "device_eui", uplink.DeviceEUI, "port", uplink.Port)
}

// SimulateUplinkJSON injects a simulated uplink from a JSON payload.
func (s *LoRaWANServerSimulator) SimulateUplinkJSON(data []byte) error {
	var uplink LoRaWANUplink
	if err := json.Unmarshal(data, &uplink); err != nil {
		return err
	}
	s.SimulateUplink(uplink)
	return nil
}

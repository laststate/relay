// Package source implements BLE GATT collector for the relay.
//
// BLE sources discover, connect to, and read characteristics from BLE
// peripherals (typically Latch-enabled MCUs) and forward collected data
// as LEP payloads through the relay's ingest pipeline.
//
// Configuration:
//
//	BLE_ADAPTER=path/to/hci0
//	BLE_SCAN_DURATION=30s
//	BLE_SERVICE_UUID=0000fff0-0000-1000-8000-00805f9b34fb
//	BLE_CHAR_UUID=0000fff1-0000-1000-8000-00805f9b34fb
//	BLE_NOTIFY_ENABLED=true
//	BLE_RSSI_THRESHOLD=-80
//	BLE_MAX_DEVICES=50
package source

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"
)

// BLEConfig describes a BLE GATT source.
type BLEConfig struct {
	Adapter         string
	ScanDuration    time.Duration
	ServiceUUID     string
	CharUUID        string
	NotifyEnabled   bool
	RSSIThreshold   int
	MaxDevices      int
	FilterByAddress []string
}

// BLEDevice represents a discovered BLE peripheral.
type BLEDevice struct {
	Address     string
	Name        string
	RSSI        int
	ServiceUUID string
	CharUUID    string
	Connected   bool
	mu          sync.RWMutex
}

// BLECharacteristic represents a GATT characteristic.
type BLECharacteristic struct {
	UUID       string
	Value      []byte
	Properties []string
	Notify     bool
}

// BLEHandler is invoked for each BLE notification or read result.
type BLEHandler func(device *BLEDevice, char *BLECharacteristic, payload []byte) error

// BLEScanner discovers BLE devices and manages connections.
type BLEScanner struct {
	config  BLEConfig
	devices []*BLEDevice
	mu      sync.RWMutex
	log     *slog.Logger
	running bool
	cancel  context.CancelFunc
}

// NewBLEScanner creates a new BLE scanner.
func NewBLEScanner(cfg BLEConfig, log *slog.Logger) *BLEScanner {
	if cfg.ScanDuration == 0 {
		cfg.ScanDuration = 30 * time.Second
	}
	if cfg.RSSIThreshold == 0 {
		cfg.RSSIThreshold = -80
	}
	if cfg.MaxDevices == 0 {
		cfg.MaxDevices = 50
	}
	return &BLEScanner{
		config:  cfg,
		devices: make([]*BLEDevice, 0, cfg.MaxDevices),
		log:     log,
	}
}

// Run starts BLE scanning and notification collection.
func (s *BLEScanner) Run(ctx context.Context, handle BLEHandler) error {
	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return fmt.Errorf("BLE scanner already running")
	}
	s.running = true
	s.mu.Unlock()

	log := s.log
	log.Info("BLE scanner starting",
		"adapter", s.config.Adapter,
		"scan_duration", s.config.ScanDuration,
		"service_uuid", s.config.ServiceUUID,
		"max_devices", s.config.MaxDevices)

	// Scan loop
	for {
		select {
		case <-ctx.Done():
			s.shutdown()
			return ctx.Err()
		default:
		}

		// Perform BLE scan
		devices, err := s.scan(ctx)
		if err != nil {
			log.Warn("BLE scan error, retrying", "error", err)
			select {
			case <-ctx.Done():
				s.shutdown()
				return ctx.Err()
			case <-time.After(5 * time.Second):
				continue
			}
		}

		// Process discovered devices
		s.mu.Lock()
		s.devices = devices
		s.mu.Unlock()

		for _, dev := range devices {
			// Connect and read characteristics
			go func(d *BLEDevice) {
				if err := s.readDevice(ctx, d, handle); err != nil {
					log.Warn("BLE read error", "address", d.Address, "error", err)
				}
			}(dev)
		}

		// Wait for scan duration
		select {
		case <-ctx.Done():
			s.shutdown()
			return ctx.Err()
		case <-time.After(s.config.ScanDuration):
		}
	}
}

// scan performs a BLE device scan and returns discovered devices.
func (s *BLEScanner) scan(ctx context.Context) ([]*BLEDevice, error) {
	return nil, fmt.Errorf("ble: native scanning is not available in this build; use the BLEDeviceSimulator for tests")
}

// readDevice connects to a BLE device and reads its characteristics.
func (s *BLEScanner) readDevice(ctx context.Context, dev *BLEDevice, handle BLEHandler) error {
	s.log.Info("BLE connecting to device", "address", dev.Address, "name", dev.Name)

	return fmt.Errorf("ble: GATT connection is not available in this build")
}

// encodeBLEPayload encodes BLE data into LEP-compatible format.
func encodeBLEPayload(data []byte, address string) []byte {
	// BLE payload format: [address:6][data_length:2][data:N]
	buf := make([]byte, 8+len(data))
	copy(buf[:6], hexDecode(address))
	buf[6] = byte(len(data) >> 8)
	buf[7] = byte(len(data))
	copy(buf[8:], data)
	return buf
}

// hexDecode decodes a hex address string to bytes.
func hexDecode(s string) []byte {
	b := make([]byte, 0, len(s)/2)
	for i := 0; i < len(s); i += 2 {
		if i+1 < len(s) {
			var v byte
			for _, c := range s[i : i+2] {
				v <<= 4
				switch {
				case c >= '0' && c <= '9':
					v |= byte(c - '0')
				case c >= 'a' && c <= 'f':
					v |= byte(c - 'a' + 10)
				case c >= 'A' && c <= 'F':
					v |= byte(c - 'A' + 10)
				}
			}
			b = append(b, v)
		}
	}
	return b
}

// GetDevices returns the currently discovered BLE devices.
func (s *BLEScanner) GetDevices() []*BLEDevice {
	s.mu.RLock()
	defer s.mu.RUnlock()
	devices := make([]*BLEDevice, len(s.devices))
	copy(devices, s.devices)
	return devices
}

// shutdown stops the BLE scanner.
func (s *BLEScanner) shutdown() {
	s.mu.Lock()
	s.running = false
	s.mu.Unlock()
}

// BLEDeviceSimulator simulates BLE devices for testing.
type BLEDeviceSimulator struct {
	Devices []*BLEDevice
	mu      sync.RWMutex
}

// NewBLEDeviceSimulator creates a BLE simulator.
func NewBLEDeviceSimulator() *BLEDeviceSimulator {
	return &BLEDeviceSimulator{
		Devices: make([]*BLEDevice, 0),
	}
}

// AddDevice adds a simulated BLE device.
func (s *BLEDeviceSimulator) AddDevice(dev *BLEDevice) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Devices = append(s.Devices, dev)
}

// SimulateScan returns simulated scan results.
func (s *BLEDeviceSimulator) SimulateScan() []*BLEDevice {
	s.mu.RLock()
	defer s.mu.RUnlock()
	devices := make([]*BLEDevice, len(s.Devices))
	copy(devices, s.Devices)
	return devices
}

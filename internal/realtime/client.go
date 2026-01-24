package realtime

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"strings"
	"time"

	"nannyagent/internal/logging"
	"nannyagent/internal/types"
)

// Backoff configuration constants
const (
	InitialBackoff = 30 * time.Second // Initial backoff duration
	MaxBackoff     = 30 * time.Minute // Maximum backoff duration
	BackoffFactor  = 2.0              // Exponential factor
)

type RealtimeMessage struct {
	Action string                 `json:"action"`
	Record map[string]interface{} `json:"record"`
}

// InvestigationHandler is a callback function that processes an investigation request
type InvestigationHandler func(investigationID, prompt string)

// PatchHandler is a callback function that processes a patch operation request
type PatchHandler func(payload types.AgentPatchPayload)

// RebootHandler is a callback function that processes a reboot operation request
type RebootHandler func(payload types.AgentRebootPayload)

// Client handles the Realtime (SSE) connection to NannyAPI
type Client struct {
	baseURL              string
	accessToken          string
	investigationHandler InvestigationHandler
	patchHandler         PatchHandler
	rebootHandler        RebootHandler
}

// NewClient creates a new Realtime client
func NewClient(baseURL, accessToken string, investigationHandler InvestigationHandler, patchHandler PatchHandler, rebootHandler RebootHandler) *Client {
	return &Client{
		baseURL:              baseURL,
		accessToken:          accessToken,
		investigationHandler: investigationHandler,
		patchHandler:         patchHandler,
		rebootHandler:        rebootHandler,
	}
}

// CalculateBackoff calculates the next backoff duration using exponential backoff
// with a maximum cap. The formula is: min(MaxBackoff, InitialBackoff * factor^attempt)
func CalculateBackoff(attempt int) time.Duration {
	if attempt <= 0 {
		return InitialBackoff
	}

	backoff := float64(InitialBackoff) * math.Pow(BackoffFactor, float64(attempt))
	if backoff > float64(MaxBackoff) {
		return MaxBackoff
	}
	return time.Duration(backoff)
}

// Start begins the SSE connection loop. It blocks until the connection is permanently closed (which shouldn't happen).
func (c *Client) Start() {
	defer func() {
		if r := recover(); r != nil {
			logging.Error("SSE connection panicked: %v", r)
		}
	}()

	consecutiveFailures := 0

	// Retry loop for SSE connection - no maximum retries, will keep trying forever
	for {
		// IMPORTANT: SSE requires a client that doesn't buffer and doesn't timeout
		customClient := &http.Client{
			Transport: &http.Transport{
				DisableCompression: true, // Crucial for SSE
			},
			Timeout: 0, // No timeout for long-lived connections
		}

		logging.Debug("Connecting to SSE at %s/api/realtime...", c.baseURL)
		resp, err := customClient.Get(c.baseURL + "/api/realtime")
		if err != nil {
			consecutiveFailures++
			backoff := CalculateBackoff(consecutiveFailures)
			logging.Warning("Connection error (attempt %d): %v, retrying in %v", consecutiveFailures, err, backoff)
			time.Sleep(backoff)
			continue
		}

		reader := bufio.NewReader(resp.Body)

		// Read the first event to get the clientId
		var clientId string
		connectSuccess := false

		// Read loop for handshake
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				logging.Warning("Error reading from stream during handshake: %v", err)
				break
			}

			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "data:") {
				data := strings.TrimPrefix(line, "data:")
				var connectEvent struct {
					ClientId string `json:"clientId"`
				}
				if err := json.Unmarshal([]byte(data), &connectEvent); err == nil && connectEvent.ClientId != "" {
					clientId = connectEvent.ClientId
					connectSuccess = true
					break
				}
			}
		}

		if !connectSuccess {
			_ = resp.Body.Close()
			consecutiveFailures++
			backoff := CalculateBackoff(consecutiveFailures)
			logging.Debug("Failed to get Client ID (attempt %d), retrying in %v...", consecutiveFailures, backoff)
			time.Sleep(backoff)
			continue
		}

		logging.Debug("Connected! Client ID: %s", clientId)

		// --- STEP 2: Authorize & Subscribe ---
		// This is where you tell PB: "I am this Agent, listen to 'investigations', 'patch_operations', and 'reboot_operations'"
		subData, _ := json.Marshal(map[string]interface{}{
			"clientId":      clientId,
			"subscriptions": []string{"investigations", "patch_operations", "reboot_operations"},
		})

		req, _ := http.NewRequest("POST", c.baseURL+"/api/realtime", bytes.NewBuffer(subData))
		req.Header.Set("Authorization", "Bearer "+c.accessToken)
		req.Header.Set("Content-Type", "application/json")

		subResp, err := http.DefaultClient.Do(req)
		if err != nil || subResp.StatusCode != 204 {
			logging.Warning("Subscription failed: %v", err)
			_ = resp.Body.Close()
			consecutiveFailures++
			backoff := CalculateBackoff(consecutiveFailures)
			logging.Debug("Retrying in %v...", backoff)
			time.Sleep(backoff)
			continue
		}
		logging.Debug("Subscribed to 'investigations', 'patch_operations', and 'reboot_operations' successfully.")

		// Reset consecutive failures on successful connection
		consecutiveFailures = 0
		logging.Debug("SSE connection established successfully")

		// --- STEP 3: Listen for Records ---
		logging.Debug("Waiting for events...")
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				logging.Debug("Connection lost: %v", err)
				break
			}

			line = strings.TrimSpace(line)

			// Debug: Log everything so we can see the 'event:' lines too
			if line != "" {
				logging.Debug("Received: %s", line)
			}

			// We only care about the data: line
			if strings.HasPrefix(line, "data:") {
				msgJSON := strings.TrimPrefix(line, "data:")

				// Ignore the initial connect message if it repeats
				if strings.Contains(msgJSON, "clientId") {
					continue
				}

				var msg RealtimeMessage
				if err := json.Unmarshal([]byte(msgJSON), &msg); err == nil {
					// Check if this is a reboot operation
					if msg.Action == "create" {
						if c.handleRebootOperation(msg) {
							continue
						}

						// Try to parse as patch operation
						if c.handlePatchOperation(msg) {
							continue
						}

						// Try to parse as investigation
						c.handleInvestigation(msg)
					}
				} else {
					logging.Error("JSON Error: %v", err)
				}
			}
		}

		// Close body and calculate backoff for reconnection
		_ = resp.Body.Close()
		consecutiveFailures++
		backoff := CalculateBackoff(consecutiveFailures)
		logging.Debug("Reconnecting in %v...", backoff)
		time.Sleep(backoff)
	}
}

// handleRebootOperation processes a reboot operation message
// Returns true if message was handled as a reboot operation
func (c *Client) handleRebootOperation(msg RealtimeMessage) bool {
	record := msg.Record

	// Check for reboot operation indicators
	rebootID, hasID := record["id"].(string)
	if !hasID {
		return false
	}

	// Check for status field with value "sent" (reboot operations have this)
	status, hasStatus := record["status"].(string)
	if !hasStatus || status != "sent" {
		return false
	}

	// Check for timeout_seconds field (unique to reboot operations)
	_, hasTimeout := record["timeout_seconds"]
	if !hasTimeout {
		return false
	}

	// This is a reboot operation
	payload := types.AgentRebootPayload{
		RebootID: rebootID,
	}

	// Extract agent_id
	if agentID, ok := record["agent_id"].(string); ok {
		payload.AgentID = agentID
	}

	// Extract optional LXC ID
	if lxcID, ok := record["lxc_id"].(string); ok {
		payload.LXCID = lxcID
	}

	// Extract optional VMID
	if vmid, ok := parseVMID(record["vmid"]); ok {
		payload.VMID = vmid
	}

	// Extract reason
	if reason, ok := record["reason"].(string); ok {
		payload.Reason = reason
	}

	// Extract timeout_seconds
	if timeout, ok := record["timeout_seconds"].(float64); ok {
		payload.TimeoutSeconds = int(timeout)
	}

	// Extract requested_at
	if requestedAt, ok := record["requested_at"].(string); ok {
		payload.RequestedAt = requestedAt
	}

	logging.Info("Received reboot operation: %s", rebootID)

	if c.rebootHandler != nil {
		go c.rebootHandler(payload)
	}
	return true
}

// handlePatchOperation processes a patch operation message
// Returns true if message was handled as a patch operation
func (c *Client) handlePatchOperation(msg RealtimeMessage) bool {
	record := msg.Record

	operationID, ok := record["id"].(string)
	if !ok {
		return false
	}

	mode, okMode := record["mode"].(string)
	if !okMode {
		return false
	}

	scriptID, okScript := record["script_id"].(string)
	if !okScript {
		return false
	}

	scriptURL, okURL := record["script_url"].(string)
	if !okURL {
		return false
	}

	// This is a patch operation
	payload := types.AgentPatchPayload{
		OperationID: operationID,
		Mode:        mode,
		ScriptURL:   scriptURL,
		ScriptID:    scriptID,
		Timestamp:   time.Now().Format(time.RFC3339),
	}

	// Optional script args
	if args, okArgs := record["script_args"].(string); okArgs {
		payload.ScriptArgs = args
	}

	// Optional LXC ID
	if lxcID, okLXC := record["lxc_id"].(string); okLXC {
		payload.LXCID = lxcID
	}

	// Optional VMID
	if vmid, ok := parseVMID(record["vmid"]); ok {
		payload.VMID = vmid
	}

	logging.Info("Received patch operation: %s (mode: %s)", operationID, mode)

	if c.patchHandler != nil {
		go c.patchHandler(payload)
	}
	return true
}

// handleInvestigation processes an investigation message
func (c *Client) handleInvestigation(msg RealtimeMessage) {
	record := msg.Record

	prompt := "N/A"
	if p, ok := record["user_prompt"]; ok {
		prompt = fmt.Sprintf("%v", p)
	}

	investigationID := ""
	if id, ok := record["id"]; ok {
		investigationID = fmt.Sprintf("%v", id)
	}

	// Trigger investigation if we have necessary data
	if prompt != "N/A" && investigationID != "" {
		logging.Info("Triggering investigation %s...", investigationID)

		// Call the handler
		if c.investigationHandler != nil {
			go c.investigationHandler(investigationID, prompt)
		}
	}
}

func parseVMID(v interface{}) (string, bool) {
	switch v := v.(type) {
	case string:
		return v, true
	case float64:
		// Use %v to preserve as integer representation without decimal
		return fmt.Sprintf("%v", v), true
	case int, int32, int64:
		return fmt.Sprintf("%d", v), true
	case nil:
		return "", false
	default:
		// Try string conversion as fallback
		return fmt.Sprintf("%v", v), true
	}
}

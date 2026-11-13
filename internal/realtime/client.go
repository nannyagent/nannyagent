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
	"nannyagent/internal/nannyapi"
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

// TokenProvider is an interface for fetching a fresh access token
type TokenProvider interface {
	GetCurrentAccessToken() (string, error)
}

// Client handles the Realtime (SSE) connection to NannyAPI
type Client struct {
	baseURL              string
	tokenProvider        TokenProvider
	investigationHandler InvestigationHandler
}

// NewClient creates a new Realtime client
func NewClient(baseURL string, tokenProvider TokenProvider, investigationHandler InvestigationHandler) *Client {
	return &Client{
		baseURL:              baseURL,
		tokenProvider:        tokenProvider,
		investigationHandler: investigationHandler,
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
		// Fetch a fresh access token on every connection attempt
		accessToken, err := c.tokenProvider.GetCurrentAccessToken()
		if err != nil {
			consecutiveFailures++
			backoff := CalculateBackoff(consecutiveFailures)
			logging.Warning("Failed to get access token (attempt %d): %v, retrying in %v", consecutiveFailures, err, backoff)
			time.Sleep(backoff)
			continue
		}

		// IMPORTANT: SSE requires a client that doesn't buffer and doesn't timeout
		customClient := &http.Client{
			Transport: &http.Transport{
				DisableCompression: true, // Crucial for SSE
			},
			Timeout: 0, // No timeout for long-lived connections
		}

		logging.Debug("Connecting to SSE at %s%s...", c.baseURL, nannyapi.EndpointRealtime)
		req, err := http.NewRequest(http.MethodGet, c.baseURL+nannyapi.EndpointRealtime, nil)
		if err != nil {
			consecutiveFailures++
			backoff := CalculateBackoff(consecutiveFailures)
			logging.Warning("Failed to create realtime request: %v", err)
			time.Sleep(backoff)
			continue
		}
		req.Header.Set(nannyapi.HeaderAuthorization, nannyapi.BearerPrefix+accessToken)

		resp, err := customClient.Do(req)
		if err != nil {
			consecutiveFailures++
			backoff := CalculateBackoff(consecutiveFailures)
			logging.Warning("Connection error (attempt %d): %v, retrying in %v", consecutiveFailures, err, backoff)
			time.Sleep(backoff)
			continue
		}
		if resp.StatusCode != http.StatusOK {
			_ = resp.Body.Close()
			consecutiveFailures++
			backoff := CalculateBackoff(consecutiveFailures)
			logging.Warning("Realtime handshake failed with status %d, retrying in %v", resp.StatusCode, backoff)
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
		// This is where you tell PB: "I am this Agent, listen to 'investigations'"
		subData, _ := json.Marshal(map[string]interface{}{
			"clientId":      clientId,
			"subscriptions": []string{"investigations"},
		})

		req, err = http.NewRequest(http.MethodPost, c.baseURL+nannyapi.EndpointRealtime, bytes.NewBuffer(subData))
		if err != nil {
			logging.Warning("Failed to create realtime subscription request: %v", err)
			_ = resp.Body.Close()
			consecutiveFailures++
			backoff := CalculateBackoff(consecutiveFailures)
			logging.Debug("Retrying in %v...", backoff)
			time.Sleep(backoff)
			continue
		}
		req.Header.Set(nannyapi.HeaderAuthorization, nannyapi.BearerPrefix+accessToken)
		req.Header.Set(nannyapi.HeaderContentType, nannyapi.ContentTypeJSON)

		subResp, err := http.DefaultClient.Do(req)
		if err != nil {
			logging.Warning("Realtime subscription request failed: %v", err)
			_ = resp.Body.Close()
			consecutiveFailures++
			backoff := CalculateBackoff(consecutiveFailures)
			logging.Debug("Retrying in %v...", backoff)
			time.Sleep(backoff)
			continue
		}
		_ = subResp.Body.Close()
		if subResp.StatusCode != http.StatusNoContent {
			logging.Warning("Realtime subscription failed with status %d", subResp.StatusCode)
			_ = resp.Body.Close()
			consecutiveFailures++
			backoff := CalculateBackoff(consecutiveFailures)
			logging.Debug("Retrying in %v...", backoff)
			time.Sleep(backoff)
			continue
		}
		logging.Debug("Subscribed to 'investigations' successfully.")

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
					if msg.Action == nannyapi.ActionCreate {
						// Try to parse as investigation
						c.handleInvestigation(msg)
					}
				} else {
					logging.Warning("Received invalid realtime payload; ignoring message")
					logging.Debug("Invalid realtime payload: %s", msgJSON)
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

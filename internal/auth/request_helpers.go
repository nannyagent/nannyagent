package auth

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"nannyagent/internal/config"
	"nannyagent/internal/logging"
	"nannyagent/internal/nannyapi"
)

type responseRetryer interface {
	clearConnErrors()
	resetRetryAttempts()
	recordConnError() bool
	incrementRetryAttempts()
	calculateBackoff() time.Duration
	getClient() *http.Client
}

type responseRetryLogConfig struct {
	transportResetFormat string
	connectionReadFormat string
	readFormat           string
}

func newHTTPClient(transport *http.Transport) *http.Client {
	return &http.Client{
		Transport: transport,
		Timeout:   5 * time.Minute,
	}
}

func calculateBackoff(attempts int, transportConfig config.HTTPTransportConfig) time.Duration {
	initialDelay := time.Duration(transportConfig.InitialRetryDelaySec) * time.Second
	maxDelay := time.Duration(transportConfig.MaxRetryDelaySec) * time.Second

	if attempts <= 0 {
		return initialDelay
	}
	if attempts > 30 {
		return maxDelay
	}

	shift := time.Duration(1) << uint(attempts)
	if shift <= 0 || initialDelay > maxDelay/shift {
		return maxDelay
	}

	backoff := initialDelay * shift
	if backoff > maxDelay {
		return maxDelay
	}
	return backoff
}

func newAPIRequest(method, url string, body []byte, headers map[string]string) (*http.Request, error) {
	req, err := http.NewRequest(method, url, bytes.NewBuffer(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	if headers == nil || headers[nannyapi.HeaderContentType] == "" {
		req.Header.Set(nannyapi.HeaderContentType, nannyapi.ContentTypeJSON)
	}
	for key, value := range headers {
		req.Header.Set(key, value)
	}

	return req, nil
}

func setBearerAuthorization(req *http.Request, token string) {
	req.Header.Set(nannyapi.HeaderAuthorization, nannyapi.BearerPrefix+token)
}

func setAgentIDHeader(req *http.Request, agentID string) {
	if agentID != "" {
		req.Header.Set(nannyapi.HeaderAgentID, agentID)
	}
}

func postJSON(client *http.Client, url string, payload any, headers map[string]string) (int, []byte, error) {
	jsonData, err := json.Marshal(payload)
	if err != nil {
		return 0, nil, fmt.Errorf("failed to marshal payload: %w", err)
	}

	req, err := newAPIRequest(http.MethodPost, url, jsonData, headers)
	if err != nil {
		return 0, nil, err
	}

	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, nil, fmt.Errorf("failed to read response body: %w", err)
	}

	return resp.StatusCode, body, nil
}

func authenticatedRequestWithRetry(retryer responseRetryer, doRequest func() (*http.Response, error), logConfig responseRetryLogConfig) (int, []byte, error) {
	for {
		resp, err := doRequest()
		if err != nil {
			return 0, nil, err
		}

		statusCode := resp.StatusCode
		respBody, readErr := io.ReadAll(resp.Body)
		_ = resp.Body.Close()

		if readErr == nil {
			retryer.clearConnErrors()
			retryer.resetRetryAttempts()
			return statusCode, respBody, nil
		}

		if isConnectionError(readErr) {
			if retryer.recordConnError() {
				logging.Info(logConfig.transportResetFormat, readErr)
			}

			backoff := retryer.calculateBackoff()
			retryer.incrementRetryAttempts()
			logging.Warning(logConfig.connectionReadFormat, readErr, backoff)
			time.Sleep(backoff)
			continue
		}

		backoff := retryer.calculateBackoff()
		retryer.incrementRetryAttempts()
		logging.Warning(logConfig.readFormat, readErr, backoff)
		retryer.getClient().CloseIdleConnections()
		time.Sleep(backoff)
	}
}

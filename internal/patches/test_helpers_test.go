package patches

import (
	"bytes"
	"io"
	"net/http"

	"nannyagent/internal/nannyapi"
)

type mockAuthManager struct {
	token string
}

func (m *mockAuthManager) AuthenticatedDo(method, url string, body []byte, headers map[string]string) (*http.Response, error) {
	req, err := http.NewRequest(method, url, bytes.NewBuffer(body))
	if err != nil {
		return nil, err
	}

	for key, value := range headers {
		req.Header.Set(key, value)
	}
	req.Header.Set(nannyapi.HeaderAuthorization, nannyapi.BearerPrefix+m.token)

	return http.DefaultClient.Do(req)
}

func (m *mockAuthManager) AuthenticatedRequest(method, url string, body []byte, headers map[string]string) (int, []byte, error) {
	resp, err := m.AuthenticatedDo(method, url, body, headers)
	if err != nil {
		return 0, nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp.StatusCode, nil, err
	}

	return resp.StatusCode, respBody, nil
}

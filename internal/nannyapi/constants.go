package nannyapi

const (
	EndpointAgent    = "/api/agent"
	EndpointRealtime = "/api/realtime"

	HeaderAuthorization = "Authorization"
	HeaderContentType   = "Content-Type"
	HeaderAgentID       = "X-Agent-ID"

	BearerPrefix    = "Bearer "
	ContentTypeJSON = "application/json"

	ActionDeviceAuthStart   = "device-auth-start"
	ActionAuthorize         = "authorize"
	ActionRegister          = "register"
	ActionRegisterWithToken = "register-with-token"
	ActionRefresh           = "refresh"
	ActionRenewRefreshToken = "renew-refresh-token"
	ActionIngestMetrics     = "ingest-metrics"
	ActionCreate            = "create"
)

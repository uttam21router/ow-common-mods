package owsec

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/gofiber/fiber"
	"github.com/routerarchitects/ow-common-mods/servicerpc/common"
	"github.com/routerarchitects/ra-common-mods/apperror"
)

const serviceName = "owsec"

type SecurityClient struct {
	deps *common.ServiceRPCBase
}

func NewSecurityClient(deps *common.ServiceRPCBase) *SecurityClient {
	return &SecurityClient{
		deps: deps,
	}
}

// ValidateToken validates token by checking both subscription-token and
// regular-token endpoints.
//
// Caller must pass ctx with timeout/deadline.
func (s *SecurityClient) ValidateToken(ctx context.Context, rawToken string) error {
	token := strings.TrimSpace(rawToken)
	if token == "" {
		return apperror.New(apperror.CodeUnauthorized, "unauthorized")
	}

	subResp, subErr := s.deps.Send(ctx, http.MethodGet, "/api/v1/validateSubToken?token="+url.QueryEscape(token), nil, serviceName)
	if subResp != nil {
		defer subResp.Close()
	}

	if subErr != nil {
		return subErr
	}

	if subResp != nil && subResp.StatusCode() == http.StatusOK {
		return nil
	}

	tokenResp, tokenErr := s.deps.Send(ctx, http.MethodGet, "/api/v1/validateToken?token="+url.QueryEscape(token), nil, serviceName)
	if tokenResp != nil {
		defer tokenResp.Close()
	}

	if tokenErr != nil {
		s.deps.Logger().With("service", serviceName, "operation", "validateToken").Error("validation request failed")
		return tokenErr
	}

	if tokenResp == nil {
		return apperror.New(apperror.CodeInternal, "token validation response is empty")
	}

	if tokenResp.StatusCode() == http.StatusOK {
		return nil
	}

	subStatus := http.StatusInternalServerError
	if subResp != nil {
		subStatus = subResp.StatusCode()
	}

	if isInvalidTokenStatus(subStatus) && isInvalidTokenStatus(tokenResp.StatusCode()) {
		return apperror.New(apperror.CodeUnauthorized, "unauthorized")
	}

	return apperror.New(apperror.CodeInternal, fmt.Sprintf("token validation failed (subtoken=%d token=%d)", subStatus, tokenResp.StatusCode()))
}

func isInvalidTokenStatus(status int) bool {
	return status == http.StatusUnauthorized || status == http.StatusForbidden || status == http.StatusNotFound
}

func (v *SecurityClient) ValidateAPIKey(ctx context.Context, apiKey string) error {
	apiKey = strings.TrimSpace(apiKey)

	resp, err := v.deps.Send(ctx, fiber.MethodGet, "/api/v1/validateAPIKey?apiKey="+url.QueryEscape(apiKey), nil, serviceName)
	if resp != nil {
		defer resp.Close()
	}

	if err == nil && resp != nil && resp.StatusCode() == fiber.StatusOK {
		return nil
	}

	return apperror.Wrap(apperror.CodeUnauthorized, "unauthorized", err)

}

func (s *SecurityClient) ValidateAPIKey(ctx context.Context, apiKey string) error {
	resp, err := s.deps.Send(ctx, http.MethodGet, "/api/v1/validateAPIKey?apiKey="+url.QueryEscape(apiKey), nil, serviceName)
	if resp != nil {
		defer resp.Close()
	}

	if err != nil || resp == nil || resp.StatusCode() != http.StatusOK {
		s.deps.Logger().With("service", serviceName, "operation", "validateAPIKey").Error("validation request failed")
		return apperror.Wrap(apperror.CodeUnauthorized, "unauthorized", err)
	}

	return nil
}

package service

import (
	"context"
	"fmt"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ssooidc"
)

type AWSSSOOAuthService struct{}

func NewAWSSSOOAuthService() *AWSSSOOAuthService {
	return &AWSSSOOAuthService{}
}

type AWSSSODeviceAuthResult struct {
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete"`
	UserCode                string `json:"user_code"`
	DeviceCode              string `json:"device_code"`
	ClientID                string `json:"client_id"`
	ClientSecret            string `json:"client_secret"`
	ExpiresIn               int32  `json:"expires_in"`
	Interval                int32  `json:"interval"`
}

type AWSSSOPollInput struct {
	SSORegion    string
	ClientID     string
	ClientSecret string
	DeviceCode   string
}

type AWSSSOTokenResult struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int32  `json:"expires_in"`
	TokenType   string `json:"token_type"`
}

// StartDeviceAuth registers an OIDC client and starts the device authorization flow.
func (s *AWSSSOOAuthService) StartDeviceAuth(ctx context.Context, ssoStartURL, ssoRegion string) (*AWSSSODeviceAuthResult, error) {
	cfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(ssoRegion))
	if err != nil {
		return nil, fmt.Errorf("load aws config: %w", err)
	}

	oidcClient := ssooidc.NewFromConfig(cfg)

	// Step 1: Register OIDC client
	registerOutput, err := oidcClient.RegisterClient(ctx, &ssooidc.RegisterClientInput{
		ClientName: stringPtr("sub2api"),
		ClientType: stringPtr("public"),
	})
	if err != nil {
		return nil, fmt.Errorf("register OIDC client: %w", err)
	}

	// Step 2: Start device authorization
	deviceAuthOutput, err := oidcClient.StartDeviceAuthorization(ctx, &ssooidc.StartDeviceAuthorizationInput{
		ClientId:     registerOutput.ClientId,
		ClientSecret: registerOutput.ClientSecret,
		StartUrl:     &ssoStartURL,
	})
	if err != nil {
		return nil, fmt.Errorf("start device authorization: %w", err)
	}

	return &AWSSSODeviceAuthResult{
		VerificationURI:         ptrToString(deviceAuthOutput.VerificationUri),
		VerificationURIComplete: ptrToString(deviceAuthOutput.VerificationUriComplete),
		UserCode:                ptrToString(deviceAuthOutput.UserCode),
		DeviceCode:              ptrToString(deviceAuthOutput.DeviceCode),
		ClientID:                ptrToString(registerOutput.ClientId),
		ClientSecret:            ptrToString(registerOutput.ClientSecret),
		ExpiresIn:               deviceAuthOutput.ExpiresIn,
		Interval:                deviceAuthOutput.Interval,
	}, nil
}

// PollForToken polls for the access token after the user has completed device authorization.
func (s *AWSSSOOAuthService) PollForToken(ctx context.Context, input *AWSSSOPollInput) (*AWSSSOTokenResult, error) {
	cfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(input.SSORegion))
	if err != nil {
		return nil, fmt.Errorf("load aws config: %w", err)
	}

	oidcClient := ssooidc.NewFromConfig(cfg)

	tokenOutput, err := oidcClient.CreateToken(ctx, &ssooidc.CreateTokenInput{
		ClientId:     &input.ClientID,
		ClientSecret: &input.ClientSecret,
		DeviceCode:   &input.DeviceCode,
		GrantType:    stringPtr("urn:ietf:params:oauth:grant-type:device_code"),
	})
	if err != nil {
		return nil, fmt.Errorf("create token: %w", err)
	}

	return &AWSSSOTokenResult{
		AccessToken: ptrToString(tokenOutput.AccessToken),
		ExpiresIn:   tokenOutput.ExpiresIn,
		TokenType:   ptrToString(tokenOutput.TokenType),
	}, nil
}

func stringPtr(s string) *string {
	return &s
}

func ptrToString(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

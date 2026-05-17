package service

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/sso"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

type AWSSTSService struct {
	accountRepo AccountRepository
	mu          sync.Map // per-account lock to prevent concurrent refresh
}

func NewAWSSTSService(accountRepo AccountRepository) *AWSSTSService {
	return &AWSSTSService{
		accountRepo: accountRepo,
	}
}

// RefreshCredentials refreshes temporary AWS credentials for IAM Role/STS and AWS SSO accounts.
func (s *AWSSTSService) RefreshCredentials(ctx context.Context, account *Account) error {
	if account.IsAWSIAMRole() {
		return s.refreshSTSCredentials(ctx, account)
	}
	if account.IsAWSSSO() {
		return s.refreshSSOCredentials(ctx, account)
	}
	return nil
}

func (s *AWSSTSService) getAccountLock(accountID int64) *sync.Mutex {
	val, _ := s.mu.LoadOrStore(accountID, &sync.Mutex{})
	return val.(*sync.Mutex)
}

func (s *AWSSTSService) refreshSTSCredentials(ctx context.Context, account *Account) error {
	lock := s.getAccountLock(account.ID)
	lock.Lock()
	defer lock.Unlock()

	// Double-check after acquiring lock
	if !account.NeedsAWSCredentialRefresh() {
		return nil
	}

	roleARN := account.GetCredential("role_arn")
	if roleARN == "" {
		return fmt.Errorf("role_arn not found in credentials")
	}

	sessionName := account.GetCredential("session_name")
	if sessionName == "" {
		sessionName = "sub2api-session"
	}

	// Build AWS config with source credentials if provided
	var opts []func(*awsconfig.LoadOptions) error
	opts = append(opts, awsconfig.WithRegion(account.GetAWSRegion()))

	sourceKeyID := account.GetCredential("source_access_key_id")
	sourceSecretKey := account.GetCredential("source_secret_access_key")
	if sourceKeyID != "" && sourceSecretKey != "" {
		opts = append(opts, awsconfig.WithCredentialsProvider(
			credentials.NewStaticCredentialsProvider(sourceKeyID, sourceSecretKey, ""),
		))
	}

	cfg, err := awsconfig.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return fmt.Errorf("load aws config: %w", err)
	}

	stsClient := sts.NewFromConfig(cfg)

	input := &sts.AssumeRoleInput{
		RoleArn:         aws.String(roleARN),
		RoleSessionName: aws.String(sessionName),
		DurationSeconds: aws.Int32(3600),
	}

	externalID := account.GetCredential("external_id")
	if externalID != "" {
		input.ExternalId = aws.String(externalID)
	}

	result, err := stsClient.AssumeRole(ctx, input)
	if err != nil {
		return fmt.Errorf("STS AssumeRole failed: %w", err)
	}

	if result.Credentials == nil {
		return fmt.Errorf("STS AssumeRole returned nil credentials")
	}

	// Update account credentials in memory and database
	account.Credentials["aws_access_key_id"] = *result.Credentials.AccessKeyId
	account.Credentials["aws_secret_access_key"] = *result.Credentials.SecretAccessKey
	account.Credentials["aws_session_token"] = *result.Credentials.SessionToken
	account.Credentials["credentials_expire_at"] = result.Credentials.Expiration.Format(time.RFC3339)

	if err := s.accountRepo.UpdateCredentials(ctx, account.ID, account.Credentials); err != nil {
		slog.Error("failed to persist refreshed STS credentials", "account_id", account.ID, "error", err)
		return fmt.Errorf("persist STS credentials: %w", err)
	}

	slog.Info("refreshed STS credentials", "account_id", account.ID, "expires_at", result.Credentials.Expiration)
	return nil
}

func (s *AWSSTSService) refreshSSOCredentials(ctx context.Context, account *Account) error {
	lock := s.getAccountLock(account.ID)
	lock.Lock()
	defer lock.Unlock()

	if !account.NeedsAWSCredentialRefresh() {
		return nil
	}

	accessToken := account.GetCredential("access_token")
	if accessToken == "" {
		return fmt.Errorf("SSO access_token not found in credentials, please re-authenticate")
	}

	ssoAccountID := account.GetCredential("sso_account_id")
	if ssoAccountID == "" {
		return fmt.Errorf("sso_account_id not found in credentials")
	}

	ssoRoleName := account.GetCredential("sso_role_name")
	if ssoRoleName == "" {
		return fmt.Errorf("sso_role_name not found in credentials")
	}

	ssoRegion := account.GetCredential("sso_region")
	if ssoRegion == "" {
		ssoRegion = account.GetAWSRegion()
	}

	cfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(ssoRegion))
	if err != nil {
		return fmt.Errorf("load aws config for SSO: %w", err)
	}

	ssoClient := sso.NewFromConfig(cfg)

	result, err := ssoClient.GetRoleCredentials(ctx, &sso.GetRoleCredentialsInput{
		AccessToken: aws.String(accessToken),
		AccountId:   aws.String(ssoAccountID),
		RoleName:    aws.String(ssoRoleName),
	})
	if err != nil {
		return fmt.Errorf("SSO GetRoleCredentials failed: %w", err)
	}

	if result.RoleCredentials == nil {
		return fmt.Errorf("SSO GetRoleCredentials returned nil")
	}

	expireAt := time.UnixMilli(result.RoleCredentials.Expiration)

	account.Credentials["aws_access_key_id"] = aws.ToString(result.RoleCredentials.AccessKeyId)
	account.Credentials["aws_secret_access_key"] = aws.ToString(result.RoleCredentials.SecretAccessKey)
	account.Credentials["aws_session_token"] = aws.ToString(result.RoleCredentials.SessionToken)
	account.Credentials["credentials_expire_at"] = expireAt.Format(time.RFC3339)

	if err := s.accountRepo.UpdateCredentials(ctx, account.ID, account.Credentials); err != nil {
		slog.Error("failed to persist refreshed SSO credentials", "account_id", account.ID, "error", err)
		return fmt.Errorf("persist SSO credentials: %w", err)
	}

	slog.Info("refreshed SSO credentials", "account_id", account.ID, "expires_at", expireAt)
	return nil
}

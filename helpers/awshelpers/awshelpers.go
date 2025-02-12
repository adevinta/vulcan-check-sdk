package awshelpers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/aws-sdk-go/aws/arn"
)

// VulcanAssumeRoleProvider is a custom AWS credentials provider that assumes a role using the Vulcan assume role service.
type VulcanAssumeRoleProvider struct {
	URL       string
	AccountID string
	Role      string
	Duration  int
	cli       http.Client
}

// NewVulcanAssumeRoleProvider creates a VulcanAssumeRoleProvider.
func NewVulcanAssumeRoleProvider(url, accountID, role string, duration int) *VulcanAssumeRoleProvider {
	return &VulcanAssumeRoleProvider{
		URL:       url,
		AccountID: accountID,
		Role:      role,
		Duration:  duration,
		cli:       http.Client{},
	}
}

// Retrieve retrieves the credentials from the Vulcan assume role service.
func (p *VulcanAssumeRoleProvider) Retrieve(ctx context.Context) (aws.Credentials, error) {
	var emptyCreds aws.Credentials
	m := map[string]any{"account_id": p.AccountID, "duration": p.Duration}
	if p.Role != "" {
		m["role"] = p.Role
	}
	expires := time.Now().Add(time.Second * time.Duration(p.Duration))
	jsonBody, err := json.Marshal(m)
	if err != nil {
		return emptyCreds, fmt.Errorf("unable to marshal body: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, "POST", p.URL, bytes.NewBuffer(jsonBody))
	if err != nil {
		return emptyCreds, fmt.Errorf("unable to create request for the assume role service: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := p.cli.Do(req)
	select {
	case <-ctx.Done():
		return emptyCreds, ctx.Err()
	default:
	}
	if err != nil {
		return emptyCreds, fmt.Errorf("cannot do request to the assume role service: %w", err)
	}
	defer resp.Body.Close() // nolint
	if resp.StatusCode != http.StatusOK {
		return emptyCreds, fmt.Errorf("invalid status code from assume role service: %v", resp.StatusCode)
	}
	type AssumeRoleResponse struct {
		AccessKey       string `json:"access_key"`
		SecretAccessKey string `json:"secret_access_key"`
		SessionToken    string `json:"session_token"`
	}
	assumeRoleResponse := AssumeRoleResponse{}
	buf, err := io.ReadAll(resp.Body)
	if err != nil {
		return emptyCreds, fmt.Errorf("can not read request body from assume role service %w", err)
	}

	err = json.Unmarshal(buf, &assumeRoleResponse)
	if err != nil {
		return emptyCreds, fmt.Errorf("cannot unmarshal response from assume role service: %w", err)
	}
	return aws.Credentials{
		Source:          "VulcanAssumeRoleProvider",
		AccessKeyID:     assumeRoleResponse.AccessKey,
		SecretAccessKey: assumeRoleResponse.SecretAccessKey,
		SessionToken:    assumeRoleResponse.SessionToken,
		AccountID:       p.AccountID,
		CanExpire:       true,
		Expires:         expires,
	}, nil
}

// GetAwsConfigWithVulcanAssumeRole returns an AWS config with the provided assume role endpoint, account ARN, role and duration.
func GetAwsConfigWithVulcanAssumeRole(ctx context.Context, assumeRoleEndpoint, accountArn, role string, duration int) (aws.Config, error) {
	var cfg aws.Config
	parsedARN, err := arn.Parse(accountArn)
	if err != nil {
		return cfg, err
	}
	cfg, err = config.LoadDefaultConfig(
		ctx,
		config.WithRegion("us-east-1"),
		config.WithCredentialsProvider(
			NewVulcanAssumeRoleProvider(assumeRoleEndpoint, parsedARN.AccountID, role, duration),
		))
	if err != nil {
		return cfg, fmt.Errorf("unable to create AWS config: %w", err)
	}
	// Validate that the account id in the target ARN matches the account id in the credentials
	if req, err := sts.NewFromConfig(cfg).GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{}); err != nil {
		return cfg, fmt.Errorf("unable to get caller identity: %w", err)
	} else if *req.Account != parsedARN.AccountID {
		return cfg, fmt.Errorf("account id in target ARN does not match the account id in the credentials (target ARN: %s, credentials account id: %s)", parsedARN.AccountID, *req.Account)
	}
	return cfg, nil
}

// GetAwsConfig returns an AWS config with the provided account ARN and role.
// If role is not empty, the config will be created with the provided role and the specified duration.
func GetAwsConfig(ctx context.Context, accountArn, role string, duration int) (aws.Config, error) {
	var cfg aws.Config
	parsedARN, err := arn.Parse(accountArn)
	if err != nil {
		return cfg, err
	}
	cfg, err = config.LoadDefaultConfig(ctx, config.WithRegion("us-east-1"))
	if err != nil {
		return cfg, fmt.Errorf("unable to create default AWS config: %w", err)
	}
	if role != "" {
		cfg, err = config.LoadDefaultConfig(
			ctx,
			config.WithCredentialsProvider(
				stscreds.NewAssumeRoleProvider(
					sts.NewFromConfig(cfg),
					fmt.Sprintf("arn:aws:iam::%s:role/%s", parsedARN.AccountID, role),
					func(o *stscreds.AssumeRoleOptions) {
						if duration != 0 {
							o.Duration = time.Duration(duration) * time.Second
						}
					},
				)))
	}
	if err != nil {
		return cfg, fmt.Errorf("unable to create AWS config: %w", err)
	}
	// Validate that the account id in the target ARN matches the account id in the credentials
	if req, err := sts.NewFromConfig(cfg).GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{}); err != nil {
		return cfg, fmt.Errorf("unable to get caller identity: %w", err)
	} else if *req.Account != parsedARN.AccountID {
		return cfg, fmt.Errorf("account id in target ARN does not match the account id in the credentials (target ARN: %s, credentials account id: %s)", parsedARN.AccountID, *req.Account)
	}
	return cfg, nil
}

// GetAccountAlias gets the first one of the current aliases for the account that the
// credentials passed belong to.
func GetAccountAlias(ctx context.Context, cfg aws.Config) (string, error) {
	svc := iam.NewFromConfig(cfg)
	resp, err := svc.ListAccountAliases(ctx, &iam.ListAccountAliasesInput{})
	if err != nil {
		return "", err
	}
	if len(resp.AccountAliases) == 0 {
		// No aliases found for the aws account.
		return "", nil
	}
	a := resp.AccountAliases[0]
	return a, nil
}

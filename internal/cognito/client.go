package cognito

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"

	"auth-microservice/internal/models"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider/types"
)

type Client struct {
	client       *cognitoidentityprovider.Client
	clientID     string
	clientSecret string
	userPoolID   string
}

// NewClient creates a new Cognito client
func NewClient(ctx context.Context, region, clientID, clientSecret, userPoolID string) (*Client, error) {
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %w", err)
	}

	return &Client{
		client:       cognitoidentityprovider.NewFromConfig(cfg),
		clientID:     clientID,
		clientSecret: clientSecret,
		userPoolID:   userPoolID,
	}, nil
}

// computeSecretHash computes the secret hash required for Cognito operations
func (c *Client) computeSecretHash(username string) string {
	mac := hmac.New(sha256.New, []byte(c.clientSecret))
	mac.Write([]byte(username + c.clientID))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

// SignUp registers a new user in Cognito
func (c *Client) SignUp(ctx context.Context, email, password, name string) error {
	secretHash := c.computeSecretHash(email)

	userAttributes := []types.AttributeType{
		{
			Name:  aws.String("email"),
			Value: aws.String(email),
		},
	}

	if name != "" {
		userAttributes = append(userAttributes, types.AttributeType{
			Name:  aws.String("name"),
			Value: aws.String(name),
		})
	}

	input := &cognitoidentityprovider.SignUpInput{
		ClientId:       aws.String(c.clientID),
		SecretHash:     aws.String(secretHash),
		Username:       aws.String(email),
		Password:       aws.String(password),
		UserAttributes: userAttributes,
	}

	_, err := c.client.SignUp(ctx, input)
	if err != nil {
		return fmt.Errorf("signup failed: %w", err)
	}

	return nil
}

// Login authenticates a user and returns tokens
func (c *Client) Login(ctx context.Context, email, password string) (*models.CognitoTokens, error) {
	secretHash := c.computeSecretHash(email)

	input := &cognitoidentityprovider.InitiateAuthInput{
		AuthFlow: types.AuthFlowTypeUserPasswordAuth,
		ClientId: aws.String(c.clientID),
		AuthParameters: map[string]string{
			"USERNAME":    email,
			"PASSWORD":    password,
			"SECRET_HASH": secretHash,
		},
	}

	result, err := c.client.InitiateAuth(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("login failed: %w", err)
	}

	if result.AuthenticationResult == nil {
		return nil, fmt.Errorf("authentication failed: no tokens returned")
	}

	return &models.CognitoTokens{
		AccessToken:  aws.ToString(result.AuthenticationResult.AccessToken),
		IDToken:      aws.ToString(result.AuthenticationResult.IdToken),
		RefreshToken: aws.ToString(result.AuthenticationResult.RefreshToken),
		ExpiresIn:    result.AuthenticationResult.ExpiresIn,
	}, nil
}

// RefreshToken refreshes the access token using a refresh token
func (c *Client) RefreshToken(ctx context.Context, refreshToken, username string) (*models.CognitoTokens, error) {
	secretHash := c.computeSecretHash(username)

	input := &cognitoidentityprovider.InitiateAuthInput{
		AuthFlow: types.AuthFlowTypeRefreshTokenAuth,
		ClientId: aws.String(c.clientID),
		AuthParameters: map[string]string{
			"REFRESH_TOKEN": refreshToken,
			"SECRET_HASH":   secretHash,
		},
	}

	result, err := c.client.InitiateAuth(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("token refresh failed: %w", err)
	}

	if result.AuthenticationResult == nil {
		return nil, fmt.Errorf("token refresh failed: no tokens returned")
	}

	return &models.CognitoTokens{
		AccessToken:  aws.ToString(result.AuthenticationResult.AccessToken),
		IDToken:      aws.ToString(result.AuthenticationResult.IdToken),
		RefreshToken: refreshToken,
		ExpiresIn:    result.AuthenticationResult.ExpiresIn,
	}, nil
}

// GetUser retrieves user information from an access token
func (c *Client) GetUser(ctx context.Context, accessToken string) (*models.User, error) {
	input := &cognitoidentityprovider.GetUserInput{
		AccessToken: aws.String(accessToken),
	}

	result, err := c.client.GetUser(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	user := &models.User{
		ID:            aws.ToString(result.Username),
		EmailVerified: false,
	}

	for _, attr := range result.UserAttributes {
		switch aws.ToString(attr.Name) {
		case "email":
			user.Email = aws.ToString(attr.Value)
		case "email_verified":
			user.EmailVerified = aws.ToString(attr.Value) == "true"
		case "name":
			user.Name = aws.ToString(attr.Value)
		}
	}

	return user, nil
}

// GlobalSignOut signs out the user from all devices
func (c *Client) GlobalSignOut(ctx context.Context, accessToken string) error {
	input := &cognitoidentityprovider.GlobalSignOutInput{
		AccessToken: aws.String(accessToken),
	}

	_, err := c.client.GlobalSignOut(ctx, input)
	if err != nil {
		return fmt.Errorf("global signout failed: %w", err)
	}

	return nil
}

// ConfirmSignUp confirms a user's email with a verification code
func (c *Client) ConfirmSignUp(ctx context.Context, email, code string) error {
	secretHash := c.computeSecretHash(email)

	input := &cognitoidentityprovider.ConfirmSignUpInput{
		ClientId:         aws.String(c.clientID),
		SecretHash:       aws.String(secretHash),
		Username:         aws.String(email),
		ConfirmationCode: aws.String(code),
	}

	_, err := c.client.ConfirmSignUp(ctx, input)
	if err != nil {
		return fmt.Errorf("email verification failed: %w", err)
	}

	return nil
}

// ResendConfirmationCode resends the verification code to the user's email
func (c *Client) ResendConfirmationCode(ctx context.Context, email string) error {
	secretHash := c.computeSecretHash(email)

	input := &cognitoidentityprovider.ResendConfirmationCodeInput{
		ClientId:   aws.String(c.clientID),
		SecretHash: aws.String(secretHash),
		Username:   aws.String(email),
	}

	_, err := c.client.ResendConfirmationCode(ctx, input)
	if err != nil {
		return fmt.Errorf("failed to resend verification code: %w", err)
	}

	return nil
}

package iam

import (
	"fmt"

	awssdk "github.com/aws/aws-sdk-go/aws"
	awsarn "github.com/aws/aws-sdk-go/aws/arn"
	"github.com/aws/aws-sdk-go/aws/awserr"
	awsiam "github.com/aws/aws-sdk-go/service/iam"
	"github.com/aws/aws-sdk-go/service/iam/iamiface"
	"github.com/sethvargo/go-password/password"

	"github.com/redradrat/cloud-objects/aws"
)

func createUser(svc iamiface.IAMAPI, userName string) (*awsiam.CreateUserOutput, error) {

	result, err := svc.CreateUser(&awsiam.CreateUserInput{
		UserName: awssdk.String(userName),
	})
	if err != nil {
		return nil, err
	}

	return result, nil
}

func updateUser(svc iamiface.IAMAPI, userName string, arn awsarn.ARN) (*awsiam.UpdateUserOutput, error) {

	result, err := svc.UpdateUser(&awsiam.UpdateUserInput{
		NewUserName: awssdk.String(userName),
		UserName:    awssdk.String(FriendlyNamefromARN(arn)),
	})
	if err != nil {
		return nil, err
	}

	return result, nil
}

func createLoginProfile(svc iamiface.IAMAPI, user string) (*LoginProfileCredentials, error) {
	pass, err := password.Generate(20, 8, 4, false, false)
	if err != nil {
		return nil, err
	}

	_, err = svc.CreateLoginProfile(&awsiam.CreateLoginProfileInput{
		Password:              awssdk.String(pass),
		PasswordResetRequired: awssdk.Bool(false),
		UserName:              awssdk.String(user),
	})
	if err != nil && !aws.IsAlreadyExistsError(err) {
		return nil, err
	}

	return NewLoginProfileCredentials(user, pass), nil
}

func deleteLoginProfile(svc iamiface.IAMAPI, arn awsarn.ARN) error {
	user := FriendlyNamefromARN(arn)

	_, err := svc.DeleteLoginProfile(&awsiam.DeleteLoginProfileInput{
		UserName: awssdk.String(user),
	})
	if err != nil && !aws.IsNotExistsError(err) {
		return err
	}

	return nil
}

func createAccessKey(svc iamiface.IAMAPI, user string) (*AccessKey, error) {
	out, err := svc.CreateAccessKey(&awsiam.CreateAccessKeyInput{
		UserName: awssdk.String(user),
	})
	if err != nil && !aws.IsAlreadyExistsError(err) {
		return nil, err
	}

	id := awssdk.StringValue(out.AccessKey.AccessKeyId)
	secret := awssdk.StringValue(out.AccessKey.SecretAccessKey)

	return NewAccessKey(id, secret), nil
}

func deleteAccessKeys(svc iamiface.IAMAPI, arn awsarn.ARN) error {
	user := FriendlyNamefromARN(arn)

	out, err := svc.ListAccessKeys(&awsiam.ListAccessKeysInput{
		UserName: awssdk.String(user),
	})
	if err != nil {
		return err
	}

	for _, key := range out.AccessKeyMetadata {
		_, err := svc.DeleteAccessKey(&awsiam.DeleteAccessKeyInput{
			AccessKeyId: key.AccessKeyId,
			UserName:    awssdk.String(user),
		})
		if err != nil {
			return err
		}
	}

	return nil
}

func deleteUser(svc iamiface.IAMAPI, arn awsarn.ARN) (*awsiam.DeleteUserOutput, error) {

	res, err := svc.DeleteUser(&awsiam.DeleteUserInput{
		UserName: awssdk.String(FriendlyNamefromARN(arn)),
	})
	if err != nil {
		if err.(awserr.Error).Code() != awsiam.ErrCodeNoSuchEntityException {
			return nil, err
		}
	}

	return res, nil
}

func getUser(svc iamiface.IAMAPI, userArn awsarn.ARN) (*awsiam.GetUserOutput, error) {

	result, err := svc.GetUser(&awsiam.GetUserInput{
		UserName: awssdk.String(FriendlyNamefromARN(userArn)),
	})

	if err != nil {
		return nil, err
	}

	return result, nil
}

type LoginProfileCredentials struct {
	username string
	password string
}

func NewLoginProfileCredentials(user string, pass string) *LoginProfileCredentials {
	return &LoginProfileCredentials{
		username: user,
		password: pass,
	}
}

func (lpc *LoginProfileCredentials) Username() string {
	return lpc.username
}
func (lpc *LoginProfileCredentials) Password() string {
	return lpc.password
}

type AccessKey struct {
	id     string
	secret string
}

func NewAccessKey(id string, secret string) *AccessKey {
	return &AccessKey{
		id:     id,
		secret: secret,
	}
}

func (ak *AccessKey) Id() string {
	return ak.id
}
func (ak *AccessKey) Secret() string {
	return ak.secret
}

type UserInstance struct {
	Name                          string
	LoginProfile                  bool
	loginProfileCredentials       *LoginProfileCredentials
	existingLoginProfile          bool
	ProgrammaticAccess            bool
	existingAccessKey             bool
	programmaticAccessCredentials *AccessKey
	arn                           awsarn.ARN
}

func NewUserInstance(name string, loginProfile, programmaticAccess bool) *UserInstance {
	return &UserInstance{
		Name:               name,
		LoginProfile:       loginProfile,
		ProgrammaticAccess: programmaticAccess,
	}
}

func NewExistingUserInstance(name string, loginProfile, existingLoginProfile, programmaticAccess, existingAccessKey bool, arn awsarn.ARN) *UserInstance {
	return &UserInstance{
		Name:                 name,
		LoginProfile:         loginProfile,
		ProgrammaticAccess:   programmaticAccess,
		existingLoginProfile: existingLoginProfile,
		existingAccessKey:    existingAccessKey,
		arn:                  arn,
	}
}

// Create creates an AWS User
func (u *UserInstance) Create(svc iamiface.IAMAPI) error {
	var newarn awsarn.ARN
	out, err := createUser(svc, u.Name)
	if err != nil {
		return err
	}
	newarn, err = awsarn.Parse(awssdk.StringValue(out.User.Arn))
	if err != nil {
		return err
	}
	u.arn = newarn
	// Create Access if required
	if err = u.updateAccess(svc); err != nil {
		return err
	}
	return nil
}

func (u *UserInstance) Read(svc iamiface.IAMAPI) error {
	panic("Implement me")
	return nil
}

func (u *UserInstance) Update(svc iamiface.IAMAPI) error {
	if !u.IsCreated(svc) {
		return aws.NewInstanceNotYetCreatedError(fmt.Sprintf("User '%s' not yet created", u.Name))
	}

	_, err := updateUser(svc, u.Name, u.arn)
	if err != nil {
		return err
	}

	// Update Access if required
	if err = u.updateAccess(svc); err != nil {
		return err
	}

	return nil
}

func (u *UserInstance) Delete(svc iamiface.IAMAPI) error {
	if !u.IsCreated(svc) {
		return aws.NewInstanceNotYetCreatedError(fmt.Sprintf("User '%s' not yet created", u.Name))
	}

	if err := u.deleteAccess(svc); err != nil {
		return err
	}

	_, err := deleteUser(svc, u.arn)
	if err != nil {
		return err
	}

	return nil
}

func (u *UserInstance) ARN() awsarn.ARN {
	return u.arn
}

func (u *UserInstance) IsCreated(svc iamiface.IAMAPI) bool {
	return u.arn.String() != awsarn.ARN{}.String()
}

func (u *UserInstance) LoginProfileCredentials() *LoginProfileCredentials {
	return u.loginProfileCredentials
}

func (u *UserInstance) AccessKey() *AccessKey {
	return u.programmaticAccessCredentials
}

func (u *UserInstance) updateAccess(svc iamiface.IAMAPI) error {
	if u.LoginProfile && !u.existingLoginProfile {
		creds, err := createLoginProfile(svc, u.Name)
		if err != nil {
			return err
		}
		u.loginProfileCredentials = creds
	}
	if !u.LoginProfile && u.existingLoginProfile {
		if err := deleteLoginProfile(svc, u.arn); err != nil {
			return err
		}
		u.loginProfileCredentials = nil
	}
	if u.ProgrammaticAccess && !u.existingAccessKey {
		creds, err := createAccessKey(svc, u.Name)
		if err != nil {
			return err
		}
		u.programmaticAccessCredentials = creds
	}
	if !u.ProgrammaticAccess && u.existingAccessKey {
		if err := deleteAccessKeys(svc, u.arn); err != nil {
			return err
		}
	}

	return nil
}

func (u *UserInstance) deleteAccess(svc iamiface.IAMAPI) error {
	if u.existingLoginProfile {
		if err := deleteLoginProfile(svc, u.arn); err != nil {
			return err
		}
	}
	if u.existingAccessKey {
		if err := deleteAccessKeys(svc, u.arn); err != nil {
			return err
		}
	}
	return nil
}

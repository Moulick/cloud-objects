package iam

import (
	"fmt"
	"strings"
	"testing"

	awssdk "github.com/aws/aws-sdk-go/aws"
	awsarn "github.com/aws/aws-sdk-go/aws/arn"
	"github.com/aws/aws-sdk-go/aws/awserr"
	awsiam "github.com/aws/aws-sdk-go/service/iam"
	"github.com/stretchr/testify/assert"

	"github.com/redradrat/cloud-objects/aws"
)

///////////////
// IAM MOCKS //
///////////////

const (
	ReferenceRoleName            = "thisismyrole"
	ReferenceExistingRoleName    = "thisismyexistingrole"
	ReferenceRoleDescription     = "description"
	ReferenceRoleSessionDuration = 3600
	ReferenceRoleId              = "AROA1234567890EXAMPLE"
	ReferenceRegion              = "eu-west-1"
)

func (m *mockIAMClient) CreateRole(input *awsiam.CreateRoleInput) (*awsiam.CreateRoleOutput, error) {
	if *input.RoleName == ReferenceExistingRoleName {
		return nil, fmt.Errorf("Role already exists")
	}

	if strings.Contains(*input.RoleName, "/") {
		return nil, fmt.Errorf("malformed Role Name")
	}
	// Check if input values are still as we want them to be
	assert.Equal(m.t, getReferenceCreateRoleInput(), input)
	out := createMockCreateRoleOutput(input)
	return out, nil
}

func (m *mockIAMClient) UpdateRole(input *awsiam.UpdateRoleInput) (*awsiam.UpdateRoleOutput, error) {

	// Check if input values are still as we want them to be
	assert.Equal(m.t, getReferenceUpdateRoleInput(), input)

	return &awsiam.UpdateRoleOutput{}, nil
}

func (m *mockIAMClient) UpdateAssumeRolePolicy(input *awsiam.UpdateAssumeRolePolicyInput) (*awsiam.UpdateAssumeRolePolicyOutput, error) {

	// Check if input values are still as we want them to be
	assert.Equal(m.t, getReferenceUpdateAssumeRolePolicyInput(), input)

	return &awsiam.UpdateAssumeRolePolicyOutput{}, nil
}

func (m *mockIAMClient) DeleteRole(input *awsiam.DeleteRoleInput) (*awsiam.DeleteRoleOutput, error) {
	// Check if input values are still as we want them to be
	assert.Equal(m.t, awssdk.String(ReferenceExistingRoleName), input.RoleName)

	return &awsiam.DeleteRoleOutput{}, nil
}

func (m *mockIAMClient) GetRole(input *awsiam.GetRoleInput) (*awsiam.GetRoleOutput, error) {
	var ro *awsiam.GetRoleOutput
	if awssdk.StringValue(input.RoleName) == FriendlyNamefromARN(getReferenceRoleNonExistingArn()) {
		return ro, awserr.New(awsiam.ErrCodeNoSuchEntityException, "", fmt.Errorf("entity not found"))
	}

	assert.Equal(m.t, getReferenceGetRoleInput(), input)
	return createMockGetRoleOutput(input), nil
}

func createMockCreateRoleOutput(input *awsiam.CreateRoleInput) *awsiam.CreateRoleOutput {
	return &awsiam.CreateRoleOutput{
		Role: &awsiam.Role{
			Arn:                      awssdk.String(getReferencePolicyExistingArn().String()),
			AssumeRolePolicyDocument: input.AssumeRolePolicyDocument,
			CreateDate:               awssdk.Time(getReferenceCreateTimestamp()),
			Description:              input.Description,
			Path:                     input.Path,
			RoleId:                   awssdk.String(ReferenceRoleId),
			RoleLastUsed: &awsiam.RoleLastUsed{
				LastUsedDate: awssdk.Time(getReferenceUpdateTimestamp()),
				Region:       awssdk.String(ReferenceRegion),
			},
			RoleName: input.RoleName,
			Tags:     input.Tags,
		},
	}
}

func createMockGetRoleOutput(input *awsiam.GetRoleInput) *awsiam.GetRoleOutput {

	return &awsiam.GetRoleOutput{
		Role: &awsiam.Role{
			Arn:                      awssdk.String(getReferencePolicyExistingArn().String()),
			AssumeRolePolicyDocument: awssdk.String(string(getMarshaledReferencePolicyDocument())),
			CreateDate:               awssdk.Time(getReferenceCreateTimestamp()),
			Description:              awssdk.String(ReferenceRoleDescription),
			RoleId:                   awssdk.String(ReferenceRoleId),
			RoleLastUsed: &awsiam.RoleLastUsed{
				LastUsedDate: awssdk.Time(getReferenceUpdateTimestamp()),
				Region:       awssdk.String(ReferenceRegion),
			},
			RoleName: input.RoleName,
		},
	}
}

///////////
// TESTS //
///////////

func TestRoleInstance_Create(t *testing.T) {
	// Setup Test
	mockSvc := &mockIAMClient{t: t}

	pd := getReferencePolicyDocument()
	rolIns := NewRoleInstance(ReferenceRoleName, ReferenceRoleDescription, ReferenceRoleSessionDuration, pd)
	err := rolIns.Create(mockSvc)
	assert.NoError(t, err)
	assert.True(t, rolIns.IsCreated(mockSvc))

	rolIns = NewRoleInstance(ReferenceExistingRoleName, ReferenceRoleDescription, ReferenceRoleSessionDuration, pd)
	err = rolIns.Create(mockSvc)
	assert.Error(t, err)
}

func TestRoleInstance_Update(t *testing.T) {
	// Setup Test
	mockSvc := &mockIAMClient{t: t}

	pd := getReferencePolicyDocument()
	rolIns := NewRoleInstance(ReferenceRoleName, ReferenceRoleDescription, ReferenceRoleSessionDuration, pd)

	err := rolIns.Update(mockSvc)
	assert.Error(t, err)
	assert.True(t, err.(aws.InstanceError).IsOfErrorCode(aws.ErrAWSInstanceNotYetCreated))
	assert.False(t, rolIns.IsCreated(mockSvc))

	rolIns = NewExistingRoleInstance(ReferenceRoleName, ReferenceRoleDescription, ReferenceRoleSessionDuration, pd, getReferenceRoleExistingArn())
	err = rolIns.Update(mockSvc)
	assert.NoError(t, err)
}

func TestRoleInstance_Delete(t *testing.T) {
	// Setup Test
	mockSvc := &mockIAMClient{t: t}

	pd := getReferencePolicyDocument()
	rolIns := NewRoleInstance(ReferenceRoleName, ReferenceRoleDescription, ReferenceRoleSessionDuration, pd)

	err := rolIns.Delete(mockSvc)
	assert.Error(t, err)
	assert.True(t, err.(aws.InstanceError).IsOfErrorCode(aws.ErrAWSInstanceNotYetCreated))
	assert.False(t, rolIns.IsCreated(mockSvc))

	rolIns = NewExistingRoleInstance(ReferenceRoleName, ReferenceRoleDescription, ReferenceRoleSessionDuration, pd, getReferenceRoleExistingArn())
	err = rolIns.Delete(mockSvc)
	assert.NoError(t, err)
}

func TestNewRoleInstance(t *testing.T) {
	pi := NewRoleInstance(ReferenceRoleName, ReferenceRoleDescription, ReferenceRoleSessionDuration, getReferencePolicyDocument())
	assert.Equal(t, getReferenceRoleInstance(), pi)
}

func TestNewExistingRoleInstance(t *testing.T) {
	ri := NewExistingRoleInstance(ReferenceRoleName, ReferenceRoleDescription, ReferenceRoleSessionDuration, getReferencePolicyDocument(), getReferenceRoleExistingArn())
	riWithArn := getReferenceRoleInstance()
	riWithArn.arn = getReferenceRoleExistingArn()
	assert.Equal(t, riWithArn, ri)
}

func TestRoleInstance_ARN(t *testing.T) {
	assert.True(t, awsarn.IsARN(getReferenceRoleInstance().ARN().String()))
}

func TestRoleInstance_createRole(t *testing.T) {
	// Setup Test
	mockSvc := &mockIAMClient{t: t}

	_, err := createRole(mockSvc, "test/name", "test", 3600, getReferencePolicyDocument())
	assert.Error(t, err)
}

/////////////
// HELPERS //
/////////////

func getReferenceRoleExistingArn() awsarn.ARN {
	arn, _ := awsarn.Parse(fmt.Sprintf("arn:aws:iam::123456789012:role/%s", ReferenceExistingRoleName))
	return arn
}

func getReferenceRoleNonExistingArn() awsarn.ARN {
	arn, _ := awsarn.Parse(fmt.Sprintf("arn:aws:iam::123456789012:role/%s-NE", ReferenceRoleName))
	return arn
}

func getReferenceGetRoleInput() *awsiam.GetRoleInput {
	return &awsiam.GetRoleInput{RoleName: awssdk.String(ReferenceRoleName)}
}

func getReferenceCreateRoleInput() *awsiam.CreateRoleInput {
	return &awsiam.CreateRoleInput{
		AssumeRolePolicyDocument: awssdk.String(string(getMarshaledReferencePolicyDocument())),
		Description:              awssdk.String(ReferenceRoleDescription),
		MaxSessionDuration:       awssdk.Int64(ReferenceRoleSessionDuration),
		RoleName:                 awssdk.String(ReferenceRoleName),
	}
}

func getReferenceUpdateRoleInput() *awsiam.UpdateRoleInput {
	return &awsiam.UpdateRoleInput{
		Description: awssdk.String(ReferenceRoleDescription),
		RoleName:    awssdk.String(ReferenceExistingRoleName),
	}
}

func getReferenceUpdateAssumeRolePolicyInput() *awsiam.UpdateAssumeRolePolicyInput {
	return &awsiam.UpdateAssumeRolePolicyInput{
		RoleName:       awssdk.String(ReferenceExistingRoleName),
		PolicyDocument: awssdk.String(string(getMarshaledReferencePolicyDocument())),
	}
}

func getReferenceRoleInstance() *RoleInstance {
	return &RoleInstance{
		Name:               ReferenceRoleName,
		Description:        ReferenceRoleDescription,
		PolicyDocument:     getReferencePolicyDocument(),
		MaxSessionDuration: ReferenceRoleSessionDuration,
	}
}

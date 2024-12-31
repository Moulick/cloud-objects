package iam

import (
	"encoding/json"
	"fmt"

	awssdk "github.com/aws/aws-sdk-go/aws"
	awsarn "github.com/aws/aws-sdk-go/aws/arn"
	"github.com/aws/aws-sdk-go/aws/awserr"
	awsiam "github.com/aws/aws-sdk-go/service/iam"
	"github.com/aws/aws-sdk-go/service/iam/iamiface"

	"github.com/redradrat/cloud-objects/aws"
)

func createRole(svc iamiface.IAMAPI, rn string, roleDesc string, sessionDuration int64, pd PolicyDocument) (*awsiam.CreateRoleOutput, error) {

	b, err := json.Marshal(&pd)
	if err != nil {
		return nil, err
	}

	result, err := svc.CreateRole(&awsiam.CreateRoleInput{
		AssumeRolePolicyDocument: awssdk.String(string(b)),
		Description:              awssdk.String(roleDesc),
		MaxSessionDuration:       awssdk.Int64(sessionDuration),
		RoleName:                 awssdk.String(rn),
	})
	if err != nil {
		return nil, err
	}

	return result, nil
}

func updateRole(svc iamiface.IAMAPI, roleArn awsarn.ARN, roleDesc string, pd PolicyDocument) (*awsiam.UpdateRoleOutput, error) {

	result, err := svc.UpdateRole(&awsiam.UpdateRoleInput{
		RoleName:    awssdk.String(FriendlyNamefromARN(roleArn)),
		Description: awssdk.String(roleDesc),
	})
	if err != nil {
		return nil, err
	}
	// Update AssumeRolePolicy
	b, err := json.Marshal(&pd)
	if err != nil {
		return nil, err
	}

	_, err = svc.UpdateAssumeRolePolicy(&awsiam.UpdateAssumeRolePolicyInput{
		RoleName:       awssdk.String(FriendlyNamefromARN(roleArn)),
		PolicyDocument: awssdk.String(string(b)),
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

func deleteRole(svc iamiface.IAMAPI, roleArn awsarn.ARN) (*awsiam.DeleteRoleOutput, error) {

	res, err := svc.DeleteRole(&awsiam.DeleteRoleInput{
		RoleName: awssdk.String(FriendlyNamefromARN(roleArn)),
	})
	if err != nil {
		if err.(awserr.Error).Code() != awsiam.ErrCodeNoSuchEntityException {
			return nil, err
		}
	}

	return res, nil
}

func getRole(svc iamiface.IAMAPI, roleArn awsarn.ARN) (*awsiam.GetRoleOutput, error) {

	result, err := svc.GetRole(&awsiam.GetRoleInput{
		RoleName: awssdk.String(FriendlyNamefromARN(roleArn)),
	})

	if err != nil {
		return nil, err
	}

	return result, nil
}

func getRoleByName(roleName string, svc iamiface.IAMAPI) (*awsiam.GetRoleOutput, error) {

	result, err := svc.GetRole(&awsiam.GetRoleInput{
		RoleName: awssdk.String(roleName),
	})

	if err != nil {
		return nil, err
	}

	return result, nil
}

type RoleInstance struct {
	Name               string
	Description        string
	PolicyDocument     PolicyDocument
	MaxSessionDuration int64
	arn                awsarn.ARN
}

func NewRoleInstance(name string, description string, sessionDuration int64, poldoc PolicyDocument) *RoleInstance {
	return &RoleInstance{
		Name:               name,
		Description:        description,
		PolicyDocument:     poldoc,
		MaxSessionDuration: sessionDuration,
	}
}

func NewExistingRoleInstance(name string, description string, sessionDuration int64, poldoc PolicyDocument, arn awsarn.ARN) *RoleInstance {
	return &RoleInstance{
		Name:               name,
		Description:        description,
		PolicyDocument:     poldoc,
		MaxSessionDuration: sessionDuration,
		arn:                arn,
	}
}

// An old fetch implementation; abandoned due to sync problems
//func NewExistingRoleInstance(svc iamiface.IAMAPI, arn awsarn.ARN) (*RoleInstance, error) {
//	var ri *RoleInstance
//	emptyarn := awsarn.ARN{}.String()
//	if arn.String() == emptyarn {
//		return ri, fmt.Errorf("given ARN is empty")
//	}
//
//	out, err := getRole(svc, arn)
//	if err != nil {
//		return ri, err
//	}
//
//	var pd PolicyDocument
//	policyJson, err := url.QueryUnescape(awssdk.StringValue(out.Role.AssumeRolePolicyDocument))
//	if err != nil {
//		return ri, err
//	}
//	if err = json.Unmarshal([]byte(policyJson), &pd); err != nil {
//		return ri, err
//	}
//	ri = &RoleInstance{
//		Name:           awssdk.StringValue(out.Role.RoleName),
//		Description:    awssdk.StringValue(out.Role.Description),
//		PolicyDocument: pd,
//		arn:            arn,
//	}
//
//	return ri, nil
//}

// Reconcile creates or updates an AWS Role
func (r *RoleInstance) Create(svc iamiface.IAMAPI) error {
	var newarn awsarn.ARN
	out, err := createRole(svc, r.Name, r.Description, r.MaxSessionDuration, r.PolicyDocument)
	if err != nil {
		return err
	}
	newarn, err = awsarn.Parse(awssdk.StringValue(out.Role.Arn))
	if err != nil {
		return err
	}
	r.arn = newarn
	return nil
}

func (r *RoleInstance) Read(svc iamiface.IAMAPI) error {
	roleout, err := getRoleByName(r.Name, svc)
	if err != nil {
		return err
	}
	arns, err := aws.ARNify(awssdk.StringValue(roleout.Role.Arn))
	if err != nil {
		return err
	}
	r.arn = arns[0]
	r.Description = *roleout.Role.Description
	r.MaxSessionDuration = *roleout.Role.MaxSessionDuration
	r.Name = *roleout.Role.RoleName
	return nil
}

func (r *RoleInstance) Update(svc iamiface.IAMAPI) error {
	if !r.IsCreated(svc) {
		return aws.NewInstanceNotYetCreatedError(fmt.Sprintf("Role '%s' not yet created", r.Name))
	}

	_, err := updateRole(svc, r.arn, r.Description, r.PolicyDocument)
	if err != nil {
		return err
	}
	return nil
}

func (r *RoleInstance) Delete(svc iamiface.IAMAPI) error {
	if !r.IsCreated(svc) {
		return aws.NewInstanceNotYetCreatedError(fmt.Sprintf("Role '%s' not yet created", r.Name))
	}

	_, err := deleteRole(svc, r.arn)
	if err != nil {
		return err
	}
	return nil
}

func (r *RoleInstance) ARN() awsarn.ARN {
	return r.arn
}

func (r *RoleInstance) IsCreated(svc iamiface.IAMAPI) bool {
	return r.arn.String() != awsarn.ARN{}.String()
}

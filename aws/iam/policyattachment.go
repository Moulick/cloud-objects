package iam

import (
	"fmt"

	awssdk "github.com/aws/aws-sdk-go/aws"
	awsarn "github.com/aws/aws-sdk-go/aws/arn"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/aws/aws-sdk-go/service/iam/iamiface"

	"github.com/redradrat/cloud-objects/aws"
)

func createPolicyAttachment(svc iamiface.IAMAPI, attachType AttachmentType, policyArn, targetArn awsarn.ARN) error {
	var err error
	switch attachType {
	case RoleAttachmentType:
		_, err = svc.AttachRolePolicy(&iam.AttachRolePolicyInput{
			PolicyArn: awssdk.String(policyArn.String()),
			RoleName:  awssdk.String(FriendlyNamefromARN(targetArn)),
		})
	case UserAttachmentType:
		_, err = svc.AttachUserPolicy(&iam.AttachUserPolicyInput{
			PolicyArn: awssdk.String(policyArn.String()),
			UserName:  awssdk.String(FriendlyNamefromARN(targetArn)),
		})
	case GroupAttachmentType:
		_, err = svc.AttachGroupPolicy(&iam.AttachGroupPolicyInput{
			PolicyArn: awssdk.String(policyArn.String()),
			GroupName: awssdk.String(FriendlyNamefromARN(targetArn)),
		})
	default:
		return aws.NewInstanceError(ErrAttachmentTypeUnknown, fmt.Sprintf("unknown attachment type '%s", attachType))
	}
	if err != nil {
		return err
	}

	return nil
}

func deletePolicyAttachment(svc iamiface.IAMAPI, attachType AttachmentType, policyArn, targetArn awsarn.ARN) error {
	var err error

	switch attachType {
	case RoleAttachmentType:
		_, err = svc.DetachRolePolicy(&iam.DetachRolePolicyInput{
			PolicyArn: awssdk.String(policyArn.String()),
			RoleName:  awssdk.String(FriendlyNamefromARN(targetArn)),
		})
	case UserAttachmentType:
		_, err = svc.DetachUserPolicy(&iam.DetachUserPolicyInput{
			PolicyArn: awssdk.String(policyArn.String()),
			UserName:  awssdk.String(FriendlyNamefromARN(targetArn)),
		})
	case GroupAttachmentType:
		_, err = svc.DetachGroupPolicy(&iam.DetachGroupPolicyInput{
			PolicyArn: awssdk.String(policyArn.String()),
			GroupName: awssdk.String(FriendlyNamefromARN(targetArn)),
		})
	default:
		return aws.NewInstanceError(ErrAttachmentTypeUnknown, fmt.Sprintf("unknown attachment type '%s", attachType))
	}
	if err != nil {
		if err.(awserr.Error).Code() != iam.ErrCodeNoSuchEntityException {
			return err
		}
	}

	return nil
}
func getPolicyAttachment(svc iamiface.IAMAPI, attachType AttachmentType, policyArn, targetArn awsarn.ARN) (*iam.AttachedPolicy, error) {
	var aps []*iam.AttachedPolicy

	switch attachType {
	case RoleAttachmentType:
		out, err := svc.ListAttachedRolePolicies(&iam.ListAttachedRolePoliciesInput{
			RoleName: awssdk.String(FriendlyNamefromARN(targetArn)),
		})
		if err != nil {
			if err.(awserr.Error).Code() != iam.ErrCodeNoSuchEntityException {
				return nil, err
			}
		}
		aps = out.AttachedPolicies
	case UserAttachmentType:
		out, err := svc.ListAttachedUserPolicies(&iam.ListAttachedUserPoliciesInput{
			UserName: awssdk.String(FriendlyNamefromARN(targetArn)),
		})
		if err != nil {
			if err.(awserr.Error).Code() != iam.ErrCodeNoSuchEntityException {
				return nil, err
			}
		}
		aps = out.AttachedPolicies
	case GroupAttachmentType:
		out, err := svc.ListAttachedGroupPolicies(&iam.ListAttachedGroupPoliciesInput{
			GroupName: awssdk.String(FriendlyNamefromARN(targetArn)),
		})
		if err != nil {
			if err.(awserr.Error).Code() != iam.ErrCodeNoSuchEntityException {
				return nil, err
			}
		}
		aps = out.AttachedPolicies
	default:
		return nil, aws.NewInstanceError(ErrAttachmentTypeUnknown, fmt.Sprintf("unknown attachment type '%s", attachType))
	}

	for _, policy := range aps {
		if *policy.PolicyName == FriendlyNamefromARN(policyArn) {
			return policy, nil
		}
	}

	return nil, fmt.Errorf("policy not attached to specified target")
}

const (
	RoleAttachmentType       AttachmentType = "role"
	UserAttachmentType       AttachmentType = "user"
	GroupAttachmentType      AttachmentType = "group"
	ErrAttachmentTypeUnknown aws.ErrorCode  = "AttachmentType is unknown"
)

type AttachmentType string

type PolicyAttachmentInstance struct {
	PolicyRef awsarn.ARN
	Type      AttachmentType
	TargetRef awsarn.ARN
}

func NewPolicyAttachmentInstance(policyRef awsarn.ARN, attType AttachmentType, ref awsarn.ARN) *PolicyAttachmentInstance {
	return &PolicyAttachmentInstance{PolicyRef: policyRef, TargetRef: ref, Type: attType}
}

// Create attaches the referenced policy on referenced target type
func (pa *PolicyAttachmentInstance) Create(svc iamiface.IAMAPI) error {
	if err := createPolicyAttachment(svc, pa.Type, pa.PolicyRef, pa.TargetRef); err != nil {
		return err
	}
	return nil
}

func (pa *PolicyAttachmentInstance) Read(svc iamiface.IAMAPI) error {
	panic("Implement me")
}

// Update for PolicyAttachmentInstance doesn't do anything
func (pa *PolicyAttachmentInstance) Update(svc iamiface.IAMAPI) error {
	// PolicyAttachment not updateable
	return nil
}

// Delete removes the referenced Policy from referenced target type
func (pa *PolicyAttachmentInstance) Delete(svc iamiface.IAMAPI) error {
	if !pa.IsCreated(svc) {
		return aws.NewInstanceNotYetCreatedError("PolicyAttachment not yet created")
	}

	if err := deletePolicyAttachment(svc, pa.Type, pa.PolicyRef, pa.TargetRef); err != nil {
		return err
	}

	return nil
}

// Returns the target ARN when created
func (pa *PolicyAttachmentInstance) ARN() awsarn.ARN {
	return pa.TargetRef
}

func (pa *PolicyAttachmentInstance) IsCreated(svc iamiface.IAMAPI) bool {
	_, err := getPolicyAttachment(svc, pa.Type, pa.PolicyRef, pa.TargetRef)
	return err == nil
}

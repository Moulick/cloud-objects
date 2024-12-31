package iam

import (
	"fmt"

	awssdk "github.com/aws/aws-sdk-go/aws"
	awsarn "github.com/aws/aws-sdk-go/aws/arn"
	"github.com/aws/aws-sdk-go/aws/awserr"
	awsiam "github.com/aws/aws-sdk-go/service/iam"
	"github.com/aws/aws-sdk-go/service/iam/iamiface"

	"github.com/redradrat/cloud-objects/aws"
)

func createGroup(svc iamiface.IAMAPI, gn string) (*awsiam.CreateGroupOutput, error) {

	result, err := svc.CreateGroup(&awsiam.CreateGroupInput{
		GroupName: awssdk.String(gn),
	})
	if err != nil {
		return nil, err
	}

	return result, nil
}

func updateGroup(svc iamiface.IAMAPI, groupName string, groupArn awsarn.ARN) (*awsiam.UpdateGroupOutput, error) {

	result, err := svc.UpdateGroup(&awsiam.UpdateGroupInput{
		GroupName:    awssdk.String(FriendlyNamefromARN(groupArn)),
		NewGroupName: awssdk.String(groupName),
	})
	if err != nil {
		return nil, err
	}

	return result, nil
}

func deleteGroup(svc iamiface.IAMAPI, groupArn awsarn.ARN) (*awsiam.DeleteGroupOutput, error) {

	getGroupOutput, err := svc.GetGroup(&awsiam.GetGroupInput{
		GroupName: awssdk.String(FriendlyNamefromARN(groupArn)),
	})
	if err != nil {
		return nil, err
	}

	for _, user := range getGroupOutput.Users {
		userArn, err := awsarn.Parse(*user.Arn)
		if err != nil {
			return nil, err
		}

		if err := removeUserFromGroup(svc, userArn, groupArn); err != nil {
			return nil, err
		}
	}

	res, err := svc.DeleteGroup(&awsiam.DeleteGroupInput{
		GroupName: awssdk.String(FriendlyNamefromARN(groupArn)),
	})
	if err != nil {
		if err.(awserr.Error).Code() != awsiam.ErrCodeNoSuchEntityException {
			return nil, err
		}
	}

	return res, nil
}

func getGroup(svc iamiface.IAMAPI, groupArn awsarn.ARN) (*awsiam.GetGroupOutput, error) {

	result, err := svc.GetGroup(&awsiam.GetGroupInput{
		GroupName: awssdk.String(FriendlyNamefromARN(groupArn)),
	})

	if err != nil {
		return nil, err
	}

	return result, nil
}

func addUserToGroup(svc iamiface.IAMAPI, userArn, groupArn awsarn.ARN) error {
	_, err := svc.AddUserToGroup(&awsiam.AddUserToGroupInput{
		GroupName: awssdk.String(FriendlyNamefromARN(groupArn)),
		UserName:  awssdk.String(FriendlyNamefromARN(userArn)),
	})
	if err != nil && !aws.IsAlreadyExistsError(err) {
		return err
	}

	return nil
}

func removeUserFromGroup(svc iamiface.IAMAPI, userArn, groupArn awsarn.ARN) error {
	_, err := svc.RemoveUserFromGroup(&awsiam.RemoveUserFromGroupInput{
		GroupName: awssdk.String(FriendlyNamefromARN(groupArn)),
		UserName:  awssdk.String(FriendlyNamefromARN(userArn)),
	})
	if err != nil && !aws.IsNotExistsError(err) {
		return err
	}

	return nil
}

type GroupInstance struct {
	Name string
	arn  awsarn.ARN
}

func NewGroupInstance(name string) *GroupInstance {
	return &GroupInstance{Name: name}
}

func NewExistingGroupInstance(name string, arn awsarn.ARN) *GroupInstance {
	return &GroupInstance{
		Name: name,
		arn:  arn,
	}
}

// Create an AWS Group
func (g *GroupInstance) Create(svc iamiface.IAMAPI) error {
	var newarn awsarn.ARN
	out, err := createGroup(svc, g.Name)
	if err != nil {
		return err
	}
	newarn, err = awsarn.Parse(awssdk.StringValue(out.Group.Arn))
	if err != nil {
		return err
	}
	g.arn = newarn
	return nil
}

func (g *GroupInstance) Read(svc iamiface.IAMAPI) error {
	panic("Implement me")
	return nil
}

func (g *GroupInstance) Update(svc iamiface.IAMAPI) error {
	if !g.IsCreated(svc) {
		return aws.NewInstanceNotYetCreatedError(fmt.Sprintf("Group '%s' not yet created", g.Name))
	}

	_, err := updateGroup(svc, g.Name, g.arn)
	if err != nil {
		return err
	}
	return nil
}

func (g *GroupInstance) Delete(svc iamiface.IAMAPI) error {
	if !g.IsCreated(svc) {
		return aws.NewInstanceNotYetCreatedError(fmt.Sprintf("Group '%s' not yet created", g.Name))
	}

	_, err := deleteGroup(svc, g.arn)
	if err != nil {
		return err
	}
	return nil
}

func (g *GroupInstance) ARN() awsarn.ARN {
	return g.arn
}

func (g *GroupInstance) IsCreated(svc iamiface.IAMAPI) bool {
	return g.arn.String() != awsarn.ARN{}.String()
}

func (g *GroupInstance) AddUser(svc iamiface.IAMAPI, userArn awsarn.ARN) error {
	if !g.IsCreated(svc) {
		return aws.NewInstanceNotYetCreatedError(fmt.Sprintf("Group '%s' not yet created", g.Name))
	}
	return addUserToGroup(svc, userArn, g.arn)
}

func (g *GroupInstance) RemoveUser(svc iamiface.IAMAPI, userArn awsarn.ARN) error {
	if !g.IsCreated(svc) {
		return aws.NewInstanceNotYetCreatedError(fmt.Sprintf("Group '%s' not yet created", g.Name))
	}
	return removeUserFromGroup(svc, userArn, g.arn)
}

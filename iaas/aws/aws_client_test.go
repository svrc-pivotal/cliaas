package aws_test

import (
	"errors"

	iaasaws "github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/c0-ops/cliaas/iaas"
	. "github.com/c0-ops/cliaas/iaas/aws"
	"github.com/c0-ops/cliaas/iaas/aws/awsfakes"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Aws Client", func() {
	Describe("AWSClientAPI", func() {
		var client *AWSClientAPI
		var err error

		Describe("given a GetVMInfo method", func() {
			Context("when called with a valid filter", func() {
				var fakeAWSClient *awsfakes.FakeAWSClient
				BeforeEach(func() {
					fakeAWSClient = new(awsfakes.FakeAWSClient)
					client, err = NewAWSClientAPI(
						ConfigAWSClient(fakeAWSClient),
						ConfigVPC("some vpc"),
					)
					Expect(client).ShouldNot(BeNil())
				})

				It("then the instance should be found", func() {
					instanceList := []*ec2.Instance{&ec2.Instance{}}
					fakeAWSClient.ListReturns(instanceList, nil)
					instance, err := client.GetVMInfo(iaas.Filter{NameRegexString: "Test*"})
					Expect(err).ShouldNot(HaveOccurred())
					Expect(instance).ShouldNot(BeNil())
				})

				It("then error when no instances", func() {
					instanceList := []*ec2.Instance{}
					fakeAWSClient.ListReturns(instanceList, nil)
					instance, err := client.GetVMInfo(iaas.Filter{NameRegexString: "Test*"})
					Expect(err).Should(HaveOccurred())
					Expect(err.Error()).Should(BeEquivalentTo("No instance matches found"))
					Expect(instance).Should(BeNil())
				})
				It("then error when more than 1 instance", func() {
					instanceList := []*ec2.Instance{&ec2.Instance{}, &ec2.Instance{}}
					fakeAWSClient.ListReturns(instanceList, nil)
					instance, err := client.GetVMInfo(iaas.Filter{NameRegexString: "Test*"})
					Expect(err).Should(HaveOccurred())
					Expect(err.Error()).Should(BeEquivalentTo("Found more than one match"))
					Expect(instance).Should(BeNil())
				})

				It("then error when error is returned", func() {
					fakeAWSClient.ListReturns(nil, errors.New("got an error"))
					instance, err := client.GetVMInfo(iaas.Filter{NameRegexString: "Test*"})
					Expect(err).Should(HaveOccurred())
					Expect(err.Error()).Should(BeEquivalentTo("call List on aws client failed: got an error"))
					Expect(instance).Should(BeNil())
				})
			})
		})

		Describe("given a Stop method", func() {
			Context("when called", func() {
				var fakeAWSClient *awsfakes.FakeAWSClient
				BeforeEach(func() {
					fakeAWSClient = new(awsfakes.FakeAWSClient)
					client, err = NewAWSClientAPI(
						ConfigAWSClient(fakeAWSClient),
						ConfigVPC("some vpc"),
					)
					Expect(client).ShouldNot(BeNil())
				})

				It("then the instance should be stopped", func() {
					fakeAWSClient.StopReturns(nil)
					err := client.StopVM(ec2.Instance{InstanceId: iaasaws.String("foo")})
					Expect(err).ToNot(HaveOccurred())
					Expect(fakeAWSClient.StopCallCount()).Should(BeEquivalentTo(1))
					instanceID := fakeAWSClient.StopArgsForCall(0)
					Expect(instanceID).Should(BeEquivalentTo("foo"))
				})
				It("then it should error", func() {
					fakeAWSClient.StopReturns(errors.New("got an error"))
					err := client.StopVM(ec2.Instance{InstanceId: iaasaws.String("foo")})
					Expect(err).To(HaveOccurred())
					Expect(err.Error()).Should(BeEquivalentTo("call stop on aws client failed: got an error"))
					instanceID := fakeAWSClient.StopArgsForCall(0)
					Expect(instanceID).Should(BeEquivalentTo("foo"))
				})
			})
		})
		Describe("given a Delete method", func() {
			Context("when called", func() {
				var fakeAWSClient *awsfakes.FakeAWSClient
				BeforeEach(func() {
					fakeAWSClient = new(awsfakes.FakeAWSClient)
					client, err = NewAWSClientAPI(
						ConfigAWSClient(fakeAWSClient),
						ConfigVPC("some vpc"),
					)
					Expect(client).ShouldNot(BeNil())
				})

				It("then the instance should be stopped", func() {
					fakeAWSClient.DeleteReturns(nil)
					err := client.DeleteVM(ec2.Instance{InstanceId: iaasaws.String("foo")})
					Expect(err).ToNot(HaveOccurred())
					Expect(fakeAWSClient.DeleteCallCount()).Should(BeEquivalentTo(1))
					instanceID := fakeAWSClient.DeleteArgsForCall(0)
					Expect(instanceID).Should(BeEquivalentTo("foo"))
				})
				It("then it should error", func() {
					fakeAWSClient.DeleteReturns(errors.New("got an error"))
					err := client.DeleteVM(ec2.Instance{InstanceId: iaasaws.String("foo")})
					Expect(err).To(HaveOccurred())
					Expect(err.Error()).Should(BeEquivalentTo("call delete on aws client failed: got an error"))
					instanceID := fakeAWSClient.DeleteArgsForCall(0)
					Expect(instanceID).Should(BeEquivalentTo("foo"))
				})
			})
		})
	})
})
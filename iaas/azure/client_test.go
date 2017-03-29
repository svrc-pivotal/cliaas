package azure_test

import (
	"errors"

	"github.com/Azure/azure-sdk-for-go/arm/compute"
	"github.com/Azure/go-autorest/autorest"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/pivotal-cf/cliaas/iaas/azure"
	"github.com/pivotal-cf/cliaas/iaas/azure/azurefakes"
	errwrap "github.com/pkg/errors"
)

var _ = Describe("Azure", func() {
	Describe("Client", func() {
		Describe("Replace()", func() {
			/*
				given a call to replace with a valid identifier and a valid vhdURL
				when there is a single match on a identifier regex
				then it should spin down the matching vm and
					copy its config and
					apply its config to a new vm object and
					replace the new vm objects Disk image with the given vhdURL and
					start the new instance of the vm with a name using a standard convention
			*/

			Context("when there is a single match on a identifier regex", func() {
				It("it should spin down the matching vm instance", func() {
					//Expect()
				})
				It("it should copy the existing vms config into the new vm instance's config ", func() {})
				It("it should replace the disk image on the new vm instance's config with the given new version", func() {})
				It("it should apply a new unique name to the new vm instance's config", func() {})
				It("it should start a vm using the new vm instance's config", func() {})
			})

			XContext("when there are no matches for the identifier regex", func() {

			})

			XContext("when there are multiple matches for the identifier regex", func() {

			})
		})

		Describe("Delete()", func() {
			var azureClient *azure.Client
			var err error
			var identifier string
			var fakeVirtualMachinesClient *azurefakes.FakeComputeVirtualMachinesClient

			JustBeforeEach(func() {
				azureClient.VirtualMachinesClient = fakeVirtualMachinesClient
				err = azureClient.Delete(identifier)
			})

			XContext("when azure running VMs list returns more than a single page of results", func() {
				It("then we should properly walk through all pages to apply our regex", func() {
					Expect(true).Should(BeFalse())
				})
			})

			Context("when given an identifier with a single match of VM name on our regex", func() {
				controlRegex := "ops*"
				BeforeEach(func() {
					fakeVirtualMachinesClient = new(azurefakes.FakeComputeVirtualMachinesClient)
					controlValue := make([]compute.VirtualMachine, 0)
					controlName := "ops-manager"
					controlValue = append(controlValue, compute.VirtualMachine{
						Name: &controlName,
					})
					fakeVirtualMachinesClient.ListReturns(compute.VirtualMachineListResult{Value: &controlValue}, nil)
					fakeVirtualMachinesClient.DeleteReturns(autorest.Response{}, nil)
					azureClient = new(azure.Client)
					identifier = controlRegex
				})
				It("should delete the VM instance", func() {
					Expect(err).ShouldNot(HaveOccurred())
					Expect(fakeVirtualMachinesClient.DeleteCallCount()).Should(Equal(1))
					_, vmName, _ := fakeVirtualMachinesClient.DeleteArgsForCall(0)
					Expect(vmName).Should(MatchRegexp(controlRegex))
					var deleteErr error
					fakeVirtualMachinesClient.DeleteReturnsOnCall(1, autorest.Response{}, deleteErr)
					Expect(deleteErr).ShouldNot(HaveOccurred())
				})
			})

			Context("when unable to list (failed api call) existing VMs to match against", func() {
				controlErr := errors.New("random list err")
				BeforeEach(func() {
					fakeVirtualMachinesClient = new(azurefakes.FakeComputeVirtualMachinesClient)
					fakeVirtualMachinesClient.ListReturns(compute.VirtualMachineListResult{}, controlErr)
					azureClient = new(azure.Client)
					identifier = "ops-manager"
				})
				It("should not delete any VM instances and should exit unsuccessfully", func() {
					Expect(fakeVirtualMachinesClient.DeleteCallCount()).Should(Equal(0), "the number of times deletes gets called should be zero")
					Expect(err).Should(HaveOccurred())
					Expect(errwrap.Cause(err)).Should(Equal(controlErr))
				})
			})

			Context("when given an identifier and no VMs are found in Azure (vm empty set)", func() {
				BeforeEach(func() {
					fakeVirtualMachinesClient = new(azurefakes.FakeComputeVirtualMachinesClient)
					controlValue := make([]compute.VirtualMachine, 0)
					fakeVirtualMachinesClient.ListReturns(compute.VirtualMachineListResult{Value: &controlValue}, nil)
					azureClient = new(azure.Client)
					identifier = "ops-manager"
				})
				It("should not delete any VM instances and should exit unsuccessfully", func() {
					Expect(fakeVirtualMachinesClient.DeleteCallCount()).Should(Equal(0), "the number of times deletes gets called should be zero")
					Expect(err).Should(HaveOccurred())
					Expect(errwrap.Cause(err)).Should(Equal(azure.NoMatchesErr))
				})
			})

			Context("when given an identifier with a populated VMs list from azure and no matching VM name regex", func() {
				BeforeEach(func() {
					fakeVirtualMachinesClient = new(azurefakes.FakeComputeVirtualMachinesClient)
					controlValue := make([]compute.VirtualMachine, 0)
					controlName := "blah"
					controlValue = append(controlValue, compute.VirtualMachine{
						Name: &controlName,
					})
					fakeVirtualMachinesClient.ListReturns(compute.VirtualMachineListResult{Value: &controlValue}, nil)
					azureClient = new(azure.Client)
					identifier = "ops-manager"
				})
				It("should not delete any VM instances and should exit unsuccessfully", func() {
					Expect(fakeVirtualMachinesClient.DeleteCallCount()).Should(Equal(0), "the number of times deletes gets called should be zero")
					Expect(err).Should(HaveOccurred())
					Expect(errwrap.Cause(err)).Should(Equal(azure.NoMatchesErr))
				})
			})

			Context("when given an identifier with multiple matches on VM name from our regex", func() {
				BeforeEach(func() {
					fakeVirtualMachinesClient = new(azurefakes.FakeComputeVirtualMachinesClient)
					controlValue := make([]compute.VirtualMachine, 0)
					controlName := "ops-manager"
					controlValue = append(controlValue, compute.VirtualMachine{
						Name: &controlName,
					})
					controlValue = append(controlValue, compute.VirtualMachine{
						Name: &controlName,
					})
					fakeVirtualMachinesClient.ListReturns(compute.VirtualMachineListResult{Value: &controlValue}, nil)
					azureClient = new(azure.Client)
					identifier = "ops*"
				})
				It("should not delete any VM instances and should exit unsuccessfully", func() {
					Expect(fakeVirtualMachinesClient.DeleteCallCount()).Should(Equal(0), "the number of times deletes gets called should be zero")
					Expect(err).Should(HaveOccurred())
					Expect(errwrap.Cause(err)).Should(Equal(azure.MultipleMatchesErr))
				})
			})
		})
	})

	Describe("NewClient", func() {
		var azureClient *azure.Client
		var err error
		var subID string
		var clientID string
		var clientSecret string
		var tenantID string
		var resourceGroupName string
		var resourceManagerEndpoint string

		JustBeforeEach(func() {
			azureClient, err = azure.NewClient(
				subID,
				clientID,
				clientSecret,
				tenantID,
				resourceGroupName,
				resourceManagerEndpoint,
			)
		})

		Context("when provided a valid set of configuration values", func() {
			BeforeEach(func() {
				subID = "asdf"
				clientID = "asdf"
				clientSecret = "asdf"
				tenantID = "asdf"
				resourceGroupName = "asdf"
				resourceManagerEndpoint = ""
			})
			It("should return a azure client", func() {
				Expect(err).ShouldNot(HaveOccurred())
				Expect(azureClient).ShouldNot(BeNil())
			})
		})

		Context("when provided a invalid set of configuration values", func() {
			BeforeEach(func() {
				subID = ""
				clientID = ""
				clientSecret = ""
				tenantID = ""
				resourceGroupName = ""
			})
			It("should return an error that the client was not able to be created", func() {
				Expect(err).Should(HaveOccurred())
				Expect(azureClient).Should(BeNil())
			})
		})
	})
})
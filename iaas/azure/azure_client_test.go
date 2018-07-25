package azure_test

import (
	"errors"
	"fmt"

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
		var controlDiskSize = int32(10)
		Describe("Replace() unmanaged disk", func() {
			var azureClient *azure.Client
			var err error
			var identifier string
			var fakeVirtualMachinesClient *azurefakes.FakeComputeVirtualMachinesClient
			var fakeBlobServiceClient *azurefakes.FakeBlobCopier
			var controlNewImageURL = "some-control-new-image-url"
			var controlRegex = "ops*"
			var controlValue []compute.VirtualMachine
			var controlID = "some-id"
			var controlOldImageURL = "some-image-url"
			var controlOldName = "ops-manager"
			var controlContainerName = "mycontainer"
			var controlStorageAccountName = "myaccount"
			var controlNewImageLocalContainerURL = fmt.Sprintf("https://%s.blob.core.windows.net/%s/%s", controlStorageAccountName, controlContainerName, controlOldName+"_....*")

			JustBeforeEach(func() {
				fakeVirtualMachinesClient.ListReturns(compute.VirtualMachineListResult{Value: &controlValue}, nil)
				fakeVirtualMachinesClient.DeallocateReturns(autorest.Response{}, nil)
				azureClient = new(azure.Client)
				identifier = controlRegex
				azureClient.VirtualMachinesClient = fakeVirtualMachinesClient
				azureClient.BlobServiceClient = fakeBlobServiceClient
				azureClient.SetStorageAccountName(controlStorageAccountName)
				azureClient.SetStorageContainerName(controlContainerName)
				azureClient.SetStorageBaseURL(azure.DefaultBaseURL)
				err = azureClient.Replace(identifier, controlNewImageURL, int64(controlDiskSize))
			})

			BeforeEach(func() {
				controlValue = make([]compute.VirtualMachine, 0)
			})

			Context("when there is a single match on a identifier regex", func() {
				controlNewNameRegex := controlOldName + "_....*"
				BeforeEach(func() {
					fakeVirtualMachinesClient = new(azurefakes.FakeComputeVirtualMachinesClient)
					fakeBlobServiceClient = new(azurefakes.FakeBlobCopier)
					vm := newVirtualMachine(controlID, controlOldName, controlOldImageURL, "nil", controlDiskSize)
					fakeVirtualMachinesClient.GetReturns(vm, nil)
					controlValue = append(controlValue, vm)
				})

				It("should not return an error", func() {
					Expect(err).ShouldNot(HaveOccurred())
				})

				It("should never pass any resources when creating the new instance", func() {
					Expect(fakeVirtualMachinesClient.CreateOrUpdateCallCount()).Should(Equal(1), "we should have called CreateOrUpdate exactly once")
					_, _, instance, _ := fakeVirtualMachinesClient.CreateOrUpdateArgsForCall(0)
					Expect(instance.Resources).Should(BeNil(), "instance resources need to be purged or azure will fail on large sets")
				})

				It("should copy the blob from the given public vhd URL into our local account's blob service container", func() {
					Expect(fakeBlobServiceClient.CopyBlobCallCount()).Should(Equal(1), "we should have called CopyBlob exactly once")
					container, localImageFilename, sourceBlob := fakeBlobServiceClient.CopyBlobArgsForCall(0)
					Expect(container).Should(Equal(controlContainerName))
					Expect(localImageFilename).Should(MatchRegexp(controlNewNameRegex))
					Expect(sourceBlob).Should(Equal(controlNewImageURL))
				})

				It("should spin down & delete the matching vm instance", func() {
					Expect(fakeVirtualMachinesClient.DeallocateCallCount()).Should(Equal(1), "we should call deallocate exactly once")
					_, vmName, _ := fakeVirtualMachinesClient.DeallocateArgsForCall(0)
					Expect(vmName).Should(MatchRegexp(controlRegex))
					var deallocateErr error
					fakeVirtualMachinesClient.DeallocateReturnsOnCall(1, autorest.Response{}, deallocateErr)
					Expect(deallocateErr).ShouldNot(HaveOccurred())

					Expect(fakeVirtualMachinesClient.DeleteCallCount()).Should(Equal(1), "we should call delete exactly once")
					_, vmName, _ = fakeVirtualMachinesClient.DeleteArgsForCall(0)
					Expect(vmName).Should(MatchRegexp(controlRegex))
				})

				It("should copy the existing vms config into the new vm instance's config ", func() {
					Expect(fakeVirtualMachinesClient.CreateOrUpdateCallCount()).Should(Equal(1), "we should call createorupdate exactly once")
					_, _, parameters, _ := fakeVirtualMachinesClient.CreateOrUpdateArgsForCall(0)
					Expect(*parameters.ID).Should(Equal(controlID))
				})

				/* TODO: the parameters in this function are not being properly tested.
				 * parameters is being set by the fake when the function called (proper behavior)
				 * however, the arguments we are passing from our mock vm are being converted into the parameters
				 * read by the client, even when the client does nothing with them
				 */
				It("should replace the disk image on the new vm instance's config with the local copy of the given Public VHD", func() {
					Expect(fakeVirtualMachinesClient.CreateOrUpdateCallCount()).Should(Equal(1), "we should call createorupdate exactly once")
					_, _, parameters, _ := fakeVirtualMachinesClient.CreateOrUpdateArgsForCall(0)
					var imageURL = *parameters.VirtualMachineProperties.StorageProfile.OsDisk.Image.URI
					var imageDiskSize = *parameters.VirtualMachineProperties.StorageProfile.OsDisk.DiskSizeGB
					Expect(imageURL).ShouldNot(Equal(controlOldImageURL))
					Expect(imageURL).ShouldNot(Equal(controlNewImageURL))
					Expect(imageURL).Should(MatchRegexp(controlNewImageLocalContainerURL))
					Expect(imageDiskSize).Should(Equal(controlDiskSize))
				})

				It("should apply a new unique name to the new vm instance's config", func() {
					Expect(fakeVirtualMachinesClient.CreateOrUpdateCallCount()).Should(Equal(1), "we should call createorupdate exactly once")
					_, _, parameters, _ := fakeVirtualMachinesClient.CreateOrUpdateArgsForCall(0)
					var name = *parameters.Name
					Expect(name).ShouldNot(Equal(controlOldName))
					Expect(name).Should(MatchRegexp(controlNewNameRegex))
				})
			})

			Context("when there are no matches for the identifier regex", func() {
				BeforeEach(func() {
					fakeVirtualMachinesClient = new(azurefakes.FakeComputeVirtualMachinesClient)
				})
				It("should not try to deallocate anything and exit in error", func() {
					Expect(fakeVirtualMachinesClient.DeallocateCallCount()).Should(Equal(0), "we should never call deallocate without a matching VM")
					Expect(err).Should(HaveOccurred())
					Expect(errwrap.Cause(err)).Should(Equal(azure.NoMatchesErr))
				})
			})

			Context("when there are multiple matches for the identifier regex", func() {
				BeforeEach(func() {
					fakeVirtualMachinesClient = new(azurefakes.FakeComputeVirtualMachinesClient)
					vm := newVirtualMachine(controlID, controlOldName, controlOldImageURL, "nil", controlDiskSize)
					controlValue = append(controlValue, vm, vm)
				})

				It("should not try to deallocate anything and exit in error", func() {
					Expect(fakeVirtualMachinesClient.DeallocateCallCount()).Should(Equal(0), "we should never call deallocate without a matching VM")
					Expect(err).Should(HaveOccurred())
					Expect(errwrap.Cause(err)).Should(Equal(azure.MultipleMatchesErr))
				})
			})
		})

		Describe("Replace() managed disk", func() {
			var azureClient *azure.Client
			var err error
			var identifier string
			var fakeVirtualMachinesClient *azurefakes.FakeComputeVirtualMachinesClient
			var fakeBlobServiceClient *azurefakes.FakeBlobCopier
			var fakeImageServiceClient *azurefakes.FakeComputeImagesClient
			var controlNewImageURL = "some-control-new-image-url"
			var controlRegex = "ops*"
			var controlValue []compute.VirtualMachine
			var controlID = "some-id"
			//var controlOldImageURL = "some-image-url"
			var controlManagedImageName = "some-managed-image"
			var controlOldName = "ops-manager"
			var controlContainerName = "mycontainer"
			var controlStorageAccountName = "myaccount"
			//var controlNewImageLocalContainerURL = fmt.Sprintf("https://%s.blob.core.windows.net/%s/%s", controlStorageAccountName, controlContainerName, controlOldName+"_....*")

			JustBeforeEach(func() {
				fakeVirtualMachinesClient.ListReturns(compute.VirtualMachineListResult{Value: &controlValue}, nil)
				fakeVirtualMachinesClient.DeallocateReturns(autorest.Response{}, nil)
				azureClient = new(azure.Client)
				identifier = controlRegex
				azureClient.VirtualMachinesClient = fakeVirtualMachinesClient
				azureClient.BlobServiceClient = fakeBlobServiceClient
				azureClient.ImagesClient = fakeImageServiceClient
				azureClient.SetStorageAccountName(controlStorageAccountName)
				azureClient.SetStorageContainerName(controlContainerName)
				azureClient.SetStorageBaseURL(azure.DefaultBaseURL)
				err = azureClient.Replace(identifier, controlNewImageURL, int64(controlDiskSize))
			})

			BeforeEach(func() {
				controlValue = make([]compute.VirtualMachine, 0)
			})

			Context("when there is a single match on a identifier regex", func() {
				controlNewNameRegex := controlOldName + "_....*"
				BeforeEach(func() {
					fakeVirtualMachinesClient = new(azurefakes.FakeComputeVirtualMachinesClient)
					fakeBlobServiceClient = new(azurefakes.FakeBlobCopier)
					fakeImageServiceClient = new(azurefakes.FakeComputeImagesClient)
					vm := newVirtualMachine(controlID, controlOldName, "nil", controlManagedImageName, controlDiskSize)
					fakeVirtualMachinesClient.GetReturns(vm, nil)
					controlValue = append(controlValue, vm)
				})

				It("should not return an error", func() {
					Expect(err).ShouldNot(HaveOccurred())
				})

				It("should never pass any resources when creating the new instance", func() {
					Expect(fakeVirtualMachinesClient.CreateOrUpdateCallCount()).Should(Equal(1), "we should have called CreateOrUpdate exactly once")
					_, _, instance, _ := fakeVirtualMachinesClient.CreateOrUpdateArgsForCall(0)
					Expect(instance.Resources).Should(BeNil(), "instance resources need to be purged or azure will fail on large sets")
				})

				It("should copy the blob from the given public vhd URL into our local account's blob service container", func() {
					Expect(fakeBlobServiceClient.CopyBlobCallCount()).Should(Equal(1), "we should have called CopyBlob exactly once")
					container, localImageFilename, sourceBlob := fakeBlobServiceClient.CopyBlobArgsForCall(0)
					Expect(container).Should(Equal(controlContainerName))
					Expect(localImageFilename).Should(MatchRegexp(controlNewNameRegex))
					Expect(sourceBlob).Should(Equal(controlNewImageURL))
				})

				It("should create a new managed image from the given public vhd URL", func() {
					Expect(fakeImageServiceClient.CreateOrUpdateCallCount()).Should(Equal(1), "we should call createorupdate exactly once")
					_, localManagedImageName, _, _ := fakeImageServiceClient.CreateOrUpdateArgsForCall(0)
					Expect(localManagedImageName).Should(MatchRegexp(controlRegex))
				})

				It("should spin down & delete the matching vm instance", func() {
					Expect(fakeVirtualMachinesClient.DeallocateCallCount()).Should(Equal(1), "we should call deallocate exactly once")
					_, vmName, _ := fakeVirtualMachinesClient.DeallocateArgsForCall(0)
					Expect(vmName).Should(MatchRegexp(controlRegex))
					var deallocateErr error
					fakeVirtualMachinesClient.DeallocateReturnsOnCall(1, autorest.Response{}, deallocateErr)
					Expect(deallocateErr).ShouldNot(HaveOccurred())

					Expect(fakeVirtualMachinesClient.DeleteCallCount()).Should(Equal(1), "we should call delete exactly once")
					_, vmName, _ = fakeVirtualMachinesClient.DeleteArgsForCall(0)
					Expect(vmName).Should(MatchRegexp(controlRegex))
				})

				It("should copy the existing vms config into the new vm instance's config ", func() {
					Expect(fakeVirtualMachinesClient.CreateOrUpdateCallCount()).Should(Equal(1), "we should call createorupdate exactly once")
					_, _, parameters, _ := fakeVirtualMachinesClient.CreateOrUpdateArgsForCall(0)
					Expect(*parameters.ID).Should(Equal(controlID))
				})

				/* TODO: the parameters in this function are not being properly tested.
				 * parameters is being set by the fake when the function called (proper behavior)
				 * however, the arguments we are passing from our mock vm are being converted into the parameters
				 * read by the client, even when the client does nothing with them
				 */
				It("should replace the disk image on the new vm instance's config with the local copy of the given Public VHD", func() {
					Expect(fakeVirtualMachinesClient.CreateOrUpdateCallCount()).Should(Equal(1), "we should call createorupdate exactly once")
					_, _, parameters, _ := fakeVirtualMachinesClient.CreateOrUpdateArgsForCall(0)
					var managedImageID = *parameters.VirtualMachineProperties.StorageProfile.ImageReference.ID
					var imageDiskSize = *parameters.VirtualMachineProperties.StorageProfile.OsDisk.DiskSizeGB
					Expect(managedImageID).Should(MatchRegexp(controlNewNameRegex))
					Expect(imageDiskSize).Should(Equal(controlDiskSize))
				})

				It("should apply a new unique name to the new vm instance's config", func() {
					Expect(fakeVirtualMachinesClient.CreateOrUpdateCallCount()).Should(Equal(1), "we should call createorupdate exactly once")
					_, _, parameters, _ := fakeVirtualMachinesClient.CreateOrUpdateArgsForCall(0)
					var name = *parameters.Name
					Expect(name).ShouldNot(Equal(controlOldName))
					Expect(name).Should(MatchRegexp(controlNewNameRegex))
				})
			})

			Context("when there are no matches for the identifier regex", func() {
				BeforeEach(func() {
					fakeVirtualMachinesClient = new(azurefakes.FakeComputeVirtualMachinesClient)
				})
				It("should not try to deallocate anything and exit in error", func() {
					Expect(fakeVirtualMachinesClient.DeallocateCallCount()).Should(Equal(0), "we should never call deallocate without a matching VM")
					Expect(err).Should(HaveOccurred())
					Expect(errwrap.Cause(err)).Should(Equal(azure.NoMatchesErr))
				})
			})

			Context("when there are multiple matches for the identifier regex", func() {
				BeforeEach(func() {
					fakeVirtualMachinesClient = new(azurefakes.FakeComputeVirtualMachinesClient)
					vm := newVirtualMachine(controlID, controlOldName, "nil", controlManagedImageName, controlDiskSize)
					controlValue = append(controlValue, vm, vm)
				})

				It("should not try to deallocate anything and exit in error", func() {
					Expect(fakeVirtualMachinesClient.DeallocateCallCount()).Should(Equal(0), "we should never call deallocate without a matching VM")
					Expect(err).Should(HaveOccurred())
					Expect(errwrap.Cause(err)).Should(Equal(azure.MultipleMatchesErr))
				})
			})
		})

		Describe("Delete()", func() {
			var azureClient *azure.Client
			var err error
			var identifier string
			var fakeVirtualMachinesClient *azurefakes.FakeComputeVirtualMachinesClient
			var controlValue []compute.VirtualMachine

			JustBeforeEach(func() {
				azureClient.VirtualMachinesClient = fakeVirtualMachinesClient
				err = azureClient.Delete(identifier)
			})

			BeforeEach(func() {
				fakeVirtualMachinesClient = new(azurefakes.FakeComputeVirtualMachinesClient)
				controlValue = make([]compute.VirtualMachine, 0)
				azureClient = new(azure.Client)
			})

			Context("when azure running VMs list returns more than a single page of results", func() {
				BeforeEach(func() {
					identifier = "testid"
					vmMatch := newVirtualMachine(identifier, identifier, "testurl", "nil", controlDiskSize)
					vmNothing := newVirtualMachine("nomatch", "nomatch", "testurl", "nil", controlDiskSize)
					fakeVirtualMachinesClient.ListReturns(compute.VirtualMachineListResult{Value: &[]compute.VirtualMachine{vmNothing}}, nil)
					fakeVirtualMachinesClient.ListAllNextResultsReturnsOnCall(
						0,
						compute.VirtualMachineListResult{
							Value: &[]compute.VirtualMachine{vmMatch},
						},
						nil,
					)
					fakeVirtualMachinesClient.ListAllNextResultsReturnsOnCall(1, compute.VirtualMachineListResult{}, nil)
				})
				It("should properly walk through all pages to apply our regex", func() {
					Expect(err).ShouldNot(HaveOccurred())
				})
			})

			Context("when given an identifier with a single match of VM name on our regex", func() {
				controlRegex := "ops*"
				BeforeEach(func() {
					controlName := "ops-manager"
					controlValue = append(controlValue, compute.VirtualMachine{
						Name: &controlName,
					})
					fakeVirtualMachinesClient.ListReturns(compute.VirtualMachineListResult{Value: &controlValue}, nil)
					fakeVirtualMachinesClient.DeleteReturns(autorest.Response{}, nil)
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
					fakeVirtualMachinesClient.ListReturns(compute.VirtualMachineListResult{}, controlErr)
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
					fakeVirtualMachinesClient.ListReturns(compute.VirtualMachineListResult{Value: &controlValue}, nil)
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
					controlName := "some-name"
					controlValue = append(controlValue,
						compute.VirtualMachine{Name: &controlName})
					fakeVirtualMachinesClient.ListReturns(compute.VirtualMachineListResult{Value: &controlValue}, nil)
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
					controlName := "ops-manager"
					controlValue = append(controlValue,
						compute.VirtualMachine{Name: &controlName},
						compute.VirtualMachine{Name: &controlName})
					fakeVirtualMachinesClient.ListReturns(compute.VirtualMachineListResult{Value: &controlValue}, nil)
					identifier = "ops*"
				})
				It("should not delete any VM instances and should exit unsuccessfully", func() {
					Expect(fakeVirtualMachinesClient.DeleteCallCount()).Should(Equal(0), "the number of times deletes gets called should be zero")
					Expect(err).Should(HaveOccurred())
					Expect(errwrap.Cause(err)).Should(Equal(azure.MultipleMatchesErr))
				})
			})
		})

		Describe("GetDisk() unmanaged disk", func() {
			var fakeVirtualMachinesClient *azurefakes.FakeComputeVirtualMachinesClient
			var identifier string
			var url string
			var controlValue []compute.VirtualMachine
			var azureClient *azure.Client
			var vm compute.VirtualMachine

			BeforeEach(func() {
				azureClient = new(azure.Client)
				identifier = "testid"
				url = "testurl"
				fakeVirtualMachinesClient = new(azurefakes.FakeComputeVirtualMachinesClient)
				vm = newVirtualMachine(identifier, identifier, url, "nil", controlDiskSize)
				azureClient.VirtualMachinesClient = fakeVirtualMachinesClient
				controlValue = append(controlValue, vm)
			})

			Context("when given an identifier with a single match of disk name on our regex", func() {
				It("should return the disk size", func() {
					fakeVirtualMachinesClient.GetReturns(vm, nil)
					disk, err := azureClient.GetDisk(identifier)
					Expect(err).ToNot(HaveOccurred())
					Expect(disk.SizeGB).To(BeEquivalentTo(controlDiskSize))
				})
			})

			Context("when given an identifier and no disk is found in Azure", func() {
				It("should return an error", func() {
					fakeVirtualMachinesClient.GetReturns(compute.VirtualMachine{}, errors.New("error"))
					_, err := azureClient.GetDisk(identifier + "nomatch")
					Expect(err).To(HaveOccurred())
				})
			})
		})

		Describe("GetDisk() managed disk", func() {
			var fakeVirtualMachinesClient *azurefakes.FakeComputeVirtualMachinesClient
			var identifier string
			var url string
			var controlValue []compute.VirtualMachine
			var azureClient *azure.Client
			var vm compute.VirtualMachine

			BeforeEach(func() {
				azureClient = new(azure.Client)
				identifier = "testid"
				url = "testurl"
				fakeVirtualMachinesClient = new(azurefakes.FakeComputeVirtualMachinesClient)
				vm = newVirtualMachine(identifier, identifier, "nil", url, controlDiskSize)
				azureClient.VirtualMachinesClient = fakeVirtualMachinesClient
				controlValue = append(controlValue, vm)
			})

			Context("when given an identifier with a single match of disk name on our regex", func() {
				It("should return the disk size", func() {
					fakeVirtualMachinesClient.GetReturns(vm, nil)
					disk, err := azureClient.GetDisk(identifier)
					Expect(err).ToNot(HaveOccurred())
					Expect(disk.SizeGB).To(BeEquivalentTo(controlDiskSize))
				})
			})

			Context("when given an identifier and no disk is found in Azure", func() {
				It("should return an error", func() {
					fakeVirtualMachinesClient.GetReturns(compute.VirtualMachine{}, errors.New("error"))
					_, err := azureClient.GetDisk(identifier + "nomatch")
					Expect(err).To(HaveOccurred())
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
				subID = "some-sub-id"
				clientID = "some-client-id"
				clientSecret = "some-client-secret"
				tenantID = "some-tenant-id"
				resourceGroupName = "some-resource-group-name"
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

func newVirtualMachine(id string, name string, vmDiskURL string, managedImageName string, diskSize int32) compute.VirtualMachine {
	tmpID := id
	tmpName := name
	tmpURL := vmDiskURL
	tmpManagedImageName := managedImageName

	if tmpManagedImageName != "nil" {
		vm := compute.VirtualMachine{
			ID:   &tmpID,
			Name: &tmpName,
			Resources: &[]compute.VirtualMachineExtension{
				compute.VirtualMachineExtension{},
				compute.VirtualMachineExtension{},
				compute.VirtualMachineExtension{},
				compute.VirtualMachineExtension{},
			},
			VirtualMachineProperties: &compute.VirtualMachineProperties{
				OsProfile: &compute.OSProfile{},
				StorageProfile: &compute.StorageProfile{
					OsDisk: &compute.OSDisk{
						DiskSizeGB: &diskSize,
					},
					ImageReference: &compute.ImageReference{
						ID: &managedImageName,
					},
				},
			},
		}
		return vm
	} else {
		vm := compute.VirtualMachine{
			ID:   &tmpID,
			Name: &tmpName,
			Resources: &[]compute.VirtualMachineExtension{
				compute.VirtualMachineExtension{},
				compute.VirtualMachineExtension{},
				compute.VirtualMachineExtension{},
				compute.VirtualMachineExtension{},
			},
			VirtualMachineProperties: &compute.VirtualMachineProperties{
				OsProfile: &compute.OSProfile{},
				StorageProfile: &compute.StorageProfile{
					OsDisk: &compute.OSDisk{
						DiskSizeGB: &diskSize,
						Vhd: &compute.VirtualHardDisk{
							URI: &tmpURL,
						},
						Image: &compute.VirtualHardDisk{
							URI: &tmpURL,
						},
					},
				},
			},
		}
		return vm
	}
}

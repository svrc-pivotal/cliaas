package azure

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/Azure/azure-sdk-for-go/arm/compute"
	"github.com/Azure/azure-sdk-for-go/arm/examples/helpers"
	"github.com/Azure/azure-sdk-for-go/storage"
	"github.com/Azure/go-autorest/autorest"
	"github.com/pivotal-cf/cliaas/iaas"
	errwrap "github.com/pkg/errors"
)

const defaultResourceManagerEndpoint = "https://management.azure.com/"
const DefaultBaseURL = "core.windows.net"
const DefaultStorageType = "Standard_LRS"

type Client struct {
	BlobServiceClient     BlobCopier
	VirtualMachinesClient ComputeVirtualMachinesClient
	ImagesClient          ComputeImagesClient
	resourceGroupName     string
	storageContainerName  string
	storageAccountName    string
	storageBaseURL        string
	vmAdminPassword       string
	managedDisks          bool
	storageAccountType    string
}

type BlobCopier interface {
	CopyBlob(container, name, sourceBlob string) error
}

type ComputeVirtualMachinesClient interface {
	Get(resourceGroupName string, vmName string, expand compute.InstanceViewTypes) (result compute.VirtualMachine, err error)
	ListAllNextResults(lastResults compute.VirtualMachineListResult) (result compute.VirtualMachineListResult, err error)
	CreateOrUpdate(resourceGroupName string, vmName string, parameters compute.VirtualMachine, cancel <-chan struct{}) (result autorest.Response, err error)
	Delete(resourceGroupName string, vmName string, cancel <-chan struct{}) (result autorest.Response, err error)
	Deallocate(resourceGroupName string, vmName string, cancel <-chan struct{}) (result autorest.Response, err error)
	List(resourceGroupName string) (result compute.VirtualMachineListResult, err error)
}

type ComputeImagesClient interface {
	CreateOrUpdate(resourceGroupName string, imageName string, parameters compute.Image, cancel <-chan struct{}) (result autorest.Response, err error)
}

var InvalidAzureClientErr = errors.New("invalid azure sdk client defined")
var NoMatchesErr = errors.New("no VM names match the provided prefix")
var MultipleMatchesErr = errors.New("multiple VM names match the provided prefix")

func NewClient(subscriptionID string, clientID string, clientSecret string, tenantID string, resourceGroupName string, resourceManagerEndpoint string) (*Client, error) {
	c := map[string]string{
		"AZURE_CLIENT_ID":       clientID,
		"AZURE_CLIENT_SECRET":   clientSecret,
		"AZURE_SUBSCRIPTION_ID": subscriptionID,
		"AZURE_TENANT_ID":       tenantID,
	}
	if err := checkEnvVar(c); err != nil {
		return nil, errwrap.Wrap(err, "failed on check of env vars")
	}
	if resourceManagerEndpoint == "" {
		resourceManagerEndpoint = defaultResourceManagerEndpoint
	}

	spt, err := helpers.NewServicePrincipalTokenFromCredentials(c, resourceManagerEndpoint)
	if err != nil {
		return nil, errwrap.Wrap(err, "failed to generate new service principal token")
	}
	client := compute.NewVirtualMachinesClient(subscriptionID)
	client.Authorizer = spt

	imageClient := compute.NewImagesClient(subscriptionID)
	imageClient.Authorizer = spt

	return &Client{
		VirtualMachinesClient: &client,
		ImagesClient:          &imageClient,
		resourceGroupName:     resourceGroupName,
	}, nil
}

/* Cliaas Client Interface */
func (s *Client) Delete(identifier string) error {
	_, err := s.executeFunctionOnMatchingVM(identifier, s.VirtualMachinesClient.Delete)
	return err
}

func (s *Client) Replace(identifier string, vhdURL string, diskSizeGB int64) error {
	instance, err := s.deallocate(identifier)
	if err != nil {
		return errwrap.Wrap(err, "error shutting down VM")
	}

	tmpName := generateInstanceName(*instance.Name)
	localBlobName := tmpName + "-image.vhd"
	localDiskName := tmpName + "-osdisk"
	localManagedImageName := tmpName + "-image"

	err = s.BlobServiceClient.CopyBlob(s.storageContainerName, localBlobName, vhdURL)
	if err != nil {
		return errwrap.Wrap(err, "error copying source blob to local blob")
	}

	localImageURL := generateLocalImageURL(s.storageAccountName, s.storageBaseURL, s.storageContainerName, localBlobName)
	localDiskURL := generateLocalImageURL(s.storageAccountName, s.storageBaseURL, s.storageContainerName, localDiskName+".vhd")
	if &instance.StorageProfile.OsDisk.ManagedDisk != nil || s.managedDisks == true {

		image := &compute.Image{
			Location: instance.Location,
			ImageProperties: &compute.ImageProperties{
				StorageProfile: &compute.ImageStorageProfile{
					OsDisk: &compute.ImageOSDisk{
						OsType:  "Linux",
						BlobURI: &localImageURL,
						OsState: "Generalized",
					},
				},
			},
		}

		_, err := s.ImagesClient.CreateOrUpdate(s.resourceGroupName, localManagedImageName, *image, nil)
		if err != nil {
			return errwrap.Wrap(err, "error creating image from local blob")
		}

		newInstance, err := s.generateInstanceCopyFromManagedImage(*instance.Name, tmpName, localDiskName, image, int32(diskSizeGB))
		if err != nil {
			return errwrap.Wrap(err, "failed to generate a new instance object")
		}

		err = s.Delete(identifier)
		if err != nil {
			return errwrap.Wrap(err, "failed removing original VM")
		}

		_, err = s.VirtualMachinesClient.CreateOrUpdate(s.resourceGroupName, *newInstance.Name, *newInstance, nil)
		return err

	} else {

		newInstance, err := s.generateInstanceCopyFromUnmanagedImage(*instance.Name, tmpName, localImageURL, localDiskURL, int32(diskSizeGB))
		if err != nil {
			return errwrap.Wrap(err, "failed to generate a new instance object")
		}

		err = s.Delete(identifier)
		if err != nil {
			return errwrap.Wrap(err, "failed removing original VM")
		}

		_, err = s.VirtualMachinesClient.CreateOrUpdate(s.resourceGroupName, *newInstance.Name, *newInstance, nil)
		return err

	}
}

func (s *Client) GetDisk(identifier string) (iaas.Disk, error) {
	instance, err := s.VirtualMachinesClient.Get(s.resourceGroupName, identifier, compute.InstanceView)
	if err != nil {
		return iaas.Disk{}, errwrap.Wrap(err, "unable to get virtual machine instance from azure api for disk")
	}
	return iaas.Disk{SizeGB: int64(*instance.StorageProfile.OsDisk.DiskSizeGB)}, nil
}

/* End Cliaas Client Interface */

func (s *Client) SetVMAdminPassword(password string) {
	s.vmAdminPassword = password
}

func (s *Client) SetManagedDisks(managedDisks bool) {
	s.managedDisks = managedDisks
}

func (s *Client) SetStorageAccountType(storageAccountType string) {
	s.storageAccountType = storageAccountType
}

func (s *Client) SetStorageContainerName(name string) {
	s.storageContainerName = name
}

func (s *Client) SetStorageAccountName(name string) {
	s.storageAccountName = name
}

func (s *Client) SetStorageBaseURL(baseURL string) {
	s.storageBaseURL = baseURL
}

func (s *Client) SetBlobServiceClient(storageAccountName string, storageAccountKey string, storageURL string) error {
	blobClient, err := newBlobClient(storageAccountName, storageAccountKey, storageURL)
	if err != nil {
		return errwrap.Wrap(err, "failed creating a blob client")
	}
	s.BlobServiceClient = blobClient
	return nil
}

func (s *Client) generateInstanceCopyFromManagedImage(sourceInstanceName string, newInstanceName string, localOSDiskName string, localManagedImage *compute.Image, diskSizeGB int32) (*compute.VirtualMachine, error) {
	instance, err := s.VirtualMachinesClient.Get(s.resourceGroupName, sourceInstanceName, compute.InstanceView)
	if err != nil {
		return nil, errwrap.Wrap(err, "unable to get virtual machine instance from azure api")
	}

	instance.Name = &newInstanceName
	instance.VirtualMachineProperties.StorageProfile.OsDisk = &compute.OSDisk{
		ManagedDisk: &compute.ManagedDiskParameters{
			StorageAccountType: compute.StorageAccountTypes(s.storageAccountType),
		},
		CreateOption: "fromImage",
		Name:         &localOSDiskName,
	}
	nullString := "null"
	instance.VirtualMachineProperties.StorageProfile.ImageReference = &compute.ImageReference{
		ID: localManagedImage.ID,
	}

	instance.VirtualMachineProperties.VMID = nil
	instance.Resources = nil

	if s.vmAdminPassword == "" {
		s.vmAdminPassword = getGUID()
	}
	adminUsername := "ubuntu"
	instance.VirtualMachineProperties.OsProfile = &compute.OSProfile{
		AdminUsername: &adminUsername,
		AdminPassword: &s.vmAdminPassword,
		ComputerName:  &newInstanceName,
	}

	return &instance, nil
}

func (s *Client) generateInstanceCopyFromUnmanagedImage(sourceInstanceName string, newInstanceName string, localImageURL string, localOSDiskURL string, diskSizeGB int32) (*compute.VirtualMachine, error) {
	instance, err := s.VirtualMachinesClient.Get(s.resourceGroupName, sourceInstanceName, compute.InstanceView)
	if err != nil {
		return nil, errwrap.Wrap(err, "unable to get virtual machine instance from azure api")
	}

	instance.Name = &newInstanceName
	instance.VirtualMachineProperties.StorageProfile.OsDisk.DiskSizeGB = &diskSizeGB
	instance.VirtualMachineProperties.StorageProfile.OsDisk.Image.URI = &localImageURL
	instance.VirtualMachineProperties.StorageProfile.OsDisk.Vhd.URI = &localOSDiskURL

	instance.VirtualMachineProperties.VMID = nil
	instance.Resources = nil

	if s.vmAdminPassword == "" {
		s.vmAdminPassword = getGUID()
	}
	instance.VirtualMachineProperties.OsProfile.AdminPassword = &s.vmAdminPassword
	return &instance, nil
}

func (s *Client) deallocate(identifier string) (*compute.VirtualMachine, error) {
	return s.executeFunctionOnMatchingVM(identifier, s.VirtualMachinesClient.Deallocate)
}

func (s *Client) executeFunctionOnMatchingVM(identifier string, f func(resourceGroupName string, vmName string, cancel <-chan struct{}) (result autorest.Response, err error)) (*compute.VirtualMachine, error) {
	matchingInstances, err := s.getFilteredList(identifier)
	if err != nil {
		return nil, errwrap.Wrap(err, "error when attempting to get filtered vm list")
	}

	switch len(matchingInstances) {
	case 0:
		return nil, NoMatchesErr
	case 1:
		_, err = f(s.resourceGroupName, *matchingInstances[0].Name, nil)
		return &matchingInstances[0], err
	default:
		return nil, MultipleMatchesErr
	}
}

func (s *Client) getFilteredList(identifier string) ([]compute.VirtualMachine, error) {
	vmListResults, err := s.VirtualMachinesClient.List(s.resourceGroupName)
	if err != nil {
		return nil, errwrap.Wrap(err, "error in getting list of VMs from azure")
	}

	var matchingInstances = make([]compute.VirtualMachine, 0)
	var vmNameFilter = regexp.MustCompile(identifier)

	for vmListResults.Value != nil && len(*vmListResults.Value) > 0 {
		matchingInstances = getMatchingInstances(*vmListResults.Value, vmNameFilter, matchingInstances)
		vmListResults, err = s.VirtualMachinesClient.ListAllNextResults(vmListResults)
		if err != nil {
			return nil, errwrap.Wrap(err, "ListAllNextResults call failed")
		}
	}
	return matchingInstances, nil
}

func newBlobClient(accountName string, accountKey string, baseURL string) (*storage.BlobStorageClient, error) {
	client, err := storage.NewClient(accountName, accountKey, baseURL, storage.DefaultAPIVersion, true)
	if err != nil {
		return nil, err
	}
	blobClient := client.GetBlobService()
	return &blobClient, nil
}

func generateLocalImageURL(accountName string, baseURL string, containerName string, localBlobName string) string {
	return fmt.Sprintf("https://%s.blob.%s/%s/%s", accountName, baseURL, containerName, localBlobName)
}

func getGUID() string {
	uuid, _ := uuid.NewRandom()
	localString := uuid.String()
	return localString
}

func checkEnvVar(envVars map[string]string) error {
	var missingVars []string
	for varName, value := range envVars {
		if value == "" {
			missingVars = append(missingVars, varName)
		}
	}
	if len(missingVars) > 0 {
		return fmt.Errorf("Missing environment variables %v", missingVars)
	}
	return nil
}

func generateInstanceName(currentName string) string {
	tstamp := time.Now().Format("20060112123456")
	splits := strings.Split(currentName, "_")
	if len(splits) == 1 {
		return currentName + "_" + tstamp
	}

	truncatedSplits := splits[:len(splits)-1]
	truncatedSplits = append(truncatedSplits, tstamp)
	return strings.Join(truncatedSplits, "_")
}

func getMatchingInstances(vmList []compute.VirtualMachine, identifierRegex *regexp.Regexp, matchingInstances []compute.VirtualMachine) []compute.VirtualMachine {

	for _, instance := range vmList {
		if identifierRegex.MatchString(*instance.Name) {
			matchingInstances = append(matchingInstances, instance)
		}
	}
	return matchingInstances
}

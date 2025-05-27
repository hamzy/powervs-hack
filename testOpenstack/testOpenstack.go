//
// Parts borrowed from:
//	https://github.com/openshift/installer/tree/main/pkg/infrastructure/openstack/preprovision/rhcosimage.go
//	https://github.com/openshift/installer/tree/main/pkg/rhcos/cache/cache.go
//	https://github.com/openshift/installer/tree/main/pkg/types/openstack/defaults/client.go 
//	https://github.com/openshift/installer/tree/main/pkg/types/openstack/defaults/clientopts.go 
//
// (/bin/rm go.*; go mod init example/user/testOpenstack; go mod tidy; go get github.com/h2non/filetype@v1.1.1)
// (echo "vet:"; go vet || exit 1; echo "build:"; go build *.go || exit 1; ./testOpenstack image-upload --cloud "powervc" --rhcosImage "https://rhcos.mirror.openshift.com/art/storage/prod/streams/rhel-9.6/builds/9.6.20250402-0/ppc64le/rhcos-9.6.20250402-0-powervs.ppc64le.ova.gz" --imageName "hamzy-test" --infraID "rdr-hamzy-openstack-abcde")
// (echo "vet:"; go vet || exit 1; echo "build:"; go build *.go || exit 1; ./testOpenstack volume-create --cloud "powervc" --volumeName "hamzy-volume-test" --volumeSize 10 --availabilityZone "nova" --imageID "7bf9857f-f4d0-4970-8e11-5310da46d539")
//

package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
//	"reflect"
	"strings"
	"time"

	igntypes "github.com/coreos/ignition/v2/config/v3_2/types"
	"github.com/gophercloud/gophercloud/v2"
	"github.com/gophercloud/gophercloud/v2/openstack"
	"github.com/gophercloud/gophercloud/v2/openstack/blockstorage/v2/volumes"
	"github.com/gophercloud/gophercloud/v2/openstack/compute/v2/servers"
	"github.com/gophercloud/gophercloud/v2/openstack/identity/v3/tokens"
	"github.com/gophercloud/gophercloud/v2/openstack/image/v2/imagedata"
	"github.com/gophercloud/gophercloud/v2/openstack/image/v2/images"
	"github.com/gophercloud/gophercloud/v2/openstack/networking/v2/ports"
	"github.com/gophercloud/gophercloud/v2/pagination"
	"github.com/gophercloud/utils/v2/openstack/clientconfig"
	"github.com/h2non/filetype/matchers"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/thedevsaddam/retry"
	"github.com/ulikunitz/xz"
	"github.com/vincent-petithory/dataurl"
	"golang.org/x/sys/unix"
	"k8s.io/utils/ptr"
)

// urlWithIntegrity pairs a URL with an optional expected sha256 checksum (after decompression, if any)
// If the query string contains sha256 parameter (i.e. https://example.com/data.bin?sha256=098a5a...),
// then the downloaded data checksum will be compared with the provided value.
type urlWithIntegrity struct {
	location           url.URL
	uncompressedSHA256 string
}

func (u *urlWithIntegrity) uncompressedName() string {
	n := filepath.Base(u.location.Path)
	return strings.TrimSuffix(strings.TrimSuffix(n, ".gz"), ".xz")
}

// download obtains a file from a given URL, puts it in the cache folder, defined by dataType parameter,
// and returns the local file path.
func (u *urlWithIntegrity) download(dataType, applicationName string) (string, error) {
	fileName := u.uncompressedName()

	cacheDir, err := GetCacheDir(dataType, applicationName)
	if err != nil {
		return "", err
	}

	filePath, err := GetFileFromCache(fileName, cacheDir)
	if err != nil {
		return "", err
	}
	if filePath != "" {
		// Found cached file
		return filePath, nil
	}

	// Send a request to get the file
	err = retry.DoFunc(3, 5*time.Second, func() error {
		resp, err := http.Get(u.location.String())
		if err != nil {
			return err
		}
		defer resp.Body.Close()

		// Let's find the content length for future debugging
		logrus.Debugf("image download content length: %d", resp.ContentLength)

		// Check server response
		if resp.StatusCode != http.StatusOK {
			return errors.Errorf("bad status: %s", resp.Status)
		}

		filePath = filepath.Join(cacheDir, fileName)
		return cacheFile(resp.Body, filePath, u.uncompressedSHA256)
	})
	if err != nil {
		return "", err
	}

	return filePath, nil
}

// GetFileFromCache returns path of the cached file if found, otherwise returns an empty string
// or error.
func GetFileFromCache(fileName string, cacheDir string) (string, error) {
	filePath := filepath.Join(cacheDir, fileName)

	// If the file has already been cached, return its path
	_, err := os.Stat(filePath)
	if err == nil {
		logrus.Debugf("The file was found in cache: %v. Reusing...", filePath)
		return filePath, nil
	}
	if !os.IsNotExist(err) {
		return "", err
	}

	return "", nil
}

// GetCacheDir returns a local path of the cache, where the installer should put the data:
// <user_cache_dir>/agent/<dataType>_cache
// If the directory doesn't exist, it will be automatically created.
func GetCacheDir(dataType, applicationName string) (string, error) {
	if dataType == "" {
		return "", errors.Errorf("data type can't be an empty string")
	}

	userCacheDir, err := os.UserCacheDir()
	if err != nil {
		return "", err
	}

	cacheDir := filepath.Join(userCacheDir, applicationName, dataType+"_cache")

	_, err = os.Stat(cacheDir)
	if err != nil {
		if os.IsNotExist(err) {
			err = os.MkdirAll(cacheDir, 0755)
			if err != nil {
				return "", err
			}
		} else {
			return "", err
		}
	}

	return cacheDir, nil
}

// cacheFile puts data in the cache.
func cacheFile(reader io.Reader, filePath string, sha256Checksum string) (err error) {
	logrus.Debugf("Unpacking file into %q...", filePath)

	flockPath := fmt.Sprintf("%s.lock", filePath)
	flock, err := os.Create(flockPath)
	if err != nil {
		return err
	}
	defer flock.Close()
	defer func() {
		err2 := os.Remove(flockPath)
		if err == nil {
			err = err2
		}
	}()

	err = unix.Flock(int(flock.Fd()), unix.LOCK_EX)
	if err != nil {
		return err
	}
	defer func() {
		err2 := unix.Flock(int(flock.Fd()), unix.LOCK_UN)
		if err == nil {
			err = err2
		}
	}()

	_, err = os.Stat(filePath)
	if err != nil && !os.IsNotExist(err) {
		return nil // another cacheFile beat us to it
	}

	tempPath := fmt.Sprintf("%s.tmp", filePath)

	// Delete the temporary file that may have been left over from previous launches.
	err = os.Remove(tempPath)
	if err != nil {
		if !os.IsNotExist(err) {
			return errors.Errorf("failed to clean up %s: %v", tempPath, err)
		}
	} else {
		logrus.Debugf("Temporary file %v that remained after the previous launches was deleted", tempPath)
	}

	file, err := os.OpenFile(tempPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0444)
	if err != nil {
		return err
	}
	closed := false
	defer func() {
		if !closed {
			file.Close()
		}
	}()

	// Detect whether we know how to decompress the file
	// See http://golang.org/pkg/net/http/#DetectContentType for why we use 512
	buf := make([]byte, 512)
	_, err = reader.Read(buf)
	if err != nil {
		return err
	}

	reader = io.MultiReader(bytes.NewReader(buf), reader)
	switch {
	case matchers.Gz(buf):
		logrus.Debug("decompressing the image archive as gz")
		uncompressor, err := gzip.NewReader(reader)
		if err != nil {
			return err
		}
		defer uncompressor.Close()
		reader = uncompressor
	case matchers.Xz(buf):
		logrus.Debug("decompressing the image archive as xz")
		uncompressor, err := xz.NewReader(reader)
		if err != nil {
			return err
		}
		reader = uncompressor
	default:
		// No need for an interposer otherwise
		logrus.Debug("no known archive format detected for image, assuming no decompression necessary")
	}

	// Wrap the reader in TeeReader to calculate sha256 checksum on the fly
	hasher := sha256.New()
	if sha256Checksum != "" {
		reader = io.TeeReader(reader, hasher)
	}

	written, err := io.Copy(file, reader)
	if err != nil {
		return err
	}

	// Let's find out how much data was written
	// for future troubleshooting
	logrus.Debugf("writing the RHCOS image was %d bytes", written)

	err = file.Close()
	if err != nil {
		return err
	}
	closed = true

	// Validate sha256 checksum
	if sha256Checksum != "" {
		foundChecksum := fmt.Sprintf("%x", hasher.Sum(nil))
		if sha256Checksum != foundChecksum {
			logrus.Error("File sha256 checksum is invalid.")
			return errors.Errorf("Checksum mismatch for %s; expected=%s found=%s", filePath, sha256Checksum, foundChecksum)
		}

		logrus.Debug("Checksum validation is complete...")
	}

	return os.Rename(tempPath, filePath)
}

// DownloadImageFile is a helper function that obtains an image file from a given URL,
// puts it in the cache and returns the local file path.  If the file is compressed
// by a known compressor, the file is uncompressed prior to being returned.
func DownloadImageFile(baseURL string, applicationName string) (string, error) {
	return DownloadImageFileWithSha(baseURL, applicationName, "")
}

// DownloadImageFileWithSha sets the sha256Checksum which is checked on download.
func DownloadImageFileWithSha(baseURL string, applicationName string, sha256Checksum string) (string, error) {
	logrus.Debugf("Obtaining RHCOS image file from '%v'", baseURL)

	var u urlWithIntegrity
	parsedURL, err := url.ParseRequestURI(baseURL)
	if err != nil {
		return "", err
	}
	q := parsedURL.Query()
	if sha256Checksum != "" {
		u.uncompressedSHA256 = sha256Checksum
	}
	if uncompressedSHA256, ok := q["sha256"]; ok {
		if sha256Checksum != "" && uncompressedSHA256[0] != sha256Checksum {
			return "", errors.Errorf("supplied sha256Checksum does not match URL")
		}
		u.uncompressedSHA256 = uncompressedSHA256[0]
		q.Del("sha256")
		parsedURL.RawQuery = q.Encode()
	}
	u.location = *parsedURL

	return u.download("image", applicationName)
}

// UploadBaseImage creates a new image in Glance and uploads the RHCOS image there.
func UploadBaseImage(ctx context.Context, cloud string, rhcosImage string, imageName string, infraID string, imageProperties map[string]string) error {
	url, err := url.Parse(rhcosImage)
	if err != nil {
		return err
	}

	// We support 'http(s)' and 'file' schemes. If the scheme is http(s), then we will upload a file from that
	// location. Otherwise will take local file path from the URL.
	var localFilePath string
	switch url.Scheme {
	case "http", "https":
		localFilePath, err = DownloadImageFile(rhcosImage, "openshift-installer")
		if err != nil {
			return err
		}
	case "file":
		localFilePath = filepath.FromSlash(url.Path)
	default:
		return fmt.Errorf("unsupported URL scheme: %q", url.Scheme)
	}

	logrus.Debugln("Creating a Glance image for RHCOS...")

	f, err := os.Open(localFilePath)
	if err != nil {
		return err
	}
	defer f.Close()

	conn, err := NewServiceClient(ctx, "image", DefaultClientOpts(cloud))
	if err != nil {
		return err
	}

	// @TODO - HAMZY BEGIN
	// By default we use "qcow2" disk format, but if the file extension is "raw",
	// then we set the disk format as "raw".
	extension := filepath.Ext(localFilePath)
	var diskFormat, containerFormat string
	switch extension {
	case ".qcow2":
		containerFormat = "bare"
		diskFormat = "qcow2"
	case ".raw":
		containerFormat = "bare"
		diskFormat = "raw"
	case ".ova.gz":
		containerFormat = "ova"
		diskFormat = "raw"
	case ".ova":
		containerFormat = "ova"
		diskFormat = "raw"
	default:
		return fmt.Errorf("unsupported file extension: %q", extension)
	}
	fmt.Printf("extension = %s\n", extension)
	fmt.Printf("diskFormat = %s\n", diskFormat)
	fmt.Printf("containerFormat = %s\n", containerFormat)
	// @TODO - HAMZY END

	img, err := images.Create(ctx, conn, images.CreateOpts{
		Name:            imageName,
		ContainerFormat: containerFormat,
		DiskFormat:      diskFormat,
		Tags:            []string{"openshiftClusterID=" + infraID},
		Properties:      imageProperties,
	}).Extract()
	if err != nil {
		return err
	}

	// Use direct upload (see
	// https://github.com/openshift/installer/issues/3403 for a discussion
	// on web-download)
	logrus.Debugf("Upload RHCOS to the image %q (%s)", img.Name, img.ID)
	res := imagedata.Upload(ctx, conn, img.ID, f)
	if res.Err != nil {
		return err
	}
	logrus.Debugf("RHCOS image upload completed.")

	return nil
}

// UploadIgnitionAndBuildShim uploads the bootstrap Ignition config in Glance.
func UploadIgnitionAndBuildShim(ctx context.Context, cloud string, infraID string, imageName string, bootstrapIgn []byte) ([]byte, error) {
	opts := DefaultClientOpts(cloud)
	conn, err := NewServiceClient(ctx, "image", opts)
	if err != nil {
		return nil, err
	}

	var userCA []byte
	{
		cloudConfig, err := clientconfig.GetCloudFromYAML(opts)
		if err != nil {
			return nil, err
		}
		// Get the ca-cert-bundle key if there is a value for cacert in clouds.yaml
		if caPath := cloudConfig.CACertFile; caPath != "" {
			userCA, err = os.ReadFile(caPath)
			if err != nil {
				return nil, fmt.Errorf("failed to read clouds.yaml ca-cert from disk: %w", err)
			}
		}
	}
	fmt.Printf("userCA = %v\n", userCA)

	// we need to obtain Glance public endpoint that will be used by Ignition to download bootstrap ignition files.
	// By design this should be done by using https://www.terraform.io/docs/providers/openstack/d/identity_endpoint_v3.html
	// but OpenStack default policies forbid to use this API for regular users.
	// On the other hand when a user authenticates in OpenStack (i.e. gets a token), it includes the whole service
	// catalog in the output json. So we are able to parse the data and get the endpoint from there
	// https://docs.openstack.org/api-ref/identity/v3/?expanded=token-authentication-with-scoped-authorization-detail#token-authentication-with-scoped-authorization
	// Unfortunately this feature is not currently supported by Terraform, so we had to implement it here.
	var glancePublicURL string
	{
		// Authenticate in OpenStack, get the token and extract the service catalog
		var serviceCatalog *tokens.ServiceCatalog
		{
			authResult := conn.GetAuthResult()
			auth, ok := authResult.(tokens.CreateResult)
			if !ok {
				return nil, fmt.Errorf("unable to extract service catalog")
			}

			var err error
			serviceCatalog, err = auth.ExtractServiceCatalog()
			if err != nil {
				return nil, err
			}
		}
		clientConfigCloud, err := clientconfig.GetCloudFromYAML(DefaultClientOpts(cloud))
		if err != nil {
			return nil, err
		}
		glancePublicURL, err = openstack.V3EndpointURL(serviceCatalog, gophercloud.EndpointOpts{
			Type:         "image",
			Availability: gophercloud.AvailabilityPublic,
			Region:       clientConfigCloud.RegionName,
		})
		if err != nil {
			return nil, fmt.Errorf("cannot retrieve Glance URL from the service catalog: %w", err)
		}
	}
	fmt.Printf("glancePublicURL = %v\n", glancePublicURL)

	// upload the bootstrap Ignition config in Glance and save its location
	var bootstrapConfigURL string
	{
		img, err := images.Create(ctx, conn, images.CreateOpts{
			Name:            imageName,
			ContainerFormat: "bare",
			DiskFormat:      "raw",
			Tags:            []string{"openshiftClusterID=" + infraID},
		}).Extract()
		if err != nil {
			return nil, fmt.Errorf("unable to create a Glance image for the bootstrap server's Ignition file: %w", err)
		}

		if res := imagedata.Upload(ctx, conn, img.ID, bytes.NewReader(bootstrapIgn)); res.Err != nil {
			return nil, fmt.Errorf("unable to upload a Glance image for the bootstrap server's Ignition file: %w", res.Err)
		}

		bootstrapConfigURL = glancePublicURL + img.File
	}
	fmt.Printf("bootstrapConfigURL = %v\n", bootstrapConfigURL)

	// To allow Ignition to download its config on the bootstrap machine from a location secured by a
	// self-signed certificate, we have to provide it a valid custom ca bundle.
	// To do so we generate a small ignition config that contains just Security section with the bundle
	// and later append it to the main ignition config.
	tokenID, err := conn.GetAuthResult().ExtractTokenID()
	if err != nil {
		return nil, fmt.Errorf("unable to extract an OpenStack token: %w", err)
	}
	fmt.Printf("tokenID = %v\n", tokenID)

	caRefs, err := parseCertificateBundle(userCA)
	if err != nil {
		return nil, err
	}

	var ignProxy igntypes.Proxy

	data, err := Marshal(igntypes.Config{
		Ignition: igntypes.Ignition{
			Version: igntypes.MaxVersion.String(),
			Timeouts: igntypes.Timeouts{
				HTTPResponseHeaders: ptr.To(120),
			},
			Security: igntypes.Security{
				TLS: igntypes.TLS{
					CertificateAuthorities: caRefs,
				},
			},
			Config: igntypes.IgnitionConfig{
				Merge: []igntypes.Resource{
					{
						Source: &bootstrapConfigURL,
						HTTPHeaders: []igntypes.HTTPHeader{
							{
								Name:  "X-Auth-Token",
								Value: &tokenID,
							},
						},
					},
				},
			},
			Proxy: ignProxy,
		},
		Storage: igntypes.Storage{
			Files: []igntypes.File{
				{
					Node: igntypes.Node{
						Path:      "/etc/hostname",
						Overwrite: ptr.To(true),
					},
					FileEmbedded1: igntypes.FileEmbedded1{
						Mode: ptr.To(420),
						Contents: igntypes.Resource{
							Source: ptr.To(dataurl.EncodeBytes([]byte(infraID + "bootstrap"))),
						},
					},
				},
				{
					Node: igntypes.Node{
						Path:      "/opt/openshift/tls/cloud-ca-cert.pem",
						Overwrite: ptr.To(true),
					},
					FileEmbedded1: igntypes.FileEmbedded1{
						Mode: ptr.To(420),
						Contents: igntypes.Resource{
							Source: ptr.To(dataurl.EncodeBytes(userCA)),
						},
					},
				},
			},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("unable to encode the Ignition shim: %w", err)
	}
	fmt.Printf("data = %v\n", data)

	// Check the size of the base64-rendered ignition shim isn't to big for nova
	// https://docs.openstack.org/nova/latest/user/metadata.html#user-data
	if len(base64.StdEncoding.EncodeToString(data)) > 65535 {
		return nil, fmt.Errorf("rendered bootstrap ignition shim exceeds the 64KB limit for nova user data -- try reducing the size of your CA cert bundle")
	}
	return data, nil
}

// ParseCertificateBundle loads each certificate in the bundle to the Ignition
// carrier type, ignoring any invisible character before, after and in between
// certificates.
func parseCertificateBundle(userCA []byte) ([]igntypes.Resource, error) {
	var caRefs []igntypes.Resource
	userCA = bytes.TrimSpace(userCA)
	for len(userCA) > 0 {
		var block *pem.Block
		block, userCA = pem.Decode(userCA)
		if block == nil {
			return nil, fmt.Errorf("unable to parse certificate, please check the cacert section of clouds.yaml")
		}
		caRefs = append(caRefs, igntypes.Resource{Source: ptr.To(dataurl.EncodeBytes(pem.EncodeToMemory(block)))})
		userCA = bytes.TrimSpace(userCA)
	}
	return caRefs, nil
}

// Marshal is a helper function to use the marshaler function from "github.com/clarketm/json".
// It supports zero values of structs with the omittempty annotation.
// In effect this excludes empty pointer struct fields from the marshaled data,
// instead of inserting nil values into them.
// This is necessary for ignition configs to pass openAPI validation on fields
// that are not supposed to contain nil pointers, but e.g. strings.
// It can be used as a dropin replacement for "encoding/json".Marshal
func Marshal(input interface{}) ([]byte, error) {
	return json.Marshal(input)
}

// getUserAgent generates a Gophercloud UserAgent to help cloud operators
// disambiguate openshift-installer requests.
func getUserAgent() (gophercloud.UserAgent, error) {
	ua := gophercloud.UserAgent{}

	ua.Prepend(fmt.Sprintf("openshift-installer/%s", "1.0"))
	return ua, nil
}

// NewServiceClient is a wrapper around Gophercloud's NewServiceClient that
// ensures we consistently set a user-agent.
func NewServiceClient(ctx context.Context, service string, opts *clientconfig.ClientOpts) (*gophercloud.ServiceClient, error) {
	ua, err := getUserAgent()
	if err != nil {
		return nil, err
	}

	client, err := clientconfig.NewServiceClient(ctx, service, opts)
	if err != nil {
		return nil, err
	}

	client.UserAgent = ua

	return client, nil
}

// DefaultClientOpts generates default client opts based on cloud name
func DefaultClientOpts(cloudName string) *clientconfig.ClientOpts {
	opts := new(clientconfig.ClientOpts)
	opts.Cloud = cloudName
	// We explicitly disable reading auth data from env variables by setting an invalid EnvPrefix.
	// By doing this, we make sure that the data from clouds.yaml is enough to authenticate.
	// For more information: https://github.com/gophercloud/utils/blob/8677e053dcf1f05d0fa0a616094aace04690eb94/openstack/clientconfig/requests.go#L508
	opts.EnvPrefix = "NO_ENV_VARIABLES_"
	return opts
}

func createVolume (ctx context.Context, cloud string, volumeName string, volumeSize int, availabilityZone string, imageID string) error {
	var (
		err error
	)

	conn, err := NewServiceClient(ctx, "volume", DefaultClientOpts(cloud))
	if err != nil {
		panic(err)
	}

//	schedulerHintOpts := volumes.SchedulerHintOpts{
//		SameHost: []string{
//			"e980",
//		},
//	}

	createOpts := volumes.CreateOpts{
		Name:              volumeName,
		Size:              volumeSize,
		AvailabilityZone:  availabilityZone,
		ImageID:           imageID,
	}

	volume, err := volumes.Create(ctx, conn, createOpts, nil).Extract()
	if err != nil {
		panic(err)
	}

	logrus.Debugf("volume = %+v", volume)

	return nil
}

func createServer (ctx context.Context, cloud string) error {
	var (
		addressPairs      []ports.AddressPair
		builder           ports.CreateOptsBuilder
		portCreateOpts    = ports.CreateOpts{
			Name:                  "hamzy-test-rhcos-port",
			// openstack --os-cloud=... network list --format csv
			// "1762f355-b17e-4d13-9bca-d5b53c929ab0","vlan...","['ae643a65-d0fc-4408-90c6-a820340bfade']"
			NetworkID:             "1762f355-b17e-4d13-9bca-d5b53c929ab0",
			Description:           "hamzy test",
			AdminStateUp:          nil,
			MACAddress:            ptr.Deref(nil, ""),
			AllowedAddressPairs:   addressPairs,
			ValueSpecs:            nil,
			PropagateUplinkStatus: nil,
		}
		tags              [1]string // @TBD

		portList          []servers.Network
		userData          []byte

		serverCreateOpts  servers.CreateOptsBuilder

		schedulerHintOpts servers.SchedulerHintOptsBuilder
	)

	tags = [...]string{ "openshiftClusterID=rdr-hamzy-openstack-abcdef" }
	fmt.Printf("tags = %+v\n", tags)

	connNetwork, err := NewServiceClient(ctx, "network", DefaultClientOpts(cloud))
	if err != nil {
		return err
	}
	fmt.Printf("connNetwork = %+v\n", connNetwork)

	connCompute, err := NewServiceClient(ctx, "compute", DefaultClientOpts(cloud))
	if err != nil {
		return err
	}
	fmt.Printf("connCompute = %+v\n", connCompute)

	builder = portCreateOpts
	fmt.Printf("builder = %+v\n", builder)

	port, err := ports.Create(ctx, connNetwork, builder).Extract()
	if err != nil {
		return err
	}
	fmt.Printf("port = %+v\n", port)
	fmt.Printf("port.ID = %v\n", port.ID)

	portList = []servers.Network{
		{ Port: port.ID, },
	}

	userData, err = bootstrapIgnitionFile ()
	if err != nil {
		return err
	}

	serverCreateOpts = servers.CreateOpts{
		Name:             "hamzy-test-rhcos",
		// openstack --os-cloud=... image list --format csv
		// "0cc93e4b-48c1-4167-b8af-64f218b25fb6","...","active"
		ImageRef:         "0cc93e4b-48c1-4167-b8af-64f218b25fb6",
		// openstack --os-cloud=powervc flavor list --format csv
		// "9b4818ba-edf7-41e3-a516-53ee08b760fe","...",16384,25,0,4,True
		FlavorRef:        "9b4818ba-edf7-41e3-a516-53ee08b760fe",
		AvailabilityZone: "e980",
		Networks:         portList,
		UserData:         userData,
		// Additional properties are not allowed ('tags' was unexpected)
//		Tags:             tags[:],
//		Metadata:         instanceSpec.Metadata,
//		ConfigDrive:      &instanceSpec.ConfigDrive,
//		BlockDevice:      blockDevices,
	}
	fmt.Printf("serverCreateOpts = %+v\n", serverCreateOpts)

	fmt.Printf("schedulerHintOpts = %+v\n", schedulerHintOpts)

	server, err := servers.Create(ctx, connCompute, serverCreateOpts, schedulerHintOpts).Extract()
	if err != nil {
		return err
	}
	fmt.Printf("server = %+v\n", server)

	return err
}

func bootstrapIgnitionFile () ([]byte, error) {
	var (
		byteData []byte
		strData  string
		err      error
	)

	byteData, err = Marshal(igntypes.Config{
		Ignition: igntypes.Ignition{
			Version: igntypes.MaxVersion.String(),
			Timeouts: igntypes.Timeouts{
				HTTPResponseHeaders: ptr.To(120),
			},
		},
		Passwd: igntypes.Passwd{
			Users: []igntypes.PasswdUser{
				igntypes.PasswdUser{
					Name:             "core",
					PasswordHash:      ptr.To("$1$nt2LMmfV$gHmLQRT0xNm86H.iW7DIi0"),
					SSHAuthorizedKeys: []igntypes.SSHAuthorizedKey{
						"ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQCfrxxUx9MKdEWDStyVVkVTnxPQRHjQU7Gnu+USEbGCq3gb1t4Hs863mkJ3cgH9h4TsXxY7SofDu1MNw3QMt+S2BiUN6RlaQbkhJ41bzdCvy4tg3NiJdiUY0EtiLV5rXR+/wQbEIlkThhXCYEXxOcBA+0GMkAGuyAM2zZekpWh9xmkex1KQy0A8FEgS+gC8d0ok3u1ozZ85hlGxrKT2pxWhS9P2KdAx5Vrt5lsCZyif6HucAjp5EYoZbaJLHmOP3F7f+Rbf+yIxXTCZfcOQN/nf6wz5L4VPCvSjmV4GauVLcbOZCADdRDdE71ky8owHSxoxfjr6ukkU8btecF/JLJeZoaQWGCd6XrkvCjFTS6n2PEckR80UF4j7TGthSmZcI1ach5GROyyb9Oajeciwq6zJeNvDJAcvXLi5fQYbvAOhjTEkqYtlLvcyNCwp8vexPA5G8n381t/3F5kxkrrRYcbQf+N21Mo10CecaO86peV+sIpPPsYCgbE9QVG07okY1XrKkfBrtOoMwn12n1DX/UJbYeiqY3sI+QikbDgL+kDRP4tn4VYLs9uNDaKlBNDrRNwniWO8YKOZQGsonG1JeuU2UMbNfDnR7BzVUkAjMKFfZKA/yfOuIC09BoxmkQ7wDMwb10QNZ7/Y5XDRAKN6o0SFqsBq4FnBQ31+wPd3HBSpGw== hamzy@li-3d08e84c-2e1c-11b2-a85c-e2db7bb078fc.ibm.com",
					},
				},
			},
		},
	})
	fmt.Printf("byteData = %v\n", byteData)

	if err != nil {
		return nil, fmt.Errorf("unable to encode the Ignition: %w", err)
	}

	strData = base64.StdEncoding.EncodeToString(byteData)
	fmt.Printf("strData = %v\n", strData)

	// Check the size of the base64-rendered ignition shim isn't to big for nova
	// https://docs.openstack.org/nova/latest/user/metadata.html#user-data
	if len(strData) > 65535 {
		return nil, fmt.Errorf("rendered bootstrap ignition shim exceeds the 64KB limit for nova user data")
	}

	return byteData, nil
}

func fixServer (ctx context.Context, cloud string, serverName string) error {
	var (
		pager             pagination.Page
		allServers        []servers.Server
		server            servers.Server
		found             = false
		imageRef          string
		flavorRef         string
		ok                bool
		serverCreateOpts  servers.CreateOptsBuilder
		err               error
	)

	connCompute, err := NewServiceClient(ctx, "compute", DefaultClientOpts(cloud))
	if err != nil {
		return err
	}
	fmt.Printf("connCompute = %+v\n", connCompute)

	pager, err = servers.List(connCompute, nil).AllPages(ctx)
	if err != nil {
		return err
	}
//	fmt.Printf("pager = %+v\n", pager)

	allServers, err = servers.ExtractServers(pager)
	if err != nil {
		return err
	}
//	fmt.Printf("allServers = %+v\n", allServers)

	for _, server = range allServers {
		if !strings.EqualFold(server.Name, serverName) {
			continue
		}
		fmt.Printf("server = %+v\n", server)
		found = true
	}
	if !found {
		return fmt.Errorf("Error: did not find server named %s", serverName)
	}

	imageRef, ok = server.Image["id"].(string)
	if !ok {
		return fmt.Errorf("Error: did not find image id in %+v", server.Image)
	}

	flavorRef, ok = server.Flavor["id"].(string)
	if !ok {
		return fmt.Errorf("Error: did not find image id in %+v", server.Image)
	}

	// @TODO - server.Tags:<nil> for some reason

	serverCreateOpts = servers.CreateOpts{
		Name:             server.Name,
		ImageRef:         imageRef,
		FlavorRef:        flavorRef,
		AvailabilityZone: server.AvailabilityZone,
//		Networks:         portList,
//		UserData:         userData,
		// @TODO - Additional properties are not allowed ('tags' was unexpected)
//		Tags:             tags[:],
//		Metadata:         instanceSpec.Metadata,
//		ConfigDrive:      &instanceSpec.ConfigDrive,
//		BlockDevice:      blockDevices,
	}
	fmt.Printf("serverCreateOpts = %+v\n", serverCreateOpts)

	return nil
}

func dhcpdConf (ctx context.Context, cloud string, serverSearch string) error {
	var (
		pager             pagination.Page
		allServers        []servers.Server
		server            servers.Server
		subnetContents    []interface {}
		mapSubNetwork     map[string]interface{}
		ok                bool
		ipAddress         string
		err               error
	)

	connCompute, err := NewServiceClient(ctx, "compute", DefaultClientOpts(cloud))
	if err != nil {
		return err
	}
//	fmt.Printf("connCompute = %+v\n", connCompute)

	pager, err = servers.List(connCompute, nil).AllPages(ctx)
	if err != nil {
		return err
	}
//	fmt.Printf("pager = %+v\n", pager)

	allServers, err = servers.ExtractServers(pager)
	if err != nil {
		return err
	}
//	fmt.Printf("allServers = %+v\n", allServers)

	fmt.Printf("#\n")
	fmt.Printf("# DHCP Server Configuration file.\n")
	fmt.Printf("#   see /usr/share/doc/dhcp-server/dhcpd.conf.example\n")
	fmt.Printf("#   see dhcpd.conf(5) man page\n")
	fmt.Printf("#\n")
	fmt.Printf("\n")
	fmt.Printf("# Persist interface configuration when dhcpcd exits.\n")
	fmt.Printf("persistent;\n")
	fmt.Printf("\n")
	fmt.Printf("default-lease-time 2678400;\n")
	fmt.Printf("max-lease-time 2678400;\n")
	fmt.Printf("\n")
	fmt.Printf("subnet 10.20.176.0 netmask 255.255.240.0 {\n")
	fmt.Printf("   interface env2;\n")
	fmt.Printf("   option routers 10.20.176.1;\n")
	fmt.Printf("   option subnet-mask 255.255.240.0;\n")
	fmt.Printf("   option domain-name-servers 10.0.10.4, 9.9.9.9;\n")
	fmt.Printf("#  option domain-name \"pokprv.stglabs.ibm.com\";\n")
	fmt.Printf("   option domain-name \"powervs-openshift-ipi.cis.ibm.net\";\n")
	fmt.Printf("   ignore unknown-clients;\n")
	fmt.Printf("#  update-static-leases true;\n")
	fmt.Printf("}\n")
	fmt.Printf("\n")
	fmt.Printf("host hamzy-test-centos {\n")
	fmt.Printf("    hardware ethernet    fa:cd:76:47:3b:20;\n")
	fmt.Printf("    fixed-address        10.20.176.157;\n")
	fmt.Printf("    max-lease-time       84600;\n")
	fmt.Printf("}\n")
	fmt.Printf("\n")
	fmt.Printf("host hamzy-test-rhcos {\n")
	fmt.Printf("    hardware ethernet    fa:16:3e:11:90:1b;\n")
	fmt.Printf("    fixed-address        10.20.176.158;\n")
	fmt.Printf("    max-lease-time       84600;\n")
	fmt.Printf("}\n")
	fmt.Printf("\n")

	for _, server = range allServers {
		if !strings.Contains(strings.ToLower(server.Name), strings.ToLower(serverSearch)) {
			continue
		}
//		fmt.Printf("server = %+v\n", server)

		for key := range server.Addresses {
//			fmt.Printf("key = %+v\n", key)

			// Addresses:map[vlan1337:[map[OS-EXT-IPS-MAC:mac_addr:fa:16:3e:b1:33:03 OS-EXT-IPS:type:fixed addr:10.20.182.169 version:4]]]
			subnetContents, ok = server.Addresses[key].([]interface {})
			if !ok {
				return fmt.Errorf("Error: did not convert to [] of interface {}: %v", server.Addresses)
			}

			for _, subnetValue := range subnetContents {
//				fmt.Printf("subnetValue = %+v\n", subnetValue)
//				fmt.Printf("subnetValue = %+v\n", reflect.TypeOf(subnetValue))

				mapSubNetwork, ok = subnetValue.(map[string]interface{})
				if !ok {
					return fmt.Errorf("Error: did not convert to map[string] of interface {}: %v", server.Addresses)
				}

//				fmt.Printf("mapSubNetwork = %+v\n", mapSubNetwork)

				macAddr, ok := mapSubNetwork["OS-EXT-IPS-MAC:mac_addr"]
				if !ok {
					return fmt.Errorf("Error: mapSubNetwork did not contain \"OS-EXT-IPS-MAC:mac_addr\": %v", mapSubNetwork)
				}

/*
				if strings.Contains(strings.ToLower(server.Name), "bootstrap") {
					ipAddress = "10.20.176.159";
				} else if strings.Contains(strings.ToLower(server.Name), "master-0") {
					ipAddress = "10.20.176.160";
				} else if strings.Contains(strings.ToLower(server.Name), "master-1") {
					ipAddress = "10.20.176.161";
				} else if strings.Contains(strings.ToLower(server.Name), "master-2") {
					ipAddress = "10.20.176.162";
				}
*/
				ipAddressI, ok := mapSubNetwork["addr"]
				if !ok {
					return fmt.Errorf("Error: mapSubNetwork did not contain \"addr\": %v", mapSubNetwork)
				}
				ipAddress, ok = ipAddressI.(string)
				if !ok {
					return fmt.Errorf("Error: ipAddressI was not a string: %v", ipAddressI)
				}

				fmt.Printf("host %s {\n", server.Name)
				fmt.Printf("    hardware ethernet    %s;\n", macAddr)
				fmt.Printf("    fixed-address        %s;\n", ipAddress)
				fmt.Printf("    max-lease-time       84600;\n")
				fmt.Printf("    option host-name     \"%s\";\n", server.Name)
				fmt.Printf("    ddns-hostname        %s;\n", server.Name)
				fmt.Printf("}\n")
				fmt.Printf("\n")

//				for subNetworkKey := range mapSubNetwork {
//					fmt.Printf("subNetworkKey = %+v\n", subNetworkKey)
//				}
			}
		}
	}

	return nil
}

func haproxyCfg (ctx context.Context, cloud string, serverSearch string) error {
	var (
		pager             pagination.Page
		allServers        []servers.Server
		server            servers.Server
		subnetContents    []interface {}
		mapSubNetwork     map[string]interface{}
		ok                bool
		ipAddress         string
		err               error
	)

	connCompute, err := NewServiceClient(ctx, "compute", DefaultClientOpts(cloud))
	if err != nil {
		return err
	}
//	fmt.Printf("connCompute = %+v\n", connCompute)

	pager, err = servers.List(connCompute, nil).AllPages(ctx)
	if err != nil {
		return err
	}
//	fmt.Printf("pager = %+v\n", pager)

	allServers, err = servers.ExtractServers(pager)
	if err != nil {
		return err
	}
//	fmt.Printf("allServers = %+v\n", allServers)

	fmt.Printf("#\n")
	fmt.Printf("global\n")
	fmt.Printf("daemon\n")
	fmt.Printf("\n")
	fmt.Printf("defaults\n")
	fmt.Printf("log global\n")
	fmt.Printf("timeout connect 5s\n")
	fmt.Printf("timeout client 50s\n")
	fmt.Printf("timeout server 50s\n")
	fmt.Printf("\n")
	fmt.Printf("listen stats # Define a listen section called \"stats\"\n")
	fmt.Printf("  bind :9000 # Listen on localhost:9000\n")
	fmt.Printf("  mode http\n")
	fmt.Printf("  stats enable  # Enable stats page\n")
	fmt.Printf("  stats hide-version  # Hide HAProxy version\n")
	fmt.Printf("  stats realm Haproxy\\ Statistics  # Title text for popup window\n")
	fmt.Printf("  stats uri /haproxy_stats  # Stats URI\n")
	fmt.Printf("  stats auth Username:Password  # Authentication credentials\n")
	fmt.Printf("\n")
/*
listen api
bind *:6443
mode tcp
server bootstrap 10.20.179.192:6443 check
server master0 10.20.179.64:6443 check
server master1 10.20.179.131:6443 check
server master2 10.20.184.150:6443 check

listen machine-config-server
bind *:22623
mode tcp
server bootstrap 10.20.179.192:22623 check
server master0 10.20.179.64:22623 check
server master1 10.20.179.131:22623 check
server master2 10.20.184.150:22623 check
*/

	// listen ingress-http
	fmt.Printf("listen ingress-http\n")
	fmt.Printf("bind *:80\n")
	fmt.Printf("mode tcp\n")
	for _, server = range allServers {
		if !strings.Contains(strings.ToLower(server.Name), strings.ToLower(serverSearch)) {
			continue
		}
		if !strings.Contains(strings.ToLower(server.Name), "worker") {
			continue
		}

		for key := range server.Addresses {
			subnetContents, ok = server.Addresses[key].([]interface {})
			if !ok {
				return fmt.Errorf("Error: did not convert to [] of interface {}: %v", server.Addresses)
			}

			for _, subnetValue := range subnetContents {
				mapSubNetwork, ok = subnetValue.(map[string]interface{})
				if !ok {
					return fmt.Errorf("Error: did not convert to map[string] of interface {}: %v", server.Addresses)
				}

				ipAddressI, ok := mapSubNetwork["addr"]
				if !ok {
					return fmt.Errorf("Error: mapSubNetwork did not contain \"addr\": %v", mapSubNetwork)
				}
				ipAddress, ok = ipAddressI.(string)
				if !ok {
					return fmt.Errorf("Error: ipAddressI was not a string: %v", ipAddressI)
				}

				fmt.Printf("server %s %s:80 check\n", server.Name, ipAddress)
			}
		}
	}
	fmt.Printf("\n")

	// listen ingress-https
	fmt.Printf("listen ingress-https\n")
	fmt.Printf("bind *:443\n")
	fmt.Printf("mode tcp\n")
	for _, server = range allServers {
		if !strings.Contains(strings.ToLower(server.Name), strings.ToLower(serverSearch)) {
			continue
		}
		if !strings.Contains(strings.ToLower(server.Name), "worker") {
			continue
		}

		for key := range server.Addresses {
			subnetContents, ok = server.Addresses[key].([]interface {})
			if !ok {
				return fmt.Errorf("Error: did not convert to [] of interface {}: %v", server.Addresses)
			}

			for _, subnetValue := range subnetContents {
				mapSubNetwork, ok = subnetValue.(map[string]interface{})
				if !ok {
					return fmt.Errorf("Error: did not convert to map[string] of interface {}: %v", server.Addresses)
				}

				ipAddressI, ok := mapSubNetwork["addr"]
				if !ok {
					return fmt.Errorf("Error: mapSubNetwork did not contain \"addr\": %v", mapSubNetwork)
				}
				ipAddress, ok = ipAddressI.(string)
				if !ok {
					return fmt.Errorf("Error: ipAddressI was not a string: %v", ipAddressI)
				}

				fmt.Printf("server %s %s:443 check\n", server.Name, ipAddress)
			}
		}
	}
	fmt.Printf("\n")

	// listen api
	fmt.Printf("listen api\n")
	fmt.Printf("bind *:6443\n")
	fmt.Printf("mode tcp\n")
	for _, server = range allServers {
		if !strings.Contains(strings.ToLower(server.Name), strings.ToLower(serverSearch)) {
			continue
		}
		if !(strings.Contains(strings.ToLower(server.Name), "bootstrap") || strings.Contains(strings.ToLower(server.Name), "master")) {
			continue
		}

		for key := range server.Addresses {
			subnetContents, ok = server.Addresses[key].([]interface {})
			if !ok {
				return fmt.Errorf("Error: did not convert to [] of interface {}: %v", server.Addresses)
			}

			for _, subnetValue := range subnetContents {
				mapSubNetwork, ok = subnetValue.(map[string]interface{})
				if !ok {
					return fmt.Errorf("Error: did not convert to map[string] of interface {}: %v", server.Addresses)
				}

				ipAddressI, ok := mapSubNetwork["addr"]
				if !ok {
					return fmt.Errorf("Error: mapSubNetwork did not contain \"addr\": %v", mapSubNetwork)
				}
				ipAddress, ok = ipAddressI.(string)
				if !ok {
					return fmt.Errorf("Error: ipAddressI was not a string: %v", ipAddressI)
				}

				fmt.Printf("server %s %s:6443 check\n", server.Name, ipAddress)
			}
		}
	}
	fmt.Printf("\n")

	// listen machine-config-server
	fmt.Printf("listen machine-config-server\n")
	fmt.Printf("bind *:22623\n")
	fmt.Printf("mode tcp\n")
	for _, server = range allServers {
		if !strings.Contains(strings.ToLower(server.Name), strings.ToLower(serverSearch)) {
			continue
		}
		if !(strings.Contains(strings.ToLower(server.Name), "bootstrap") || strings.Contains(strings.ToLower(server.Name), "master")) {
			continue
		}

		for key := range server.Addresses {
			subnetContents, ok = server.Addresses[key].([]interface {})
			if !ok {
				return fmt.Errorf("Error: did not convert to [] of interface {}: %v", server.Addresses)
			}

			for _, subnetValue := range subnetContents {
				mapSubNetwork, ok = subnetValue.(map[string]interface{})
				if !ok {
					return fmt.Errorf("Error: did not convert to map[string] of interface {}: %v", server.Addresses)
				}

				ipAddressI, ok := mapSubNetwork["addr"]
				if !ok {
					return fmt.Errorf("Error: mapSubNetwork did not contain \"addr\": %v", mapSubNetwork)
				}
				ipAddress, ok = ipAddressI.(string)
				if !ok {
					return fmt.Errorf("Error: ipAddressI was not a string: %v", ipAddressI)
				}

				fmt.Printf("server %s %s:22623 check\n", server.Name, ipAddress)
			}
		}
	}

	return nil
}

func dnsRecords (ctx context.Context, cloud string, serverSearch string, dnsDomain string) error {
	var (
		pager             pagination.Page
		allServers        []servers.Server
		server            servers.Server
		clusterName       string
		subnetContents    []interface {}
		mapSubNetwork     map[string]interface{}
		ok                bool
		ipAddress         string
		err               error
	)

	connCompute, err := NewServiceClient(ctx, "compute", DefaultClientOpts(cloud))
	if err != nil {
		return err
	}
//	fmt.Printf("connCompute = %+v\n", connCompute)

	pager, err = servers.List(connCompute, nil).AllPages(ctx)
	if err != nil {
		return err
	}
//	fmt.Printf("pager = %+v\n", pager)

	allServers, err = servers.ExtractServers(pager)
	if err != nil {
		return err
	}
//	fmt.Printf("allServers = %+v\n", allServers)

	fmt.Printf("\n")
	fmt.Printf(`(set -e; FILE=$(mktemp); trap "/bin/rm -rf ${FILE}" EXIT; ibmcloud cis instance-set $(ibmcloud cis instances --output json | jq -r '.[].id'); export DNS_DOMAIN_ID=$(ibmcloud cis domains --output json | jq -r '.[].id'); echo "DNS_DOMAIN_ID=${DNS_DOMAIN_ID}"; PAGE=1; while true; do ibmcloud cis dns-records ${DNS_DOMAIN_ID} --page ${PAGE} --output json > ${FILE}; if (( $(jq -r 'length' < ${FILE}) == 0 )); then break; fi; (while read UUID NAME; do echo "Deleting: ${NAME}"; ibmcloud cis dns-record-delete ${DNS_DOMAIN_ID} ${UUID}; done) < <(jq -r '.[] | select (.name|test("rdr-hamzy-openstack")) | "\(.id) \(.name)"' < ${FILE}); PAGE=$((PAGE+1)); done)`)

	for _, server = range allServers {
		if !strings.Contains(strings.ToLower(server.Name), strings.ToLower(serverSearch)) {
			continue
		}

		idx := strings.Index(server.Name, serverSearch)
		clusterName = server.Name[0:idx-1]
		break
	}

	fmt.Printf("ibmcloud cis dns-record-create %s --json '{ \"name\": \"api.%s.powervs-openshift-ipi.cis.ibm.net\", \"type\": \"A\", \"content\": \"10.20.184.56\", \"ttl\": 60 }'\n", dnsDomain, clusterName)
	fmt.Printf("ibmcloud cis dns-record-create %s --json '{ \"name\": \"api-int.%s.powervs-openshift-ipi.cis.ibm.net\", \"type\": \"A\", \"content\": \"10.20.184.56\", \"ttl\": 60 }'\n", dnsDomain, clusterName)
	fmt.Printf("ibmcloud cis dns-record-create %s --json '{ \"name\": \"*.apps.%s.powervs-openshift-ipi.cis.ibm.net\", \"type\": \"CNAME\", \"content\": \"api.%s.powervs-openshift-ipi.cis.ibm.net\" }'\n", dnsDomain, clusterName, clusterName)


	for _, server = range allServers {
		if !strings.Contains(strings.ToLower(server.Name), strings.ToLower(serverSearch)) {
			continue
		}

		for key := range server.Addresses {
			subnetContents, ok = server.Addresses[key].([]interface {})
			if !ok {
				return fmt.Errorf("Error: did not convert to [] of interface {}: %v", server.Addresses)
			}

			for _, subnetValue := range subnetContents {
				mapSubNetwork, ok = subnetValue.(map[string]interface{})
				if !ok {
					return fmt.Errorf("Error: did not convert to map[string] of interface {}: %v", server.Addresses)
				}

				ipAddressI, ok := mapSubNetwork["addr"]
				if !ok {
					return fmt.Errorf("Error: mapSubNetwork did not contain \"addr\": %v", mapSubNetwork)
				}
				ipAddress, ok = ipAddressI.(string)
				if !ok {
					return fmt.Errorf("Error: ipAddressI was not a string: %v", ipAddressI)
				}

				fmt.Printf("ibmcloud cis dns-record-create %s --json '{ \"name\": \"%s.powervs-openshift-ipi.cis.ibm.net\", \"type\": \"A\", \"content\": \"%s\", \"ttl\": 60 }'\n", dnsDomain, server.Name, ipAddress)
			}
		}
	}

	return nil
}

func imageUploadCommand (imageUploadFlags *flag.FlagSet, args []string) error {
	var (
		ptrCloud            *string
		ptrRhcosImage       *string
		ptrImageName        *string
		ptrInfraID          *string

		ctx                 context.Context
		cancel              context.CancelFunc

		imageProperties     map[string]string
	)

	ptrCloud = imageUploadFlags.String("cloud", "", "The cloud to use in clouds.yaml")
	ptrRhcosImage = imageUploadFlags.String("rhcosImage", "", "The URL to download the RHCOS image")
	ptrImageName = imageUploadFlags.String("imageName", "", "The image name to save into")
	ptrInfraID = imageUploadFlags.String("infraID", "", "The infrastructure ID to tag with")

	imageUploadFlags.Parse(args)

	if ptrCloud == nil || *ptrCloud == "" {
		fmt.Println("Error: --cloud not specified")
		os.Exit(1)
	}
	if ptrRhcosImage == nil || *ptrRhcosImage == "" {
		fmt.Println("Error: --rhcosImage not specified")
		os.Exit(1)
	}
	if ptrImageName == nil || *ptrImageName == "" {
		fmt.Println("Error: --imageName not specified")
		os.Exit(1)
	}
	if ptrInfraID == nil || *ptrInfraID == "" {
		fmt.Println("Error: --infraID not specified")
		os.Exit(1)
	}
	if len(imageUploadFlags.Args()) != 0 {
		fmt.Printf("Error: extra options specified: %v\n", imageUploadFlags.Args())
		os.Exit(1)
	}

	ctx, cancel = context.WithTimeout(context.TODO(), 15*time.Minute)
	defer cancel()

	return UploadBaseImage(ctx, *ptrCloud, *ptrRhcosImage, *ptrImageName, *ptrInfraID, imageProperties)
}

func bootstrapUploadCommand (bootstrapUploadFlags *flag.FlagSet, args []string) error {
	var (
		ptrCloud            *string
		ptrImageName        *string
		ptrInfraID          *string
		ptrIgnitionFile     *string

		ctx                 context.Context
		cancel              context.CancelFunc

		bootstrapIgnIn      []byte
		bootstrapIgnOut     []byte

		err                 error
	)

	ptrCloud = bootstrapUploadFlags.String("cloud", "", "The cloud to use in clouds.yaml")
	ptrImageName = bootstrapUploadFlags.String("imageName", "", "The image name to save into")
	ptrInfraID = bootstrapUploadFlags.String("infraID", "", "The infrastructure ID to tag with")
	ptrIgnitionFile = bootstrapUploadFlags.String("ignitionFile", "", "The location of the ignition file")

	bootstrapUploadFlags.Parse(args)

	if ptrCloud == nil || *ptrCloud == "" {
		fmt.Println("Error: --cloud not specified")
		os.Exit(1)
	}
	if ptrImageName == nil || *ptrImageName == "" {
		fmt.Println("Error: --imageName not specified")
		os.Exit(1)
	}
	if ptrInfraID == nil || *ptrInfraID == "" {
		fmt.Println("Error: --infraID not specified")
		os.Exit(1)
	}
	if ptrIgnitionFile == nil || *ptrIgnitionFile == "" {
		fmt.Println("Error: --ignitionFile not specified")
		os.Exit(1)
	}
	if len(bootstrapUploadFlags.Args()) != 0 {
		fmt.Printf("Error: extra options specified: %v\n", bootstrapUploadFlags.Args())
		os.Exit(1)
	}

	ctx, cancel = context.WithTimeout(context.TODO(), 15*time.Minute)
	defer cancel()

	bootstrapIgnIn, err = os.ReadFile(*ptrIgnitionFile)
	if err != nil {
		return err
	}

	bootstrapIgnOut, err = UploadIgnitionAndBuildShim(ctx, *ptrCloud, *ptrInfraID, *ptrImageName, bootstrapIgnIn)

	fmt.Printf("bootstrapIgnOut = %v\n", bootstrapIgnOut)

	return err
}

func volumeCreateCommand (volumeCreateFlags *flag.FlagSet, args []string) error {
	var (
		ptrCloud            *string
		ptrVolumeName       *string
		ptrVolumeSize       *int
		ptrAvailabilityZone *string
		ptrImageID          *string

		ctx                 context.Context
		cancel              context.CancelFunc
	)

	ptrCloud = volumeCreateFlags.String("cloud", "", "The cloud to use in clouds.yaml")
	ptrVolumeName = volumeCreateFlags.String("volumeName", "", "The name of the volume to create")
	ptrVolumeSize = volumeCreateFlags.Int("volumeSize", 0, "The size of the volume to create")
	ptrAvailabilityZone = volumeCreateFlags.String("availabilityZone", "", "The availability zone to use")
	ptrImageID = volumeCreateFlags.String("imageID", "", "The UUID of the image to copy from")

	volumeCreateFlags.Parse(args)

	if ptrCloud == nil || *ptrCloud == "" {
		fmt.Println("Error: --cloud not specified")
		os.Exit(1)
	}
	if ptrVolumeName == nil || *ptrVolumeName == "" {
		fmt.Println("Error: --volumeName not specified")
		os.Exit(1)
	}
	if ptrVolumeSize == nil {
		fmt.Println("Error: --volumeSize not specified")
		os.Exit(1)
	}
	if *ptrVolumeSize == 0 {
		fmt.Println("Error: --volumeSize should not be 0")
		os.Exit(1)
	}
	if ptrAvailabilityZone == nil || *ptrAvailabilityZone == "" {
		fmt.Println("Error: --availabilityZone not specified")
		os.Exit(1)
	}
	if ptrImageID == nil || *ptrImageID == "" {
		fmt.Println("Error: --imageID not specified")
		os.Exit(1)
	}

	ctx, cancel = context.WithTimeout(context.TODO(), 15*time.Minute)
	defer cancel()

	return createVolume (ctx, *ptrCloud, *ptrVolumeName, *ptrVolumeSize, *ptrAvailabilityZone, *ptrImageID)
}

func serverCreateCommand (serverCreateFlags *flag.FlagSet, args []string) error {
	var (
		ptrCloud            *string

		ctx                 context.Context
		cancel              context.CancelFunc
	)

	ptrCloud = serverCreateFlags.String("cloud", "", "The cloud to use in clouds.yaml")

	serverCreateFlags.Parse(args)

	if ptrCloud == nil || *ptrCloud == "" {
		fmt.Println("Error: --cloud not specified")
		os.Exit(1)
	}

	ctx, cancel = context.WithTimeout(context.TODO(), 15*time.Minute)
	defer cancel()

	return createServer (ctx, *ptrCloud)
}

func serverFixCommand (serverFixFlags *flag.FlagSet, args []string) error {
	var (
		ptrCloud            *string
		ptrServerName       *string

		ctx                 context.Context
		cancel              context.CancelFunc
	)

	ptrCloud = serverFixFlags.String("cloud", "", "The cloud to use in clouds.yaml")
	ptrServerName = serverFixFlags.String("serverName", "", "The name of the server to copy")

	serverFixFlags.Parse(args)

	if ptrCloud == nil || *ptrCloud == "" {
		fmt.Println("Error: --cloud not specified")
		os.Exit(1)
	}
	if ptrServerName == nil || *ptrServerName == "" {
		fmt.Println("Error: --serverName not specified")
		os.Exit(1)
	}

	ctx, cancel = context.WithTimeout(context.TODO(), 15*time.Minute)
	defer cancel()

	return fixServer (ctx, *ptrCloud, *ptrServerName)
}

func createDhcpdConf (createDhcpdConfFlags *flag.FlagSet, args []string) error {
	var (
		ptrCloud            *string
		ptrServerSearch     *string

		ctx                 context.Context
		cancel              context.CancelFunc
	)

	ptrCloud = createDhcpdConfFlags.String("cloud", "", "The cloud to use in clouds.yaml")
	ptrServerSearch = createDhcpdConfFlags.String("serverSearch", "", "The name of the servers to show MACs")

	createDhcpdConfFlags.Parse(args)

	if ptrCloud == nil || *ptrCloud == "" {
		fmt.Println("Error: --cloud not specified")
		os.Exit(1)
	}
	if ptrServerSearch == nil || *ptrServerSearch == "" {
		fmt.Println("Error: --serverSearch not specified")
		os.Exit(1)
	}

	ctx, cancel = context.WithTimeout(context.TODO(), 15*time.Minute)
	defer cancel()

	return dhcpdConf (ctx, *ptrCloud, *ptrServerSearch)
}

func createHaproxyCfg (createHaproxyCfgFlags *flag.FlagSet, args []string) error {
	var (
		ptrCloud            *string
		ptrServerSearch     *string

		ctx                 context.Context
		cancel              context.CancelFunc
	)

	ptrCloud = createHaproxyCfgFlags.String("cloud", "", "The cloud to use in clouds.yaml")
	ptrServerSearch = createHaproxyCfgFlags.String("serverSearch", "", "The name of the servers to show MACs")

	createHaproxyCfgFlags.Parse(args)

	if ptrCloud == nil || *ptrCloud == "" {
		fmt.Println("Error: --cloud not specified")
		os.Exit(1)
	}
	if ptrServerSearch == nil || *ptrServerSearch == "" {
		fmt.Println("Error: --serverSearch not specified")
		os.Exit(1)
	}

	ctx, cancel = context.WithTimeout(context.TODO(), 15*time.Minute)
	defer cancel()

	return haproxyCfg (ctx, *ptrCloud, *ptrServerSearch)
}

func createDnsRecords (createDnsRecordsFlags *flag.FlagSet, args []string) error {
	var (
		ptrCloud        *string
		ptrServerSearch *string
		ptrDnsDomain    *string

		ctx             context.Context
		cancel          context.CancelFunc
	)

	ptrCloud = createDnsRecordsFlags.String("cloud", "", "The cloud to use in clouds.yaml")
	ptrServerSearch = createDnsRecordsFlags.String("serverSearch", "", "The name of the servers to show MACs")
	ptrDnsDomain = createDnsRecordsFlags.String("dnsDomain", "", "The DNS domain to use")

	createDnsRecordsFlags.Parse(args)

	if ptrCloud == nil || *ptrCloud == "" {
		fmt.Println("Error: --cloud not specified")
		os.Exit(1)
	}
	if ptrServerSearch == nil || *ptrServerSearch == "" {
		fmt.Println("Error: --serverSearch not specified")
		os.Exit(1)
	}
	if ptrDnsDomain == nil || *ptrDnsDomain == "" {
		fmt.Println("Error: --dnsDomain not specified")
		os.Exit(1)
	}

	ctx, cancel = context.WithTimeout(context.TODO(), 15*time.Minute)
	defer cancel()

	return dnsRecords (ctx, *ptrCloud, *ptrServerSearch, *ptrDnsDomain)
}

func main () {
	var (
		imageUploadFlags      *flag.FlagSet
		bootstrapUploadFlags  *flag.FlagSet
		volumeCreateFlags     *flag.FlagSet
		serverCreateFlags     *flag.FlagSet
		serverFixFlags        *flag.FlagSet
		createDhcpdConfFlags  *flag.FlagSet
		createHaproxyCfgFlags *flag.FlagSet
		createDnsRecordsFlags *flag.FlagSet
		err                  error
	)

	if len(os.Args) == 1 {
		fmt.Println("Error: testOpenstack [ image-upload | bootstrap-upload | volume-create | server-create | server-fix | create-dhcpd-conf | create-haproxy-cfg | dns-record-create ]")
		os.Exit(1)
	}

	imageUploadFlags = flag.NewFlagSet("image-upload", flag.ExitOnError)
	bootstrapUploadFlags = flag.NewFlagSet("bootstrap-upload", flag.ExitOnError)
	volumeCreateFlags = flag.NewFlagSet("volume-create", flag.ExitOnError)
	serverCreateFlags = flag.NewFlagSet("server-create", flag.ExitOnError)
	serverFixFlags = flag.NewFlagSet("server-fix", flag.ExitOnError)
	createDhcpdConfFlags = flag.NewFlagSet("create-dhcpd-conf", flag.ExitOnError)
	createHaproxyCfgFlags = flag.NewFlagSet("create-haproxy-cfg", flag.ExitOnError)
	createDnsRecordsFlags = flag.NewFlagSet("dns-record-create", flag.ExitOnError)

	switch strings.ToLower(os.Args[1]) {
	case "image-upload":
		err = imageUploadCommand(imageUploadFlags, os.Args[2:])

	case "bootstrap-upload":
		err = bootstrapUploadCommand(bootstrapUploadFlags, os.Args[2:])

	case "volume-create":
		err = volumeCreateCommand(volumeCreateFlags, os.Args[2:])

	case "server-create":
		err = serverCreateCommand(serverCreateFlags, os.Args[2:])

	case "server-fix":
		err = serverFixCommand(serverFixFlags, os.Args[2:])

	case "create-dhcpd-conf":
		err = createDhcpdConf(createDhcpdConfFlags, os.Args[2:])

	case "create-haproxy-cfg":
		err = createHaproxyCfg(createHaproxyCfgFlags, os.Args[2:])

	case "dns-record-create":
		err = createDnsRecords(createDnsRecordsFlags, os.Args[2:])

	default:
		fmt.Printf("Error: Unknown command %s\n", os.Args[1])
		os.Exit(1)
	}

	if err != nil {
		panic(err)
	}
}

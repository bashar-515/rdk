package config_test

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/pkg/errors"
	pb "go.viam.com/api/app/v1"
	"go.viam.com/test"
	"go.viam.com/utils/rpc"

	"go.viam.com/rdk/config"
	"go.viam.com/rdk/config/testutils"
	"go.viam.com/rdk/grpc"
	"go.viam.com/rdk/logging"
	"go.viam.com/rdk/utils"
)

func TestFromReader(t *testing.T) {
	const (
		robotPartID = "forCachingTest"
		secret      = testutils.FakeCredentialPayLoad
	)
	var (
		logger = logging.NewTestLogger(t)
		ctx    = context.Background()
	)

	// clear cache
	setupClearCache := func(t *testing.T) {
		t.Helper()
		config.ClearCache(robotPartID)
		_, err := config.ReadFromCache(robotPartID)
		test.That(t, os.IsNotExist(err), test.ShouldBeTrue)
	}

	t.Run("online", func(t *testing.T) {
		setupClearCache(t)

		fakeServer, cleanup := testutils.NewFakeCloudServer(t, ctx, logger)
		defer cleanup()

		cloudResponse := &config.Cloud{
			ManagedBy:        "acme",
			SignalingAddress: "abc",
			ID:               robotPartID,
			Secret:           secret,
			FQDN:             "fqdn",
			LocalFQDN:        "localFqdn",
			LocationSecrets:  []config.LocationSecret{},
			LocationID:       "the-location",
			PrimaryOrgID:     "the-primary-org",
			MachineID:        "the-machine",
		}
		certProto := &pb.CertificateResponse{
			TlsCertificate: "cert",
			TlsPrivateKey:  "key",
		}

		cloudConfProto, err := config.CloudConfigToProto(cloudResponse)
		test.That(t, err, test.ShouldBeNil)
		protoConfig := &pb.RobotConfig{Cloud: cloudConfProto}
		fakeServer.StoreDeviceConfig(robotPartID, protoConfig, certProto)

		appAddress := fmt.Sprintf("http://%s", fakeServer.Addr().String())
		cloudResponse.AppAddress = appAddress
		appConn, err := grpc.NewAppConn(ctx, cloudResponse, logger)
		test.That(t, err, test.ShouldBeNil)
		defer appConn.Close()
		cfgText := fmt.Sprintf(`{"cloud":{"id":%q,"app_address":%q,"secret":%q}}`, robotPartID, appAddress, secret)
		gotCfg, err := config.FromReader(ctx, "", strings.NewReader(cfgText), logger, appConn)
		test.That(t, err, test.ShouldBeNil)

		expectedCloud := *cloudResponse
		expectedCloud.AppAddress = appAddress
		expectedCloud.TLSCertificate = certProto.TlsCertificate
		expectedCloud.TLSPrivateKey = certProto.TlsPrivateKey
		expectedCloud.RefreshInterval = time.Duration(10000000000)
		test.That(t, gotCfg.Cloud, test.ShouldResemble, &expectedCloud)

		test.That(t, gotCfg.StoreToCache(), test.ShouldBeNil)
		defer config.ClearCache(robotPartID)
		cachedCfg, err := config.ReadFromCache(robotPartID)
		test.That(t, err, test.ShouldBeNil)
		expectedCloud.AppAddress = ""
		test.That(t, cachedCfg.Cloud, test.ShouldResemble, &expectedCloud)
	})

	t.Run("offline with cached config", func(t *testing.T) {
		setupClearCache(t)

		cachedCloud := &config.Cloud{
			ManagedBy:        "acme",
			SignalingAddress: "abc",
			ID:               robotPartID,
			Secret:           secret,
			FQDN:             "fqdn",
			LocalFQDN:        "localFqdn",
			TLSCertificate:   "cert",
			TLSPrivateKey:    "key",
			LocationID:       "the-location",
			PrimaryOrgID:     "the-primary-org",
			MachineID:        "the-machine",
		}
		cachedConf := &config.Config{Cloud: cachedCloud}

		cfgToCache := &config.Config{Cloud: &config.Cloud{ID: robotPartID}}
		cfgToCache.SetToCache(cachedConf)
		err := cfgToCache.StoreToCache()
		test.That(t, err, test.ShouldBeNil)
		defer config.ClearCache(robotPartID)

		fakeServer, cleanup := testutils.NewFakeCloudServer(t, ctx, logger)
		defer cleanup()
		fakeServer.FailOnConfigAndCertsWith(context.DeadlineExceeded)
		fakeServer.StoreDeviceConfig(robotPartID, nil, nil)

		appAddress := fmt.Sprintf("http://%s", fakeServer.Addr().String())
		cfgText := fmt.Sprintf(`{"cloud":{"id":%q,"app_address":%q,"secret":%q}}`, robotPartID, appAddress, secret)
		cachedCloud.AppAddress = appAddress
		appConn, err := grpc.NewAppConn(ctx, cachedCloud, logger)
		test.That(t, err, test.ShouldBeNil)
		defer appConn.Close()

		gotCfg, err := config.FromReader(ctx, "", strings.NewReader(cfgText), logger, appConn)
		test.That(t, err, test.ShouldBeNil)

		expectedCloud := *cachedCloud
		expectedCloud.AppAddress = appAddress
		expectedCloud.TLSCertificate = "cert"
		expectedCloud.TLSPrivateKey = "key"
		expectedCloud.RefreshInterval = time.Duration(10000000000)
		test.That(t, gotCfg.Cloud, test.ShouldResemble, &expectedCloud)
	})

	t.Run("online with insecure signaling", func(t *testing.T) {
		setupClearCache(t)

		fakeServer, cleanup := testutils.NewFakeCloudServer(t, ctx, logger)
		defer cleanup()

		cloudResponse := &config.Cloud{
			ManagedBy:         "acme",
			SignalingAddress:  "abc",
			SignalingInsecure: true,
			ID:                robotPartID,
			Secret:            secret,
			FQDN:              "fqdn",
			LocalFQDN:         "localFqdn",
			LocationSecrets:   []config.LocationSecret{},
			LocationID:        "the-location",
			PrimaryOrgID:      "the-primary-org",
			MachineID:         "the-machine",
		}
		certProto := &pb.CertificateResponse{}

		cloudConfProto, err := config.CloudConfigToProto(cloudResponse)
		test.That(t, err, test.ShouldBeNil)
		protoConfig := &pb.RobotConfig{Cloud: cloudConfProto}
		fakeServer.StoreDeviceConfig(robotPartID, protoConfig, certProto)

		appAddress := fmt.Sprintf("http://%s", fakeServer.Addr().String())
		cfgText := fmt.Sprintf(`{"cloud":{"id":%q,"app_address":%q,"secret":%q}}`, robotPartID, appAddress, secret)
		cloudResponse.AppAddress = appAddress
		appConn, err := grpc.NewAppConn(ctx, cloudResponse, logger)
		test.That(t, err, test.ShouldBeNil)
		defer appConn.Close()
		gotCfg, err := config.FromReader(ctx, "", strings.NewReader(cfgText), logger, appConn)
		test.That(t, err, test.ShouldBeNil)

		expectedCloud := *cloudResponse
		expectedCloud.AppAddress = appAddress
		expectedCloud.RefreshInterval = time.Duration(10000000000)
		test.That(t, gotCfg.Cloud, test.ShouldResemble, &expectedCloud)

		err = gotCfg.StoreToCache()
		defer config.ClearCache(robotPartID)
		test.That(t, err, test.ShouldBeNil)
		cachedCfg, err := config.ReadFromCache(robotPartID)
		test.That(t, err, test.ShouldBeNil)
		expectedCloud.AppAddress = ""
		test.That(t, cachedCfg.Cloud, test.ShouldResemble, &expectedCloud)
	})
}

func TestStoreToCache(t *testing.T) {
	logger := logging.NewTestLogger(t)
	ctx := context.Background()
	cfg, err := config.FromReader(ctx, "", strings.NewReader(`{}`), logger, &grpc.AppConn{})

	test.That(t, err, test.ShouldBeNil)

	cloud := &config.Cloud{
		ManagedBy:        "acme",
		SignalingAddress: "abc",
		ID:               "forCachingTest",
		Secret:           "ghi",
		FQDN:             "fqdn",
		LocalFQDN:        "localFqdn",
		TLSCertificate:   "cert",
		TLSPrivateKey:    "key",
		AppAddress:       "https://app.viam.dev:443",
		LocationID:       "the-location",
		PrimaryOrgID:     "the-primary-org",
		MachineID:        "the-machine",
	}
	cfg.Cloud = cloud

	// errors if no unprocessed config to cache
	cfgToCache := &config.Config{Cloud: &config.Cloud{ID: "forCachingTest"}}
	err = cfgToCache.StoreToCache()
	test.That(t, err.Error(), test.ShouldContainSubstring, "no unprocessed config to cache")

	// store our config to the cache
	cfgToCache.SetToCache(cfg)
	err = cfgToCache.StoreToCache()
	test.That(t, err, test.ShouldBeNil)

	// read config from cloud, confirm consistency
	appConn, err := grpc.NewAppConn(ctx, cloud, logger)
	test.That(t, err, test.ShouldBeNil)
	defer appConn.Close()
	cloudCfg, err := config.ReadFromCloud(ctx, cfg, nil, true, false, logger, appConn)
	test.That(t, err, test.ShouldBeNil)
	cloudCfg.ToCache = nil
	test.That(t, cloudCfg, test.ShouldResemble, cfg)

	// Modify our config
	newRemote := config.Remote{Name: "test", Address: "foo"}
	cfg.Remotes = append(cfg.Remotes, newRemote)

	// read config from cloud again, confirm that the cached config differs from cfg
	cloudCfg2, err := config.ReadFromCloud(ctx, cfg, nil, true, false, logger, appConn)
	test.That(t, err, test.ShouldBeNil)
	cloudCfg2.ToCache = nil
	test.That(t, cloudCfg2, test.ShouldNotResemble, cfgToCache)

	// store the updated config to the cloud
	cfgToCache.SetToCache(cfg)
	err = cfgToCache.StoreToCache()
	test.That(t, err, test.ShouldBeNil)

	test.That(t, cfg.Ensure(true, logger), test.ShouldBeNil)

	// read updated cloud config, confirm that it now matches our updated cfg
	cloudCfg3, err := config.ReadFromCloud(ctx, cfg, nil, true, false, logger, appConn)
	test.That(t, err, test.ShouldBeNil)
	cloudCfg3.ToCache = nil
	test.That(t, cloudCfg3, test.ShouldResemble, cfg)
}

func TestCacheInvalidation(t *testing.T) {
	id := uuid.New().String()
	// store invalid config in cache
	cachePath := config.GetCloudCacheFilePath(id)
	err := os.WriteFile(cachePath, []byte("invalid-json"), 0o750)
	test.That(t, err, test.ShouldBeNil)

	// read from cache, should return parse error and remove file
	_, err = config.ReadFromCache(id)
	test.That(t, err.Error(), test.ShouldContainSubstring, "cannot parse the cached config as json")

	// read from cache again and file should not exist
	_, err = config.ReadFromCache(id)
	test.That(t, os.IsNotExist(err), test.ShouldBeTrue)
}

func TestShouldCheckForCert(t *testing.T) {
	cloud1 := config.Cloud{
		ManagedBy:        "acme",
		SignalingAddress: "abc",
		ID:               "forCachingTest",
		Secret:           "ghi",
		FQDN:             "fqdn",
		LocalFQDN:        "localFqdn",
		TLSCertificate:   "cert",
		TLSPrivateKey:    "key",
		LocationID:       "the-location",
		PrimaryOrgID:     "the-primary-org",
		MachineID:        "the-machine",
		LocationSecrets: []config.LocationSecret{
			{ID: "id1", Secret: "secret1"},
			{ID: "id2", Secret: "secret2"},
		},
	}
	cloud2 := cloud1
	test.That(t, config.ShouldCheckForCert(&cloud1, &cloud2), test.ShouldBeFalse)

	cloud2.TLSCertificate = "abc"
	test.That(t, config.ShouldCheckForCert(&cloud1, &cloud2), test.ShouldBeFalse)

	cloud2 = cloud1
	cloud2.LocationSecret = "something else"
	test.That(t, config.ShouldCheckForCert(&cloud1, &cloud2), test.ShouldBeTrue)

	cloud2 = cloud1
	cloud2.LocationSecrets = []config.LocationSecret{
		{ID: "id1", Secret: "secret1"},
		{ID: "id2", Secret: "secret3"},
	}
	test.That(t, config.ShouldCheckForCert(&cloud1, &cloud2), test.ShouldBeTrue)
}

func TestProcessReadConfig(t *testing.T) {
	logger := logging.NewTestLogger(t)
	unprocessedConfig := config.Config{
		ConfigFilePath: "path",
	}

	cfg, err := config.ProcessReadConfig(&unprocessedConfig, true, logger)
	test.That(t, err, test.ShouldBeNil)
	test.That(t, *cfg, test.ShouldResemble, unprocessedConfig)
}

func TestReadTLSFromCache(t *testing.T) {
	logger := logging.NewTestLogger(t)
	ctx := context.Background()
	cfg, err := config.FromReader(ctx, "", strings.NewReader(`{}`), logger, &grpc.AppConn{})
	test.That(t, err, test.ShouldBeNil)

	robotPartID := "forCachingTest"
	t.Run("no cached config", func(t *testing.T) {
		config.ClearCache(robotPartID)
		test.That(t, err, test.ShouldBeNil)

		tls := config.TlsConfig{}
		err = tls.ReadFromCache(robotPartID, logger)
		test.That(t, err, test.ShouldBeNil)
	})

	t.Run("cache config without cloud", func(t *testing.T) {
		defer config.ClearCache(robotPartID)
		cfg.Cloud = nil

		cfgToCache := &config.Config{Cloud: &config.Cloud{ID: robotPartID}}
		cfgToCache.SetToCache(cfg)
		err = cfgToCache.StoreToCache()
		test.That(t, err, test.ShouldBeNil)

		tls := config.TlsConfig{}
		err = tls.ReadFromCache(robotPartID, logger)
		test.That(t, err, test.ShouldBeNil)
	})

	t.Run("invalid cached TLS", func(t *testing.T) {
		defer config.ClearCache(robotPartID)
		cloud := &config.Cloud{
			ID:            robotPartID,
			TLSPrivateKey: "key",
		}
		cfg.Cloud = cloud

		cfgToCache := &config.Config{Cloud: &config.Cloud{ID: robotPartID}}
		cfgToCache.SetToCache(cfg)
		err = cfgToCache.StoreToCache()
		test.That(t, err, test.ShouldBeNil)

		tls := config.TlsConfig{}
		err = tls.ReadFromCache(robotPartID, logger)
		test.That(t, err, test.ShouldNotBeNil)

		_, err = config.ReadFromCache(robotPartID)
		test.That(t, errors.Is(err, fs.ErrNotExist), test.ShouldBeTrue)
	})

	t.Run("invalid cached TLS but insecure signaling", func(t *testing.T) {
		defer config.ClearCache(robotPartID)
		cloud := &config.Cloud{
			ID:                robotPartID,
			TLSPrivateKey:     "key",
			SignalingInsecure: true,
		}
		cfg.Cloud = cloud

		cfgToCache := &config.Config{Cloud: &config.Cloud{ID: robotPartID}}
		cfgToCache.SetToCache(cfg)
		err = cfgToCache.StoreToCache()
		test.That(t, err, test.ShouldBeNil)

		tls := config.TlsConfig{}
		err = tls.ReadFromCache(robotPartID, logger)
		test.That(t, err, test.ShouldBeNil)

		_, err = config.ReadFromCache(robotPartID)
		test.That(t, err, test.ShouldBeNil)
	})

	t.Run("valid cached TLS", func(t *testing.T) {
		defer config.ClearCache(robotPartID)
		cloud := &config.Cloud{
			ID:             robotPartID,
			TLSCertificate: "cert",
			TLSPrivateKey:  "key",
		}
		cfg.Cloud = cloud

		cfgToCache := &config.Config{Cloud: &config.Cloud{ID: robotPartID}}
		cfgToCache.SetToCache(cfg)
		err = cfgToCache.StoreToCache()
		test.That(t, err, test.ShouldBeNil)

		// the config is missing several fields required to start the robot, but this
		// should not prevent us from reading TLS information from it.
		_, err = config.ProcessConfigFromCloud(cfg, logger)
		test.That(t, err, test.ShouldNotBeNil)
		tls := config.TlsConfig{}
		err = tls.ReadFromCache(robotPartID, logger)
		test.That(t, err, test.ShouldBeNil)
	})
}

func TestAdditionalModuleEnvVars(t *testing.T) {
	t.Run("empty", func(t *testing.T) {
		expected := map[string]string{}
		observed := config.AdditionalModuleEnvVars(nil, config.AuthConfig{})
		test.That(t, observed, test.ShouldResemble, expected)
	})

	cloud1 := config.Cloud{
		ID:           "test",
		LocationID:   "the-location",
		PrimaryOrgID: "the-primary-org",
		MachineID:    "the-machine",
	}
	t.Run("cloud", func(t *testing.T) {
		expected := map[string]string{
			utils.MachinePartIDEnvVar: cloud1.ID,
			utils.MachineIDEnvVar:     cloud1.MachineID,
			utils.PrimaryOrgIDEnvVar:  cloud1.PrimaryOrgID,
			utils.LocationIDEnvVar:    cloud1.LocationID,
		}
		observed := config.AdditionalModuleEnvVars(&cloud1, config.AuthConfig{})
		test.That(t, observed, test.ShouldResemble, expected)
	})

	authWithExternalCreds := config.AuthConfig{
		Handlers: []config.AuthHandlerConfig{{Type: rpc.CredentialsTypeExternal}},
	}

	t.Run("auth with external creds", func(t *testing.T) {
		expected := map[string]string{}
		observed := config.AdditionalModuleEnvVars(nil, authWithExternalCreds)
		test.That(t, observed, test.ShouldResemble, expected)
	})
	apiKeyID := "abc"
	apiKey := "def"
	authWithAPIKeyCreds := config.AuthConfig{
		Handlers: []config.AuthHandlerConfig{{Type: rpc.CredentialsTypeAPIKey, Config: utils.AttributeMap{
			apiKeyID: apiKey,
			"keys":   []string{apiKeyID},
		}}},
	}

	t.Run("auth with api key creds", func(t *testing.T) {
		expected := map[string]string{
			utils.APIKeyEnvVar:   apiKey,
			utils.APIKeyIDEnvVar: apiKeyID,
		}
		observed := config.AdditionalModuleEnvVars(nil, authWithAPIKeyCreds)
		test.That(t, observed, test.ShouldResemble, expected)
	})

	apiKeyID2 := "uvw"
	apiKey2 := "xyz"
	order1 := config.AuthConfig{
		Handlers: []config.AuthHandlerConfig{{Type: rpc.CredentialsTypeAPIKey, Config: utils.AttributeMap{
			apiKeyID:  apiKey,
			apiKeyID2: apiKey2,
			"keys":    []string{apiKeyID, apiKeyID2},
		}}},
	}
	order2 := config.AuthConfig{
		Handlers: []config.AuthHandlerConfig{{Type: rpc.CredentialsTypeAPIKey, Config: utils.AttributeMap{
			apiKeyID2: apiKey2,
			apiKeyID:  apiKey,
			"keys":    []string{apiKeyID, apiKeyID2},
		}}},
	}

	t.Run("auth with keys in different order are stable", func(t *testing.T) {
		expected := map[string]string{
			utils.APIKeyEnvVar:   apiKey,
			utils.APIKeyIDEnvVar: apiKeyID,
		}
		observed := config.AdditionalModuleEnvVars(nil, order1)
		test.That(t, observed, test.ShouldResemble, expected)

		observed = config.AdditionalModuleEnvVars(nil, order2)
		test.That(t, observed, test.ShouldResemble, expected)
	})

	t.Run("full", func(t *testing.T) {
		expected := map[string]string{
			utils.MachinePartIDEnvVar: cloud1.ID,
			utils.MachineIDEnvVar:     cloud1.MachineID,
			utils.PrimaryOrgIDEnvVar:  cloud1.PrimaryOrgID,
			utils.LocationIDEnvVar:    cloud1.LocationID,
			utils.APIKeyEnvVar:        apiKey,
			utils.APIKeyIDEnvVar:      apiKeyID,
		}
		observed := config.AdditionalModuleEnvVars(&cloud1, authWithAPIKeyCreds)
		test.That(t, observed, test.ShouldResemble, expected)
	})
}

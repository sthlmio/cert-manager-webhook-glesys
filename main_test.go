package main

import (
	"os"
	"testing"
	"time"

	acmetest "github.com/cert-manager/cert-manager/test/acme"
)

var (
	zone         = os.Getenv("TEST_ZONE_NAME")
	manifestPath = os.Getenv("TEST_MANIFEST_PATH")
)

func TestRunsSuite(t *testing.T) {
	solver := &glesysDNSProviderSolver{}

	fixture := acmetest.NewFixture(solver,
		acmetest.SetResolvedZone(zone),
		acmetest.SetAllowAmbientCredentials(false),
		acmetest.SetManifestPath(manifestPath),
		// acmetest.SetBinariesPath("_test/kubebuilder/bin"),
		acmetest.SetPollInterval(time.Second*2),
		acmetest.SetPropagationLimit(time.Second*60),
		acmetest.SetUseAuthoritative(false),
	)

	//need to uncomment and  RunConformance delete runBasic and runExtended once https://github.com/cert-manager/cert-manager/pull/4835 is merged
	// fixture.RunConformance(t)
	fixture.RunBasic(t)
	fixture.RunExtended(t)
}

package main

import (
	"os"
	"testing"

	"github.com/jetstack/cert-manager/test/acme/dns"
)

var (
	zone               = os.Getenv("TEST_ZONE_NAME")
	kubeBuilderBinPath = "./_out/kubebuilder/bin"
)

func TestRunsSuite(t *testing.T) {
	/* The manifest path should contain a file named config.json that is a
	   snippet of valid configuration that should be included on the
	   ChallengeRequest passed as part of the test cases.*/

	fixture := dns.NewFixture(&linodeDNSProviderSolver{},
		dns.SetBinariesPath(kubeBuilderBinPath),
		dns.SetManifestPath("testdata/linode"),
		dns.SetResolvedZone(zone),
		dns.SetAllowAmbientCredentials(false),
	)

	fixture.RunConformance(t)
}

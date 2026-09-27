package cmd

import (
	"bytes"
	"testing"
)

func TestCloudCommands(t *testing.T) {
	buf := new(bytes.Buffer)
	cloudCmd.SetOut(buf)
	cloudCmd.SetErr(buf)

	cloudCmd.SetArgs([]string{"--help"})
	if err := cloudCmd.Execute(); err != nil {
		t.Fatalf("cloudCmd.Execute() error = %v", err)
	}

	cloudInspectCmd.SetArgs([]string{"--help"})
	if err := cloudInspectCmd.Execute(); err != nil {
		t.Fatalf("cloudInspectCmd.Execute() error = %v", err)
	}
}

func TestDiskCommands(t *testing.T) {
	buf := new(bytes.Buffer)
	diskCmd.SetOut(buf)
	diskCmd.SetErr(buf)

	diskCmd.SetArgs([]string{"--help"})
	if err := diskCmd.Execute(); err != nil {
		t.Fatalf("diskCmd.Execute() error = %v", err)
	}

	diskListCmd.SetArgs([]string{"--help"})
	if err := diskListCmd.Execute(); err != nil {
		t.Fatalf("diskListCmd.Execute() error = %v", err)
	}
}

func TestNetworkCommands(t *testing.T) {
	buf := new(bytes.Buffer)
	networkCmd.SetOut(buf)
	networkCmd.SetErr(buf)

	networkCmd.SetArgs([]string{"--help"})
	if err := networkCmd.Execute(); err != nil {
		t.Fatalf("networkCmd.Execute() error = %v", err)
	}

	networkStatusCmd.SetArgs([]string{"--help"})
	if err := networkStatusCmd.Execute(); err != nil {
		t.Fatalf("networkStatusCmd.Execute() error = %v", err)
	}

	networkSetupCmd.SetArgs([]string{"--help"})
	if err := networkSetupCmd.Execute(); err != nil {
		t.Fatalf("networkSetupCmd.Execute() error = %v", err)
	}
}

func TestDoctorCommand(t *testing.T) {
	buf := new(bytes.Buffer)
	doctorCmd.SetOut(buf)
	doctorCmd.SetErr(buf)

	doctorCmd.SetArgs([]string{"--help"})
	if err := doctorCmd.Execute(); err != nil {
		t.Fatalf("doctorCmd.Execute() error = %v", err)
	}
}

func TestSecurityHardenCommand(t *testing.T) {
	buf := new(bytes.Buffer)
	securityHardenCmd.SetOut(buf)
	securityHardenCmd.SetErr(buf)

	securityHardenCmd.SetArgs([]string{"--help"})
	if err := securityHardenCmd.Execute(); err != nil {
		t.Fatalf("securityHardenCmd.Execute() error = %v", err)
	}
}

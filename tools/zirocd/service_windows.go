package main

import (
	"context"
	"time"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

const serviceName = "zirocd"

type winService struct{}

func (winService) Execute(args []string, req <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	status <- svc.Status{State: svc.StartPending}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- serveDaemon(ctx) }()
	status <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	for {
		select {
		case err := <-done:
			cancel()
			if err != nil {
				return true, 1
			}
			return false, 0
		case c := <-req:
			switch c.Cmd {
			case svc.Interrogate:
				status <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				status <- svc.Status{State: svc.StopPending}
				cancel()
				<-done
				return false, 0
			}
		}
	}
}

func runAsService() (bool, error) {
	is, err := svc.IsWindowsService()
	if err != nil || !is {
		return false, err
	}
	return true, svc.Run(serviceName, winService{})
}

// installService registers zirocd as an automatic LocalSystem service that the service
// manager restarts whenever it exits (updates and rollbacks exit with code 3).
func installService(exe string) error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	if s, err := m.OpenService(serviceName); err == nil {
		s.Close()
		return uninstallAndReinstall(m, exe)
	}
	return create(m, exe)
}

func create(m *mgr.Mgr, exe string) error {
	s, err := m.CreateService(serviceName, exe, mgr.Config{
		DisplayName: "Ziro client daemon", Description: "Joins this computer to Ziro router networks",
		StartType: mgr.StartAutomatic, ServiceStartName: "LocalSystem",
	}, "daemon")
	if err != nil {
		return err
	}
	defer s.Close()
	restart := []mgr.RecoveryAction{{Type: mgr.ServiceRestart, Delay: 2 * time.Second}, {Type: mgr.ServiceRestart, Delay: 5 * time.Second}, {Type: mgr.ServiceRestart, Delay: 30 * time.Second}}
	if err := s.SetRecoveryActions(restart, 86400); err != nil {
		return err
	}
	_ = s.SetRecoveryActionsOnNonCrashFailures(true)
	return s.Start()
}

func uninstallAndReinstall(m *mgr.Mgr, exe string) error {
	if err := uninstallService(); err != nil {
		return err
	}
	time.Sleep(2 * time.Second)
	return create(m, exe)
}

func uninstallService() error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService(serviceName)
	if err != nil {
		return nil
	}
	defer s.Close()
	_, _ = s.Control(svc.Stop)
	return s.Delete()
}

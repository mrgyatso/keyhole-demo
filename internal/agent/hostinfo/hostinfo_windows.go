//go:build windows

package hostinfo

import (
	"context"
	"fmt"

	"golang.org/x/sys/windows/registry"
)

func machineID(context.Context) (string, error) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Cryptography`, registry.QUERY_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return "", fmt.Errorf("open HKLM\\SOFTWARE\\Microsoft\\Cryptography: %w", err)
	}
	defer k.Close()
	id, _, err := k.GetStringValue("MachineGuid")
	if err != nil {
		return "", fmt.Errorf("read MachineGuid: %w", err)
	}
	return id, nil
}

func osVersion(context.Context) (string, error) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion`, registry.QUERY_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return "", fmt.Errorf("open HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion: %w", err)
	}
	defer k.Close()
	product, _, err := k.GetStringValue("ProductName")
	if err != nil {
		return "", fmt.Errorf("read ProductName: %w", err)
	}
	display, _, _ := k.GetStringValue("DisplayVersion")
	if display == "" {
		display, _, _ = k.GetStringValue("ReleaseId") // before 20H2
	}
	build, _, _ := k.GetStringValue("CurrentBuild")
	ubr, _, _ := k.GetIntegerValue("UBR")
	return windowsVersion(product, display, build, ubr), nil
}

package collect

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// Disks carry their device names, so two NVMe disks no longer collapse into
// one (thread 0036), and on a many-core machine the per-core readings make
// way for them.
func TestSensorNames(t *testing.T) {
	sys := t.TempDir()
	mk := func(rel, content string) {
		t.Helper()
		p := filepath.Join(sys, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	link := func(chip, target string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Join(sys, target), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(filepath.Join(sys, target), filepath.Join(sys, "class/hwmon", chip, "device")); err != nil {
			t.Fatal(err)
		}
	}
	// hwmon0: an Intel CPU, a package and 20 cores.
	mk("class/hwmon/hwmon0/name", "coretemp\n")
	mk("class/hwmon/hwmon0/temp1_label", "Package id 0\n")
	mk("class/hwmon/hwmon0/temp1_input", "52000\n")
	for i := range 20 {
		mk(fmt.Sprintf("class/hwmon/hwmon0/temp%d_label", i+2), fmt.Sprintf("Core %d\n", i))
		mk(fmt.Sprintf("class/hwmon/hwmon0/temp%d_input", i+2), "50000\n")
	}
	// hwmon1, hwmon2: two NVMe controllers (one through a namespace link).
	for i, target := range []string{"devices/pci0000:00/0000:00:01.0/nvme/nvme0", "devices/virtual/nvme-subsystem/nvme-subsys1/nvme1n1"} {
		chip := fmt.Sprintf("hwmon%d", i+1)
		mk("class/hwmon/"+chip+"/name", "nvme\n")
		mk("class/hwmon/"+chip+"/temp1_label", "Composite\n")
		mk("class/hwmon/"+chip+"/temp1_input", "41000\n")
		link(chip, target)
	}
	mk("class/hwmon/hwmon1/temp2_label", "Sensor 1\n")
	mk("class/hwmon/hwmon1/temp2_input", "45000\n")
	// hwmon3, hwmon4: two SATA disks through drivetemp; the link names the SCSI address.
	for i, dev := range []string{"sda", "sdb"} {
		chip := fmt.Sprintf("hwmon%d", i+3)
		mk("class/hwmon/"+chip+"/name", "drivetemp\n")
		mk("class/hwmon/"+chip+"/temp1_input", "38000\n")
		addr := fmt.Sprintf("devices/pci0000:00/ata%d/host%d/target%d:0:0/%d:0:0:0", i+1, i, i, i)
		link(chip, addr)
		mk(addr+"/block/"+dev+"/size", "1\n")
	}
	// hwmon5: ACPI; hwmon6: an NVMe chip without a device link keeps the old name.
	mk("class/hwmon/hwmon5/name", "acpitz\n")
	mk("class/hwmon/hwmon5/temp1_input", "27800\n")
	mk("class/hwmon/hwmon6/name", "nvme\n")
	mk("class/hwmon/hwmon6/temp1_label", "Composite\n")
	mk("class/hwmon/hwmon6/temp1_input", "40000\n")

	sensors := discoverSensors(sys)
	defer func() {
		for _, s := range sensors {
			s.f.Close()
		}
	}()
	var names []string
	cores := 0
	for _, s := range sensors {
		names = append(names, s.name)
		if reCore.MatchString(s.name) {
			cores++
		}
	}
	if len(sensors) != maxSensors {
		t.Fatalf("%d sensors: %v", len(sensors), names)
	}
	for _, want := range []string{"coretemp Package id 0", "nvme0 Composite", "nvme0 Sensor 1", "nvme1 Composite",
		"drivetemp sda", "drivetemp sdb", "acpitz temp1", "nvme Composite"} {
		if !slices.Contains(names, want) {
			t.Errorf("no %q in %v", want, names)
		}
	}
	// 8 kept above; the cores fill the rest, the first ones first.
	if cores != maxSensors-8 || !slices.Contains(names, "coretemp Core 0") || slices.Contains(names, "coretemp Core 19") {
		t.Errorf("cores kept: %d in %v", cores, names)
	}
}

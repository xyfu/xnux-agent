package collect

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/xyfu/xnux-shared/proto"
)

const maxSensors = 16

type sensor struct {
	name string
	f    *procFile
}

// discoverSensors finds hwmon and thermal-zone temperature inputs under
// sysRoot. Thermal zones whose type duplicates a hwmon chip are skipped.
func discoverSensors(sysRoot string) []sensor {
	var out []sensor
	hwmonNames := map[string]bool{}

	chips, _ := filepath.Glob(filepath.Join(sysRoot, "class/hwmon/hwmon*"))
	sort.Strings(chips)
	for _, chip := range chips {
		name := readTrim(filepath.Join(chip, "name"))
		if name == "" {
			continue
		}
		hwmonNames[name] = true
		inputs, _ := filepath.Glob(filepath.Join(chip, "temp*_input"))
		// By number: temp2 before temp10, so Core 0 comes before Core 8.
		sort.Slice(inputs, func(i, j int) bool { return inputIndex(inputs[i]) < inputIndex(inputs[j]) })
		for _, in := range inputs {
			idx := strings.TrimSuffix(strings.TrimPrefix(filepath.Base(in), "temp"), "_input")
			label := readTrim(filepath.Join(chip, "temp"+idx+"_label"))
			if label == "" {
				label = "temp" + idx
			}
			out = appendSensor(out, sensorName(chip, name, label), in)
		}
	}

	zones, _ := filepath.Glob(filepath.Join(sysRoot, "class/thermal/thermal_zone*"))
	sort.Strings(zones)
	for _, z := range zones {
		typ := readTrim(filepath.Join(z, "type"))
		if typ == "" || hwmonNames[typ] {
			continue
		}
		out = appendSensor(out, "thermal "+typ, filepath.Join(z, "temp"))
	}
	return capSensors(out)
}

var (
	reNVMe = regexp.MustCompile(`^(nvme[0-9]+)(n[0-9]+)?$`)
	reCore = regexp.MustCompile(`^coretemp Core [0-9]+$`)
)

// sensorName names a hwmon input. Disks carry their kernel device name
// (thread 0036), or two NVMe disks would both be "nvme Composite" and the
// second dropped as a duplicate: "nvme0 Composite", "drivetemp sda".
// Without a device name the chip name stays, as before.
func sensorName(chip, chipName, label string) string {
	switch chipName {
	case "nvme":
		if dev := nvmeDevice(chip); dev != "" {
			return dev + " " + label
		}
	case "drivetemp":
		if dev := blockDevice(chip); dev != "" {
			return "drivetemp " + dev
		}
	}
	return chipName + " " + label
}

// nvmeDevice is the controller (nvme0) the chip's device link points to;
// a namespace (nvme0n1) counts as its controller.
func nvmeDevice(chip string) string {
	target, err := os.Readlink(filepath.Join(chip, "device"))
	if err != nil {
		return ""
	}
	if m := reNVMe.FindStringSubmatch(filepath.Base(target)); m != nil {
		return m[1]
	}
	return ""
}

// blockDevice is the disk (sda) of a drivetemp chip. Its device link names
// the SCSI address (0:0:0:0); the disk is the one entry under its block/.
func blockDevice(chip string) string {
	disks, _ := filepath.Glob(filepath.Join(chip, "device", "block", "*"))
	if len(disks) != 1 {
		return ""
	}
	return filepath.Base(disks[0])
}

// capSensors keeps at most maxSensors. Intel's per-core readings go first:
// on a many-core machine they would otherwise crowd out the disks, and the
// package temperature already stands for the CPU.
func capSensors(out []sensor) []sensor {
	over := len(out) - maxSensors
	if over <= 0 {
		return out
	}
	drop := map[int]bool{}
	for i := len(out) - 1; i >= 0 && len(drop) < over; i-- {
		if reCore.MatchString(out[i].name) {
			drop[i] = true
		}
	}
	for i := len(out) - 1; i >= 0 && len(drop) < over; i-- {
		drop[i] = true
	}
	kept := out[:0]
	for i, s := range out {
		if drop[i] {
			s.f.Close()
			continue
		}
		kept = append(kept, s)
	}
	return kept
}

// inputIndex is N of a tempN_input path (0 when it does not parse).
func inputIndex(path string) int {
	n, _ := strconv.Atoi(strings.TrimSuffix(strings.TrimPrefix(filepath.Base(path), "temp"), "_input"))
	return n
}

func appendSensor(out []sensor, name, path string) []sensor {
	for _, s := range out {
		if s.name == name {
			return out
		}
	}
	f, err := openProcFile(path, 32)
	if err != nil {
		return out
	}
	if _, ok := readMilliC(f); !ok {
		f.Close()
		return out
	}
	return append(out, sensor{name: name, f: f})
}

// readMilliC reads a millidegree value and converts it, rejecting implausible
// readings.
func readMilliC(f *procFile) (float64, bool) {
	b, err := f.read()
	if err != nil {
		return 0, false
	}
	v, ok := parseInt(trimSpace(b))
	if !ok {
		return 0, false
	}
	c := float64(v) / 1000
	if c < -40 || c > 150 {
		return 0, false
	}
	return round(c, 1), true
}

func sampleTemps(sensors []sensor) []proto.Temp {
	if len(sensors) == 0 {
		return nil
	}
	out := make([]proto.Temp, 0, len(sensors))
	for _, s := range sensors {
		if c, ok := readMilliC(s.f); ok {
			out = append(out, proto.Temp{Name: s.name, C: c})
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func readTrim(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

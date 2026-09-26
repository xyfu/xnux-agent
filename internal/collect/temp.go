package collect

import (
	"os"
	"path/filepath"
	"sort"
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
		sort.Strings(inputs)
		for _, in := range inputs {
			idx := strings.TrimSuffix(strings.TrimPrefix(filepath.Base(in), "temp"), "_input")
			label := readTrim(filepath.Join(chip, "temp"+idx+"_label"))
			if label == "" {
				label = "temp" + idx
			}
			out = appendSensor(out, name+" "+label, in)
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
	if len(out) > maxSensors {
		for _, s := range out[maxSensors:] {
			s.f.Close()
		}
		out = out[:maxSensors]
	}
	return out
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

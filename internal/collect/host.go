package collect

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/xyfu/xnux-shared/proto"
)

// readOSRelease returns PRETTY_NAME from os-release.
func readOSRelease(root string) string {
	for _, p := range []string{"etc/os-release", "usr/lib/os-release"} {
		b, err := os.ReadFile(filepath.Join(root, p))
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(b), "\n") {
			if v, ok := strings.CutPrefix(line, "PRETTY_NAME="); ok {
				return strings.Trim(strings.TrimSpace(v), `"'`)
			}
		}
	}
	return "Linux"
}

// detectVirt classifies the host as kvm / vmware / xen / hyperv / bare /
// container / unknown.
func detectVirt(root, procRoot, sysRoot string) string {
	if inContainer(root, procRoot) {
		return "container"
	}
	vendor := strings.ToLower(readTrim(filepath.Join(sysRoot, "class/dmi/id/sys_vendor")))
	product := strings.ToLower(readTrim(filepath.Join(sysRoot, "class/dmi/id/product_name")))
	switch {
	case strings.Contains(vendor, "vmware"):
		return "vmware"
	case strings.Contains(vendor, "xen") || strings.Contains(product, "hvm domu"):
		return "xen"
	case strings.Contains(vendor, "microsoft") && strings.Contains(product, "virtual"):
		return "hyperv"
	case strings.Contains(vendor, "qemu") || strings.Contains(product, "kvm") ||
		strings.Contains(vendor, "amazon ec2") || strings.Contains(vendor, "google") ||
		strings.Contains(vendor, "alibaba") || strings.Contains(vendor, "tencent") ||
		strings.Contains(vendor, "digitalocean") || strings.Contains(vendor, "hetzner") ||
		strings.Contains(vendor, "openstack") || strings.Contains(vendor, "vultr") ||
		strings.Contains(vendor, "linode") || strings.Contains(vendor, "oracle") ||
		strings.Contains(product, "bochs"):
		return "kvm"
	}
	if cpuHasHypervisorFlag(procRoot) {
		return "unknown"
	}
	if vendor == "" {
		return "unknown"
	}
	return "bare"
}

func inContainer(root, procRoot string) bool {
	for _, p := range []string{".dockerenv", "run/.containerenv"} {
		if _, err := os.Stat(filepath.Join(root, p)); err == nil {
			return true
		}
	}
	cg := readTrim(filepath.Join(procRoot, "1/cgroup"))
	for _, s := range []string{"docker", "kubepods", "containerd", "lxc", "libpod"} {
		if strings.Contains(cg, s) {
			return true
		}
	}
	return false
}

func cpuHasHypervisorFlag(procRoot string) bool {
	b, err := os.ReadFile(filepath.Join(procRoot, "cpuinfo"))
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, "flags") {
			return strings.Contains(line, " hypervisor")
		}
	}
	return false
}

func readUptime(procRoot string) int64 {
	f, _ := nextField([]byte(readTrim(filepath.Join(procRoot, "uptime"))))
	v, _ := parseFloat(f)
	return int64(v)
}

func (s *Sampler) hostInfo() proto.Host {
	h := proto.Host{
		Hostname: readTrim(filepath.Join(s.opts.ProcRoot, "sys/kernel/hostname")),
		OS:       readOSRelease(s.opts.Root),
		Kernel:   readTrim(filepath.Join(s.opts.ProcRoot, "sys/kernel/osrelease")),
		Arch:     runtime.GOARCH,
		Cores:    s.cores,
		Uptime:   readUptime(s.opts.ProcRoot),
		Virt:     s.virt,
	}
	if h.Hostname == "" {
		h.Hostname, _ = os.Hostname()
	}
	if h.Hostname == "" {
		h.Hostname = "host"
	}
	return h
}

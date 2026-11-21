// SPDX-FileCopyrightText: 2022 Great Software Laboratory Pvt. Ltd
// SPDX-FileCopyrightText: 2021 Open Networking Foundation <info@opennetworking.org>
// Copyright 2019 free5GC.org
//
// SPDX-License-Identifier: Apache-2.0

/*
 * gNBSim Configuration Factory
 */

package factory

import (
	"fmt"
	"net"
	"os"
	"strings"

	gnbctx "github.com/omec-project/gnbsim/gnodeb/context"
	profctx "github.com/omec-project/gnbsim/profile/context"
)

const (
	// podIPKeyword in an address option stands for the pod's own address (POD_IP, POD_IPS)
	podIPKeyword = "POD_IP"

	GNBSIM_EXPECTED_CONFIG_VERSION = "1.0.0"
	GNBSIM_DEFAULT_CONFIG_PATH     = "/gnbsim/config/gnb.conf"
)

type Config struct {
	Info          *Info          `yaml:"info"`
	Configuration *Configuration `yaml:"configuration"`
	Logger        *Logger        `yaml:"logger"`
}

type Info struct {
	Version     string `yaml:"version"`
	Description string `yaml:"description"`
}

type Configuration struct {
	Gnbs                     map[string]*gnbctx.GNodeB   `yaml:"gnbs"`
	CustomProfiles           map[string]*profctx.Profile `yaml:"customProfiles"`
	Profiles                 []*profctx.Profile          `yaml:"profiles"`
	Server                   HttpServer                  `yaml:"httpServer"`
	GoProfile                ProfileServer               `yaml:"goProfile"`
	SingleInterface          bool                        `yaml:"singleInterface"`
	ExecInParallel           bool                        `yaml:"execInParallel"`
	RunConfigProfilesAtStart bool                        `yaml:"runConfigProfilesAtStart"`
}

type ProfileServer struct {
	Enable bool `yaml:"enable"`
	Port   int  `yaml:"port"`
}

type HttpServer struct {
	IpAddr string `yaml:"ipAddr"`
	Port   string `yaml:"port"`
	Enable bool   `yaml:"enable"`
}

type Logger struct {
	LogLevel string `yaml:"logLevel"`
}

func (c *Config) GetVersion() string {
	if c.Info != nil && c.Info.Version != "" {
		return c.Info.Version
	}
	return ""
}

func (c *Config) Validate() (err error) {
	if c.Info == nil {
		return fmt.Errorf("Info field missing")
	}

	if c.Configuration == nil {
		return fmt.Errorf("Configuration field missing")
	}

	if len(c.Configuration.Gnbs) == 0 {
		return fmt.Errorf("no gnbs configured")
	}
	if c.Configuration.GoProfile.Enable {
		if c.Configuration.GoProfile.Port == 0 {
			c.Configuration.GoProfile.Port = 5000
		}
	}

	if c.Configuration.Server.IpAddr == podIPKeyword {
		podIP := os.Getenv("POD_IP")
		if podIP == "" && c.Configuration.Server.Enable {
			// an empty address would make the listener bind to every interface
			return fmt.Errorf("httpServer.ipAddr is POD_IP but the POD_IP environment variable is not set")
		}
		c.Configuration.Server.IpAddr = podIP
	}

	if c.Configuration.SingleInterface {
		podIPv4, podIPv6 := podAddresses()
		for _, gnb := range c.Configuration.Gnbs {
			if gnb.GnbN3Ip == podIPKeyword {
				// the IPv4 address for compatibility, the IPv6 one on an IPv6-only pod
				gnb.GnbN3Ip = podIPv4
				if gnb.GnbN3Ip == "" {
					gnb.GnbN3Ip = podIPv6
				}
			}
			if gnb.GnbN3Ipv6 == podIPKeyword {
				gnb.GnbN3Ipv6 = podIPv6
				if gnb.GnbN3Ip == podIPv6 {
					gnb.GnbN3Ipv6 = "" // an IPv6-only pod: n3IpAddr has it already
				}
			}
		}
	}
	for name, gnb := range c.Configuration.Gnbs {
		if err := gnb.ValidateN3(); err != nil {
			return fmt.Errorf("gnbs.%s: %w", name, err)
		}
	}

	if len(c.Configuration.Profiles) == 0 {
		return fmt.Errorf("no profile information available")
	}

	if len(c.Configuration.CustomProfiles) != 0 {
		for _, v := range c.Configuration.CustomProfiles {
			if err := v.BuildIterations(); err != nil {
				return err
			}
		}

		for _, v := range c.Configuration.CustomProfiles {
			c.Configuration.Profiles = append(c.Configuration.Profiles, v)
		}
	}

	return nil
}

func (c *Configuration) GetGNodeB(name string) (*gnbctx.GNodeB, error) {
	var err error
	gnb, ok := c.Gnbs[name]
	if !ok {
		err = fmt.Errorf("no corresponding gNodeB found for:%v", name)
	}
	return gnb, err
}

// podAddresses returns the pod's first IPv4 and first IPv6 address, "" for a family it has none of.
// They come from POD_IPS (status.podIPs: the pod's addresses, comma-separated, one per family on a
// dual-stack cluster), or from POD_IP (status.podIP, the primary family only) without it.
func podAddresses() (ipv4, ipv6 string) {
	list := os.Getenv("POD_IPS")
	if strings.TrimSpace(list) == "" {
		list = os.Getenv("POD_IP")
	}
	for _, field := range strings.Split(list, ",") {
		ip := net.ParseIP(strings.TrimSpace(field))
		switch {
		case ip == nil:
		case ip.To4() != nil:
			if ipv4 == "" {
				ipv4 = ip.String()
			}
		case ipv6 == "":
			ipv6 = ip.String()
		}
	}
	return ipv4, ipv6
}

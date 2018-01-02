package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"path"
	"strings"
)

const (
	CACHE_IPS = ".cache/ips.txt"
	CACHE_AWS = ".cache/ip-ranges.json"
)

type Blocked struct {
	SyncToken  string `json:"syncToken"`
	CreateDate string `json:"createDate"`
	Prefixes   []*struct {
		IP      string   `json:"ip_prefix,omitempty"`
		IPv6    string   `json:"ipv6_prefix,omitempty"`
		Region  string   `json:"region"`
		Service string   `json:"service"`
		Blocked []net.IP `json:"blocked,omitempty"`
	} `json:"prefixes"`
}

func download(url, file string) error {
	os.MkdirAll(path.Dir(file), 0755)
	if _, err := os.Stat(file); err == nil {
		return nil
	}
	fmt.Printf("Downloading file: %s\n", url)
	var client http.Client
	resp, err := client.Get(url)
	if err != nil {
		return err
	}
	if resp.StatusCode != 200 {
		return errors.New(fmt.Sprintf("Unexpected status code: %s", resp.StatusCode))
	}
	content, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	return ioutil.WriteFile(file, content, 0644)
}

func main() {
	if err := download("https://reestr.rublacklist.net/api/ips", CACHE_IPS); err != nil {
		panic(err)
	}
	if err := download("https://ip-ranges.amazonaws.com/ip-ranges.json", CACHE_AWS); err != nil {
		panic(err)
	}

	raw_aws, err := ioutil.ReadFile(CACHE_AWS)
	if err != nil {
		panic(err)
	}
	raw_ips, err := ioutil.ReadFile(CACHE_IPS)
	if err != nil {
		panic(err)
	}

	var blocked Blocked
	err = json.Unmarshal(raw_aws, &blocked)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Amazon prefixes: %d\n", len(blocked.Prefixes))

	ips := make([]net.IP, 0)
	for _, ip := range strings.Split(strings.Trim(string(raw_ips), "\""), ";") {
		if ip == "" {
			continue
		}
		ips = append(ips, net.ParseIP(ip))
	}

	out, err := os.Create("amazon.csv")
	if err != nil {
		panic(err)
	}
	fmt.Fprintf(out, "region\tservice\tip_prefix\tip\n")
	for _, prefix := range blocked.Prefixes {
		if prefix.IP == "" {
			continue
		}
		_, net, err := net.ParseCIDR(prefix.IP)
		if err != nil || net == nil {
			continue
		}
		for _, ip := range ips {
			if net.Contains(ip) {
				prefix.Blocked = append(prefix.Blocked, ip)
				fmt.Fprintf(out, "%s\t%s\t%s\t%s\n", prefix.Region, prefix.Service, prefix.IP, ip)
			}
		}
	}
	out.Close()
}

package webroot

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"github.com/fatih/pool"
	"github.com/untangle/packetd/services/logger"
)

// LookupResult result struct for bctid lookup.
// ctid is added to allow lookup from http/https redirect server.
type LookupResult struct {
	IP string `json:"ip"`
	Ipint int `json:"ipint"`
	Reputation int `json:"reputation"`
	Status int `json:"status"`
	ThreatMask int `json:"threat_mask"`
	Source string `json:"source"`
	Ctid uint32
}

const connMaxPoolSize int = 25

var connPool pool.Pool

var webrootConn = func() (net.Conn, error) { return net.Dial("tcp", "localhost:8484") }

// Startup is called when the packetd service starts
func Startup() {
	var err error
	logger.Info("Starting up the threatprevention service\n")
	// Create a socket pool to handle request to the bcdtid daemon
	connPool, err = pool.NewChannelPool(5, connMaxPoolSize, webrootConn)
	
	if err != nil {
		logger.Info("threatprevention not able to create connection pool %v\n", err)
		return
	}
	logger.Info("Pool connections available " + strconv.Itoa(connPool.Len()) + "\n")
}

// Shutdown is called when the packetd service stops
func Shutdown() {
	logger.Info("Shutting down the threatprevention service\n")
	connPool.Close()
}

func apiQuery(cmd string, retry bool) (string, error) {
	var err error = nil
	s, err := connPool.Get()
	fmt.Fprintf(s, "%s\r\n", cmd)
	result, err := bufio.NewReader(s).ReadString('\n')
	if err != nil {
		logger.Info("threatprevention, not able to obtain connection to bctid\n")
	}
	s.Close()

	return result, err
}

// GetInfo looks up info form bctid.
// host can be IP or FQDN.
func GetInfo(host string) (string, error) {
	addr := net.ParseIP(host)
	if addr != nil {
		return queryIP(host)
	}
	return queryURL(host)
}

// ips can be single or , seperated list of IPs
func queryIP(ips string) (string, error) {
	cmd := "{\"ip/getinfo\" : {\"ips\": [\"" + ips + "\"]}}"
	return apiQuery(cmd, false)
}

// hosts can be single or , seperated list of FQDNs
func queryURL(hosts string) (string, error) {
	cmd := "{\"url/getinfo\" : {\"urls\": [\"" + hosts + "\"]}}"
	return apiQuery(cmd, false)
}

// IPLookup lookup IP address from bctid daemon.
func IPLookup(ip string) ([]LookupResult, error) {
	var res, err = queryIP(ip)
	if err != nil {
		return []LookupResult{}, err
	}
	var result []LookupResult
	json.Unmarshal([]byte(res), &result)
	return result, nil
}

// GetRiskLevel returns risk level <string> based on bctid score.
func GetRiskLevel(risk int ) string {
	var result string
	result = "Trustworthy"
	if risk < 80 {
		result = "Low Risk"
	}
	if risk < 60 {
		result = "Moderate Risk"
	}
	if risk < 40 {
		result = "Suspicious"
	}
	if risk < 20 {
		result = "High Risk"
	}
	return result
}
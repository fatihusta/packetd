package webroot

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/fatih/pool"
	"github.com/untangle/packetd/services/logger"
)

// LookupResult result struct for bctid lookup.
// ctid is added to allow lookup from http/https redirect server.
type LookupResult struct {
	IP         string `json:"ip"`
	Ipint      int    `json:"ipint"`
	Reputation int    `json:"reputation"`
	Status     int    `json:"status"`
	ThreatMask int    `json:"threat_mask"`
	Source     string `json:"source"`
	Ctid       uint32
}

type repuHostCacheEntry struct {
	value string
	age   time.Time
}

var CACHE_EXPIRE = 1 // Expiry in days

var repuHostCache map[string]repuHostCacheEntry
var repuHostCacheLock = sync.RWMutex{}

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

	repuHostCache = make(map[string]repuHostCacheEntry)
	repuHostCacheLock = sync.RWMutex{}
	go runCleanCache()

	logger.Info("Pool connections available " + strconv.Itoa(connPool.Len()) + "\n")
}

// Shutdown is called when the packetd service stops
func Shutdown() {
	logger.Info("Shutting down the threatprevention service\n")
	connPool.Close()
}

func apiQuery(cmd string, retry bool) (string, error) {
	var err error = nil
	s, _ := connPool.Get()
	fmt.Fprintf(s, "%s\r\n", cmd)
	result, err := bufio.NewReader(s).ReadString('\n')
	if err != nil {
		logger.Info("threatprevention, not able to obtain connection to bctid\n")
	}
	s.Close()

	return result, err
}

// GetInfo looks up info from bctid.
// host can be IP or FQDN.
func GetInfo(host string) (string, error) {
	return queryURL(host)
}

// ips can be single or , seperated list of IPs
func queryIP(ips string) (string, error) {
	cmd := "{\"ip/getinfo\" : {\"ips\": [\"" + ips + "\"]}}"
	return apiQuery(cmd, false)
}

// hosts can be single or , seperated list of FQDNs
func queryURL(hosts string) (string, error) {
	var entry repuHostCacheEntry
	var ok bool
	logger.Info("queryURL, lookup %v\n", hosts)
	repuHostCacheLock.RLock()
	entry, ok = repuHostCache[hosts]
	repuHostCacheLock.RUnlock()
	if ok {
		logger.Debug("queryURL, entry found cache %v\n", entry.value)
		return entry.value, nil
	}

	cmd := "{\"url/getinfo\" : {\"urls\": [\"" + hosts + "\"]}}"
	result, err := apiQuery(cmd, false)
	logger.Debug("queryURL, result %v, %v\n", result, err)

	if err == nil {
		repuHostCacheLock.Lock()
		repuHostCache[hosts] = repuHostCacheEntry{value: result, age: time.Now()}
		repuHostCacheLock.Unlock()
		logger.Debug("queryURL, adding to cache %v\n", result)
		return result, nil
	}
	logger.Debug("queryURL, failure in lookup %v\n", err)
	return "", err

}

// Lookup lookup IP address from bctid daemon.
func Lookup(ip string, ipDB bool) ([]LookupResult, error) {
	var entry repuHostCacheEntry
	var ok bool
	var result []LookupResult
	logger.Debug("Lookup, ip %v\n", ip)
	repuHostCacheLock.RLock()
	entry, ok = repuHostCache[ip]
	repuHostCacheLock.RUnlock()

	if ok {
		json.Unmarshal([]byte(entry.value), &result)
		logger.Debug("Lookup, found cache entry %v\n", result)
		return result, nil
	}

	var res string
	var err error
	if ipDB {
		res, err = queryIP(ip)
	} else {
		res, err = queryURL(ip)
	}

	logger.Debug("Lookup, result %v\n", res)
	if err != nil {
		return []LookupResult{}, err
	}
	repuHostCacheLock.Lock()
	repuHostCache[ip] = repuHostCacheEntry{value: res, age: time.Now()}
	repuHostCacheLock.Unlock()

	json.Unmarshal([]byte(res), &result)
	return result, nil
}

func cleanCache() {
	expiry := time.Now().AddDate(0, 0, -(CACHE_EXPIRE))
	// Host Cache
	repuHostCacheLock.Lock()
	logger.Debug("Begin cache clean run, row count %i\n", len(repuHostCache))
	for key, value := range repuHostCache {
		if value.age.Before(expiry) {
			delete(repuHostCache, key)
		}
	}
	logger.Debug("End cache clean run, rown count %i\n", len(repuHostCache))
	repuHostCacheLock.Unlock()
}

func runCleanCache() {
	cleanerTicker := time.NewTicker(1 * time.Hour)

	for {
		select {
		case <-cleanerTicker.C:
			cleanCache()
		}
	}
}

// GetRiskLevel returns risk level <string> based on bctid score.
func GetRiskLevel(risk int) string {
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

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

type repuCacheEntry struct {
	value string
	age   time.Time
}

type repuCache struct {
	data map[string]repuCacheEntry
	lock sync.RWMutex
	name string
}

var CACHE_EXPIRE = 1 // Expiry in days

var repuURLCache repuCache
var repuIPCache repuCache

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

	repuURLCache.data = make(map[string]repuCacheEntry)
	repuURLCache.lock = sync.RWMutex{}
	repuURLCache.name = "URL"
	repuIPCache.data = make(map[string]repuCacheEntry)
	repuIPCache.lock = sync.RWMutex{}
	repuURLCache.name = "IP"
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
	lookupRes, err := Lookup(host, false)
	if err != nil {
		return "", err
	}
	res, err := json.Marshal(lookupRes)
	return string(res), err
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

// Lookup lookup IP address from bctid daemon.
func Lookup(ip string, ipDB bool) ([]LookupResult, error) {
	var entry repuCacheEntry
	var ok bool
	var result []LookupResult
	logger.Debug("Lookup, ip %v\n", ip)

	var res string
	var err error
	if ipDB { // IP DB
		repuIPCache.lock.RLock()
		entry, ok = repuIPCache.data[ip]
		repuIPCache.lock.RUnlock()

		if ok { // Found in cache
			json.Unmarshal([]byte(entry.value), &result)
			logger.Debug("Lookup, found cache entry %v\n", result)
			return result, nil
		} else {
			res, err = queryIP(ip)
		}
	} else { // URL DB
		repuURLCache.lock.RLock()
		entry, ok = repuURLCache.data[ip]
		repuURLCache.lock.RUnlock()

		if ok { // Found in cache
			json.Unmarshal([]byte(entry.value), &result)
			logger.Debug("Lookup, found cache entry %v\n", result)
			return result, nil
		}
		res, err = queryURL(ip)
	}

	logger.Debug("Lookup, result %v\n", res)
	if err != nil {
		return []LookupResult{}, err
	}
	if ipDB {
		updateCache(&repuIPCache, ip, res)
	} else {
		updateCache(&repuURLCache, ip, res)
	}

	json.Unmarshal([]byte(res), &result)
	return result, nil
}

func cleanCache(cache *repuCache) {
	expiry := time.Now().AddDate(0, 0, -(CACHE_EXPIRE))
	repuURLCache.lock.Lock()
	logger.Debug("Begin cache %s clean run, row count %i\n", cache.name, len(repuURLCache.data))
	for key, value := range cache.data {
		if value.age.Before(expiry) {
			delete(cache.data, key)
		}
	}
	logger.Debug("End cache %s clean run, rown count %i\n", cache.name, len(repuURLCache.data))
	repuURLCache.lock.Unlock()
}

func runCleanCache() {
	cleanerTicker := time.NewTicker(1 * time.Hour)

	for {
		select {
		case <-cleanerTicker.C:
			cleanCache(&repuURLCache)
			cleanCache(&repuIPCache)
		}
	}
}

func updateCache(cache *repuCache, entry string, data string) {
	cache.lock.Lock()
	cache.data[entry] = repuCacheEntry{value: data, age: time.Now()}
	cache.lock.Unlock()
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

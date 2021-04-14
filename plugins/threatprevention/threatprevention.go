package threatprevention

import (
	"context"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/untangle/packetd/services/dispatch"
	"github.com/untangle/packetd/services/kernel"
	"github.com/untangle/packetd/services/logger"
	"github.com/untangle/packetd/services/reports"
	"github.com/untangle/packetd/services/settings"
	"github.com/untangle/packetd/services/webroot"
)

const pluginName = "threatprevention"

var tpLevel int
var tpEnabled bool = false
var tpRedirect bool = false

var ignoreIPBlocks []*net.IPNet
var rejectInfo map[string]interface{}
var rejectInfoLock sync.RWMutex

type contextKey struct {
	key string
}

var connContextKey = &contextKey{"http-conn"}

var redirectReplyTemplate = `<html>
<head>
  <title>403 Forbidden</title>
</head>
<body>
  <div style="width: 500px; margin: 100px auto;">
	<h2>Blocked IP Address.</h2>
	<p>This IP address is blocked because it violates network policy.</p>
	<p>IP: %ip</p>
	<p>Trust level of IP:  %reason</p>
	<p>Please contact your network administrator</p>
  </div>
</body>`

// PluginStartup function is called to allow plugin specific initialization. We
// increment the argumented WaitGroup so the main process can wait for
// our shutdown function to return during shutdown.
func PluginStartup() {
	logger.Info("PluginStartup(%s) has been called\n", pluginName)

	for _, cidr := range []string{
		"127.0.0.0/8",    // IPv4 loopback
		"10.0.0.0/8",     // RFC1918
		"172.16.0.0/12",  // RFC1918
		"192.168.0.0/16", // RFC1918
		"::1/128",        // IPv6 loopback
		"fe80::/10",      // IPv6 link-local
		"fc00::/7",       // IPv6 unique local addr
	} {
		_, ignore, _ := net.ParseCIDR(cidr)
		ignoreIPBlocks = append(ignoreIPBlocks, ignore)
	}

	// Read in threat prevetion settings, and register callback for changes
	syncCallbackHandler()
	settings.RegisterSyncCallback(syncCallbackHandler)

	// Need basic http server to respond to redirect to inform user why they were blocked.
	server := http.Server{
		Addr:        ":8485",
		ConnContext: saveConnInContext,
		Handler:     http.HandlerFunc(tpRedirectHandler),
	}
	go server.ListenAndServe()

	// Need basic https server to respond to redirect to inform user why they were blocked.
	sslserver := http.Server{
		Addr:        ":8486",
		ConnContext: saveConnInContext,
		Handler:     http.HandlerFunc(tpRedirectHandler),
	}
	go sslserver.ListenAndServeTLS("/tmp/cert.pem", "/tmp/cert.key")

	rejectInfo = make(map[string]interface{})
	rejectInfoLock = sync.RWMutex{}

	dispatch.InsertNfqueueSubscription(pluginName, dispatch.ThreatPreventionPriority, TpNfqueueHandler)
}

// PluginShutdown function called when the daemon is shutting down. We call Done
// for the argumented WaitGroup to let the main process know we're finished.
func PluginShutdown() {
	logger.Info("PluginShutdown(%s) has been called\n", pluginName)
}

// Is called when we do a sync setting. Need to update threat level.
func syncCallbackHandler() {
	enabled, err := settings.GetSettings([]string{"threatprevention", "enabled"})
	if err != nil || enabled == nil {
		logger.Warn("Failed to read setting value for setting threatprevention/enabled, error: %v\n", err.Error())
		tpEnabled = false
		return
	}
	assertEnable, ok := enabled.(bool)
	if ok != true || err != nil {
		logger.Warn("Unable to parse threadprevention enabled flag, error: %v\n", err.Error())
		tpEnabled = false
		return
	}

	redirect, err := settings.GetSettings([]string{"threatprevention", "redirect"})
	if err != nil || enabled == nil {
		logger.Warn("Failed to read setting value for setting threatprevention/redirect, error: %v\n", err.Error())
		tpRedirect = false
		return
	}
	assertRedirect, ok := redirect.(bool)
	if ok != true || err != nil {
		logger.Warn("Unable to parse threadprevention redirect flag, error: %v\n", err.Error())
		tpRedirect = false
		return
	}

	tpEnabled = assertEnable
	tpRedirect = assertRedirect
	// Need to load current threatprevention level from settings.
	sensitivity, err := settings.GetSettings([]string{"threatprevention", "sensitivity"})
	if err != nil {
		logger.Warn("Failed to read setting value for setting threatprevention/sensitivity, error: %v\n", err.Error())
		logger.Warn("Failed to get threatprevention level. Default to level 80\n")
		tpLevel = 80
	} else {
		tpLevel, err = strconv.Atoi(sensitivity.(string))
		if err != nil {
			logger.Warn("Failed to read setting value for setting threatprevention/sensitivity, error: %v\n", err.Error())
			logger.Warn("Failed to get threatprevention level. Default to level 80\n")
			tpLevel = 80
		}
	}
	logger.Debug("Threat prevention level set to %v\n", tpLevel)

	// Parse passlist.
	passList, err := settings.GetSettings([]string{"threatprevention", "passList"})

	for _, entry := range passList.([]interface{}) {
		if m, ok := entry.(map[string]interface{}); ok {
			logger.Debug("Inserting CIDR into ignore list: %s\n", m["host"].(string))
			_, pass, _ := net.ParseCIDR(m["host"].(string))
			ignoreIPBlocks = append(ignoreIPBlocks, pass)
		}
	}
}

// TpNfqueueHandler receives a NfqueueMessage which includes a Tuple and
// a gopacket.Packet, along with the IP and TCP or UDP layer already extracted.
// We do whatever we like with the data, and when finished, we return an
// integer via the argumented channel with any bits set that we want added to
// the packet mark.
func TpNfqueueHandler(mess dispatch.NfqueueMessage, ctid uint32, newSession bool) dispatch.NfqueueResult {
	var result dispatch.NfqueueResult
	result.SessionRelease = true

	if !tpEnabled {
		return result
	}

	if mess.IP4Layer != nil {
		logger.Debug("TpNfqueueHandler received %d BYTES from %s to %s\n%s\n", mess.Length, mess.IP4Layer.SrcIP, mess.IP4Layer.DstIP, hex.Dump(mess.Packet.Data()))
	}
	if mess.IP6Layer != nil {
		logger.Debug("TpNfqueueHandler received %d BYTES from %s to %s\n%s\n", mess.Length, mess.IP6Layer.SrcIP, mess.IP6Layer.DstIP, hex.Dump(mess.Packet.Data()))
	}

	var dstAddr net.IP

	if mess.IP6Layer != nil {
		dstAddr = mess.IP6Layer.DstIP
	}

	if mess.IP4Layer != nil {
		dstAddr = mess.IP4Layer.DstIP
	}

	// Release if the request is for private/passlist.
	if dstAddr != nil && isIgnoreIP(dstAddr) {
		logger.Debug("Address is on pass list %s\n", dstAddr)
		return result
	}

	// Lookup and get a score.
	webrootResult, err := webroot.IPLookup(dstAddr.String())
	score := webrootResult[0].Reputation
	logger.Debug("lookup %s, score %v\n", dstAddr.String(), score)
	if err != nil {
		logger.Warn("Not able to lookup %s\n", dstAddr.String())
	}
	if score == 0 { // Score does not exists for this address. Let it pass.
		return result
	}

	if score < tpLevel {
		logger.Debug("blocked %s:%v, score %v\n", dstAddr.String(), mess.MsgTuple.ServerPort, score)
		srvPort := mess.MsgTuple.ServerPort
		// Only save TP info if this is a http/https blocked connection.
		if tpRedirect && (srvPort == 80 || srvPort == 443) {
			srcPort := int(mess.Session.GetClientSideTuple().ClientPort)
			srcTpl := mess.MsgTuple.ClientAddress.String() + ":" + strconv.Itoa(srcPort)

			webrootResult[0].Ctid = ctid
			rejectInfoLock.Lock()
			rejectInfo[srcTpl] = webrootResult[0]
			rejectInfoLock.Unlock()
		}
		// Add ctid into nft set tp_redirect. nft rule will block or redirect. 60 second timeout.
		kernel.NftSetAdd("ip", "nat", "tp_redirect", ctid, 0)

		// Add stats to reporting. Ordering is important.
		var tp_stats []interface{}
		tp_stats = append(tp_stats, time.Now().UnixNano()/1000000)
		tp_stats = append(tp_stats, dstAddr.String())
		tp_stats = append(tp_stats, score)

		reports.LogThreatpreventionStats(tp_stats)
	}
	result.SessionRelease = true
	return result
}

func isIgnoreIP(ip net.IP) bool {
	for _, ignore := range ignoreIPBlocks {
		if ignore.Contains(ip) {
			return true
		}
	}
	return false
}

func saveConnInContext(ctx context.Context, c net.Conn) context.Context {
	return context.WithValue(ctx, connContextKey, c)
}

func getConn(r *http.Request) net.Conn {
	return r.Context().Value(connContextKey).(net.Conn)
}

func tpRedirectHandler(w http.ResponseWriter, r *http.Request) {
	conn := getConn(r)
	ip := conn.RemoteAddr()
	var entry webroot.LookupResult
	var ok bool

	rejectInfoLock.RLock()
	entry, ok = rejectInfo[ip.String()].(webroot.LookupResult)
	rejectInfoLock.RUnlock()

	if !ok {
		return
	}

	tmp := strings.Replace(redirectReplyTemplate, "%ip", entry.IP, 1)
	reply := strings.Replace(tmp, "%reason", webroot.GetRiskLevel(entry.Reputation), 1)
	fmt.Fprintf(w, reply)

	ctid := entry.Ctid
	kernel.NftSetRemove("ip", "nat", "tp_redirect", ctid)

	rejectInfoLock.Lock()
	delete(rejectInfo, ip.String())
	rejectInfoLock.Unlock()
}

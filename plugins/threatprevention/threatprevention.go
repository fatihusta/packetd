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

var defaultSensitivity = 20

var ignoreIPBlocks []*net.IPNet
var localNetworks []*net.IPNet
var rejectInfo map[string]interface{}
var rejectInfoLock sync.RWMutex

var httpServer http.Server
var httpExitDone sync.WaitGroup

var httpsServer http.Server
var httpsExitDone sync.WaitGroup

type contextKey struct {
	key string
}

type tpSettingType struct {
	Enabled     bool     `json: "enabled"`
	Sensitivity int      `json: "sensitivity"`
	Redirect    bool     `json: "redirect`
	PassList    []string `json: "passList"`
}

var tpSettings tpSettingType
var pluginEnabled bool
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
  </div>
</body>`

// PluginStartup function is called to allow plugin specific initialization. We
// increment the argumented WaitGroup so the main process can wait for
// our shutdown function to return during shutdown.
func PluginStartup() {
	logger.Info("PluginStartup(%s) has been called\n", pluginName)
	ignoreIPBlocks = make([]*net.IPNet, 0)
	localNetworks = make([]*net.IPNet, 0)

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
	httpExitDone = sync.WaitGroup{}
	httpServer = http.Server{
		Addr:        ":8485",
		ConnContext: saveConnInContext,
		Handler:     http.HandlerFunc(tpRedirectHandler),
	}
	httpExitDone.Add(1)
	go func() {
		defer httpExitDone.Done()
		httpServer.ListenAndServe()
	}()

	// Need basic https server to respond to redirect to inform user why they were blocked.
	httpsExitDone = sync.WaitGroup{}
	httpsServer = http.Server{
		Addr:        ":8486",
		ConnContext: saveConnInContext,
		Handler:     http.HandlerFunc(tpRedirectHandler),
	}
	httpsExitDone.Add(1)
	go func() {
		defer httpsExitDone.Done()
		httpsServer.ListenAndServeTLS("/tmp/cert.pem", "/tmp/cert.key")
	}()

	rejectInfo = make(map[string]interface{})
	rejectInfoLock = sync.RWMutex{}

	dispatch.InsertNfqueueSubscription(pluginName, dispatch.ThreatPreventionPriority, TpNfqueueHandler)
	pluginEnabled = true
}

// PluginShutdown function called when the daemon is shutting down. We call Done
// for the argumented WaitGroup to let the main process know we're finished.
func PluginShutdown() {
	logger.Info("PluginShutdown(%s) has been called\n", pluginName)

	// Unsubscribe
	dispatch.RemoveNfqueueSubscription(pluginName)

	// Shutdown the redirect servers.
	if err := httpServer.Shutdown(context.Background()); err != nil {
		logger.Warn("not able to shutdown http redirect server, err: %v\n", err)
	}
	if err := httpsServer.Shutdown(context.Background()); err != nil {
		logger.Warn("not able to shutdown http redirect server, err: %v\n", err)
	}

	httpExitDone.Wait()
	httpsExitDone.Wait()
	pluginEnabled = false
}

// PluginEnabled function returns the status (if plugin is enabled (true) or disabled (false) currently)
func PluginEnabled() bool {
	return pluginEnabled
}

func createSettings(m map[string]interface{}) {
	var err error
	tpSettings = tpSettingType{Enabled: false, Sensitivity: defaultSensitivity, Redirect: false, PassList: nil}
	if m == nil {
		logger.Warn("Failed to read setting value for setting threatprevention, using defaults\n")
	} else {
		if m["enabled"] != nil {
			tpSettings.Enabled = m["enabled"].(bool)
		}
		if m["redirect"] != nil {
			tpSettings.Redirect = m["redirect"].(bool)
		}
		if m["sensitivity"] != nil {
			tpSettings.Sensitivity, err = strconv.Atoi(m["sensitivity"].(string))
			if err != nil {
				logger.Warn("not able to set threat prevention sensitivity level, using default. Err: %v\n", err.Error())
				tpSettings.Sensitivity = defaultSensitivity
			}
		}
		if m["passlist"] != nil {
			tpSettings.PassList = m["passList"].([]string)
		}
	}
}

// Is called when we do a sync setting. Need to update threat level.
func syncCallbackHandler() {
	var systemTPsettings interface{}
	systemTPsettings, _ = settings.GetSettings([]string{"threatprevention"})
	createSettings(systemTPsettings.(map[string]interface{}))

	logger.Debug("tpSettings are (enabled, level, redirect, passList) %v\n", tpSettings)
	for _, entry := range tpSettings.PassList {
		logger.Debug("Inserting CIDR into ignore list: %s\n", entry)
		_, pass, _ := net.ParseCIDR(entry)
		ignoreIPBlocks = append(ignoreIPBlocks, pass)
	}

	// Get Local LAN networks.
	networks, _ := settings.GetSettings([]string{"network", "interfaces"})

	for _, intface := range networks.([]interface{}) {
		if m, ok := intface.(map[string]interface{}); ok {
			if m["wan"].(bool) || !m["enabled"].(bool) || m["v4StaticPrefix"] == nil || m["v4StaticAddress"] == nil {
				continue
			}
			prefix := strconv.FormatFloat(m["v4StaticPrefix"].(float64), 'f', -1, 64)
			localNetwork := fmt.Sprintf("%s/%s", m["v4StaticAddress"].(string), prefix)
			logger.Debug("Found local network %s\n", localNetwork)
			_, l, _ := net.ParseCIDR((localNetwork))
			localNetworks = append(localNetworks, l)
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
	var webrootResult []webroot.LookupResult
	result.SessionRelease = true

	if !tpSettings.Enabled {
		return result
	}

	if mess.IP4Layer != nil {
		logger.Debug("TpNfqueueHandler received %d BYTES from %s to %s\n%s\n", mess.Length, mess.IP4Layer.SrcIP, mess.IP4Layer.DstIP, hex.Dump(mess.Packet.Data()))
	}
	if mess.IP6Layer != nil {
		logger.Debug("TpNfqueueHandler received %d BYTES from %s to %s\n%s\n", mess.Length, mess.IP6Layer.SrcIP, mess.IP6Layer.DstIP, hex.Dump(mess.Packet.Data()))
	}

	var dstAddr net.IP
	var srcAddr net.IP

	if mess.IP6Layer != nil {
		dstAddr = mess.IP6Layer.DstIP
		srcAddr = mess.IP6Layer.SrcIP
	}

	if mess.IP4Layer != nil {
		dstAddr = mess.IP4Layer.DstIP
		srcAddr = mess.IP4Layer.SrcIP
	}

	// Release if the request is for private/passlist.
	if dstAddr != nil && isOnNetworkList(dstAddr, ignoreIPBlocks) {
		logger.Debug("Address is on pass list %s\n", dstAddr)
		return result
	}

	var err error
	srvPort := mess.MsgTuple.ServerPort
	// Inbound connections use IPdb
	if dstAddr != nil && srcAddr != nil && !isOnNetworkList(srcAddr, localNetworks) && isOnNetworkList(dstAddr, localNetworks) {
		webrootResult, err = webroot.Lookup(dstAddr.String(), true)
	} else if srvPort == 80 || srvPort == 443 { // For outbound HTTP/HTTPS use URLdb.
		webrootResult, err = webroot.Lookup(dstAddr.String(), false)
	} else { // Everyting else use IPdb.
		webrootResult, err = webroot.Lookup(dstAddr.String(), true)
	}

	score := webrootResult[0].Reputation
	logger.Debug("lookup %s, score %v\n", dstAddr.String(), score)
	if err != nil {
		logger.Warn("Not able to lookup %s\n", dstAddr.String())
	}
	if score == 0 { // Score does not exists for this address. Let it pass.
		return result
	}

	if score <= tpSettings.Sensitivity {
		logger.Debug("blocked %s:%v, score %v\n", dstAddr.String(), mess.MsgTuple.ServerPort, score)
		// Only save TP info if this is a http/https blocked connection.
		if tpSettings.Redirect && (srvPort == 80 || srvPort == 443) {
			srcPort := int(mess.Session.GetClientSideTuple().ClientPort)
			srcTpl := mess.MsgTuple.ClientAddress.String() + ":" + strconv.Itoa(srcPort)

			webrootResult[0].IP = dstAddr.String()
			webrootResult[0].Ctid = ctid
			rejectInfoLock.Lock()
			rejectInfo[srcTpl] = webrootResult[0]
			rejectInfoLock.Unlock()
		}
		// Add ctid into nft set tp_redirect. nft rule will block or redirect. 60 second timeout.
		kernel.NftSetAdd("ip", "nat", "tp_redirect", ctid, 0)

		// Add stats to reporting. Ordering is important.
		var tpStats []interface{}
		tpStats = append(tpStats, time.Now().UnixNano()/1000000)
		tpStats = append(tpStats, dstAddr.String())
		tpStats = append(tpStats, score)

		reports.LogThreatpreventionStats(tpStats)
	}
	result.SessionRelease = true
	return result
}

func isOnNetworkList(ip net.IP, list []*net.IPNet) bool {
	for _, address := range list {
		if address.Contains(ip) {
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

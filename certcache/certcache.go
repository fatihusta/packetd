package certcache

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"github.com/untangle/packetd/support"
	"sync"
)

var localMutex sync.Mutex

//-----------------------------------------------------------------------------

// PluginStartup function is called to allow plugin specific initialization. We
// increment the argumented WaitGroup so the main process can wait for
// our goodbye function to return during shutdown.
func PluginStartup(childsync *sync.WaitGroup) {
	support.LogMessage("PluginStartup(%s) has been called\n", "certcache")
	childsync.Add(1)
}

//-----------------------------------------------------------------------------

// PluginGoodbye function called when the daemon is shutting down. We call Done
// for the argumented WaitGroup to let the main process know we're finished.
func PluginGoodbye(childsync *sync.WaitGroup) {
	support.LogMessage("PluginGoodbye(%s) has been called\n", "certcache")
	childsync.Done()
}

//-----------------------------------------------------------------------------

// PluginNetfilterHandler is called to handle netfilter packet data. We extract
// the source and destination IP address from the packet, lookup the GeoIP
// country code for each, and store them in the conntrack dictionary.
func PluginNetfilterHandler(ch chan<- int32, tuple support.Tuple, ctid uint) {

	if tuple.ServerPort != 443 {
		ch <- 8
		return
	}

	client := fmt.Sprintf("%s", tuple.ClientAddr)

	// TODO - remove this hack once we can ignore locally generated traffic
	if client == "192.168.222.20" {
		ch <- 8
		return
	}

	var cert x509.Certificate
	var ok bool

	localMutex.Lock()

	if cert, ok = support.FindCertificate(client); ok {
		support.LogMessage("Loading certificate for %s\n", tuple.ServerAddr)
	} else {
		support.LogMessage("Fetching certificate for %s\n", tuple.ServerAddr)

		conf := &tls.Config{
			InsecureSkipVerify: true,
		}

		target := fmt.Sprintf("%s:443", tuple.ServerAddr)
		conn, err := tls.Dial("tcp", target, conf)
		if err != nil {
			support.LogMessage("TLS ERROR: %s\n", err)
		}

		cert = *conn.ConnectionState().PeerCertificates[0]
		support.InsertCertificate(client, cert)
		conn.Close()
	}

	// TODO - should the cert also be attached to the session?

	localMutex.Unlock()
	support.LogMessage("CERTIFICATE: %s\n", cert.Subject)
	ch <- 8
}

//-----------------------------------------------------------------------------

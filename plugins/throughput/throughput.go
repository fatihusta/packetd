package throughput

import (
	"os/exec"

	"github.com/untangle/packetd/services/logger"
)

var qosEnabled = false

// Start starts QoS
func Start() {
	qosEnabled = true
	Restart()
}

// Stop stops QoS
func Stop() {
	qosEnabled = false
	Restart()
}

// Restart() is called when there are any qos license changes.
func Restart() {

	cmd := exec.Command("/etc/init.d/qos", "restart")
	err := cmd.Run()

	if err != nil {
		logger.Warn("Not able to restart qos, err: %v\n", err)
	}
}

// IsEnabled() is called to inspect if qos is running.
func IsEnabled() bool {
	return qosEnabled
}

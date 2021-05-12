package qos

import (
	"os/exec"

	"github.com/untangle/packetd/services/logger"
)

var qosEnabled = true

// Restart() is called when there are any qos license changes.
func Restart() {

	cmd := exec.Command("/etc/init.d/qos restart")
	err := cmd.Run()

	if err != nil {
		logger.Warn("Not able to restart qos, err: %v\n", err)
	}
}

// IsEnabled() is called to inspect if qos is running. Always returns true.
func IsEnabled() bool {
	return qosEnabled
}
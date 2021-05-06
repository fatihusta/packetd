package license

import (
	"errors"

	"github.com/untangle/packetd/plugins/threatprevention"
	"github.com/untangle/packetd/services/logger"
)

type appHook struct {
	name    string
	start   func()
	stop    func()
	enabled func() bool
}

// licensed applications.
var validApps []appHook = []appHook{
	appHook{
		name:    "threatprevention",
		start:   threatprevention.PluginStartup,
		stop:    threatprevention.PluginShutdown,
		enabled: threatprevention.PluginEnabled,
	},
}

type Command int

// Types of commands that we accept.
const (
	Start Command = iota
	Stop
	Enabled
)

// type used for specific commands from the client license daemon.
type LicenseCommand struct {
	Name    string  `json:"name"`
	Command Command `json:"command"`
}

// Keep to track of each licensed app state.
// Need to know if the app was running or not at startup and before license-daemon
// has told what is licensed or not. E.g we will start the apps that were running
// prior to a shutdown.
type appState struct {
	Name  string
	State Command
}

var appStates []appState

func Startup() {
	// Read from cache to see what most recent state of services are.
	// TODO: Read from persistent state and enable/disable plugins per last know state.

}

// Shutdown is called when the packetd service stops
func Shutdown() {
	logger.Info("Shutting down the license service\n")
}

func DoCommand(cmd LicenseCommand) (error, bool) {
	var err error
	var app appHook
	if app, err = findApp(cmd.Name); err != nil {
		return errors.New("App not valid"), ""
	}

	switch cmd.Command {
	case Start:
		app.start()
	case Stop:
		app.stop()
	case Enabled:
		return nil, app.enabled()
	}
	// TODO: Persist state
	return nil, true
}

func findApp(name string) (appHook, error) {
	for _, o := range validApps {
		if o.name == name {
			return o, nil
		}
	}
	return appHook{}, errors.New("Invalid app name.")
}

package license

import (
	"encoding/json"
	"errors"
	"io/ioutil"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/untangle/packetd/plugins/threatprevention"
	"github.com/untangle/packetd/plugins/throughput"
	"github.com/untangle/packetd/services/logger"
)

/*
	Assumptions:
		- An app is a plugin or can at least be controlled by enabling/disabling a plugin.

	To implement a new licensed app (plugin) do the following.
		- plugin must have start (Startup), stop (Shutdown) and enabled hooks.
		- plugin shutdown hook must be idempotent.
		- The enabled hook is of type 'func() bool' and returns true if plugin is currently running/enabled, otherwise false.
		- Add plugin hooks in the validApps list.
		- Do no add the plugin Startup() and Shutown() to the normal dispatch.
*/

const appStateFilename = "/etc/config/appstate.json"

type appHook struct {
	start   func()
	stop    func()
	enabled func() bool
}

// licensed applications.
var validApps map[string]appHook = map[string]appHook{
	"untangle-node-threat-prevention": appHook{
		start:   threatprevention.PluginStartup,
		stop:    threatprevention.PluginShutdown,
		enabled: threatprevention.PluginEnabled,
	},
	"untangle-node-throughput": appHook{
		start:   throughput.Restart,
		stop:    throughput.Restart,
		enabled: throughput.IsEnabled,
	},
}

var errAppNotFoundError error = errors.New("App not found")

// State is used to set the desired state of an app.
type State int

// Types of commands that we accept.
const (
	StateEnable State = iota
	StateDisable
)

// Command is used for specific commands (SetState)
type Command struct {
	Name     string `json:"name"`
	NewState State  `json:"command"`
}

// Used to load and save appState. Need to set each app to its previous state when starting up.
type appState struct {
	Name      string `json: "appname`
	IsEnabled bool   `json: "enabled"`
}

// list of app states to be used during startup
var appStates []appState

const (
	watchDogLookTime = 6*time.Hour + 5*time.Minute // EQUAL to CLS plus a few minutes
)

var shutdownChannelLicense chan bool
var wg sync.WaitGroup
var watchDog *time.Timer

// Startup the license service.
func Startup() {
	shutdownChannelLicense = make(chan bool)
	logger.Info("Starting the license service\n")
	err := loadAppState()
	if err != nil {
		logger.Warn("Not able to retrieve previous app state. %v\n", err)
	}

	// Set each app to its previous state.
	logger.Debug("appstate %+v\n", appStates)
	for _, o := range appStates {
		if _, err = findApp(o.Name); err != nil {
			logger.Debug("App %s not found. Err: %v", o.Name, err)
			continue
		}
		cmd := Command{Name: o.Name}
		if o.IsEnabled {
			cmd.NewState = StateEnable
		} else {
			cmd.NewState = StateDisable
		}
		SetAppState(cmd, true)
	}

	// restart licenses
	err = RefreshLicenses()
	if err != nil {
		logger.Warn("Not able to restart CLS: %v\n", err)
	}

	// watchdog for if CLS is alive
	wg.Add(1)
	go func() {
		defer wg.Done()
		watchDog = time.NewTimer(watchDogLookTime)
		defer watchDog.Stop()
		for {
			select {
			case <-shutdownChannelLicense:
				logger.Info("Shutdown CLS watchdog\n")
				return
			case <-watchDog.C:
				// on watch dog seen, restart license server
				// shutdown license items if restart did not work
				logger.Warn("Watch seen\n")
				refreshErr := RefreshLicenses()
				if refreshErr != nil {
					logger.Warn("Couldn't restart CLS: %s\n", refreshErr)
					shutdownLicenses()
				} else {
					logger.Info("Restarted CLS from watchdog\n")
				}
				watchDog.Reset(watchDogLookTime)
			}
		}
	}()
}

// Shutdown is called when the packetd service stops
func Shutdown() {
	logger.Info("Shutting down the license service\n")
	if shutdownChannelLicense != nil {
		close(shutdownChannelLicense)
		wg.Wait()
	}
	shutdownLicenses()
}

// Shutdown all the licensed apps
func shutdownLicenses() {
	//remove license.json
	os.Remove("/etc/config/licenses.json")
	err := ioutil.WriteFile("/etc/config/licenses.json", []byte("{\"list\": []}"), 0444)
	if err != nil {
		logger.Warn("Failure to write non-license file: %v\n", err)
	}
	for name, _ := range validApps {
		cmd := Command{Name: name, NewState: StateDisable}
		SetAppState(cmd, false)
	}

}

// GetLicenseDefaults gets the default validApps for MFW
func GetLicenseDefaults() []string {
	logger.Debug("GetLicenseDefaults()\n")
	keys := make([]string, len(validApps))
	i := 0
	for k := range validApps {
		keys[i] = k
		i++
	}
	watchDog.Reset(watchDogLookTime)
	return keys
}

// ClsIsAlive resets watchdog as CLS is alive
func ClsIsAlive() {
	watchDog.Reset(watchDogLookTime)
}

// SetAppState sets the desired state of an app.
func SetAppState(cmd Command, save bool) error {
	var err error
	var app appHook
	logger.Debug("Setting state for app %s to %v\n", cmd.Name, cmd.NewState)
	if app, err = findApp(cmd.Name); err != nil {
		return errAppNotFoundError
	}

	switch cmd.NewState {
	case StateEnable:
		app.start()
	case StateDisable:
		app.stop()
	}
	if save {
		err = saveAppState()
	}
	return err
}

// RefreshLicences restart the client licence service
func RefreshLicenses() error {
	output, err := exec.Command("/etc/init.d/clientlic", "restart").CombinedOutput()
	if err != nil {
		logger.Warn("license fetch failed: %s\n", err.Error())
		return err
	}
	if strings.Contains(string(output), "Command failed") {
		logger.Warn("license fetch failed: %s\n", string(output))
		err = errors.New(string(output))
		return err
	}
	return nil
}

// IsEnabled is called from API to see if app is currently enabled.
func IsEnabled(appName string) (bool, error) {
	var app appHook
	var err error
	if app, err = findApp(appName); err != nil {
		return false, errAppNotFoundError
	}
	return app.enabled(), nil
}

// helper function to check if app is valid and return its hooks.
func findApp(name string) (appHook, error) {
	app, ok := validApps[name]
	if !ok {
		return appHook{}, errAppNotFoundError
	}
	return app, nil
}

// save the current app state.
func saveAppState() error {
	appStates = make([]appState, 0)
	for name, o := range validApps {
		appStates = append(appStates, appState{Name: name, IsEnabled: o.enabled()})
	}
	data, err := json.Marshal(appStates)
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(appStateFilename, data, 0644)
	return err

}

// load the previously saved app state.
func loadAppState() error {
	appStates = make([]appState, 0)
	appStateContent, err := ioutil.ReadFile(appStateFilename)
	if err != nil {
		logger.Info("Not able to find appstate file, creating new one. %v\n", err)
		return saveAppState()
	}

	err = json.Unmarshal(appStateContent, &appStates)
	if err != nil {
		logger.Warn("Not able to read content of app state file.%v \n ", err)
		return err
	}
	return nil
}

package license

import (
	"encoding/json"
	"errors"
	"io/ioutil"

	"github.com/untangle/packetd/plugins/threatprevention"
	"github.com/untangle/packetd/services/logger"
)

/*
	Assumptions:
		- An app is a plugin or can at least be controlled by enabling/disabling a plugin.

	To implement a new licensed app (plugin) do the following.
		- plugin must have start (Startup), stop (Shutdown) and enabled hooks.
		- The enabled hook is of type 'func() bool' and returns true if plugin is currently running/enabled, otherwise false.
		- Add plugin hooks in the validApps list.
		- Do no add the plugin Startup() and Shutown() to the normal dispatch.
*/

const appStateFilename = "/etc/config/appstate.json"

type appHook struct {
	name    string
	start   func()
	stop    func()
	enabled func() bool
}

// licensed applications.
var validApps []appHook = []appHook{
	{
		name:    "threatprevention",
		start:   threatprevention.PluginStartup,
		stop:    threatprevention.PluginShutdown,
		enabled: threatprevention.PluginEnabled,
	},
}

var errAppNotFoundError error = errors.New("app not found")

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

// Startup the license service.
func Startup() {
	logger.Info("Starting the license service\n")
	err := loadAppState()
	if err != nil {
		logger.Warn("Not able to retrieve previous app state. %v\n", err)
	}

	// Set each app to its previous state.
	logger.Debug("appstate %v+ %v\n", appStates)
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
		SetAppState(cmd)
	}
}

// Shutdown is called when the packetd service stops
func Shutdown() {
	logger.Info("Shutting down the license service\n")
	// Shutdown all the licensed apps.
	for _, o := range validApps {
		cmd := Command{Name: o.name, NewState: StateDisable}
		SetAppState(cmd)
	}
}

// SetAppState sets the desired state of an app.
func SetAppState(cmd Command) error {
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
	return saveAppState()
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
	for _, o := range validApps {
		if o.name == name {
			return o, nil
		}
	}
	return appHook{}, errAppNotFoundError
}

// save the current app state.
func saveAppState() error {
	appStates = make([]appState, 0)
	for _, o := range validApps {
		appStates = append(appStates, appState{Name: o.name, IsEnabled: o.enabled()})
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

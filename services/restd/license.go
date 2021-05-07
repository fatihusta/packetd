package restd

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/untangle/packetd/services/license"
	"github.com/untangle/packetd/services/logger"
)

// setAppState function sets the state for an app. enabled/disabled. Also provides status.
func setAppState(c *gin.Context) {
	var err error = nil

	logger.Debug("setAppState()\n")
	var command license.Command
	command.Name = c.Param("appname")
	cmd := c.Param("command")

	if cmd == "enable" {
		command.NewState = license.StateEnable
	} else if cmd == "disable" {
		command.NewState = license.StateDisable
	} else {
		err = errors.New("invalid request")
	}

	if err == nil {
		err = license.SetAppState(command)
	}

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.Header("Content-Type", "application/json")
	c.JSON(http.StatusOK, gin.H{"result": "OK"})
}

func licenseEnabled(c *gin.Context) {
	logger.Debug("licenseEnabled()\n")
	var appName = c.Param("appname")
	result, err := license.IsEnabled(appName)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.Header("Content-Type", "application/json")
	c.JSON(http.StatusOK, gin.H{"result": result})
}

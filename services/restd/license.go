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
		err = license.SetAppState(command, true)
	}

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.Header("Content-Type", "application/json")
	c.JSON(http.StatusOK, gin.H{"result": "OK"})
}

// licenseEnabled returns if an app is enabled
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

// getLicenseDefaults gets the licenseable apps for packetd
func getLicenseDefaults(c *gin.Context) {
	logger.Debug("getLicenseDefaults()")
	keys := license.GetLicenseDefaults()
	c.JSON(http.StatusOK, keys)
}

// fetchLicenseHandler restarts the CLS to immediately fetch licenses
func fetchLicensesHandler(c *gin.Context) {
	err := license.RefreshLicenses()
	if err != nil {
		logger.Warn("license fetch failed: %s\n", err.Error())
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch license"})
		return
	}

	logger.Notice("Fetch licenses... done\n")
	c.JSON(http.StatusOK, gin.H{"success": true})
	return
}

// clsIsAlive is called when CLS is alive
func clsIsAlive(c *gin.Context) {
	license.ClsIsAlive()
	logger.Info("CLS is Alive\n")
	c.JSON(http.StatusOK, gin.H{"result": "OK"})
}

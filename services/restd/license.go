package restd

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/untangle/packetd/services/license"
	"github.com/untangle/packetd/services/logger"
)

// licenseCommand function sets the state for an app. enabled/disabled. Also provides status.
func licenseCommand(c *gin.Context) {
	logger.Debug("licenseCommand() \n")
	var command license.LicenseCommand
	// TODO Parse body into LicenseCommand struct

	result, err := license.DoCommand(command)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err})
		return
	}

	c.Header("Content-Type", "application/json")
	c.String(http.StatusOK, string(result))
	return
}

func licenseEnabled(c *gin.Context) {
	logger.Debug("licenseCommand() \n")
	var command license.LicenseCommand
	// TODO Parse body into LicenseCommand struct

	result, err := license.DoCommand(command)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err})
		return
	}

	c.Header("Content-Type", "application/json")
	c.String(http.StatusOK, string(result))
	return
}

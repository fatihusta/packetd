package dict

import (
	"bufio"
	"fmt"
	"github.com/untangle/packetd/services/exec"
	"github.com/untangle/packetd/services/logger"
	"os"
	"strings"
	"sync"
	"net"
	"strconv"
)

const pathBase string = "/proc/net/dict"

var readMutex = &sync.Mutex{}
var logsrc = "dict"
var disabled = false

// Startup dict service
func Startup() {
	if disabled {
		return
	}

	// Load the dict module
	exec.SystemCommand("modprobe", []string{"nf_conntrack_dict"})
}

//-----------------------------------------------------------------------------

// Shutdown dict service
func Shutdown() {
}

//-----------------------------------------------------------------------------

// Disable disable dict writing
func Disable() {
	disabled = true
}

//-----------------------------------------------------------------------------

// Entry holds a dictionary entry
type Entry struct {
	Table string
	Key interface{}
	Field string
	Value interface{}
}

//-----------------------------------------------------------------------------

// Parse the table name from the argument string
func parseTable(arg string) string {
	var table string
	fmt.Sscanf(arg, "table: %s", &table)
	return table
}

//-----------------------------------------------------------------------------

// Parse the field name from the argument string
func parseField(arg string) string {
	var field string
	fmt.Sscanf(arg, "field: %s", &field)
	return field
}

//-----------------------------------------------------------------------------

// Parse the key from the argument string
func parseKey(arg string) interface{} {
	var key interface{}

	if strings.Contains(arg, "key_string: ") {
		var temp string
		fmt.Sscanf(arg, "key_string: %s", &temp)
		key = temp
	} else if strings.Contains(arg, "key_int: ") {
		var temp uint32
		fmt.Sscanf(arg, "key_int: %d", &temp)
		key = temp
	} else if strings.Contains(arg, "key_mac: ") {
		var temp string
		fmt.Sscanf(arg, "key_mac: %s", &temp)
		tempmac, _ := net.ParseMAC(temp)
		key = tempmac
	} else if strings.Contains(arg, "key_ip: ") {
		var temp string
		fmt.Sscanf(arg, "key_ip: %s", &temp)
		tempip := net.ParseIP(temp)
		key = tempip
	} else if strings.Contains(arg, "key_ip6: ") {
		var temp string
		fmt.Sscanf(arg, "key_ip6: %s", &temp)
		tempip := net.ParseIP(temp)
		key = tempip
	}

	return key
}

//-----------------------------------------------------------------------------

// Parse the value from the argument string
func parseValue(arg string) interface{} {
	var value interface{}

	if strings.Contains(arg, "string: ") {
		var temp string
		fmt.Sscanf(arg, "string: %s", &temp)
		value = temp
	} else if strings.Contains(arg, "int: ") {
		var temp uint32
		fmt.Sscanf(arg, "int: %d", &temp)
		value = temp
	} else if strings.Contains(arg, "int64: ") {
		var temp uint64
		fmt.Sscanf(arg, "int64: %d", &temp)
		value = temp
	} else if strings.Contains(arg, "mac: ") {
		var temp string
		fmt.Sscanf(arg, "mac: %s", &temp)
		tempmac, _ := net.ParseMAC(temp)
		value = tempmac
	} else if strings.Contains(arg, "ip: ") {
		var temp string
		fmt.Sscanf(arg, "ip: %s", &temp)
		tempip := net.ParseIP(temp)
		value = tempip
	} else if strings.Contains(arg, "ip6: ") {
		var temp string
		fmt.Sscanf(arg, "ip6: %s", &temp)
		tempip := net.ParseIP(temp)
		value = tempip
	} else if strings.Contains(arg, "bool: ") {
		var temp string
		fmt.Sscanf(arg, "bool: %s", &temp)
		tempbool, _ := strconv.ParseBool(temp)
		value = tempbool
	}

	return value
}

//-----------------------------------------------------------------------------

// Parse an entry from a line of output from /proc/net/dict/*
func parseEntry(line string) Entry {
	var entry Entry
	args := make([]string, 4)
	slices := strings.SplitN(line, " ", 8)
	for i := 0; i < len(args); i++ {
		args[i] = strings.Join(slices[(i*2):((i*2)+2)], " ")

		if strings.Contains(args[i], "table: ") {
			entry.Table = parseTable(args[i])
		} else if strings.Contains(args[i], "field: ") {
			entry.Field = parseField(args[i])
		} else if strings.Contains(args[i], "key_") {
			entry.Key = parseKey(args[i])
		} else {
			entry.Value = parseValue(args[i])
		}
	}

	return entry
}

//-----------------------------------------------------------------------------

// Format a Entry table string
func formatTable(table string) string {
	return fmt.Sprintf("Table: %s", table)
}

//-----------------------------------------------------------------------------

// Format a Entry field string
func formatField(field string) string {
	return fmt.Sprintf("Field: %s", field)
}

//-----------------------------------------------------------------------------

// Format a Entry key string
func formatKey(key interface{}) string {

	switch key.(type) {
		case string:
			return fmt.Sprintf("Key: %s", key.(string))
		case uint32:
			return fmt.Sprintf("Key: %d", key.(uint32))
		case net.HardwareAddr:
			return fmt.Sprintf("Key: %s", key.(net.HardwareAddr).String())
		case net.IP:
			return fmt.Sprintf("Key: %s", key.(net.IP).String())
	}

	return ""
}

//-----------------------------------------------------------------------------

// Format a Entry value string
func formatValue(value interface{}) string {

	switch value.(type) {
		case string:
			return fmt.Sprintf("Value: %s", value.(string))
		case uint32:
			return fmt.Sprintf("Value: %d", value.(uint32))
		case uint64:
			return fmt.Sprintf("Value: %d", value.(uint64))
		case net.HardwareAddr:
			return fmt.Sprintf("Value: %s", value.(net.HardwareAddr).String())
		case net.IP:
			return fmt.Sprintf("Value: %s", value.(net.IP).String())
		case bool:
			return fmt.Sprintf("Value: %s", strconv.FormatBool(value.(bool)))
	}

	return ""
}

//-----------------------------------------------------------------------------

// Print an Entry
func (p Entry) Print() {
	logger.LogInfo(logsrc, "%s %s %s %s\n", formatTable(p.Table), formatKey(p.Key), formatField(p.Field), formatValue(p.Value))
}

//-----------------------------------------------------------------------------

// GetValue gets an entry's value
func (p Entry) GetValue() interface{} {
	return p.Value
}

//-----------------------------------------------------------------------------

// GetString gets an entry's string value
func (p Entry) GetString() (string, error) {

	switch p.Value.(type) {
		case string:
			return p.Value.(string), nil
		default:
			return "", fmt.Errorf("GetString: Requested value is not a string")
	}
}

//-----------------------------------------------------------------------------

// GetInt gets an entry's integer value
func (p Entry) GetInt() (uint32, error) {

	switch p.Value.(type) {
		case uint32:
			return p.Value.(uint32), nil
		default:
			return 0, fmt.Errorf("GetInt: Requested value is not an integer")
	}
}

//-----------------------------------------------------------------------------

// GetInt64 gets an entry's 64 bit integer value
func (p Entry) GetInt64() (uint64, error) {

	switch p.Value.(type) {
		case uint64:
			return p.Value.(uint64), nil
		default:
			return 0, fmt.Errorf("GetInt64: Requested value is not a 64 bit integer")
	}
}

//-----------------------------------------------------------------------------

// GetMac gets an entry's mac value
func (p Entry) GetMac() (net.HardwareAddr, error) {

	switch p.Value.(type) {
		case net.HardwareAddr:
			return p.Value.(net.HardwareAddr), nil
		default:
			var x net.HardwareAddr
			return x, fmt.Errorf("GetMac: Requested value is not a MAC address")
	}
}

//-----------------------------------------------------------------------------

// GetIP gets an entry's IP value
func (p Entry) GetIP() (net.IP, error) {

	switch p.Value.(type) {
		case net.IP:
			return p.Value.(net.IP), nil
		default:
			var x net.IP
			return x, fmt.Errorf("GetIP: Requested value is not an IP address")
	}
}

//-----------------------------------------------------------------------------

// GetBool gets an entry's bool value
func (p Entry) GetBool() (bool, error) {

	switch p.Value.(type) {
		case bool:
			return p.Value.(bool), nil
		default:
			return false, fmt.Errorf("GetBool: Requested value is not a bool")
	}
}

//-----------------------------------------------------------------------------

// writeEntry writes out a set string to the dict proc write node
func writeEntry(setstr string) error {
	file, err := os.OpenFile(pathBase+"/write", os.O_WRONLY, 0660)

	if err != nil {
		logger.LogWarn(logsrc, "writeEntry: Failed to open %s\n", pathBase+"/write")
		return err
	}

	defer file.Close()

	_, err = file.WriteString(setstr)
	if err != nil {
		logger.LogWarn(logsrc, "writeEntry: Failed to write %s\n", setstr)
		return (err)
	}

	file.Sync()

	return err
}

//-----------------------------------------------------------------------------

// deleteEntry writes out a string to the dict proc delete node
func deleteEntry(setstr string) error {
	file, err := os.OpenFile(pathBase+"/delete", os.O_WRONLY, 0660)

	if err != nil {
		logger.LogWarn(logsrc, "deleteEntry: Failed to open %s\n", pathBase+"/write")
		return err
	}

	defer file.Close()

	_, err = file.WriteString(setstr)
	if err != nil {
		logger.LogErr(logsrc, "dict: deleteEntry: Failed to write %s\n", setstr)
		return (err)
	}

	file.Sync()

	return err
}

//-----------------------------------------------------------------------------

// generateTable generates the table token for the dict proc write string
func generateTable(table string) string {
	return fmt.Sprintf("table=%s,", table)
}

//-----------------------------------------------------------------------------

// generateField generates the field token for the dict proc write string
func generateField(field string) string {
	return fmt.Sprintf("field=%s,", field)
}

//-----------------------------------------------------------------------------

// generateString generates the value token for the dict proc write string
func generateString(value string) string {
	return fmt.Sprintf("value=%s,", value)
}

//-----------------------------------------------------------------------------

// generateMac generates the mac token for the dict proc write string
func generateMac(value net.HardwareAddr) string {
	return fmt.Sprintf("mac=%s,", value.String())
}

//-----------------------------------------------------------------------------

// generateInt generates the int token for the dict proc write string
func generateInt(value uint32) string {
	return fmt.Sprintf("int=%d,", value)
}

//-----------------------------------------------------------------------------

// generateInt64 generates the int token for the dict proc write string
func generateInt64(value uint64) string {
	return fmt.Sprintf("int64=%d,", value)
}

//-----------------------------------------------------------------------------

// generateBool generates the bool token for the dict proc write string
func generateBool(value bool) string {
	return fmt.Sprintf("bool=%s,", strconv.FormatBool(value))
}

//-----------------------------------------------------------------------------

// generateIP generates the ip token for the dict proc write string
func generateIP(value net.IP) string {
	return fmt.Sprintf("ip=%s,", value.String())
}

//-----------------------------------------------------------------------------

// generateIP6 generates the ip token for the dict proc write string
func generateIP6(value net.IP) string {
	return fmt.Sprintf("ip6=%s,", value.String())
}

//-----------------------------------------------------------------------------

// generateValue sets a field/value entry for the supplied key in the supplied table
func generateValue(value interface{}) string {
	switch value.(type) {
		case string:
			return generateString(value.(string))
		case net.HardwareAddr:
			return generateMac(value.(net.HardwareAddr))
		case net.IP:
			if value.(net.IP).To4() != nil {
				return generateIP(value.(net.IP))
			}

			return generateIP6(value.(net.IP))
		case bool:
			return generateBool(value.(bool))
		case uint32:
			return generateInt(value.(uint32))
		case uint64:
			return generateInt64(value.(uint64))
		default:
			return ""
	}
}

//-----------------------------------------------------------------------------

// generateKeyInt generates the key_int token for the dict proc write string
func generateKeyInt(key uint32) string {
	return fmt.Sprintf("key_int=%d,", key)
}

//-----------------------------------------------------------------------------

// generateKeyIP generates the key_ip token for the dict proc write string
func generateKeyIP(key net.IP) string {
	return fmt.Sprintf("key_ip=%s,", key.String())
}

//-----------------------------------------------------------------------------

// generateKeyIP6 generates the key_ip6 token for the dict proc write string
func generateKeyIP6(key net.IP) string {
	return fmt.Sprintf("key_ip6=%s,", key.String())
}

//-----------------------------------------------------------------------------

// generateKeyString generates the key_string token for the dict proc write string
func generateKeyString(key string) string {
	return fmt.Sprintf("key_string=%s,", key)
}

//-----------------------------------------------------------------------------

// generateKeyMac generates the key_mac token for the dict proc write string
func generateKeyMac(key net.HardwareAddr) string {
	return fmt.Sprintf("key_mac=%s,", key.String())
}

//-----------------------------------------------------------------------------

// generateKey sets a field/value entry for the supplied key in the supplied table
func generateKey(key interface{}) string {
	switch key.(type) {
		case string:
			return generateKeyString(key.(string))
		case net.HardwareAddr:
			return generateKeyMac(key.(net.HardwareAddr))
		case net.IP:
			if key.(net.IP).To4() != nil {
				return generateKeyIP(key.(net.IP))
			}

			return generateKeyIP6(key.(net.IP))
		case uint32:
			return generateKeyInt(key.(uint32))
		default:
			return ""
	}
}

//-----------------------------------------------------------------------------

// AddEntry sets a field/value entry for the supplied key in the supplied table
func AddEntry(table string, key interface{}, field string, value interface{}) error {
	var setstr string
	setstr = fmt.Sprintf("%s%s%s%s", generateTable(table), generateKey(key), generateField(field), generateValue(value))

	err := writeEntry(setstr)

	if err != nil {
		logger.LogWarn(logsrc, "AddEntry: Failed to write %s\n", setstr)
	}

	return err
}

//-----------------------------------------------------------------------------

// AddHostEntry sets a field/value entry for the supplied ip key in the host table
func AddHostEntry(key net.IP, field string, value interface{}) error {
	return AddEntry("host", key, field, value);
}

//-----------------------------------------------------------------------------

// AddUserEntry sets a field/value entry for the supplied string key in the user table
func AddUserEntry(key string, field string, value interface{}) error {
	return AddEntry("user", key, field, value);
}

//-----------------------------------------------------------------------------

// AddDeviceEntry sets a field/value entry for the supplied mac key in the device table
func AddDeviceEntry(key net.HardwareAddr, field string, value interface{}) error {
	return AddEntry("device", key, field, value);
}

//-----------------------------------------------------------------------------

// AddSessionEntry sets a field/value entry for the supplied int key in the session table
func AddSessionEntry(key uint32, field string, value interface{}) error {
	return AddEntry("session", key, field, value);
}

//-----------------------------------------------------------------------------

// DeleteDictionary removes a dictionary with the supplied key in the supplied table
func DeleteDictionary(table string, key interface{}) error {
	var setstr string
	setstr = fmt.Sprintf("%s%s", generateTable(table), generateKey(key))

	err := deleteEntry(setstr)

	if err != nil {
		logger.LogWarn(logsrc, "AddEntry ERROR: %s\n", err)
	}

	return err
}

//-----------------------------------------------------------------------------

// DeleteHost removes a dictionary from the host table
func DeleteHost(key net.IP) error {
	return DeleteDictionary("host", key);
}

//-----------------------------------------------------------------------------

// DeleteUser removes a dictionary from the user table
func DeleteUser(key string) error {
	return DeleteDictionary("user", key);
}

//-----------------------------------------------------------------------------

// DeleteDevice removes a dictionary from the device table
func DeleteDevice(key net.HardwareAddr) error {
	return DeleteDictionary("device", key);
}

//-----------------------------------------------------------------------------

// DeleteSession removes a dictionary from the session table
func DeleteSession(key uint32) error {
	return DeleteDictionary("session", key);
}

//-----------------------------------------------------------------------------

// GetDictionary gets all of the dictionary entries for the supplied key
func GetDictionary(table string, key interface{}) ([]Entry, error) {
	file, err := os.OpenFile(pathBase+"/read", os.O_RDWR, 0660)
	setstr := fmt.Sprintf("%s%s", generateTable(table), generateKey(key))

	if err != nil {
		logger.LogWarn(logsrc, "GetDictionary: Failed to open %s\n", pathBase+"/read")
		return nil, err
	}

	defer file.Close()

	readMutex.Lock()
	_, err = file.WriteString(setstr)

	if err != nil {
		logger.LogWarn(logsrc, "GetDictionary: Failed to write %s\n", setstr)
		return nil, err
	}

	file.Sync()

	var entries []Entry

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		entries = append(entries, parseEntry(scanner.Text()))
	}
	readMutex.Unlock()
	return entries, err
}

//-----------------------------------------------------------------------------

// GetEntry gets the dictionary entry for the specified table, key and field
func GetEntry(table string, key interface{}, field string) (Entry, error) {
	var entry Entry
	var found = false

	entries, err := GetDictionary(table, key)
	if err != nil {
		logger.LogWarn(logsrc, "GetEntry: Failed to get %s %s\n", formatTable(table), formatKey(key))
		return entry, err
	}

	for _, x := range entries {
		if 0 == strings.Compare(x.Field, field) {
			entry = x
			found = true
			break
		}
	}

	if found == false {
		err = fmt.Errorf("dict: GetEntry: %s not found in %s %s", formatField(field), formatTable(table), formatKey(key))
	}

	return entry, err
}

//-----------------------------------------------------------------------------

// GetHostEntry gets the dictionary entry from the host table with the specified key and field
func GetHostEntry(key net.IP, field string) (Entry, error) {
	return GetEntry("host", key, field);
}

//-----------------------------------------------------------------------------

// GetUserEntry gets the dictionary entry from the user table with the specified key and field
func GetUserEntry(key string, field string) (Entry, error) {
	return GetEntry("user", key, field);
}

//-----------------------------------------------------------------------------

// GetDeviceEntry gets the dictionary entry from the device table with the specified key and field
func GetDeviceEntry(key net.HardwareAddr, field string) (Entry, error) {
	return GetEntry("device", key, field);
}

//-----------------------------------------------------------------------------

// GetSessionEntry gets the dictionary entry from the session table with the specified key and field
func GetSessionEntry(key uint32, field string) (Entry, error) {
	return GetEntry("session", key, field);
}

//-----------------------------------------------------------------------------

// GetAllEntries gets all of entries for all known dictionaries
func GetAllEntries() ([]Entry, error) {
	file, err := os.OpenFile(pathBase+"/all", os.O_RDWR, 0660)

	if err != nil {
		logger.LogWarn(logsrc, "GetAll: Failed to open %s\n", pathBase+"/all")
		return nil, err
	}

	defer file.Close()

	var entries []Entry

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		entries = append(entries, parseEntry(scanner.Text()))
	}
	return entries, err
}

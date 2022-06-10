/*
Copyright 2019 Adevinta
*/

package config

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"

	"github.com/BurntSushi/toml"

	"github.com/adevinta/vulcan-check-sdk/internal/push/rest"
)

const (
	loggerLevelEnv     = "VULCAN_CHECK_LOG_LVL"
	loggerFormatterEnv = "VULCAN_CHECK_FMT"

	checkTargetEnv      = "VULCAN_CHECK_TARGET"
	checkAssetTypeEnv   = "VULCAN_CHECK_ASSET_TYPE"
	checkOptionsEnv     = "VULCAN_CHECK_OPTIONS"
	checkIDEnv          = "VULCAN_CHECK_ID"
	checkTypeNameEnv    = "VULCAN_CHECKTYPE_NAME"
	checkTypeVersionEnv = "VULCAN_CHECKTYPE_VERSION"

	commModeEnv      = "VULCAN_CHECK_COMM_MODE"
	pushAgentAddr    = "VULCAN_AGENT_ADDRESS"
	pushMsgBufferLen = "VULCAN_CHECK_MSG_BUFF_LEN"

	// Allows scanning private / reserved IP addresses.
	allowPrivateIPs = "VULCAN_ALLOW_PRIVATE_IPS"

	// CommModePull Defines the string representing pull communication for check.
	CommModePull = "pull"
	// CommModePush Defines the string representing push communication for check.
	CommModePush = "push"

	confFilePath = "local.toml"
)

// CheckConfig stores config information needed by a check.
type CheckConfig struct {
	Target           string `toml:"Target"`
	AssetType        string `toml:"AssetType"`
	Opts             string `toml:"Options"`
	CheckID          string `toml:"CheckID"`
	CheckTypeName    string `toml:"CheckTypeName"`
	CheckTypeVersion string `toml:"CheckTypeVersion"`
}

// LogConfig defines configuration params for logging.
type LogConfig struct {
	LogFmt   string `json:"log_fmt" toml:"LogFmt"`
	LogLevel string `json:"log_level" toml:"LogLevel"`
}

// Config holds all values regarding configuration.
type Config struct {
	Check           CheckConfig       `toml:"Check"`
	Log             LogConfig         `toml:"Log"`
	CommMode        string            `toml:"CommMode"`
	Push            rest.PusherConfig `toml:"Push"`
	AllowPrivateIPs *bool             `toml:"AllowPrivateIps"`
	RequiredVars    map[string]string `toml:"RequiredVars"`
}

type optionsLogConfig struct {
	Debug bool `json:"debug"`
}

// OverrideConfigFromOptions overrides config object with values setted in env vars.
func OverrideConfigFromOptions(c *Config) {
	if c.Check.Opts != "" {
		opts := &optionsLogConfig{}
		err := json.Unmarshal([]byte(c.Check.Opts), opts)
		if err == nil {
			// Only try to set the log config from opts if the options are valid json.
			if opts.Debug {
				c.Log.LogLevel = "debug"
			}
		}
	}
}

// OverrideConfigFromEnvVars overrides config object with values setted in env vars.
func OverrideConfigFromEnvVars(c *Config) error {
	overrideConfigLogEnvVars(c)
	overrideConfigCheckEnvVars(c)
	overrideCommConfigEnvVars(c)
	return overrideValidationConfigEnvVars(c)
}

func overrideValidationConfigEnvVars(c *Config) error {
	allow := os.Getenv(allowPrivateIPs)
	if allow == "" {
		return nil
	}

	b, err := strconv.ParseBool(allow)
	if err != nil {
		return fmt.Errorf("can not parse allow private IPs option from env var (%s=%s): %v", allowPrivateIPs, allow, err)
	}
	c.AllowPrivateIPs = &b
	return nil
}

func overrideCommConfigEnvVars(c *Config) {
	comMode := os.Getenv(commModeEnv)
	if comMode != "" {
		c.CommMode = comMode
	}
	// Set default comm to push by now.
	if c.CommMode == "" {
		c.CommMode = CommModePush
	}
	pushEndPoint := os.Getenv(pushAgentAddr)
	if pushEndPoint != "" {
		c.Push.AgentAddr = pushEndPoint
	}

	msgBuffLen := os.Getenv(pushMsgBufferLen)
	len, err := strconv.ParseInt(msgBuffLen, 0, 32)
	if err != nil {
		// NOTE: Review this, if env var is not a valid int maybe it's worth printing at least a warning but it implies finding way to log before
		// the log was set, kind of emergency log.
		len = 10
	}
	if msgBuffLen != "" {
		c.Push.BufferLen = int(len)
	}
}

func overrideConfigLogEnvVars(c *Config) {
	logLevel := os.Getenv(loggerLevelEnv)
	if logLevel != "" {
		c.Log.LogLevel = logLevel
	}
	logFmt := os.Getenv(loggerFormatterEnv)
	if logFmt != "" {
		c.Log.LogFmt = logFmt
	}
}

func overrideConfigCheckEnvVars(c *Config) {
	opts := os.Getenv(checkOptionsEnv)
	if opts != "" {
		c.Check.Opts = opts
	}
	target := os.Getenv(checkTargetEnv)
	if target != "" {
		c.Check.Target = target
	}
	assetType := os.Getenv(checkAssetTypeEnv)
	if assetType != "" {
		c.Check.AssetType = assetType
	}
	checkID := os.Getenv(checkIDEnv)
	if checkID != "" {
		c.Check.CheckID = checkID
	}
	checkTypeName := os.Getenv(checkTypeNameEnv)
	if checkTypeName != "" {
		c.Check.CheckTypeName = checkTypeName
	}
	checkTypeVer := os.Getenv(checkTypeVersionEnv)
	if checkTypeName != "" {
		c.Check.CheckTypeVersion = checkTypeVer
	}
}

// LoadConfigFromFile loads configuration file from a path.
func LoadConfigFromFile(filePath string) (*Config, error) {
	c := &Config{}
	configData, err := os.ReadFile(filePath) //nolint
	if err != nil {
		return c, err
	}
	if _, err := toml.Decode(string(configData), c); err != nil {
		return c, err
	}
	return c, nil
}

func fileExists(filePath string) (exists bool) {
	exists = true
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		exists = false
	}
	return
}

// BuildConfig builds a configuration struct by reading, if exists, the conf file
// and overriding the conf values from env vars.
func BuildConfig() (*Config, error) {
	c := &Config{}
	if fileExists(confFilePath) {
		fileConf, err := LoadConfigFromFile(confFilePath)
		if err != nil {
			return nil, err
		}
		c = fileConf
	}
	if err := OverrideConfigFromEnvVars(c); err != nil {
		return nil, err
	}

	OverrideConfigFromOptions(c)
	return c, nil
	// NOTE: what happens if there no config file and also no env vars setted?
}

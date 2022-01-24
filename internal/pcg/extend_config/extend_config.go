package extend_config

import (
	"fmt"
	"io/ioutil"
	"path/filepath"
	"strings"

	"github.com/lordtor/go-base-api/api"

	"github.com/imdario/mergo"
	base_config "github.com/lordtor/go-basic-config"
	logging "github.com/lordtor/go-logging"

	"gopkg.in/yaml.v3"
)

type C struct {
	base_config.ApplicationConfig `yaml:"app"`
	API                           api.ApiServerConfig `yaml:"api"`
}

func (conf *C) GetParamsFromYml(path string) error {
	if path == "" {
		if conf.ProfileName == "" {
			path, _ = filepath.Abs("./application.yml")
		} else {
			path, _ = filepath.Abs(fmt.Sprintf("./application-%s.yml", conf.ProfileName))
		}
	}
	logging.Log.Info("[EXT:GetParamsFromYml]:: Load file: ", path)
	yamlFile, err := ioutil.ReadFile(path)
	if err != nil {
		logging.Log.Fatal("[EXT:GetParamsFromYml]:: cannot open file: ", err)
		return err
	}
	err = yaml.Unmarshal(yamlFile, &conf)
	if err != nil {
		logging.Log.Fatal("[EXT:GetParamsFromYml]:: cannot unmarshal data: ", err)
		return err
	}
	err = mergo.MergeWithOverwrite(&C{}, conf)
	if err != nil {
		logging.Log.Fatal("[EXT:GetParamsFromYml]:: cannot Merge data: ", err)
		return err
	}
	return nil
}

func (conf *C) ReloadConfig() {
	logging.Log.Info("[EXT:ReloadConfig]:: Start func ReloadConfig")
	ConfServerURI := base_config.GetValueByNameFromEnv("OMNI_GLOBAL_SPRING_CLOUD_CONFIG_URI")
	AppName := base_config.GetValueByNameFromEnv("APP_NAME")
	ProfileName := base_config.GetValueByNameFromEnv("PROFILE_NAME")
	if ConfServerURI != "" {
		conf.ConfServerURI = ConfServerURI
	}
	if AppName != "" {
		conf.AppName = AppName
	}
	if ProfileName != "" {
		conf.ProfileName = ProfileName
	}
	err := conf.GetParamsFromYml("")
	if err != nil {
		logging.Log.Fatal(err)
	}
	if ProfileName != "develop" && conf.ConfServerURI != "" {
		logging.Log.Info("[EXT:ReloadConfig]:: Use config from cloud")
		conf.ParseCloudFile()

	} else {
		logging.Log.Error(conf)
		logging.Log.Error(ProfileName)
		logging.Log.Error(ConfServerURI)
	}

	secrets, file, err := conf.GetSecretsFromJson("")
	if err != nil {
		logging.Log.Error("[EXT:ReloadConfig]:: ", err)
	} else {
		logging.Log.Infof("[EXT:ReloadConfig]:: Use credential's from different file %v\n", file)
		conf.Secrets = secrets
		conf.ReloadPassword()
	}
	if conf.LogLevel == "" {
		conf.LogLevel = "Error"
	}
	logging.ChangeLogLevel(conf.LogLevel)
	logging.Log.Info(conf.LogLevel)
	if strings.ToLower(conf.LogLevel) == "debug" {
		conf.PrintConfigToLog()
	}
}
func (conf *C) ParseCloudFile() {
	cloudConfig := &C{}
	backupConfig := conf
	logging.Log.Info("[EXT:parseCloudFile]::", conf.AppName, conf.ProfileName)
	if conf.ConfServerURI == "" {
		logging.Log.Fatal("[EXT:parseCloudFile]:: ConfServerURI is empty")
	}
	rawBytes, err := base_config.FetchFileFromCloud(conf.AppName, conf.ProfileName, conf.ConfServerURI)
	if err != nil {
		logging.Log.Fatal("[EXT:parseCloudFile]:: FetchFileFromCloud: ", err)
	}
	if rawBytes != nil {
		err = yaml.Unmarshal(rawBytes, cloudConfig)
		if err != nil {
			logging.Log.Error(string(rawBytes))
			logging.Log.Fatal("[EXT:parseCloudFile]:: Unmarshal", err)
		}
		err := mergo.MergeWithOverwrite(conf, cloudConfig)
		if err != nil {
			logging.Log.Fatal(err)
		}
	}
	if conf.LogLevel != "" {
		conf.LogLevel = backupConfig.LogLevel
	}
	conf.ProfileName = backupConfig.ProfileName
	conf.ConfServerURI = backupConfig.ConfServerURI
}

// func (conf *C) ReloadPassword() {
// 	for k, v := range conf.Secrets {
// 		if v != "" {
// 			switch k {
// 			case "vault_password":
// 				conf.Camunda.Password = v
// 			case "rabbit_password":
// 				conf.Rabbit.Password = v
// 			default:
// 				for j, data := range conf.JenkinsSets {
// 					if strings.Contains(k, j) {
// 						data.Password = v
// 						conf.JenkinsSets[j] = data
// 					}
// 				}
// 			}
// 		}
// 	}
// }

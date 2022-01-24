// swagger:meta
// @termsOfService https://sample.url

// @contact.name API Support
// @contact.url https://jira.url
// @contact.email admin@mail.ru

// @license.name Apache 2.0
// @license.url http://www.apache.org/licenses/LICENSE-2.0.html

// _securityDefinitions.apikey ApiKeyAuth
// _in header
// _name Authorization

package main

import (
	"github.com/lordtor/go-vault/cmd/docs"

	"context"
	"fmt"

	ex "go-vault/internal/pkg/extend_config"

	"github.com/lordtor/go-base-api/api"

	trace "github.com/lordtor/go-trace-lib"
	"github.com/lordtor/go-vault/vault"

	logging "github.com/lordtor/go-logging"
	version "github.com/lordtor/go-version"
)

var (
	Log             = logging.Log
	Conf            = ex.C{}
	binVersion      = "0.1.1"
	aBuildNumber    = ""
	aBuildTimeStamp = ""
	aGitBranch      = ""
	aGitHash        = ""
)

func init() {
	logging.InitLog("")
	version.InitVersion(binVersion, aBuildNumber, aBuildTimeStamp, aGitBranch, aGitHash)
	Conf.ReloadConfig()
	Conf.API.App = Conf.AppName
	Conf.API.InitializeApiServerConfig(Conf.API, Conf)
	logging.ChangeLogLevel(Conf.LogLevel)
	logging.Log.Error(Conf)
}
func main() {
	ctx := context.Background()
	if Conf.API.Swagger {
		docs.SwaggerInfo.Title = fmt.Sprintf("Swagger  %s", Conf.AppName)
		docs.SwaggerInfo.Version = version.GetVersion().Version
		docs.SwaggerInfo.BasePath = fmt.Sprintf("/%s", Conf.AppName)
		docs.SwaggerInfo.Description = "Basic only internal methods!"
		docs.SwaggerInfo.Schemes = []string{Conf.API.Schema}
		hostAPI := ""
		if Conf.API.LocalSwagger {
			hostAPI = fmt.Sprintf("%s:%d", Conf.API.Host, Conf.API.ListenPort)
		} else {
			hostAPI = Conf.API.Host
		}
		docs.SwaggerInfo.Host = hostAPI
	}
	// Bootstrap tracer.
	prv, err := trace.NewProvider(trace.ProviderConfig{
		JaegerEndpoint: "",
		JaegerHost:     "localhost",
		JaegerPort:     "6831",
		ServiceName:    "client",
		ServiceVersion: "1.0.1",
		Environment:    "dev",
		Disabled:       false,
	})
	vaultConfig := vault.VaultConfig{Server: "http://localhost:8200",
		Token: "vault-root-token",
		User: vault.VaultUser{
			UserName:    "Vasya",
			Email:       "Vasya@mail.ru",
			GroupeNames: []string{"vault_devops_rw", "vault_team_devp-test"},
		}}

	vaultAPI := vault.API{}

	if err != nil {
		Log.Fatalln(err)
	}
	defer prv.Close(ctx)
	a := api.API{}
	a.Initialize(Conf.API, Conf)
	a.Mount(fmt.Sprintf("/%s/vault/", Conf.AppName), vaultAPI.Routes(vaultConfig))
	a.Run()
}

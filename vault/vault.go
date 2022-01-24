package vault

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/creasty/defaults"
	"github.com/gorilla/mux"
	"github.com/hashicorp/vault/api"
	auth "github.com/hashicorp/vault/api/auth/approle"
	common "github.com/lordtor/go-common-lib"
	logging "github.com/lordtor/go-logging"
	trace "github.com/lordtor/go-trace-lib"
	"go.opentelemetry.io/otel/attribute"
)

type VaultConfig struct {
	Token  string    `json:"-" yaml:"token"`
	Server string    `json:"server" yaml:"server"`
	User   VaultUser `json:"user,omitempty" yaml:"user"`
	Role   VaultRole `json:"role" yaml:"role"`
}
type VaultUser struct {
	GroupeNames []string `json:"grope_names" yaml:"grope_names"`
	UserName    string   `json:"user_name" yaml:"user_name"`
	Email       string   `json:"email" yaml:"email"`
}
type VaultRole struct {
	RoleNme              string   `default:"-" json:"role_name" yaml:"role_name"`
	AllowedPolicies      []string `default:"[\"default\", \"internal_lookup_revoke\", \"internal_root_list\"]" json:"allowed_policies" yaml:"allowed_policies"`
	TokenPeriod          string   `default:"28800" json:"token_period" yaml:"token_period"`
	Renewable            bool     `default:"false" json:"renewable" yaml:"renewable"`
	TokenExplicitMaxTtl  string   `default:"14400" json:"token_explicit_max_ttl" yaml:"token_explicit_max_ttl"`
	TokenType            string   `default:"service" json:"token_type" yaml:"token_type"`
	PathSuffix           string   `default:"-" json:"path_suffix" yaml:"path_suffix"`
	AllowedEntityAliases string   `default:"-" json:"allowed_entity_aliases" yaml:"allowed_entity_aliases"`
}

func (vr *VaultRole) Init() {
	err := defaults.Set(vr)
	if err != nil {
		Log.Error(err.Error())
	}
}

type Vault struct {
	Client *api.Client
	ctx    context.Context
	Conf   *VaultConfig
}

var (
	httpClient = &http.Client{
		Timeout: 10 * time.Second}
	Log = logging.Log
)

func (v Vault) New() *api.Client {
	_, span := trace.NewSpan(v.ctx, "Vault.New", nil)
	defer span.End()
	client, err := api.NewClient(&api.Config{Address: v.Conf.Server, HttpClient: httpClient})

	if err != nil {
		span.RecordError(err)
		span.SetStatus(1, "Error create new vault client")
		Log.Errorf(err.Error())
	}
	span.SetStatus(2, "Create new vault client")
	client.SetToken(v.Conf.Token)
	return client
}

func (v *Vault) GetAppRoles() ([]string, error) {
	_, span := trace.NewSpan(v.ctx, "Vault.GetAppRoles", nil)
	defer span.End()
	path := "/auth/token/roles/"
	span.SetAttributes(attribute.Key("Path").String(path))
	approles, err := v.Client.Logical().List(path)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(1, "Error get approles")
		Log.Errorf(err.Error())
		return nil, err
	}
	res, err := common.ListConvert(approles.Data["keys"])
	if err != nil {
		span.RecordError(err)
		span.SetStatus(1, "Error convert approles")
		Log.Errorf(err.Error())
		return nil, err
	}
	span.SetAttributes(attribute.Key("AppRoles").StringSlice(res))
	span.SetStatus(2, "Get approles")
	return res, nil

}
func (v *Vault) SetAppRole(roleName string) (bool, error) {
	_, span := trace.NewSpan(v.ctx, "Vault.SetAppRole", nil)
	defer span.End()
	path := fmt.Sprintf("/auth/token/roles/%s", roleName)
	span.SetAttributes(attribute.Key("Path").String(path))
	span.SetAttributes(attribute.Key("Role").String(roleName))
	// if err := defaults.Set(v.Conf.Role); err != nil {
	// 	Log.Error(err.Error())
	// 	span.RecordError(err)
	// 	span.SetStatus(1, "Vault.SetAppRole.Defaults")
	// 	return false, err
	// }
	v.Conf.Role.RoleNme = roleName
	v.Conf.Role.PathSuffix = v.Conf.User.Email
	v.Conf.Role.AllowedEntityAliases = v.Conf.User.Email
	data := map[string]interface{}{}
	data["role_name"] = roleName
	data["allowed_policies"] = append(v.Conf.Role.AllowedPolicies, roleName)
	data["token_period"] = v.Conf.Role.TokenPeriod
	data["renewable"] = v.Conf.Role.Renewable
	data["token_explicit_max_ttl"] = v.Conf.Role.TokenExplicitMaxTtl
	data["token_type"] = v.Conf.Role.TokenType
	data["path_suffix"] = v.Conf.User.Email
	data["allowed_entity_aliases"] = v.Conf.User.Email
	groupApprole, err := v.Client.Logical().Write(path, data)
	if err != nil {
		Log.Error(err.Error())
		span.RecordError(err)
		span.SetStatus(1, "Vault.SetAppRole.UpdateValue")
		return false, err
	}
	Log.Debug(groupApprole)
	span.SetStatus(2, "Update role params")
	return true, nil
}

func (v *Vault) GetAppRoleId(roleName string) (string, error) {
	_, span := trace.NewSpan(v.ctx, "Vault.GetAppRoleId", nil)
	defer span.End()
	path := fmt.Sprintf("/auth/approle/role/%s/role-id", roleName)
	span.SetAttributes(attribute.Key("Path").String(path))
	span.SetAttributes(attribute.Key("Role").String(roleName))
	role_id, err := v.Client.Logical().Read(path)
	if err != nil {
		Log.Error(err.Error())
		span.RecordError(err)
		span.SetStatus(1, "Vault.GetAppRoleId")
		return "", err
	}
	id := string(role_id.Data["role_id"].(string))
	span.SetAttributes(attribute.Key("RoleID").String(id))
	span.SetStatus(2, "Get role ID")
	return id, nil
}

func (v *Vault) GetAppRoleSecretId(roleName string, roleId string) (string, error) {
	_, span := trace.NewSpan(v.ctx, "Vault.GetAppRoleSecretId", nil)
	defer span.End()
	path := fmt.Sprintf("/auth/approle/role/%s/secret-id", roleName)
	span.SetAttributes(attribute.Key("Path").String(path))
	span.SetAttributes(attribute.Key("Role").String(roleName))
	span.SetAttributes(attribute.Key("UserName").String(v.Conf.User.UserName))
	span.SetAttributes(attribute.Key("Email").String(v.Conf.User.Email))
	data := map[string]interface{}{}
	data["metadata"] = fmt.Sprintf("{ \"group\": \"%s\",\"name\":\"%s\",\"mail\":\"%s\" }",
		roleName, v.Conf.User.UserName, v.Conf.User.Email)
	data["role_id"] = roleId
	secret_id, err := v.Client.Logical().Write(path, data)
	if err != nil {
		Log.Error(err.Error())
		span.RecordError(err)
		span.SetStatus(1, "Vault.GetAppRoleSecretId")
		return "", err
	}
	id := string(secret_id.Data["secret_id"].(string))
	span.SetAttributes(attribute.Key("SecretID").String(id))
	span.SetStatus(2, "Get secret ID")
	return id, nil
}

func (v *Vault) GetAppRoleToken(roleId string, secretId string) (string, error) {
	_, span := trace.NewSpan(v.ctx, "Vault.GetAppRoleToken", nil)
	defer span.End()
	span.SetAttributes(attribute.Key("RoleID").String(roleId))
	span.SetAttributes(attribute.Key("SecretID").String(secretId))
	span.SetAttributes(attribute.Key("UserName").String(v.Conf.User.UserName))
	span.SetAttributes(attribute.Key("Email").String(v.Conf.User.Email))
	secretID := &auth.SecretID{FromString: secretId}
	appRoleAuth, err := auth.NewAppRoleAuth(
		roleId,
		secretID,
	)
	if err != nil {
		if err != nil {
			Log.Errorf("Unable to initialize AppRole auth method: %w", err)
			span.RecordError(err)
			span.SetStatus(1, "Vault.GetAppRoleToken.NewAppRoleAuth: unable to initialize AppRole auth method")
			return "", err
		}
	}
	authInfo, err := v.Client.Auth().Login(context.TODO(), appRoleAuth)
	if err != nil {
		Log.Errorf("Unable to login to AppRole auth method: %w", err)
		span.RecordError(err)
		span.SetStatus(1, "Vault.GetAppRoleToken.Login: unable to login to AppRole auth method")
		return "", err
	}
	if authInfo == nil {
		Log.Error("No auth info was returned after login")
		span.RecordError(nil)
		span.SetStatus(1, "Vault.GetAppRoleToken.Login: no auth info was returned after login")
		return "", err
	}
	span.SetStatus(2, "Get role token")
	return authInfo.Auth.ClientToken, nil
}

func (v *Vault) GetValidRolesForUser() ([]string, error) {
	var validRoles []string
	_, span := trace.NewSpan(v.ctx, "Vault.GetValidRolesForUser", nil)
	defer span.End()
	roles, err := v.GetAppRoles()
	if err != nil {
		Log.Error(err.Error())
		span.RecordError(err)
		span.SetStatus(1, "Vault.GetValidRolesForUser.GetAppRoles")
		return nil, err
	}
	listRoles, err := common.ListConvert(roles)
	if err != nil {
		Log.Error(err.Error())
		span.RecordError(err)
		span.SetStatus(1, "Vault.GetValidRolesForUser.ListConvert")
		return nil, err
	}
	for groupId := range v.Conf.User.GroupeNames {
		if common.SliceContain(listRoles, v.Conf.User.GroupeNames[groupId]) {
			validRoles = append(validRoles, v.Conf.User.GroupeNames[groupId])
		}
	}
	span.SetAttributes(attribute.Key("ValidRoles").StringSlice(validRoles))
	span.SetStatus(2, "Get valid roles on vault by user")
	return validRoles, nil
}

var (
	DefaultCT = []string{"Content-Type", "application/json"}
)

type API struct {
	Client *Vault
}
type JSONResult struct {
	Code    int         `json:"code" `
	Message string      `json:"message,omitempty"`
	Data    interface{} `json:"data,omitempty"`
}

func (a *API) Routes(conf VaultConfig) *mux.Router {
	r := mux.NewRouter()
	vaultSubRoute := r.PathPrefix("/api/v1").Subrouter()
	vaultSubRoute.HandleFunc("/getAppRoles", a.getAppRoles(conf)).Methods(http.MethodGet)
	vaultSubRoute.HandleFunc("/getValidRolesForUser", a.getValidRolesForUser(conf)).Methods(http.MethodGet)
	vaultSubRoute.HandleFunc("/getAllAppRolesToken", a.getAllAppRolesToken(conf)).Methods(http.MethodGet)
	vaultSubRoute.HandleFunc("/getAppRoleToken", a.getAppRoleToken(conf)).Methods(http.MethodGet)
	return r
}

func (a *API) Resp(data *JSONResult, w http.ResponseWriter, ctx context.Context) {
	_, span := trace.NewSpan(ctx, "Resp", nil)
	defer span.End()
	w.Header().Set(DefaultCT[0], DefaultCT[1])
	resp, err := json.Marshal(data)
	if err != nil {
		Log.Error(err.Error())
		span.RecordError(err)
		span.SetStatus(1, data.Message)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(data.Code)
	span.SetAttributes(attribute.Key("Code").Int(data.Code))
	span.SetAttributes(attribute.Key("Message").String(data.Message))
	intE, err := w.Write(resp)
	if err != nil {
		Log.Error(err.Error())
		span.RecordError(err)
		span.SetStatus(1, data.Message)
		http.Error(w, err.Error(), intE)
		return
	}
	span.SetStatus(2, data.Message)

}

// getAppRoleToken godoc
// @Summary getAppRoleToken
// @Tags vault
// @Description vault method getAppRoleToken
// @Accept  json
// @Produce  json
// @Success 200 {object}  JSONResult "desc"
// @Failure 400,404 {object} JSONResult
// @Failure 500 {object} JSONResult
// @Router /vault/api/v1/getAppRoleToken [get]
func (a *API) getAppRoleToken(conf VaultConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		conf.User = VaultUser{
			UserName:    "Vasya",
			Email:       "Vasya@mail.ru",
			GroupeNames: []string{"vault_devops_rw", "vault_team_devp-test"},
		}
		Group := "vault_devops_rw"
		tokens := map[string]string{}
		conf.Role.Init()
		c, span := trace.NewSpan(r.Context(), "getAppRoleToken", nil)
		defer span.End()
		span.SetStatus(2, "getAppRoleToken")
		if Group == "" {
			err := errors.New("User group not set")
			Log.Error(err.Error())
			span.RecordError(err)
			span.SetStatus(1, err.Error())
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		} else if conf.User.UserName == "" {
			err := errors.New("User name not set")
			Log.Error(err.Error())
			span.RecordError(err)
			span.SetStatus(1, err.Error())
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		} else if conf.User.Email == "" {
			err := errors.New("User email not set")
			Log.Error(err.Error())
			span.RecordError(err)
			span.SetStatus(1, err.Error())
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		span.SetAttributes(attribute.Key("Username").String(conf.User.UserName))
		span.SetAttributes(attribute.Key("Email").String(conf.User.Email))
		span.SetAttributes(attribute.Key("Group").String(Group))
		v := Vault{ctx: c, Conf: &conf}
		v.Client = v.New()
		a.Client = &v
		validRoles, err := a.Client.GetValidRolesForUser()
		if err != nil {
			Log.Error(err.Error())
			span.RecordError(err)
			span.SetStatus(1, err.Error())
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if common.SliceContain(validRoles, Group) {
			a.Client.Client.SetToken(v.Conf.Token)
			t, err := a.GetSingleToken(c, Group)
			if err != nil {
				Log.Error(err.Error())
				span.RecordError(err)
				span.SetStatus(1, err.Error())
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			tokens[Group] = t
		} else {
			err := errors.New(fmt.Sprintf("User: %s not has group: %s", v.Conf.User.UserName, Group))
			Log.Error(err.Error())
			span.RecordError(err)
			span.SetStatus(1, err.Error())
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		respData := JSONResult{Code: http.StatusOK, Data: tokens, Message: ""}
		a.Resp(&respData, w, r.Context())
	}
}

// getAllAppRolesToken godoc
// @Summary getAllAppRolesToken
// @Tags vault
// @Description vault method getAllAppRolesToken
// @Accept  json
// @Produce  json
// @Success 200 {object}  JSONResult "desc"
// @Failure 400,404 {object} JSONResult
// @Failure 500 {object} JSONResult
// @Router /vault/api/v1/getAllAppRolesToken [get]
func (a *API) getAllAppRolesToken(conf VaultConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		conf.User = VaultUser{
			UserName:    "Vasya",
			Email:       "Vasya@mail.ru",
			GroupeNames: []string{"vault_devops_rw", "vault_team_devp-test"},
		}
		tokens := map[string]string{}
		conf.Role.Init()
		c, span := trace.NewSpan(r.Context(), "getAllAppRolesToken", nil)
		defer span.End()
		span.SetStatus(2, "getAllAppRolesToken")
		if len(conf.User.GroupeNames) <= 0 {
			err := errors.New("User group not set")
			Log.Error(err.Error())
			span.RecordError(err)
			span.SetStatus(1, err.Error())
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		} else if conf.User.UserName == "" {
			err := errors.New("User name not set")
			Log.Error(err.Error())
			span.RecordError(err)
			span.SetStatus(1, err.Error())
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		} else if conf.User.Email == "" {
			err := errors.New("User email not set")
			Log.Error(err.Error())
			span.RecordError(err)
			span.SetStatus(1, err.Error())
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		span.SetAttributes(attribute.Key("Username").String(conf.User.UserName))
		span.SetAttributes(attribute.Key("Email").String(conf.User.Email))
		span.SetAttributes(attribute.Key("Groupes").StringSlice(conf.User.GroupeNames))
		v := Vault{ctx: c, Conf: &conf}
		v.Client = v.New()
		a.Client = &v
		validRoles, err := a.Client.GetValidRolesForUser()
		if err != nil {
			Log.Error(err.Error())
			span.RecordError(err)
			span.SetStatus(1, err.Error())
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		for roleId := range validRoles {
			a.Client.Client.SetToken(v.Conf.Token)
			t, err := a.GetSingleToken(c, validRoles[roleId])
			if err != nil {
				Log.Error(err.Error())
				span.RecordError(err)
				span.SetStatus(1, err.Error())
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			tokens[validRoles[roleId]] = t
		}
		respData := JSONResult{Code: http.StatusOK, Data: tokens, Message: ""}
		a.Resp(&respData, w, r.Context())
	}
}

func (a *API) GetSingleToken(ctx context.Context, role string) (string, error) {
	_, span := trace.NewSpan(ctx, "GetSingleToken", nil)
	defer span.End()
	span.SetStatus(2, "GetSingleToken")
	_, err := a.Client.SetAppRole(role)
	if err != nil {
		Log.Error(err.Error())
		span.RecordError(err)
		span.SetStatus(1, err.Error())
		return "", err
	}
	appRoleId, err := a.Client.GetAppRoleId(role)
	if err != nil {
		Log.Error(err.Error())
		span.RecordError(err)
		span.SetStatus(1, err.Error())
		return "", err
	}
	span.SetAttributes(attribute.Key("RoleID").String(appRoleId))
	appRoleSecretId, err := a.Client.GetAppRoleSecretId(role, appRoleId)
	if err != nil {
		Log.Error(err.Error())
		span.RecordError(err)
		span.SetStatus(1, err.Error())
		return "", err
	}
	span.SetAttributes(attribute.Key("RoleSecretID").String(appRoleSecretId))
	Token, err := a.Client.GetAppRoleToken(appRoleId, appRoleSecretId)
	if err != nil {
		Log.Error(err.Error())
		span.RecordError(err)
		span.SetStatus(1, err.Error())
		return "", err
	}
	return Token, nil
}

// getValidRolesForUser godoc
// @Summary getValidRolesForUser
// @Tags vault
// @Description vault method getValidRolesForUser
// @Accept  json
// @Produce  json
// @Success 200 {object}  JSONResult "desc"
// @Failure 400,404 {object} JSONResult
// @Failure 500 {object} JSONResult
// @Router /vault/api/v1/getValidRolesForUser [get]
func (a *API) getValidRolesForUser(conf VaultConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		conf.User = VaultUser{
			UserName:    "Vasya",
			Email:       "Vasya@mail.ru",
			GroupeNames: []string{"vault_devops_rw"},
		}
		c, span := trace.NewSpan(r.Context(), "getValidRolesForUser", nil)
		defer span.End()
		span.SetStatus(2, "getValidRolesForUser")
		if len(conf.User.GroupeNames) <= 0 {
			err := errors.New("User group not set")
			Log.Error(err.Error())
			span.RecordError(err)
			span.SetStatus(1, err.Error())
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		span.SetAttributes(attribute.Key("UserGropes").StringSlice(conf.User.GroupeNames))
		v := Vault{ctx: c, Conf: &conf}
		v.Client = v.New()
		a.Client = &v
		t, err := a.Client.GetValidRolesForUser()
		if err != nil {
			Log.Error(err.Error())
			span.RecordError(err)
			span.SetStatus(1, err.Error())
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		respData := JSONResult{Code: http.StatusOK, Data: t, Message: ""}
		span.SetAttributes(attribute.Key("Data").StringSlice(t))
		a.Resp(&respData, w, r.Context())
	}
}

// getAppRoles godoc
// @Summary getAppRoles
// @Tags vault
// @Description vault method getAppRoles
// @Accept  json
// @Produce  json
// @Success 200 {object}  JSONResult "desc"
// @Failure 400,404 {object} JSONResult
// @Failure 500 {object} JSONResult
// @Router /vault/api/v1/getAppRoles [get]
func (a *API) getAppRoles(conf VaultConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		//ctx := context.Background()
		c, span := trace.NewSpan(r.Context(), "getAppRoles", nil)
		defer span.End()
		span.SetStatus(2, "getAppRoles")
		v := Vault{ctx: c, Conf: &conf}
		v.Client = v.New()
		a.Client = &v
		t, err := a.Client.GetAppRoles()
		if err != nil {
			Log.Error(err.Error())
			span.RecordError(err)
			span.SetStatus(1, err.Error())
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		respData := JSONResult{Code: http.StatusOK, Data: t, Message: ""}
		span.SetAttributes(attribute.Key("Data").StringSlice(t))
		a.Resp(&respData, w, r.Context())
	}
}

package cmd

import (
	"crypto/ed25519"
	sdkapi "github.com/ziro-os/ziro-os/sdk/api"

	"github.com/ziro-os/ziro-os/sdk/catalog"
	"github.com/ziro-os/ziro-os/sdk/schema"
)

// ziroctl's formats and validators live in the SDK (github.com/ziro-os/ziro-os/sdk), so plugin and
// app authors, catalog CI and API clients validate with exactly the code the host runs. These
// aliases keep ziroctl's own names.

type (
	ServiceDef     = schema.ServiceDef
	Resources      = schema.Resources
	ModuleCmd      = schema.ModuleCmd
	ModuleService  = schema.ModuleService
	ModuleFile     = schema.ModuleFile
	ModuleDir      = schema.ModuleDir
	ModuleArtifact = schema.ModuleArtifact
	ModuleManifest = schema.ModuleManifest
	Setting        = schema.Setting

	AppDef       = schema.AppDef
	AppVersion   = schema.AppVersion
	AppComponent = schema.AppComponent

	GatewayRoute      = schema.GatewayRoute
	GatewayUpstream   = schema.GatewayUpstream
	GatewayHealth     = schema.GatewayHealth
	GatewayRespond    = schema.GatewayRespond
	HeaderRules       = schema.HeaderRules
	GatewayACME       = schema.GatewayACME
	GatewayCert       = schema.GatewayCert
	GatewayConfig     = schema.GatewayConfig
	GatewayRouteState = schema.GatewayRouteState
	GatewayTarget     = schema.GatewayTarget

	APIMessage         = sdkapi.Message
	AppDeployRequest   = sdkapi.AppDeployRequest
	appCatalogInfo     = sdkapi.AppCatalogEntry
	appStatus          = sdkapi.AppStatus
	moduleInfo         = sdkapi.ModuleInfo
	NFSExport          = sdkapi.NFSExport
	NFSMount           = sdkapi.NFSMount
	NFSConfig          = sdkapi.NFSConfig
	NFSClient          = sdkapi.NFSClient
	GatewayStatus      = sdkapi.GatewayStatus
	GatewayRouteStatus = sdkapi.GatewayRouteStatus
	UpstreamHealth     = sdkapi.UpstreamHealth

	CatalogRepo  = catalog.Repo
	CatalogEntry = catalog.Entry
	CatalogIndex = catalog.Index
)

const (
	catalogMaxIndex = catalog.MaxIndex
	catalogMaxEntry = catalog.MaxEntry
)

var (
	validNameRe   = schema.NameRe
	placeholderRe = schema.PlaceholderRe
	settingNameRe = schema.SettingNameRe
	hostRe        = schema.HostRe
	pluginRoot    = schema.PluginRoot
)

func validName(name string) error                            { return schema.ValidName(name) }
func checkServicePaths(def *ServiceDef) error                { return schema.CheckServicePaths(def) }
func validateDataPaths(paths []string) error                 { return schema.ValidateDataPaths(paths) }
func validateRoute(r *GatewayRoute) error                    { return r.Validate() }
func validHost(h string) bool                                { return schema.ValidHost(h) }
func routeApps(r GatewayRoute) []string                      { return schema.RouteApps(r) }
func expand(s string, v map[string]string) (string, error)   { return schema.Expand(s, v) }
func validateSettings(defs []Setting) error                  { return schema.ValidateSettings(defs) }
func validSecretSpec(spec string) error                      { return schema.ValidSecretSpec(spec) }
func genSecret(spec string) (string, error)                  { return schema.GenSecret(spec) }
func parseManifest(b []byte) (ModuleManifest, error)         { return schema.ParseManifest(b) }
func parseAppDef(b []byte) (AppDef, error)                   { return schema.ParseAppDef(b) }
func ed25519Key(pemKey string) (ed25519.PublicKey, error)    { return catalog.Ed25519Key(pemKey) }
func safeEntryPath(p string) error                           { return catalog.SafeEntryPath(p) }
func parseSetFlags(sets []string) (map[string]string, error) { return schema.ParseSetFlags(sets) }

func resolveSettings(defs []Setting, prev, set map[string]string) (map[string]string, error) {
	return schema.ResolveSettings(defs, prev, set)
}

func verifyIndex(r CatalogRepo, raw, sig []byte) (*CatalogIndex, error) {
	return catalog.VerifyIndex(r, raw, sig, catalogNow())
}

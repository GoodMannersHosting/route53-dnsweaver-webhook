module github.com/goodmannershosting/route53-dnsweaver-webhook

// The patch version is deliberate. CI installs exactly this toolchain via
// setup-go's go-version-file, and the stdlib in 1.26.0 through 1.26.4 carries
// crypto/tls, crypto/x509 and net/http advisories that govulncheck reports as
// reachable from this code.
go 1.26.5

require (
	github.com/aws/aws-sdk-go-v2 v1.44.0
	github.com/aws/aws-sdk-go-v2/config v1.32.40
	github.com/aws/aws-sdk-go-v2/service/route53 v1.65.10
	github.com/go-chi/chi/v5 v5.3.2
	github.com/spf13/pflag v1.0.10
	github.com/spf13/viper v1.21.0
)

require (
	github.com/aws/aws-sdk-go-v2/credentials v1.19.39 // indirect
	github.com/aws/aws-sdk-go-v2/feature/ec2/imds v1.18.40 // indirect
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.4.40 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.7.40 // indirect
	github.com/aws/aws-sdk-go-v2/internal/v4a v1.4.41 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/accept-encoding v1.13.19 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/presigned-url v1.13.40 // indirect
	github.com/aws/aws-sdk-go-v2/service/signin v1.6.0 // indirect
	github.com/aws/aws-sdk-go-v2/service/sso v1.34.0 // indirect
	github.com/aws/aws-sdk-go-v2/service/ssooidc v1.39.0 // indirect
	github.com/aws/aws-sdk-go-v2/service/sts v1.46.0 // indirect
	github.com/aws/smithy-go v1.28.1 // indirect
	github.com/fsnotify/fsnotify v1.9.0 // indirect
	github.com/go-viper/mapstructure/v2 v2.4.0 // indirect
	github.com/pelletier/go-toml/v2 v2.2.4 // indirect
	github.com/sagikazarmark/locafero v0.11.0 // indirect
	github.com/sourcegraph/conc v0.3.1-0.20240121214520-5f936abd7ae8 // indirect
	github.com/spf13/afero v1.15.0 // indirect
	github.com/spf13/cast v1.10.0 // indirect
	github.com/subosito/gotenv v1.6.0 // indirect
	go.yaml.in/yaml/v3 v3.0.4 // indirect
	golang.org/x/sys v0.44.0 // indirect
	golang.org/x/text v0.39.0 // indirect
)

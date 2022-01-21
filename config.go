package tinybastion

type Config struct {
	DeviceName          string
	Port                int
	PersistentKeepalive int
	ExternalHostname    string
	CIDR                string
}

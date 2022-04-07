package secrets

type optionsStruct struct {
	vaultID    string
	vaultTitle string
	url        string
	token      string
}

// Options to pass into GetItem and LoadItem.
type Options func(*optionsStruct)

// WithVault changes the vault from the default vault (Dev) to uuid.
func WithVault(uuid string) Options {
	return func(o *optionsStruct) {
		o.vaultID = uuid
	}
}

// WithVaultTitle is equivalent to WithVault except it searches by title.
func WithVaultTitle(title string) Options {
	return func(o *optionsStruct) {
		o.vaultTitle = title
	}
}

// WithURL sets 1password connect api server url.
func WithURL(url string) Options {
	return func(o *optionsStruct) {
		o.url = url
	}
}

// WithToken sets 1password connect api token.
func WithToken(token string) Options {
	return func(o *optionsStruct) {
		o.token = token
	}
}

package secrets

type optionsStruct struct {
	vaultID    string
	vaultTitle string
	url        string
	token      string
}

type Options func(*optionsStruct)

func WithVault(uuid string) Options {
	return func(o *optionsStruct) {
		o.vaultID = uuid
	}
}

func WithVaultTitle(title string) Options {
	return func(o *optionsStruct) {
		o.vaultTitle = title
	}
}

func WithURL(url string) Options {
	return func(o *optionsStruct) {
		o.url = url
	}
}

func WithToken(token string) Options {
	return func(o *optionsStruct) {
		o.token = token
	}
}

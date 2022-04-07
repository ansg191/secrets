package secrets

import (
	"reflect"
	"strconv"

	"github.com/1Password/connect-sdk-go/connect"
	"github.com/1Password/connect-sdk-go/onepassword"
	"github.com/pkg/errors"
)

const defaultVault = "v3swqlej5igrjno7fh3zjynyey" // Dev Vault

func getOptions(opts []Options) optionsStruct {
	options := optionsStruct{
		vaultID:    defaultVault,
		vaultTitle: "",
		url:        "",
		token:      "",
	}
	for _, opt := range opts {
		opt(&options)
	}
	return options
}

func getClient(opts optionsStruct) (connect.Client, error) {
	if opts.url == "" || opts.token == "" {
		client, err := connect.NewClientFromEnvironment()
		if err != nil {
			return nil, errors.Wrap(err, "failed to get 1password tokens from environment")
		}
		return client, nil
	} else {
		return connect.NewClient(opts.url, opts.token), nil
	}
}

func getVaultFromTitle(client connect.Client, title string) (string, error) {
	vaults, err := client.GetVaultsByTitle(title)
	if err != nil {
		return "", errors.Wrap(err, "error getting vaults")
	}

	if len(vaults) == 0 {
		return "", errors.Errorf("no vault with title %s found", title)
	}

	return vaults[0].ID, nil
}

// GetItem gets a 1password item from the 1password connect api server. Options
// may be passed through the opts parameter.
func GetItem(itemName string, opts ...Options) (*onepassword.Item, error) {
	options := getOptions(opts)

	client, err := getClient(options)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get 1password client")
	}

	if options.vaultTitle != "" {
		options.vaultID, err = getVaultFromTitle(client, options.vaultTitle)
		if err != nil {
			return nil, err
		}
	}

	return client.GetItemByTitle(itemName, options.vaultID)
}

// UnmarshallItem unmarshalls item into `i`. `i` must be a pointer to a struct.
// The struct should contain exported fields of type int or string that contain
// the tag "opfield" with the name of the field to be put in the field.
func UnmarshallItem(item *onepassword.Item, i interface{}) error {
	configP := reflect.ValueOf(i)
	if configP.Kind() != reflect.Ptr {
		return errors.New("a pointer must be passed")
	}

	config := configP.Elem()
	if config.Kind() != reflect.Struct {
		return errors.New("a struct pointer must be passed")
	}

	t := config.Type()

	for j := 0; j < t.NumField(); j++ {
		value := config.Field(j)
		field := t.Field(j)
		tag := field.Tag.Get("opfield")

		if tag == "" {
			continue
		}

		if !value.CanSet() {
			return errors.New("cannot load config into private fields")
		}

		switch value.Kind() {
		case reflect.String:
			val := item.GetValue(tag)
			value.SetString(val)
		case reflect.Int:
			val := item.GetValue(tag)
			v, err := strconv.Atoi(val)
			if err != nil {
				return errors.Wrapf(err, "error wrapping %s to int for field %s", val, field.Name)
			}
			value.SetInt(int64(v))
		default:
			return errors.Errorf("unsupported type %q", value.Kind())
		}
	}

	return nil
}

// LoadItem loads an item and unmarshalls it into `i`. This is equivalent to
// calling GetItem followed by an UnmarshallItem into `i`.
func LoadItem(itemName string, i interface{}, opts ...Options) error {
	item, err := GetItem(itemName, opts...)
	if err != nil {
		return errors.Wrap(err, "error getting item from vault")
	}

	return UnmarshallItem(item, i)
}

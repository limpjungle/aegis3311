package masker

import "strings"

type fieldKind int

const (
	fkNone fieldKind = iota
	fkPerson
	fkDoc
)

// normKey — имя поля без регистра и разделителей `_ - . пробел` (userId → userid).
func normKey(k string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(k) {
		switch r {
		case '_', '-', '.', ' ':
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

var secretKeys = setOf("password", "passwd", "pwd", "pass", "secret", "clientsecret", "token", "accesstoken",
	"refreshtoken", "idtoken", "apikey", "xapikey", "apitoken", "authtoken", "privatekey", "secretkey", "accesskey",
	"awssecretaccesskey", "authorization", "proxyauthorization", "cookie", "setcookie", "credentials", "dsn",
	"connectionstring", "databaseurl", "signature", "sig", "xamzsignature", "xamzcredential",
	// ID сессии — bearer-креденшл: вырезается как секрет (решение 07.11.2026).
	"session", "sessionid", "sid")

var secretSuffixes = []string{"password", "secret", "token", "apikey", "privatekey"}

var kindKeys = map[string]fieldKind{}

func init() {
	// Идентификаторы (user_id, customer_id, order_id, login, username…) ПДн не считаются и не маскируются
	// (решение 07.11.2026); email или ФИО в их значениях находят строковые детекторы.
	for _, k := range []string{"email", "mail", "phone", "phonenumber", "telephone", "tel", "mobile", "msisdn", "fio", "fullname", "firstname", "lastname", "middlename", "patronymic"} {
		kindKeys[k] = fkPerson
	}
	for _, k := range []string{"inn", "snils", "passport", "passportnumber", "iban"} {
		kindKeys[k] = fkDoc
	}
}

func setOf(ss ...string) map[string]bool {
	m := make(map[string]bool, len(ss))
	for _, s := range ss {
		m[s] = true
	}
	return m
}

// isSecretKey — нормализованное имя поля относится к секретам (таблица или суффикс).
func isSecretKey(nk string) bool {
	if secretKeys[nk] {
		return true
	}
	for _, s := range secretSuffixes {
		if strings.HasSuffix(nk, s) {
			return true
		}
	}
	return false
}

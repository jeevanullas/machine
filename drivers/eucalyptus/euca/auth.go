package euca

type Auth struct {
	AccessKey, SecretKey, SessionToken string
}

func GetAuth(accessKey, secretKey, sessionToken string) Auth {
	return Auth{accessKey, secretKey, sessionToken}
}

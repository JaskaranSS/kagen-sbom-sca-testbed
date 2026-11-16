module github.com/kagen/testbed-go

go 1.16

require (
	github.com/gin-gonic/gin v1.6.0
	github.com/dgrijalva/jwt-go v3.2.0+incompatible
	golang.org/x/text v0.3.6
	golang.org/x/crypto v0.0.0-20200622213623-75b288015ac9
	gopkg.in/yaml.v2 v2.2.2
	github.com/gorilla/websocket v1.4.0
	github.com/old/logger v1.0.0
	github.com/go-playground/validator/v10 v10.2.0 // indirect
	golang.org/x/net v0.0.0-20200822124328-c89045814202 // indirect
)

require github.com/miekg/dns v1.0.14

replace github.com/old/logger => github.com/sirupsen/logrus v1.4.2

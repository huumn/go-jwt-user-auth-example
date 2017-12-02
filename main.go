package main

import (
    "log"
    "fmt"
    "time"
    "net/http"
    "crypto/rsa"
    "io/ioutil"
    "golang.org/x/crypto/bcrypt"
    "github.com/dgrijalva/jwt-go"
    "github.com/dgrijalva/jwt-go/request"
    "github.com/jinzhu/gorm"
    _ "github.com/jinzhu/gorm/dialects/sqlite"
)

const (
    jwtKey = "jwt.key"  // openssl genrsa -out jwt.key
    jwtPub  = "jwt.pub" // openssl rsa -in jwt.key -pubout > jwt.pub

    // openssl req -x509 -newkey rsa:4096 -keyout tls.key -out tls.cert -days 365 -nodes
    // also need to force OS to trust cert
    tlsKey = "tls.key"
    tlsCert = "tls.cert"
)

var (
    verifyKey  *rsa.PublicKey
    signKey    *rsa.PrivateKey
    db         *gorm.DB
    err        error
)

func init() {
    signBytes, err := ioutil.ReadFile(jwtKey)
    if err != nil {
        log.Fatal(err)
    }
    signKey, err = jwt.ParseRSAPrivateKeyFromPEM(signBytes)
    if err != nil {
        log.Fatal(err)
    }
    verifyBytes, err := ioutil.ReadFile(jwtPub)
    if err != nil {
        log.Fatal(err)
    }
    verifyKey, err = jwt.ParseRSAPublicKeyFromPEM(verifyBytes)
    if err != nil {
        log.Fatal(err)
    }
}

type UserClaims struct {
    jwt.StandardClaims
    Uid uint `json:"uid"`
}

type User struct {
  gorm.Model
  Username string `gorm:"unique_index;not null"`
  Password []byte `gorm:"not null"`
}

func httpErrorHandler(w http.ResponseWriter, e int) {
    w.WriteHeader(e)
    fmt.Fprintf(w, "%d HTTP Status: %s\n", e, http.StatusText(e))
}

func notFound(w http.ResponseWriter, r *http.Request) {
    httpErrorHandler(w, http.StatusNotFound)
}

func login(w http.ResponseWriter, r *http.Request) {
    if r.Method != "POST" {
        httpErrorHandler(w, http.StatusBadRequest)
        return
    }

    username := r.FormValue("username")
    password := r.FormValue("password")

    user := User{}
    if db.First(&user, &User{Username: username}).RecordNotFound() {
        // TODO: send something more informative to requester
        log.Println("User does not exist", username)
        httpErrorHandler(w, http.StatusBadRequest)
        return
    }

    err = bcrypt.CompareHashAndPassword(user.Password, []byte(password))
    if err != nil {
        // TODO: send something more informative to requester
        log.Println("Password doesn't match")
        httpErrorHandler(w, http.StatusBadRequest)
        return
    }

    log.Println("logging in user", user)
    tokenString, err := createToken(user.ID)
    if err != nil {
        httpErrorHandler(w, http.StatusInternalServerError)
        return
    }

    w.Header().Set("Content-Type", "application/jwt")
    w.WriteHeader(http.StatusOK)
    fmt.Fprintln(w, tokenString)
}

func signup(w http.ResponseWriter, r *http.Request) {
    if r.Method != "POST" {
        httpErrorHandler(w, http.StatusBadRequest)
        return
    }

    // TODO: validate username and password ... enforce all the way down to db
    username := r.FormValue("username")
    password := r.FormValue("password")

    if !db.First(&User{}, &User{Username: username}).RecordNotFound() {
        // TODO: send something more informative to requester
        log.Println("User already exists")
        httpErrorHandler(w, http.StatusBadRequest)
        return
    }

    passwordBytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
    if err != nil {
        httpErrorHandler(w, http.StatusInternalServerError)
        return
    }

    db.Create(&User{Username: username, Password: passwordBytes})

    login(w, r)
}

func createToken(userId uint) (string, error) {
    log.Println("creating token for user", userId)
    t := jwt.New(jwt.GetSigningMethod("RS256"))

    t.Claims = UserClaims{
        jwt.StandardClaims{
            // see http://tools.ietf.org/html/draft-ietf-oauth-json-web-token-20#section-4.1.4
            // 1 month from now
            ExpiresAt: time.Now().AddDate(0,1,0).Unix(),
        },
        userId,
    }

    log.Printf("generating token with claims %+v", t.Claims)

    return t.SignedString(signKey)
}

// TODO: smaller sliding sessions, each access of "restricted" generates a new/refreshed token
func restricted(w http.ResponseWriter, r *http.Request) {
    token, err := request.ParseFromRequestWithClaims(r, request.OAuth2Extractor, &UserClaims{}, func(token *jwt.Token) (interface{}, error) {
        // since we only use the one private key to sign the tokens,
        // we also only use its public counter part to verify
        return verifyKey, nil
    })

    if err != nil {
        httpErrorHandler(w, http.StatusUnauthorized)
        return
    }

    user := User{}
    if db.First(&user, token.Claims.(*UserClaims).Uid).RecordNotFound() {
        // TODO: send back something more informative, somehow we have a nonexistant user with a token
        httpErrorHandler(w, http.StatusInternalServerError)
        return
    }

    fmt.Fprintf(w, "Welcome to the restricted area, %s!", user.Username)
    return
}

func main() {
    db, err = gorm.Open("sqlite3", "test.db")
    if err != nil {
        log.Fatal("failed to connect database", err)
    }
    defer db.Close()

    db.LogMode(true)
    db.AutoMigrate(&User{})

    http.HandleFunc("/", notFound)
    http.HandleFunc("/v1/api/users", signup)
    http.HandleFunc("/v1/api/login", login)
    http.HandleFunc("/v1/api/restricted", restricted)
    log.Println("starting server on port 8000")
    log.Fatal(http.ListenAndServeTLS(":8000", tlsCert, tlsKey, nil))
}
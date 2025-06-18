package ssh

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/user"
	"path/filepath"
	"syscall"
	"time"

	"github.com/hurlebouc/sshor/config"
	"golang.org/x/crypto/ssh"
	"golang.org/x/term"
)

type Key struct{ v string }

var CURRENT_USER = Key{
	v: "CURRENT_USER",
}

func GetCurrentUser(ctx context.Context) string {
	return ctx.Value(CURRENT_USER).(string)
}

func readPassword(prompt string) string {
	print(prompt)
	bytePassword, err := term.ReadPassword(int(syscall.Stdin))
	println("")
	if err != nil {
		panic(err)
	}
	return string(bytePassword)
}

type keepassPwdCache struct {
	PasswordEnc string    `json:"password_enc"`
	ExpiresAt   time.Time `json:"expires_at"`
}

// Chemin du fichier temporaire pour le cache du mot de passe
func getKeepassPwdCachePath(path string) string {
	tmpDir := os.TempDir()
	hash := sha256.Sum256([]byte(path + os.Getenv("USER")))
	return filepath.Join(tmpDir, "sshor_keepass_"+base64.RawURLEncoding.EncodeToString(hash[:8])+".cache")
}

// Génère une clé de chiffrement à partir d'une info locale et d'un salt externe stocké dans un fichier
func getKeepassPwdKey() []byte {
	uid := os.Getenv("USER")
	if uid == "" {
		uid = os.Getenv("USERNAME")
	}
	// Lecture du salt depuis un fichier dédié
	configDir, err := os.UserConfigDir()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Erreur lors de la récupération du dossier de configuration utilisateur : %v\n", err)
		panic(err)
	}
	saltPath := filepath.Join(configDir, "sshor_keepass_salt.txt")
	data, err := ioutil.ReadFile(saltPath)
	if err != nil || len(data) != 44 { // base64 de 32 octets = 44 caractères
		fmt.Fprintf(os.Stderr, "Erreur : le fichier salt est manquant ou invalide (%s).\nVeuillez créer un fichier de 32 octets aléatoires encodés en base64 à cet emplacement : %s\n", err, saltPath)
		panic("Salt file missing or invalid")
	}
	salt := string(data)
	key := sha256.Sum256([]byte(uid + salt))
	return key[:]
}

// Chiffre le mot de passe
func encryptKeepassPwd(plain string) (string, error) {
	key := getKeepassPwdKey()
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	plaintext := []byte(plain)
	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize]
	copy(iv, key[:aes.BlockSize])
	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], plaintext)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// Déchiffre le mot de passe
func decryptKeepassPwd(enc string) (string, error) {
	key := getKeepassPwdKey()
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	ciphertext, err := base64.StdEncoding.DecodeString(enc)
	if err != nil {
		return "", err
	}
	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]
	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(ciphertext, ciphertext)
	return string(ciphertext), nil
}

// Stocke le mot de passe chiffré dans un fichier temporaire pour 60 minutes
func cacheKeepassPwd(path, pwd string) error {
	enc, err := encryptKeepassPwd(pwd)
	if err != nil {
		return err
	}
	cache := keepassPwdCache{
		PasswordEnc: enc,
		ExpiresAt:   time.Now().Add(60 * time.Minute),
	}
	data, err := json.Marshal(cache)
	if err != nil {
		return err
	}
	return ioutil.WriteFile(getKeepassPwdCachePath(path), data, 0600)
}

// Récupère le mot de passe depuis le cache si valide, sinon retourne ""
func getCachedKeepassPwd(path string) (string, bool) {
	cachePath := getKeepassPwdCachePath(path)
	data, err := ioutil.ReadFile(cachePath)
	if err != nil {
		return "", false
	}
	var cache keepassPwdCache
	if err := json.Unmarshal(data, &cache); err != nil {
		os.Remove(cachePath)
		return "", false
	}
	if time.Now().After(cache.ExpiresAt) {
		os.Remove(cachePath)
		return "", false
	}
	pwd, err := decryptKeepassPwd(cache.PasswordEnc)
	if err != nil {
		os.Remove(cachePath)
		return "", false
	}
	return pwd, true
}

func getPassword(user string, config config.Host, keepassPwdMap map[string]string) string {

	keepass := config.GetKeepass()
	if keepass != nil {
		path := keepass.Path
		id := keepass.Id
		// --- Ajout gestion cache local chiffré ---
		if pwd, ok := getCachedKeepassPwd(path); ok {
			return ReadKeepass(path, pwd, id, user)
		}
		pwd, present := keepassPwdMap[path]
		if !present {
			pwd = readPassword(fmt.Sprintf("Password for %s: ", path))
			keepassPwdMap[path] = pwd
		}
		// Stocke dans le cache local chiffré pour 60 minutes
		_ = cacheKeepassPwd(path, pwd)
		return ReadKeepass(path, pwd, id, user)
	}
	host, port := getHostPort(config)
	if host == nil {
		return readPassword(fmt.Sprintf("Password for %s ", user))
	} else {
		return readPassword(fmt.Sprintf("Password for %s@%s:%d: ", user, *host, port))
	}
}

func getAuthMethod(user string, config config.Host, keepassPwdMap map[string]string) ssh.AuthMethod {
	pwd := getPassword(user, config, keepassPwdMap)
	return ssh.Password(pwd)
}

type SshClient struct {
	Client     *ssh.Client
	ChangeUser *struct {
		login    string
		password string
	}
	Jump *SshClient
}

func (c SshClient) Close() {
	if c.Client != nil {
		c.Client.Close()
	}
	if c.Jump != nil {
		c.Jump.Close()
	}
}

func getUser(ctx context.Context, hostConfig config.Host) (string, context.Context) {
	if hostConfig.GetUser() != nil {
		user := *hostConfig.GetUser()
		newctx := context.WithValue(ctx, CURRENT_USER, user)
		return user, newctx
	}
	return GetCurrentUser(ctx), ctx
}

func newSshClientConfig(ctx context.Context, hostConfig config.Host, passwordFlag string, keepassPwdMap map[string]string) (*ssh.ClientConfig, context.Context) {
	user, newctx := getUser(ctx, hostConfig)
	var authMethod ssh.AuthMethod
	if passwordFlag != "" {
		authMethod = ssh.Password(passwordFlag)
	} else {
		authMethod = getAuthMethod(user, hostConfig, keepassPwdMap)
	}

	clientConfig := &ssh.ClientConfig{
		User: user,
		Auth: []ssh.AuthMethod{
			authMethod,
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}
	return clientConfig, newctx
}

func NewSshClient(ctx context.Context, hostConfig config.Host, passwordFlag string, keepassPwdMap map[string]string) (SshClient, context.Context) {
	var jumpClient *SshClient = nil
	if hostConfig.GetJump() != nil {
		jumpHost := *hostConfig.GetJump()
		jumpClients, nctx := NewSshClient(ctx, jumpHost, "", keepassPwdMap)
		jumpClient = &jumpClients
		ctx = nctx
	}
	if hostConfig.GetHost() == nil {
		login, ctx := getUser(ctx, hostConfig)
		password := getPassword(login, hostConfig, keepassPwdMap)
		return SshClient{
			Client: nil,
			Jump:   jumpClient,
			ChangeUser: &struct {
				login    string
				password string
			}{
				login:    login,
				password: password,
			},
		}, ctx
	}

	var longJumpSshClient *ssh.Client = nil
	if jumpClient != nil {
		longJumpSshClient = GetFirstNonNilSshClient(*jumpClient)
	}

	if longJumpSshClient != nil {
		conn, err := longJumpSshClient.Dial("tcp", fmt.Sprintf("%s:%d", *hostConfig.GetHost(), hostConfig.GetPortOrDefault(22)))
		if err != nil {
			panic(err)
		}
		clientConfig, ctx := newSshClientConfig(ctx, hostConfig, passwordFlag, keepassPwdMap)
		ncc, chans, reqs, err := ssh.NewClientConn(conn, *hostConfig.GetHost(), clientConfig)
		if err != nil {
			panic(err)
		}
		sClient := ssh.NewClient(ncc, chans, reqs)
		return SshClient{
			Client:     sClient,
			ChangeUser: nil,
			Jump:       jumpClient,
		}, ctx
	} else {
		clientConfig, ctx := newSshClientConfig(ctx, hostConfig, passwordFlag, keepassPwdMap)
		// Connect to ssh server
		conn, err := ssh.Dial("tcp", fmt.Sprintf("%s:%d", *hostConfig.GetHost(), hostConfig.GetPortOrDefault(22)), clientConfig)
		if err != nil {
			panic(err)
		}
		return SshClient{
			Client:     conn,
			ChangeUser: nil,
			Jump:       jumpClient,
		}, ctx
	}
}

func GetFirstNonNilSshClient(jumpClient SshClient) *ssh.Client {
	if jumpClient.Client != nil || jumpClient.Jump == nil {
		return jumpClient.Client
	}
	return GetFirstNonNilSshClient(*jumpClient.Jump)
}

func getHostPort(config config.Host) (*string, uint16) {
	if config.Host != nil {
		if config.Port == nil {
			return config.Host, 22
		} else {
			return config.Host, *config.Port
		}
	}
	if config.Jump != nil {
		return getHostPort(*config.Jump)
	}
	return nil, 22
}

func InitContext() context.Context {
	currentUser, err := user.Current()
	if err != nil {
		panic(err)
	}
	return context.WithValue(context.Background(), CURRENT_USER, currentUser.Username)
}

func InitKeepassPwdMap(hostConfig config.Host, keepassPwdFlag string) map[string]string {
	keepassPwdMap := map[string]string{}
	if hostConfig.GetKeepass() != nil && keepassPwdFlag != "" {
		keepassPwdMap[hostConfig.GetKeepass().Path] = keepassPwdFlag
	}
	return keepassPwdMap
}

type Options struct {
	Verbose bool
}

func getSshClient(hostConf config.Host, passwordFlag, keepassPwdFlag string) *ssh.Client {
	keepassPwdMap := InitKeepassPwdMap(hostConf, keepassPwdFlag)
	ctx := InitContext()
	sshClient, _ := NewSshClient(ctx, hostConf, passwordFlag, keepassPwdMap)
	if sshClient.Client == nil {
		log.Panicln("Cannot change user of proxied connection")
	}
	return sshClient.Client
}
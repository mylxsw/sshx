package sshx

import (
	"context"
	"crypto/md5"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

type Client interface {
	SendFile(destFilepath string, srcFilepath string, override bool, consistencyCheck bool) (written int64, err error)
	Command(ctx context.Context, cmd string, opts ...SessionOption) ([]byte, error)
	Handle(handler Handler) error
}

type Handler func(sub Client) error

// Credential Command 连接配置
type Credential struct {
	User                 string
	Password             string
	PrivateKeyPath       string
	PrivateKeyPassphrase string
}

// buildSSHClientConfig 创建 Command 连接配置
func (sc Credential) buildSSHClientConfig() (*ssh.ClientConfig, error) {
	conf := ssh.ClientConfig{
		User:            sc.User,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	if sc.Password != "" {
		conf.Auth = append(conf.Auth, ssh.Password(sc.Password))
	} else if sc.PrivateKeyPath != "" {
		pk, err := sc.getPrivateKey(sc.PrivateKeyPath, sc.PrivateKeyPassphrase)
		if err != nil {
			return nil, err
		}
		conf.Auth = append(conf.Auth, pk)
	} else {
		// if occur error "Failed to open SSH_AUTH_SOCK: dial unix: missing address",
		// execute command: eval `ssh-agent`,and enter passphrase
		conn, err := net.Dial("unix", os.Getenv("SSH_AUTH_SOCK"))
		if err != nil {
			return nil, fmt.Errorf("failed to open SSH_AUTH_SOCK: %w", err)
		}

		agentClient := agent.NewClient(conn)
		// Use a callback rather than PublicKeys so we only consult the
		// agent once the remote server wants it.
		conf.Auth = append(conf.Auth, ssh.PublicKeysCallback(agentClient.Signers))
	}

	return &conf, nil
}

// Get the private key for current user
func (sc Credential) getPrivateKey(privateKeyPath string, privateKeyPassphrase string) (ssh.AuthMethod, error) {
	if !fileExist(privateKeyPath) {
		privateKeyPath = filepath.Join(os.Getenv("HOME"), ".ssh/id_rsa")
	}

	key, err := ioutil.ReadFile(privateKeyPath)
	if err != nil {
		return nil, fmt.Errorf("unable to parse private key: %v", err)
	}

	var signer ssh.Signer
	if privateKeyPassphrase != "" {
		signer, err = ssh.ParsePrivateKeyWithPassphrase(key, []byte(privateKeyPassphrase))
	} else {
		signer, err = ssh.ParsePrivateKey(key)
	}
	if err != nil {
		return nil, fmt.Errorf("parse private key failed: %v", err)
	}

	return ssh.PublicKeys(signer), nil
}

func fileExist(path string) bool {
	_, err := os.Stat(path)
	if err != nil && os.IsNotExist(err) {
		return false
	}

	return true
}

// ErrRemoteFileExisted 远程服务器已经存在该文件
var ErrRemoteFileExisted = errors.New("remote file already exist")

// ErrSessionCanceled 会话因为上下文对象的取消而被取消
var ErrSessionCanceled = errors.New("session canceled because context canceled")

// ErrFileFingerNotMatch 文件指纹不匹配
var ErrFileFingerNotMatch = errors.New("file finger not match")

type sshClient struct {
	host      string
	conf      *ssh.ClientConfig
	md5sumBin string
	logger    Logger
}

// Option 用于设置连接配置
type Option func(server *sshClient) error

// SetEstablishTimeout 设置 ssh 连接建立超时时间
func SetEstablishTimeout(timeout time.Duration) Option {
	return func(server *sshClient) error {
		server.conf.Timeout = timeout
		return nil
	}
}

// SetMd5sumBinInServer 设置远端用于检查文件校验值的命令
func SetMd5sumBinInServer(cmd string) Option {
	return func(server *sshClient) error {
		server.md5sumBin = cmd
		return nil
	}
}

// SetLogger 设置日志实现
func SetLogger(logger Logger) Option {
	return func(server *sshClient) error {
		server.logger = logger
		return nil
	}
}

// NewClient 创建一个 sshClient 对象
func NewClient(serverAddr string, credential Credential, opts ...Option) (Client, error) {
	sshConf, err := credential.buildSSHClientConfig()
	if err != nil {
		return nil, err
	}

	server := &sshClient{host: serverAddr, conf: sshConf}
	for _, opt := range opts {
		if err := opt(server); err != nil {
			return nil, err
		}
	}

	if server.md5sumBin == "" {
		server.md5sumBin = "/usr/bin/md5sum"
	}
	if server.logger == nil {
		server.logger = DefaultLogger{}
	}

	return server, nil
}

func (s *sshClient) transferFile(client *ssh.Client, dest string, src string, override bool, checkConsistency bool) (written int64, err error) {
	sftpClient, err := sftp.NewClient(client)
	if err != nil {
		return 0, fmt.Errorf("creates SFTP client failed: %w", err)
	}
	defer sftpClient.Close()

	if !override && s.remoteFileExist(sftpClient, dest) {
		if checkConsistency {
			matched, err := s.checkFileConsistency(src, dest)
			if err != nil {
				return 0, fmt.Errorf("check local & remote file (existed) consistency failed: %w", err)
			}

			if !matched {
				return 0, ErrFileFingerNotMatch
			}
		}

		return 0, ErrRemoteFileExisted
	}

	destTmp := filepath.Join(filepath.Dir(dest), fmt.Sprintf("%s.tmp_%d", filepath.Base(dest), time.Now().UnixNano()))
	written, err = s.transferToRemoteTmp(sftpClient, destTmp, src)
	if err != nil {
		return 0, fmt.Errorf("transfer local file to remote failed: %w", err)
	}
	defer sftpClient.Remove(destTmp)

	if err := sftpClient.PosixRename(destTmp, dest); err != nil {
		return 0, err
	}

	if checkConsistency {
		matched, err := s.checkFileConsistency(src, dest)
		if err != nil {
			return 0, fmt.Errorf("check local & remote file consistency failed: %w", err)
		}

		if !matched {
			return 0, ErrFileFingerNotMatch
		}
	}

	return written, nil
}

// SendFile 将本地文件传输到远程服务器
func (s *sshClient) SendFile(dest string, src string, override bool, consistencyCheck bool) (written int64, err error) {
	conn, err := ssh.Dial("tcp", s.host, s.conf)
	if err != nil {
		return 0, fmt.Errorf("can not establish a connection to %s: %w", s.host, err)
	}
	defer conn.Close()

	return s.transferFile(conn, dest, src, override, consistencyCheck)
}

func (s *sshClient) checkFileConsistency(src string, remoteDest string) (bool, error) {
	localFinger := md5file(src)
	ctx, cancel := context.WithTimeout(context.TODO(), 10*time.Second)
	defer cancel()

	remoteFingerBytes, err := s.Command(ctx, fmt.Sprintf("%s %s", s.md5sumBin, remoteDest))
	if err != nil {
		return false, fmt.Errorf("check file md5sum for remote file failed: %w", err)
	}

	remoteFinger := strings.SplitN(strings.TrimSpace(string(remoteFingerBytes)), " ", 2)
	if s.logger.DebugEnabled() {
		s.logger.Debugf("consistency: local=%s, remote=%s, matched=%v", localFinger, remoteFinger[0], strings.EqualFold(localFinger, remoteFinger[0]))
	}

	return strings.EqualFold(localFinger, remoteFinger[0]), nil
}

func (s *sshClient) transferToRemoteTmp(client *sftp.Client, destTmp string, src string) (int64, error) {
	srcFile, err := os.Open(src)
	if err != nil {
		return 0, fmt.Errorf("open local file %s failed: %w", src, err)
	}
	defer srcFile.Close()

	destFile, err := client.Create(destTmp)
	if err != nil {
		return 0, fmt.Errorf("create remote temp file %s failed: %w", destTmp, err)
	}
	defer destFile.Close()

	return io.Copy(destFile, srcFile)
}

func (s *sshClient) remoteFileExist(client *sftp.Client, path string) bool {
	_, err := client.Stat(path)
	if err != nil && os.IsNotExist(err) {
		return false
	}

	return true
}

type SessionOption func(session *ssh.Session) error

func RequestPty(width int, height int, terminalModes ...ssh.TerminalModes) SessionOption {
	if len(terminalModes) == 0 {
		terminalModes = []ssh.TerminalModes{
			{
				ssh.ECHO:          0,
				ssh.TTY_OP_ISPEED: 14400,
				ssh.TTY_OP_OSPEED: 14400,
			},
		}
	}

	return func(session *ssh.Session) error {
		return session.RequestPty("xterm", width, height, terminalModes[0])
	}
}

func (s *sshClient) ssh(ctx context.Context, client *ssh.Client, cmd string, opts ...SessionOption) ([]byte, error) {
	session, err := client.NewSession()
	if err != nil {
		return nil, fmt.Errorf("create session failed: %w", err)
	}
	defer session.Close()

	for _, opt := range opts {
		if err := opt(session); err != nil {
			return nil, err
		}
	}

	var resp []byte
	stopped := make(chan interface{}, 0)
	go func() {
		resp, err = session.CombinedOutput(cmd)
		stopped <- struct{}{}
	}()

	select {
	case <-ctx.Done():
		_ = session.Signal(ssh.SIGKILL)
		err = ErrSessionCanceled
	case <-stopped:
	}

	return resp, err
}

// Command 在远程服务器上执行命令
func (s *sshClient) Command(ctx context.Context, cmd string, opts ...SessionOption) ([]byte, error) {
	client, err := ssh.Dial("tcp", s.host, s.conf)
	if err != nil {
		return nil, err
	}
	defer client.Close()

	return s.ssh(ctx, client, cmd, opts...)
}

// Handle 在同一个连接中执行 handler 中的所有操作
func (s *sshClient) Handle(handler Handler) error {
	conn, err := ssh.Dial("tcp", s.host, s.conf)
	if err != nil {
		return err
	}
	defer conn.Close()

	return handler(&subClient{
		client: s,
		conn:   conn,
	})
}

type subClient struct {
	client *sshClient
	conn   *ssh.Client
}

func (sc *subClient) SendFile(destFilepath string, srcFilepath string, override bool, consistencyCheck bool) (written int64, err error) {
	return sc.client.transferFile(sc.conn, destFilepath, srcFilepath, override, consistencyCheck)
}

func (sc *subClient) Command(ctx context.Context, cmd string, opts ...SessionOption) ([]byte, error) {
	return sc.client.ssh(ctx, sc.conn, cmd, opts...)
}

func (sc *subClient) Handle(handler Handler) error {
	return handler(sc)
}

func md5file(filename string) string {
	file, _ := ioutil.ReadFile(filename)
	return fmt.Sprintf("%x", md5.Sum(file))
}

package sshx

import (
	"bytes"
	"context"
	"crypto/md5"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"math/rand"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/kr/fs"
	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

type Client interface {
	ReceiveFile(dest string, src string, override bool, consistencyCheck bool) (written int64, err error)
	ReceiveFileOverride(destFilepath string, srcFilepath string) (written int64, err error)
	ReadFile(src string) ([]byte, error)

	SendFile(destFilepath string, srcFilepath string, override bool, consistencyCheck bool) (written int64, err error)
	SendFileOverride(destFilepath string, srcFilepath string) (written int64, err error)

	WriteFile(destFilepath string, dataReader io.Reader, override bool) (written int64, err error)
	WriteFileOverride(destFilepath string, dataReader io.Reader) (written int64, err error)

	Command(ctx context.Context, cmd string, opts ...SessionOption) ([]byte, error)
	Handle(handler Handler) error
}

type EnhanceClient interface {
	ReceiveFile(dest string, src string, override bool, consistencyCheck bool) (written int64, err error)
	ReceiveFileOverride(destFilepath string, srcFilepath string) (written int64, err error)
	ReadFile(src string) ([]byte, error)

	SendFile(destFilepath string, srcFilepath string, override bool, consistencyCheck bool) (written int64, err error)
	SendFileOverride(destFilepath string, srcFilepath string) (written int64, err error)

	WriteFile(destFilepath string, dataReader io.Reader, override bool) (written int64, err error)
	WriteFileOverride(destFilepath string, dataReader io.Reader) (written int64, err error)

	SendDirectory(destDirectory string, srcDirectory string) error
	SendFiles(destDirectory string, srcFiles ...string) error
	TempWriteFile(dataReader io.Reader, fn func(tempFilepath string) error) error
	TempSendFile(srcFilepath string, fn func(tempFilepath string) error) error

	Command(ctx context.Context, cmd string, opts ...SessionOption) ([]byte, error)

	Create(path string) (*sftp.File, error)
	Walk(root string) *fs.Walker
	ReadDir(p string) ([]os.FileInfo, error)
	Stat(p string) (os.FileInfo, error)
	Lstat(p string) (os.FileInfo, error)
	ReadLink(p string) (string, error)
	Link(oldname, newname string) error
	Symlink(oldname, newname string) error
	Chtimes(path string, atime time.Time, mtime time.Time) error
	Chown(path string, uid, gid int) error
	Chmod(path string, mode os.FileMode) error
	Truncate(path string, size int64) error
	Open(path string) (*sftp.File, error)
	OpenFile(path string, f int) (*sftp.File, error)
	StatVFS(path string) (*sftp.StatVFS, error)
	Join(elem ...string) string
	Remove(path string) error
	RemoveDirectory(path string) error
	Rename(oldname, newname string) error
	PosixRename(oldname, newname string) error
	Getwd() (string, error)
	Mkdir(path string) error
	MkdirAll(path string) error
	Glob(pattern string) (matches []string, err error)
}

type Handler func(sub EnhanceClient) error

// Credential Command 连接配置
// 优先级： Password > PrivateKey > PrivateKeyPath
type Credential struct {
	User                 string
	Password             string
	PrivateKey           string
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
	} else if sc.PrivateKey != "" {
		pk, err := sc.parsePrivateKey(sc.PrivateKey)
		if err != nil {
			return nil, err
		}

		conf.Auth = append(conf.Auth, pk)
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

// parsePrivateKey parse a private key from input
func (sc Credential) parsePrivateKey(privateKey string) (ssh.AuthMethod, error) {
	signer, err := ssh.ParsePrivateKey([]byte(privateKey))
	if err != nil {
		return nil, fmt.Errorf("parse private key failed: %v", err)
	}

	return ssh.PublicKeys(signer), nil
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

// ErrLocalFileExisted 本地已经存在该文件
var ErrLocalFileExisted = errors.New("local file already exist")

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

func (s *sshClient) readFile(sftpClient *sftp.Client, src string) ([]byte, error) {
	srcFile, err := sftpClient.Open(src)
	if err != nil {
		return nil, err
	}
	defer srcFile.Close()

	buf := bytes.NewBuffer(nil)
	if _, err := io.Copy(buf, srcFile); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

func (s *sshClient) writeFile(sftpClient *sftp.Client, dest string, dataReader io.Reader, override bool) (written int64, err error) {
	if !override && s.remoteFileExist(sftpClient, dest) {
		return 0, ErrRemoteFileExisted
	}

	destTmp := s.generateTempFilename(dest)
	written, err = s.writeToRemoteTmp(sftpClient, destTmp, dataReader)
	if err != nil {
		return 0, fmt.Errorf("transfer local file to remote failed: %w", err)
	}
	defer sftpClient.Remove(destTmp)

	if err := sftpClient.PosixRename(destTmp, dest); err != nil {
		return 0, err
	}

	return written, nil
}

func (s *sshClient) generateTempFilename(dest string) string {
	return filepath.Join(filepath.Dir(dest), fmt.Sprintf(".sshx_tmp_%x%s", md5.Sum([]byte(fmt.Sprintf("%s-%d", filepath.Base(dest), time.Now().UnixNano()))), filepath.Ext(dest)))
}

func (s *sshClient) transferFileFromRemote(sftpClient *sftp.Client, dest string, src string, override bool, checkConsistency bool) (written int64, err error) {
	if !override && fileExist(dest) {
		if checkConsistency {
			matched, err := s.checkFileConsistency(dest, src)
			if err != nil {
				return 0, fmt.Errorf("check local & remote file (existed) consistency failed: %w", err)
			}

			if !matched {
				return 0, ErrFileFingerNotMatch
			}
		}

		return 0, ErrLocalFileExisted
	}

	destTmp := s.generateTempFilename(dest)
	written, err = s.transferToLocalTmp(sftpClient, destTmp, src)
	if err != nil {
		return 0, fmt.Errorf("transfer remote file to local failed: %w", err)
	}
	defer os.Remove(destTmp)

	if err := os.Rename(destTmp, dest); err != nil {
		return 0, err
	}

	if checkConsistency {
		matched, err := s.checkFileConsistency(dest, src)
		if err != nil {
			return 0, fmt.Errorf("check local & remote file consistency failed: %w", err)
		}

		if !matched {
			return 0, ErrFileFingerNotMatch
		}
	}

	return written, nil
}

func (s *sshClient) transferFile(sftpClient *sftp.Client, dest string, src string, override bool, checkConsistency bool) (written int64, err error) {
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

	destTmp := s.generateTempFilename(dest)
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

// ReadFile read a file from remote server
func (s *sshClient) ReadFile(src string) ([]byte, error) {
	conn, err := ssh.Dial("tcp", s.host, s.conf)
	if err != nil {
		return nil, fmt.Errorf("can not establish a connection to %s: %w", s.host, err)
	}
	defer conn.Close()

	sftpClient, err := sftp.NewClient(conn)
	if err != nil {
		return nil, fmt.Errorf("creates SFTP client failed: %w", err)
	}
	defer sftpClient.Close()

	return s.readFile(sftpClient, src)
}

func (s *sshClient) WriteFileOverride(dest string, dataReader io.Reader) (written int64, err error) {
	return s.WriteFile(dest, dataReader, true)
}

func (s *sshClient) WriteFile(dest string, dataReader io.Reader, override bool) (written int64, err error) {
	conn, err := ssh.Dial("tcp", s.host, s.conf)
	if err != nil {
		return 0, fmt.Errorf("can not establish a connection to %s: %w", s.host, err)
	}
	defer conn.Close()

	sftpClient, err := sftp.NewClient(conn)
	if err != nil {
		return 0, fmt.Errorf("creates SFTP client failed: %w", err)
	}
	defer sftpClient.Close()

	return s.writeFile(sftpClient, dest, dataReader, override)
}

func (s *sshClient) SendFileOverride(dest string, src string) (written int64, err error) {
	return s.SendFile(dest, src, true, false)
}

func (s *sshClient) ReceiveFileOverride(dest string, src string) (written int64, err error) {
	return s.ReceiveFile(dest, src, true, false)
}

// ReceiveFile 从远程服务器接收文件
func (s *sshClient) ReceiveFile(dest string, src string, override bool, consistencyCheck bool) (written int64, err error) {
	conn, err := ssh.Dial("tcp", s.host, s.conf)
	if err != nil {
		return 0, fmt.Errorf("can not establish a connection to %s: %w", s.host, err)
	}
	defer conn.Close()

	sftpClient, err := sftp.NewClient(conn)
	if err != nil {
		return 0, fmt.Errorf("creates SFTP client failed: %w", err)
	}
	defer sftpClient.Close()

	return s.transferFileFromRemote(sftpClient, dest, src, override, consistencyCheck)
}

// SendFile 将本地文件传输到远程服务器
func (s *sshClient) SendFile(dest string, src string, override bool, consistencyCheck bool) (written int64, err error) {
	conn, err := ssh.Dial("tcp", s.host, s.conf)
	if err != nil {
		return 0, fmt.Errorf("can not establish a connection to %s: %w", s.host, err)
	}
	defer conn.Close()

	sftpClient, err := sftp.NewClient(conn)
	if err != nil {
		return 0, fmt.Errorf("creates SFTP client failed: %w", err)
	}
	defer sftpClient.Close()

	return s.transferFile(sftpClient, dest, src, override, consistencyCheck)
}

// Command 在远程服务器上执行命令
func (s *sshClient) Command(ctx context.Context, cmd string, opts ...SessionOption) ([]byte, error) {
	client, err := ssh.Dial("tcp", s.host, s.conf)
	if err != nil {
		return nil, fmt.Errorf("can not establish a connection to %s: %w", s.host, err)
	}
	defer client.Close()

	return s.ssh(ctx, client, cmd, opts...)
}

// Handle 在同一个连接中执行 handler 中的所有操作
func (s *sshClient) Handle(handler Handler) error {
	conn, err := ssh.Dial("tcp", s.host, s.conf)
	if err != nil {
		return fmt.Errorf("can not establish a connection to %s: %w", s.host, err)
	}
	defer conn.Close()

	sftpClient, err := sftp.NewClient(conn)
	if err != nil {
		return fmt.Errorf("creates SFTP client failed: %w", err)
	}
	defer sftpClient.Close()

	return handler(&subClient{
		client:     s,
		sftpClient: sftpClient,
		conn:       conn,
	})
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

func (s *sshClient) writeToRemoteTmp(client *sftp.Client, destTmp string, dataReader io.Reader) (int64, error) {
	destFile, err := client.Create(destTmp)
	if err != nil {
		return 0, fmt.Errorf("create remote temp file %s failed: %w", destTmp, err)
	}
	defer destFile.Close()

	return io.Copy(destFile, dataReader)
}

func (s *sshClient) writeToLocalTmp(destTmp string, dataReader io.Reader) (int64, error) {
	destFile, err := os.Create(destTmp)
	if err != nil {
		return 0, fmt.Errorf("create loacal temp file %s failed: %w", destTmp, err)
	}
	defer destFile.Close()

	return io.Copy(destFile, dataReader)
}

func (s *sshClient) transferToLocalTmp(client *sftp.Client, destTmp string, src string) (int64, error) {
	srcFile, err := client.Open(src)
	if err != nil {
		return 0, fmt.Errorf("open remote file %s failed: %w", src, err)
	}
	defer srcFile.Close()

	return s.writeToLocalTmp(destTmp, srcFile)
}

func (s *sshClient) transferToRemoteTmp(client *sftp.Client, destTmp string, src string) (int64, error) {
	srcFile, err := os.Open(src)
	if err != nil {
		return 0, fmt.Errorf("open local file %s failed: %w", src, err)
	}
	defer srcFile.Close()

	return s.writeToRemoteTmp(client, destTmp, srcFile)
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

type subClient struct {
	client     *sshClient
	sftpClient *sftp.Client
	conn       *ssh.Client
}

func (sc *subClient) Create(path string) (*sftp.File, error) {
	return sc.sftpClient.Create(path)
}

func (sc *subClient) Walk(root string) *fs.Walker {
	return sc.sftpClient.Walk(root)
}

func (sc *subClient) ReadDir(p string) ([]os.FileInfo, error) {
	return sc.sftpClient.ReadDir(p)
}

func (sc *subClient) Stat(p string) (os.FileInfo, error) {
	return sc.sftpClient.Stat(p)
}

func (sc *subClient) Lstat(p string) (os.FileInfo, error) {
	return sc.sftpClient.Lstat(p)
}

func (sc *subClient) ReadLink(p string) (string, error) {
	return sc.sftpClient.ReadLink(p)
}

func (sc *subClient) Link(oldname, newname string) error {
	return sc.sftpClient.Link(oldname, newname)
}

func (sc *subClient) Symlink(oldname, newname string) error {
	return sc.sftpClient.Symlink(oldname, newname)
}

func (sc *subClient) Chtimes(path string, atime time.Time, mtime time.Time) error {
	return sc.sftpClient.Chtimes(path, atime, mtime)
}

func (sc *subClient) Chown(path string, uid, gid int) error {
	return sc.sftpClient.Chown(path, uid, gid)
}

func (sc *subClient) Chmod(path string, mode os.FileMode) error {
	return sc.sftpClient.Chmod(path, mode)
}

func (sc *subClient) Truncate(path string, size int64) error {
	return sc.sftpClient.Truncate(path, size)
}

func (sc *subClient) Open(path string) (*sftp.File, error) {
	return sc.sftpClient.Open(path)
}

func (sc *subClient) OpenFile(path string, f int) (*sftp.File, error) {
	return sc.sftpClient.OpenFile(path, f)
}

func (sc *subClient) StatVFS(path string) (*sftp.StatVFS, error) {
	return sc.sftpClient.StatVFS(path)
}

func (sc *subClient) Join(elem ...string) string {
	return sc.sftpClient.Join(elem...)
}

func (sc *subClient) Remove(path string) error {
	return sc.sftpClient.Remove(path)
}

func (sc *subClient) RemoveDirectory(path string) error {
	return sc.sftpClient.RemoveDirectory(path)
}

func (sc *subClient) Rename(oldname, newname string) error {
	return sc.sftpClient.Rename(oldname, newname)
}

func (sc *subClient) PosixRename(oldname, newname string) error {
	return sc.sftpClient.PosixRename(oldname, newname)
}

func (sc *subClient) Getwd() (string, error) {
	return sc.sftpClient.Getwd()
}

func (sc *subClient) Mkdir(path string) error {
	return sc.sftpClient.Mkdir(path)
}

func (sc *subClient) MkdirAll(path string) error {
	return sc.sftpClient.MkdirAll(path)
}

func (sc *subClient) Glob(pattern string) (matches []string, err error) {
	return sc.sftpClient.Glob(pattern)
}

func (sc *subClient) ReadFile(src string) ([]byte, error) {
	return sc.client.readFile(sc.sftpClient, src)
}

func (sc *subClient) ReceiveFile(dest string, src string, override bool, consistencyCheck bool) (written int64, err error) {
	return sc.client.transferFileFromRemote(sc.sftpClient, dest, src, override, consistencyCheck)
}

func (sc *subClient) SendFile(destFilepath string, srcFilepath string, override bool, consistencyCheck bool) (written int64, err error) {
	return sc.client.transferFile(sc.sftpClient, destFilepath, srcFilepath, override, consistencyCheck)
}

func (sc *subClient) WriteFile(destFilepath string, dataReader io.Reader, override bool) (written int64, err error) {
	return sc.client.writeFile(sc.sftpClient, destFilepath, dataReader, override)
}

func (sc *subClient) WriteFileOverride(destFilepath string, dataReader io.Reader) (written int64, err error) {
	return sc.WriteFile(destFilepath, dataReader, true)
}

func (sc *subClient) SendFiles(destDirectory string, srcFiles ...string) error {
	if err := sc.MkdirAll(destDirectory); err != nil {
		return err
	}

	for _, src := range srcFiles {
		if _, err := sc.SendFile(filepath.Join(destDirectory, filepath.Base(src)), src, true, false); err != nil {
			return err
		}
	}

	return nil
}

func (sc *subClient) SendDirectory(destDirectory string, srcDirectory string) error {
	if err := sc.MkdirAll(destDirectory); err != nil {
		return err
	}

	return filepath.Walk(srcDirectory, func(path string, info os.FileInfo, err error) error {
		relPath, err := filepath.Rel(srcDirectory, path)
		if err != nil {
			return err
		}

		targetPath := filepath.Join(destDirectory, relPath)
		if info.IsDir() {
			if err := sc.MkdirAll(targetPath); err != nil {
				return err
			}

			return nil
		}

		if !sc.client.remoteFileExist(sc.sftpClient, filepath.Dir(targetPath)) {
			if err := sc.MkdirAll(filepath.Dir(targetPath)); err != nil {
				return err
			}
		}

		_, err = sc.SendFileOverride(targetPath, path)
		return err
	})
}

func (sc *subClient) ReceiveFileOverride(destFilepath string, srcFilepath string) (written int64, err error) {
	return sc.ReceiveFile(destFilepath, srcFilepath, true, false)
}

func (sc *subClient) SendFileOverride(destFilepath string, srcFilepath string) (written int64, err error) {
	return sc.SendFile(destFilepath, srcFilepath, true, false)
}

func (sc *subClient) TempWriteFile(dataReader io.Reader, fn func(tempFilepath string) error) error {
	tempFilepath := sc.client.generateTempFilename(fmt.Sprintf("%d-%f.tmp", time.Now().Nanosecond(), rand.Float64()*10000))
	_, err := sc.WriteFileOverride(tempFilepath, dataReader)
	if err != nil {
		return err
	}
	defer sc.sftpClient.Remove(tempFilepath)

	return fn(tempFilepath)
}

func (sc *subClient) TempSendFile(srcFilepath string, fn func(tempFilepath string) error) error {
	srcFile, err := os.Open(srcFilepath)
	if err != nil {
		return err
	}

	return sc.TempWriteFile(srcFile, fn)
}

func (sc *subClient) Command(ctx context.Context, cmd string, opts ...SessionOption) ([]byte, error) {
	return sc.client.ssh(ctx, sc.conn, cmd, opts...)
}

func md5file(filename string) string {
	file, _ := ioutil.ReadFile(filename)
	return fmt.Sprintf("%x", md5.Sum(file))
}

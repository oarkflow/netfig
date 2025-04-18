package netconf

import (
	"bytes"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"encoding/xml"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

const (
	msgSeperator     = "]]>]]>"
	msgSeperator_v11 = "\n##\n"
)

var DefaultCapabilities = []string{
	"urn:ietf:params:netconf:base:1.0",
	"urn:ietf:params:netconf:base:1.1",
}

type HelloMessage struct {
	XMLName      xml.Name `xml:"urn:ietf:params:xml:ns:netconf:base:1.0 hello"`
	Capabilities []string `xml:"capabilities>capability"`
	SessionID    int      `xml:"session-id,omitempty"`
}

type Transport interface {
	Send([]byte) error
	Receive() ([]byte, error)
	Close() error
	ReceiveHello() (*HelloMessage, error)
	SendHello(*HelloMessage) error
	SetVersion(version string)
}

type transportBasicIO struct {
	io.ReadWriteCloser
	//new add
	version string
}

func (t *transportBasicIO) SetVersion(version string) {
	t.version = version
}

func (t *transportBasicIO) Send(data []byte) error {
	var seperator []byte
	var dataInfo []byte
	//headlen := 0
	if t.version == "v1.1" {
		seperator = append(seperator, []byte(msgSeperator_v11)...)
	} else {
		seperator = append(seperator, []byte(msgSeperator)...)
	}

	if t.version == "v1.1" {
		header := fmt.Sprintf("\n#%d\n", len(string(data)))
		dataInfo = append(dataInfo, header...)
	}
	dataInfo = append(dataInfo, data...)
	dataInfo = append(dataInfo, seperator...)
	_, err := t.Write(dataInfo)

	return err
}

func (t *transportBasicIO) Receive() ([]byte, error) {
	var seperator []byte
	if t.version == "v1.1" {
		seperator = append(seperator, []byte(msgSeperator_v11)...)
	} else {
		seperator = append(seperator, []byte(msgSeperator)...)
	}
	return t.WaitForBytes([]byte(seperator))
}

func (t *transportBasicIO) SendHello(hello *HelloMessage) error {
	val, err := xml.Marshal(hello)
	if err != nil {
		return err
	}

	header := []byte(xml.Header)
	val = append(header, val...)
	err = t.Send(val)
	return err
}

func (t *transportBasicIO) ReceiveHello() (*HelloMessage, error) {
	hello := new(HelloMessage)
	val, err := t.Receive()
	if err != nil {
		return hello, err
	}
	err = xml.Unmarshal(val, hello)
	return hello, err
}

func (t *transportBasicIO) Writeln(b []byte) (int, error) {
	t.Write(b)
	t.Write([]byte("\n"))
	return 0, nil
}

func (t *transportBasicIO) WaitForFunc(f func([]byte) (int, error)) ([]byte, error) {
	var out bytes.Buffer
	buf := make([]byte, 8192)
	pos := 0
	for {
		n, err := t.Read(buf[pos : pos+(len(buf)/2)])
		if err != nil {
			if err != io.EOF {
				return nil, err
			}
			break
		}
		if n > 0 {
			end, err := f(buf[0 : pos+n])
			if err != nil {
				return nil, err
			}
			if end > -1 {
				out.Write(buf[0:end])
				return out.Bytes(), nil
			}
			if pos > 0 {
				out.Write(buf[0:pos])
				copy(buf, buf[pos:pos+n])
			}
			pos = n
		}
	}
	return nil, fmt.Errorf("WaitForFunc failed")
}

func (t *transportBasicIO) WaitForBytes(b []byte) ([]byte, error) {
	return t.WaitForFunc(func(buf []byte) (int, error) {
		return bytes.Index(buf, b), nil
	})
}

func (t *transportBasicIO) WaitForString(s string) (string, error) {
	out, err := t.WaitForBytes([]byte(s))
	if out != nil {
		return string(out), err
	}
	return "", err
}

func (t *transportBasicIO) WaitForRegexp(re *regexp.Regexp) ([]byte, [][]byte, error) {
	var matches [][]byte
	out, err := t.WaitForFunc(func(buf []byte) (int, error) {
		loc := re.FindSubmatchIndex(buf)
		if loc != nil {
			for i := 2; i < len(loc); i += 2 {
				matches = append(matches, buf[loc[i]:loc[i+1]])
			}
			return loc[1], nil
		}
		return -1, nil
	})
	return out, matches, err
}

type ReadWriteCloser struct {
	io.Reader
	io.WriteCloser
}

func NewReadWriteCloser(r io.Reader, w io.WriteCloser) *ReadWriteCloser {
	return &ReadWriteCloser{r, w}
}

type Session struct {
	Transport          Transport
	SessionID          int
	ServerCapabilities []string
	ErrOnWarning       bool
}

func (s *Session) Close() error {
	return s.Transport.Close()
}

func (s *Session) Exec(methods ...RPCMethod) (*RPCReply, error) {
	rpc := NewRPCMessage(methods)
	request, err := xml.Marshal(rpc)
	if err != nil {
		return nil, err
	}
	header := []byte(xml.Header)
	request = append(header, request...)
	err = s.Transport.Send(request)
	if err != nil {
		return nil, err
	}
	rawXML, err := s.Transport.Receive()
	if err != nil {
		return nil, err
	}
	reply, err := newRPCReply(rawXML, s.ErrOnWarning, rpc.MessageID)
	if err != nil {
		return nil, err
	}
	return reply, nil
}

func NewSession(t Transport) *Session {
	s := new(Session)
	s.Transport = t
	serverHello, _ := t.ReceiveHello()
	s.SessionID = serverHello.SessionID
	s.ServerCapabilities = serverHello.Capabilities
	t.SendHello(&HelloMessage{Capabilities: DefaultCapabilities})
	t.SetVersion("v1.0")
	for _, capability := range s.ServerCapabilities {
		if strings.Contains(capability, "urn:ietf:params:netconf:base:1.1") {
			t.SetVersion("v1.1")
			break
		}
	}
	return s
}

const (
	editConfigXml = `<edit-config>
<target><%s/></target>
<default-operation>merge</default-operation>
<error-option>rollback-on-error</error-option>
<config>%s</config>
</edit-config>`
)

type RPCMessage struct {
	MessageID string
	Methods   []RPCMethod
}

func NewRPCMessage(methods []RPCMethod) *RPCMessage {
	return &RPCMessage{
		MessageID: msgID(),
		Methods:   methods,
	}
}

func (m *RPCMessage) MarshalXML(e *xml.Encoder, start xml.StartElement) error {
	var buf bytes.Buffer
	for _, method := range m.Methods {
		buf.WriteString(method.MarshalMethod())
	}
	data := struct {
		MessageID string `xml:"message-id,attr"`
		Xmlns     string `xml:"xmlns,attr"`
		Methods   []byte `xml:",innerxml"`
	}{
		m.MessageID,
		"urn:ietf:params:xml:ns:netconf:base:1.0",
		buf.Bytes(),
	}
	start.Name.Local = "rpc"
	return e.EncodeElement(data, start)
}

type RPCReply struct {
	XMLName   xml.Name   `xml:"rpc-reply"`
	Errors    []RPCError `xml:"rpc-error,omitempty"`
	Data      string     `xml:",innerxml"`
	Ok        bool       `xml:",omitempty"`
	RawReply  string     `xml:"-"`
	MessageID string     `xml:"-"`
}

func newRPCReply(rawXML []byte, ErrOnWarning bool, messageID string) (*RPCReply, error) {
	reply := &RPCReply{}
	reply.RawReply = string(rawXML)
	if err := xml.Unmarshal(rawXML, reply); err != nil {
		return nil, err
	}
	reply.MessageID = messageID
	if reply.Errors != nil {
		for _, rpcErr := range reply.Errors {
			if rpcErr.Severity == "error" || ErrOnWarning {
				return reply, &rpcErr
			}
		}
	}
	return reply, nil
}

type RPCError struct {
	Type     string `xml:"error-type"`
	Tag      string `xml:"error-tag"`
	Severity string `xml:"error-severity"`
	Path     string `xml:"error-path"`
	Message  string `xml:"error-message"`
	Info     string `xml:",innerxml"`
}

func (re *RPCError) Error() string {
	return fmt.Sprintf("netconf rpc [%s] '%s'", re.Severity, re.Message)
}

type RPCMethod interface {
	MarshalMethod() string
}

type RawMethod string

func (r RawMethod) MarshalMethod() string {
	return string(r)
}

func MethodLock(target string) RawMethod {
	return RawMethod(fmt.Sprintf("<lock><target><%s/></target></lock>", target))
}

func MethodUnlock(target string) RawMethod {
	return RawMethod(fmt.Sprintf("<unlock><target><%s/></target></unlock>", target))
}

func MethodGetConfig(source string) RawMethod {
	return RawMethod(fmt.Sprintf("<get-config><source><%s/></source></get-config>", source))
}

func MethodGet(filterType string, dataXml string) RawMethod {
	return RawMethod(fmt.Sprintf("<get><filter type=\"%s\">%s</filter></get>", filterType, dataXml))
}

func MethodEditConfig(database string, dataXml string) RawMethod {
	return RawMethod(fmt.Sprintf(editConfigXml, database, dataXml))
}

var msgID = uuid

func uuid() string {
	b := make([]byte, 16)
	io.ReadFull(rand.Reader, b)
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}

type TransportJunos struct {
	transportBasicIO
	cmd *exec.Cmd
}

func (t *TransportJunos) Close() error {
	if t.cmd != nil {
		t.ReadWriteCloser.Close()
	}
	return nil
}

func (t *TransportJunos) Open() error {
	var err error
	t.cmd = exec.Command("xml-mode", "netconf", "need-trailer")
	w, err := t.cmd.StdinPipe()
	if err != nil {
		return err
	}
	r, err := t.cmd.StdoutPipe()
	if err != nil {
		return err
	}
	t.ReadWriteCloser = NewReadWriteCloser(r, w)
	return t.cmd.Start()
}

func DialJunos() (*Session, error) {
	var t TransportJunos
	err := t.Open()
	if err != nil {
		return nil, err
	}
	return NewSession(&t), nil
}

const (
	sshDefaultPort      = 830
	sshNetconfSubsystem = "netconf"
)

type TransportSSH struct {
	transportBasicIO
	sshClient  *ssh.Client
	sshSession *ssh.Session
}

func (t *TransportSSH) Close() error {
	if t == nil {
		return nil
	}
	if t.sshSession != nil {
		if err := t.sshSession.Close(); err != nil {
			t.sshClient.Close()
			return err
		}
	}
	if t.sshClient != nil {
		return t.sshClient.Close()
	}
	return fmt.Errorf("No connection to close")
}

func (t *TransportSSH) Dial(target string, config *ssh.ClientConfig) error {
	if !strings.Contains(target, ":") {
		target = fmt.Sprintf("%s:%d", target, sshDefaultPort)
	}
	var err error
	t.sshClient, err = ssh.Dial("tcp", target, config)
	if err != nil {
		return err
	}
	err = t.setupSession()
	return err
}

func (t *TransportSSH) setupSession() error {
	var err error
	t.sshSession, err = t.sshClient.NewSession()
	if err != nil {
		return err
	}
	writer, err := t.sshSession.StdinPipe()
	if err != nil {
		return err
	}
	reader, err := t.sshSession.StdoutPipe()
	if err != nil {
		return err
	}
	t.ReadWriteCloser = NewReadWriteCloser(reader, writer)
	return t.sshSession.RequestSubsystem(sshNetconfSubsystem)
}

func NewSSHSession(conn net.Conn, config *ssh.ClientConfig) (*Session, error) {
	t, err := connToTransport(conn, config)
	if err != nil {
		return nil, err
	}
	return NewSession(t), nil
}

func DialSSH(target string, config *ssh.ClientConfig) (*Session, error) {
	var t TransportSSH
	err := t.Dial(target, config)
	if err != nil {
		t.Close()
		return nil, err
	}
	return NewSession(&t), nil
}

func DialSSHTimeout(target string, config *ssh.ClientConfig, timeout time.Duration) (*Session, error) {
	bareConn, err := net.DialTimeout("tcp", target, timeout)
	if err != nil {
		return nil, err
	}
	conn := &deadlineConn{Conn: bareConn, timeout: timeout}
	t, err := connToTransport(conn, config)
	if err != nil {
		if t != nil {
			t.Close()
		}
		return nil, err
	}
	go func() {
		ticker := time.NewTicker(timeout / 2)
		defer ticker.Stop()
		for range ticker.C {
			_, _, err := t.sshClient.Conn.SendRequest("KEEP_ALIVE", true, nil)
			if err != nil {
				return
			}
		}
	}()
	return NewSession(t), nil
}

func SSHConfigPassword(user string, pass string) *ssh.ClientConfig {
	return &ssh.ClientConfig{
		User: user,
		Auth: []ssh.AuthMethod{
			ssh.Password(pass),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}
}

func SSHConfigPubKeyFile(user string, file string, passphrase string) (*ssh.ClientConfig, error) {
	buf, err := ioutil.ReadFile(file)
	if err != nil {
		return nil, err
	}
	block, rest := pem.Decode(buf)
	if len(rest) > 0 {
		return nil, fmt.Errorf("pem: unable to decode file %s", file)
	}
	if x509.IsEncryptedPEMBlock(block) {
		b, err := x509.DecryptPEMBlock(block, []byte(passphrase))
		if err != nil {
			return nil, err
		}
		buf = pem.EncodeToMemory(&pem.Block{
			Type:  block.Type,
			Bytes: b,
		})
	}
	key, err := ssh.ParsePrivateKey(buf)
	if err != nil {
		return nil, err
	}
	return &ssh.ClientConfig{
		User: user,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(key),
		},
	}, nil

}

func SSHConfigPubKeyAgent(user string) (*ssh.ClientConfig, error) {
	c, err := net.Dial("unix", os.Getenv("SSH_AUTH_SOCK"))
	if err != nil {
		return nil, err
	}
	return &ssh.ClientConfig{
		User: user,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeysCallback(agent.NewClient(c).Signers),
		},
	}, nil
}

func connToTransport(conn net.Conn, config *ssh.ClientConfig) (*TransportSSH, error) {
	c, chans, reqs, err := ssh.NewClientConn(conn, conn.RemoteAddr().String(), config)
	if err != nil {
		return nil, err
	}
	t := &TransportSSH{}
	t.sshClient = ssh.NewClient(c, chans, reqs)
	err = t.setupSession()
	if err != nil {
		return nil, err
	}
	return t, nil
}

type deadlineConn struct {
	net.Conn
	timeout time.Duration
}

func (c *deadlineConn) Read(b []byte) (n int, err error) {
	c.SetReadDeadline(time.Now().Add(c.timeout))
	return c.Conn.Read(b)
}

func (c *deadlineConn) Write(b []byte) (n int, err error) {
	c.SetWriteDeadline(time.Now().Add(c.timeout))
	return c.Conn.Write(b)
}

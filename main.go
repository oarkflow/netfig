package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/oarkflow/bcl"
	"golang.org/x/crypto/ssh"

	"github.com/oarkflow/netfig/netconf"

	"github.com/oarkflow/netfig/dsl"
)

func startHTTPServer() {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/config", func(w http.ResponseWriter, r *http.Request) {
		log.Println("[HTTP API] Received configuration request.")
		body, err := io.ReadAll(r.Body)
		if err == nil {
			log.Printf("[HTTP API] Config payload: %s", string(body))
		}
		time.Sleep(500 * time.Millisecond)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status": "success"}`))
	})
	mux.HandleFunc("/restconf/data/config", func(w http.ResponseWriter, r *http.Request) {
		log.Println("[RESTCONF] Received configuration request.")
		body, err := io.ReadAll(r.Body)
		if err == nil {
			log.Printf("[RESTCONF] Config payload: %s", string(body))
		}
		time.Sleep(500 * time.Millisecond)
		w.WriteHeader(http.StatusNoContent)
	})
	addr := ":8080"
	log.Printf("Starting HTTP server on %s (for API and RESTCONF)", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatalf("HTTP server failed: %v", err)
	}
}

func generatePrivateKey() ([]byte, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	privateKey := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}
	return pem.EncodeToMemory(privateKey), nil
}

func startSSHServer() {
	privateKeyBytes, err := generatePrivateKey()
	if err != nil {
		log.Fatalf("Failed to generate SSH private key: %v", err)
	}
	signer, err := ssh.ParsePrivateKey(privateKeyBytes)
	if err != nil {
		log.Fatalf("Failed to parse SSH private key: %v", err)
	}
	config := &ssh.ServerConfig{
		NoClientAuth: true,
	}
	config.AddHostKey(signer)
	listener, err := net.Listen("tcp", ":2222")
	if err != nil {
		log.Fatalf("Failed to start SSH server on port 2222: %v", err)
	}
	log.Println("SSH server started on :2222")
	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("SSH accept error: %v", err)
			continue
		}
		go handleSSHConnection(conn, config)
	}
}

func handleSSHConnection(conn net.Conn, config *ssh.ServerConfig) {
	sshConn, chans, reqs, err := ssh.NewServerConn(conn, config)
	if err != nil {
		log.Printf("SSH handshake failed: %v", err)
		return
	}
	defer sshConn.Close()
	log.Printf("SSH connection established from %s", sshConn.RemoteAddr())
	go ssh.DiscardRequests(reqs)
	for newChannel := range chans {
		if newChannel.ChannelType() != "session" {
			newChannel.Reject(ssh.UnknownChannelType, "unknown channel type")
			continue
		}
		channel, requests, err := newChannel.Accept()
		if err != nil {
			log.Printf("SSH channel accept error: %v", err)
			continue
		}
		go handleSSHChannel(channel, requests)
	}
}

func handleSSHChannel(channel ssh.Channel, requests <-chan *ssh.Request) {
	defer channel.Close()
	for req := range requests {
		switch req.Type {
		case "exec":
			var payload struct{ Command string }
			if err := ssh.Unmarshal(req.Payload, &payload); err != nil {
				req.Reply(false, nil)
				continue
			}
			log.Printf("SSH server received command: %s", payload.Command)
			response := "Simulated CLI response: configuration applied.\n"
			channel.Write([]byte(response))
			req.Reply(true, nil)
			return
		case "shell":
			req.Reply(true, nil)
			buf := make([]byte, 1024)
			n, err := channel.Read(buf)
			if err == nil {
				cmd := strings.TrimSpace(string(buf[:n]))
				log.Printf("SSH server shell received command: %s", cmd)
				response := fmt.Sprintf("Simulated shell response for '%s': configuration applied.\n", cmd)
				channel.Write([]byte(response))
			}
			return
		default:
			req.Reply(false, nil)
		}
	}
}

func startNETCONFServer() {
	listener, err := net.Listen("tcp", ":830")
	if err != nil {
		log.Fatalf("Failed to start NETCONF server on port 830: %v", err)
	}
	log.Println("NETCONF server started on :830")
	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("NETCONF accept error: %v", err)
			continue
		}
		go handleNETCONFConnection(conn)
	}
}

func handleNETCONFConnection(conn net.Conn) {
	defer conn.Close()
	buf, err := io.ReadAll(conn)
	if err != nil {
		log.Printf("NETCONF read error: %v", err)
		return
	}
	xmlRequest := string(buf)
	log.Printf("NETCONF server received XML:\n%s", xmlRequest)

	reply := `<?xml version="1.0" encoding="UTF-8"?>
<rpc-reply message-id="101" xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
  <ok/>
</rpc-reply>`
	conn.Write([]byte(reply))
}

type AdapterSettings struct {
	SSHPort         int
	SSHTimeout      time.Duration
	APIPort         int
	APITimeout      time.Duration
	SNMPPort        int
	RESTCONFPort    int
	RESTCONFTimeout time.Duration
	NETCONFPort     int
	NETCONFTimeout  time.Duration
}

var defaultSettings = AdapterSettings{
	SSHPort:         2222,
	SSHTimeout:      5 * time.Second,
	APIPort:         8080,
	APITimeout:      5 * time.Second,
	SNMPPort:        161,
	RESTCONFPort:    8080,
	RESTCONFTimeout: 5 * time.Second,
	NETCONFPort:     830,
	NETCONFTimeout:  5 * time.Second,
}

func getIntParam(extra map[string]interface{}, key string, def int) int {
	if val, ok := extra[key]; ok {
		switch v := val.(type) {
		case int:
			return v
		case float64:
			return int(v)
		case string:
			if i, err := strconv.Atoi(v); err == nil {
				return i
			}
		}
	}
	return def
}

func getDurationParam(extra map[string]interface{}, key string, def time.Duration) time.Duration {
	if val, ok := extra[key]; ok {
		switch v := val.(type) {
		case int:
			return time.Duration(v) * time.Second
		case float64:
			return time.Duration(v) * time.Second
		case string:
			if d, err := time.ParseDuration(v); err == nil {
				return d
			}
		}
	}
	return def
}

type DeviceAdapter interface {
	ApplyConfig(ctx context.Context, d *dsl.Device) error
}

type SSHAdapter struct{}

func (a *SSHAdapter) ApplyConfig(ctx context.Context, d *dsl.Device) error {
	ip, ok := d.Extra["ip"]
	if !ok {
		return fmt.Errorf("SSH adapter: missing ip for device %s", d.Name)
	}
	username, ok := d.Extra["username"].(string)
	if !ok {
		return fmt.Errorf("SSH adapter: missing username for device %s", d.Name)
	}
	password, ok := d.Extra["password"].(string)
	if !ok {
		return fmt.Errorf("SSH adapter: missing password for device %s", d.Name)
	}
	port := getIntParam(d.Extra, "ssh_port", defaultSettings.SSHPort)
	config := &ssh.ClientConfig{
		User:            username,
		Auth:            []ssh.AuthMethod{ssh.Password(password)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         getDurationParam(d.Extra, "ssh_timeout", defaultSettings.SSHTimeout),
	}
	conn, err := ssh.Dial("tcp", fmt.Sprintf("%s:%d", ip, port), config)
	if err != nil {
		return fmt.Errorf("SSH dial failed for device %s: %v", d.Name, err)
	}
	defer conn.Close()
	session, err := conn.NewSession()
	if err != nil {
		return fmt.Errorf("SSH new session failed for device %s: %v", d.Name, err)
	}
	defer session.Close()
	command := generateCommandForDevice(d)
	var output bytes.Buffer
	session.Stdout = &output
	if err := session.Run(command); err != nil {
		return fmt.Errorf("SSH run command failed for device %s: %v", d.Name, err)
	}
	log.Printf("SSH config applied on device %s, output: %s", d.Name, output.String())
	return nil
}

type APIAdapterOption func(*APIAdapter)

type APIAdapter struct {
	EndpointFormat string // e.g., "http://%s:%d/api/config"
	ContentType    string // e.g., "application/json"
}

func NewAPIAdapter(opts ...APIAdapterOption) *APIAdapter {
	a := &APIAdapter{
		EndpointFormat: "http://%s:%d/api/config",
		ContentType:    "application/json",
	}
	for _, opt := range opts {
		opt(a)
	}
	return a
}

func (a *APIAdapter) ApplyConfig(ctx context.Context, d *dsl.Device) error {
	ip, ok := d.Extra["ip"]
	if !ok {
		return fmt.Errorf("API adapter: missing ip for device %s", d.Name)
	}
	token, ok := d.Extra["api_token"].(string)
	if !ok {
		return fmt.Errorf("API adapter: missing api_token for device %s", d.Name)
	}
	payloadBytes, err := generateAPIPayloadForDevice(d)
	if err != nil {
		return fmt.Errorf("API payload generation failed for device %s: %v", d.Name, err)
	}
	port := getIntParam(d.Extra, "api_port", defaultSettings.APIPort)
	url := fmt.Sprintf(a.EndpointFormat, ip, port)
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(payloadBytes))
	if err != nil {
		return fmt.Errorf("API new request failed for device %s: %v", d.Name, err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", a.ContentType)
	client := &http.Client{
		Timeout: getDurationParam(d.Extra, "api_timeout", defaultSettings.APITimeout),
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("API request failed for device %s: %v", d.Name, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("API config failed for device %s: status %d, body: %s", d.Name, resp.StatusCode, string(body))
	}
	log.Printf("API config applied on device %s", d.Name)
	return nil
}

type SNMPAdapter struct{}

func (a *SNMPAdapter) ApplyConfig(ctx context.Context, d *dsl.Device) error {
	ipRaw, ok := d.Extra["ip"]
	if !ok {
		return fmt.Errorf("SNMP adapter: missing ip for device %s", d.Name)
	}
	ip := fmt.Sprintf("%v", ipRaw)
	community, ok := d.Extra["community"].(string)
	if !ok {
		return fmt.Errorf("SNMP adapter: missing community for device %s", d.Name)
	}
	port := getIntParam(d.Extra, "snmp_port", defaultSettings.SNMPPort)
	log.Printf("Simulated SNMP config for device %s on %s:%d with community %s", d.Name, ip, port, community)
	return nil
}

type RESTCONFAdapterOption func(*RESTCONFAdapter)

type RESTCONFAdapter struct {
	EndpointFormat string
	ContentType    string
}

func NewRESTCONFAdapter(opts ...RESTCONFAdapterOption) *RESTCONFAdapter {
	a := &RESTCONFAdapter{
		EndpointFormat: "http://%s:%d/restconf/data/config",
		ContentType:    "application/yang-data+json",
	}
	for _, opt := range opts {
		opt(a)
	}
	return a
}

func (a *RESTCONFAdapter) ApplyConfig(ctx context.Context, d *dsl.Device) error {
	ip, ok := d.Extra["ip"]
	if !ok {
		return fmt.Errorf("RESTCONF adapter: missing ip for device %s", d.Name)
	}
	username, ok := d.Extra["username"].(string)
	if !ok {
		return fmt.Errorf("RESTCONF adapter: missing username for device %s", d.Name)
	}
	password, ok := d.Extra["password"].(string)
	if !ok {
		return fmt.Errorf("RESTCONF adapter: missing password for device %s", d.Name)
	}
	port := getIntParam(d.Extra, "restconf_port", defaultSettings.RESTCONFPort)
	endpoint := fmt.Sprintf(a.EndpointFormat, ip, port)
	payload, err := generateAPIPayloadForDevice(d)
	if err != nil {
		return fmt.Errorf("RESTCONF payload generation failed for device %s: %v", d.Name, err)
	}
	req, err := http.NewRequestWithContext(ctx, "PUT", endpoint, bytes.NewBuffer(payload))
	if err != nil {
		return fmt.Errorf("RESTCONF request creation failed for device %s: %v", d.Name, err)
	}
	req.SetBasicAuth(username, password)
	req.Header.Set("Content-Type", a.ContentType)
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{
		Timeout:   getDurationParam(d.Extra, "restconf_timeout", defaultSettings.RESTCONFTimeout),
		Transport: tr,
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("RESTCONF request failed for device %s: %v", d.Name, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("RESTCONF config failed for device %s: status %d, body: %s", d.Name, resp.StatusCode, string(body))
	}
	log.Printf("RESTCONF config applied on device %s", d.Name)
	return nil
}

type NETCONFAdapter struct{}

func (a *NETCONFAdapter) ApplyConfig(ctx context.Context, d *dsl.Device) error {
	ip, ok := d.Extra["ip"]
	if !ok {
		return fmt.Errorf("NETCONF adapter: missing ip for device %s", d.Name)
	}
	username, ok := d.Extra["username"].(string)
	if !ok {
		return fmt.Errorf("NETCONF adapter: missing username for device %s", d.Name)
	}
	password, ok := d.Extra["password"].(string)
	if !ok {
		return fmt.Errorf("NETCONF adapter: missing password for device %s", d.Name)
	}
	port := getIntParam(d.Extra, "netconf_port", defaultSettings.NETCONFPort)
	target := fmt.Sprintf("%s:%d", ip, port)
	sshConfig := &ssh.ClientConfig{
		User:            username,
		Auth:            []ssh.AuthMethod{ssh.Password(password)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         getDurationParam(d.Extra, "netconf_timeout", defaultSettings.NETCONFTimeout),
	}
	session, err := netconf.DialSSH(target, sshConfig)
	if err != nil {
		return fmt.Errorf("NETCONF dial failed for device %s: %v", d.Name, err)
	}
	defer session.Close()
	configData, err := generateNETCONFPayloadForDevice(d)
	if err != nil {
		return fmt.Errorf("NETCONF payload generation failed for device %s: %v", d.Name, err)
	}
	rpcPayload := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<rpc message-id="101" xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
  <edit-config>
    <target>
      <running/>
    </target>
    <config>
      %s
    </config>
  </edit-config>
</rpc>`, configData)
	reply, err := session.Exec(netconf.RawMethod(rpcPayload))
	if err != nil {
		return fmt.Errorf("NETCONF edit-config failed for device %s: %v", d.Name, err)
	}
	log.Printf("NETCONF config applied on device %s, reply: %v", d.Name, reply)
	return nil
}

func getDeviceAdapter(d *dsl.Device) DeviceAdapter {
	method, ok := d.Extra["connection_method"]
	if !ok {
		method = "ssh"
	}
	switch method {
	case "ssh":
		return &SSHAdapter{}
	case "api":
		return NewAPIAdapter()
	case "snmp":
		return &SNMPAdapter{}
	case "restconf":
		return NewRESTCONFAdapter()
	case "netconf":
		return &NETCONFAdapter{}
	default:
		return &SSHAdapter{}
	}
}

func generateCommandForDevice(d *dsl.Device) string {
	cmd := fmt.Sprintf("configure terminal\nhostname %s\n", d.Name)
	for ifaceName, iface := range d.Interfaces {
		cmd += fmt.Sprintf("interface %s\n", ifaceName)
		if iface.IP != "" {
			cmd += fmt.Sprintf("ip address %s\n", iface.IP)
		}
		cmd += "no shutdown\nexit\n"
	}
	cmd += "end\nwrite memory\n"
	return cmd
}

func generateAPIPayloadForDevice(d *dsl.Device) ([]byte, error) {
	payload := map[string]interface{}{
		"device": d.Name,
		"type":   d.Type,
		"config": d.Interfaces,
	}
	return json.Marshal(payload)
}

func generateNETCONFPayloadForDevice(d *dsl.Device) (string, error) {
	xmlPayload := `<config>
  <device xmlns="http://example.com/device">
    <name>` + d.Name + `</name>
    <interfaces>`
	for ifaceName, iface := range d.Interfaces {
		xmlPayload += `
      <interface>
        <name>` + ifaceName + `</name>`
		if iface.IP != "" {
			xmlPayload += `
        <ipAddress>` + iface.IP + `</ipAddress>`
		}
		xmlPayload += `
      </interface>`
	}
	xmlPayload += `
    </interfaces>
  </device>
</config>`
	return xmlPayload, nil
}

func applyConfigurations(netw *dsl.Network) {
	var wg sync.WaitGroup
	for i := range netw.Devices {
		wg.Add(1)
		d := &netw.Devices[i]
		go func(dev *dsl.Device) {
			defer wg.Done()
			adapter := getDeviceAdapter(dev)
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			if err := adapter.ApplyConfig(ctx, dev); err != nil {
				log.Printf("Failed to apply config on device %s: %v", dev.Name, err)
			} else {
				log.Printf("Successfully applied config on device %s", dev.Name)
			}
		}(d)
	}
	wg.Wait()
}

func runConfigApplier() {
	input, err := os.ReadFile("network.bcl")
	if err != nil {
		panic(err)
	}
	var config dsl.NetworkConfig
	_, err = bcl.Unmarshal([]byte(input), &config)
	if err != nil {
		panic(err)
	}
	fmt.Println("Unmarshalled Config:")
	fmt.Printf("%+v\n\n", config)
	for _, netw := range config.Networks {
		log.Printf("Starting configuration application for network: %s", netw.Name)
		applyConfigurations(&netw)
		log.Println("Configuration application complete.")
	}
}

func main() {
	go startHTTPServer()
	go startSSHServer()
	go startNETCONFServer()
	log.Println("Device simulator is running on ports:")
	log.Println(" - HTTP API/RESTCONF: 8080")
	log.Println(" - SSH: 2222")
	log.Println(" - NETCONF: 830")
	log.Println("Press Ctrl+C to exit.")
	go runConfigApplier()
	select {}
}

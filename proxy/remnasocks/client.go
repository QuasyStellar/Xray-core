package remnasocks

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	std_net "net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/signal"
	"github.com/xtls/xray-core/common/task"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
	"google.golang.org/protobuf/types/known/emptypb"
)

type ProxyParams struct {
	Type string `json:"type"`
	Host string `json:"host"`
	Port uint16 `json:"port"`
	User string `json:"user"`
	Pass string `json:"pass"`
}

type ProxyList []ProxyParams

func (pl *ProxyList) UnmarshalJSON(data []byte) error {
	var single ProxyParams
	if err := json.Unmarshal(data, &single); err == nil && single.Host != "" {
		*pl = []ProxyParams{single}
		return nil
	}

	var list []ProxyParams
	if err := json.Unmarshal(data, &list); err == nil {
		*pl = list
		return nil
	}

	return fmt.Errorf("failed to unmarshal ProxyList")
}

type UserProxies struct {
	MultiProxy  map[string]ProxyList
	SingleProxy ProxyList
}

type BufferedConn struct {
	std_net.Conn
	Reader io.Reader
}

func (c *BufferedConn) Read(b []byte) (int, error) {
	return c.Reader.Read(b)
}

type PooledConn struct {
	conn      std_net.Conn
	createdAt time.Time
}

type ProxyPool struct {
	mu         sync.Mutex
	conns      map[string]chan PooledConn
	lastActive map[string]time.Time
}

var (
	proxyMap      = make(map[string]*UserProxies)
	proxyMapMutex sync.RWMutex

	globalPool = &ProxyPool{
		conns:      make(map[string]chan PooledConn),
		lastActive: make(map[string]time.Time),
	}
)

type Client struct {
	file          string
	policyManager policy.Manager
	mu            sync.Mutex
	lastModTime   time.Time
}

func NewClient(ctx context.Context, config *emptypb.Empty) (*Client, error) {
	v := core.MustFromContext(ctx)
	
	filePath := "/etc/xray/proxies.json"

	c := &Client{
		file:          filePath,
		policyManager: v.GetFeature(policy.ManagerType()).(policy.Manager),
	}

	go c.startOrchestrator()

	return c, nil
}

func (c *Client) startOrchestrator() {
	c.loadProxiesFile()
	go c.watchProxiesFile()
	go globalPool.cleanupWorker(c)
}

func (c *Client) loadProxiesFile() {
	file, err := os.Open(c.file)
	if err != nil {
		return
	}
	defer file.Close()

	stat, err := file.Stat()
	if err == nil {
		c.mu.Lock()
		c.lastModTime = stat.ModTime()
		c.mu.Unlock()
	}

	var rawMap map[string]json.RawMessage
	err = json.NewDecoder(file).Decode(&rawMap)
	if err != nil {
		if err == io.EOF {
			proxyMapMutex.Lock()
			proxyMap = make(map[string]*UserProxies)
			proxyMapMutex.Unlock()
		}
		return
	}

	newMap := make(map[string]*UserProxies)
	for userID, rawVal := range rawMap {
		var multiProxy map[string]ProxyList
		var singleProxy ProxyList

		if err := json.Unmarshal(rawVal, &multiProxy); err != nil || len(multiProxy) == 0 || hasEmptyProxyHost(multiProxy) {
			multiProxy = nil
			var sp ProxyList
			if err := json.Unmarshal(rawVal, &sp); err == nil && len(sp) > 0 {
				singleProxy = sp
			}
		}

		if len(multiProxy) > 0 || len(singleProxy) > 0 {
			newMap[userID] = &UserProxies{
				MultiProxy:  multiProxy,
				SingleProxy: singleProxy,
			}
		}
	}

	proxyMapMutex.Lock()
	proxyMap = newMap
	proxyMapMutex.Unlock()
}

func hasEmptyProxyHost(m map[string]ProxyList) bool {
	for _, plist := range m {
		for _, p := range plist {
			if p.Host == "" {
				return true
			}
		}
	}
	return false
}

func (c *Client) watchProxiesFile() {
	for {
		time.Sleep(1 * time.Second)
		stat, err := os.Stat(c.file)
		if err != nil {
			continue
		}
		c.mu.Lock()
		lastMod := c.lastModTime
		c.mu.Unlock()
		if stat.ModTime().After(lastMod) {
			c.loadProxiesFile()
		}
	}
}

func (p *ProxyPool) cleanupWorker(c *Client) {
	for {
		time.Sleep(5 * time.Second)
		p.mu.Lock()
		now := time.Now()
		for key, ch := range p.conns {
			size := len(ch)
			for i := 0; i < size; i++ {
				select {
				case pc := <-ch:
					if now.Sub(pc.createdAt) > 10*time.Second {
						pc.conn.Close()
					} else {
						select {
						case ch <- pc:
						default:
							pc.conn.Close()
						}
					}
				default:
				}
			}
			
			lastUse, exists := p.lastActive[key]
			if exists && now.Sub(lastUse) > 60*time.Second {
				closeChan := p.conns[key]
				delete(p.conns, key)
				delete(p.lastActive, key)
				go func(c chan PooledConn) {
					for {
						select {
						case pc := <-c:
							if pc.conn != nil {
								pc.conn.Close()
							}
						default:
							return
						}
					}
				}(closeChan)
			}
		}
		p.mu.Unlock()
	}
}

func isConnAlive(conn std_net.Conn) bool {
	conn.SetReadDeadline(time.Now().Add(1 * time.Millisecond))
	one := make([]byte, 1)
	_, err := conn.Read(one)
	conn.SetReadDeadline(time.Time{})
	if err != nil {
		if netErr, ok := err.(std_net.Error); ok && netErr.Timeout() {
			return true
		}
		return false
	}
	return false
}

func getUserProxyConfig(userID string, country string) (bool, ProxyList, error) {
	proxyMapMutex.RLock()
	defer proxyMapMutex.RUnlock()

	if userID != "" {
		if userProxies, found := proxyMap[userID]; found && userProxies != nil {

			if proxyList, ok := userProxies.MultiProxy[country]; ok && len(proxyList) > 0 {
				return true, proxyList, nil
			}

			if len(userProxies.SingleProxy) > 0 {
				return true, userProxies.SingleProxy, nil
			}
		}
	}

	if country == "" {
		return false, nil, nil
	}

	global, found := proxyMap[country]
	if !found || global == nil {
		return false, nil, nil
	}

	if global.MultiProxy != nil {
		for _, plist := range global.MultiProxy {
			if len(plist) > 0 {
				return true, plist, nil
			}
		}
	}

	if len(global.SingleProxy) > 0 {
		return true, global.SingleProxy, nil
	}

	return false, nil, nil
}

func (p *ProxyPool) Get(proxy *ProxyParams, targetHost string, targetPort uint16) (std_net.Conn, error) {
	key := fmt.Sprintf("%s:%s:%d:%s:%s", proxy.Type, proxy.Host, proxy.Port, proxy.User, proxy.Pass)
	
	p.mu.Lock()
	p.lastActive[key] = time.Now()
	ch, exists := p.conns[key]
	if !exists {
		ch = make(chan PooledConn, 3)
		p.conns[key] = ch
	}
	p.mu.Unlock()

	for {
		select {
		case pc := <-ch:
			if isConnAlive(pc.conn) {
				go p.replenish(proxy, key, ch)
				return p.finalizeConnection(pc.conn, proxy, targetHost, targetPort)
			}
			pc.conn.Close()
		default:
			return dialAndEstablishProxy(proxy, targetHost, targetPort)
		}
	}
}

func (p *ProxyPool) replenish(proxy *ProxyParams, key string, ch chan PooledConn) {
	p.mu.Lock()
	lastUse := p.lastActive[key]
	p.mu.Unlock()

	if time.Since(lastUse) > 30*time.Second {
		return
	}

	if len(ch) >= cap(ch) {
		return
	}

	conn, err := prewarmConnection(proxy)
	if err != nil {
		return
	}

	select {
	case ch <- PooledConn{conn: conn, createdAt: time.Now()}:
	default:
		conn.Close()
	}
}

func prewarmConnection(proxy *ProxyParams) (std_net.Conn, error) {
	conn, err := std_net.DialTimeout("tcp", fmt.Sprintf("%s:%d", proxy.Host, proxy.Port), 5*time.Second)
	if err != nil {
		return nil, err
	}

	if strings.ToLower(proxy.Type) == "http" {
		return conn, nil
	}

	var handshakePayload []byte
	isAuthRequired := proxy.User != "" && proxy.Pass != ""

	if !isAuthRequired {
		handshakePayload = []byte{0x05, 0x01, 0x00}
	} else {
		handshakePayload = []byte{0x05, 0x01, 0x02}
		userBytes := []byte(proxy.User)
		passBytes := []byte(proxy.Pass)
		authReq := make([]byte, 0, 2+len(userBytes)+1+len(passBytes))
		authReq = append(authReq, 0x01, byte(len(userBytes)))
		authReq = append(authReq, userBytes...)
		authReq = append(authReq, byte(len(passBytes)))
		authReq = append(authReq, passBytes...)
		handshakePayload = append(handshakePayload, authReq...)
	}

	if _, err := conn.Write(handshakePayload); err != nil {
		conn.Close()
		return nil, err
	}

	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		conn.Close()
		return nil, err
	}
	if resp[0] != 0x05 {
		conn.Close()
		return nil, fmt.Errorf("invalid socks version")
	}

	selectedMethod := resp[1]
	if selectedMethod == 0x02 {
		if !isAuthRequired {
			conn.Close()
			return nil, fmt.Errorf("proxy requires auth but none provided")
		}
		authResp := make([]byte, 2)
		if _, err := io.ReadFull(conn, authResp); err != nil {
			conn.Close()
			return nil, err
		}
		if authResp[0] != 0x01 || authResp[1] != 0x00 {
			conn.Close()
			return nil, fmt.Errorf("authentication failed")
		}
	} else if selectedMethod != 0x00 {
		conn.Close()
		return nil, fmt.Errorf("unsupported authentication method: %d", selectedMethod)
	}

	return conn, nil
}

func (p *ProxyPool) finalizeConnection(conn std_net.Conn, proxy *ProxyParams, targetHost string, targetPort uint16) (std_net.Conn, error) {
	if strings.ToLower(proxy.Type) == "http" {
		req := fmt.Sprintf("CONNECT %s:%d HTTP/1.1\r\nHost: %s:%d\r\n", targetHost, targetPort, targetHost, targetPort)
		if proxy.User != "" && proxy.Pass != "" {
			auth := proxy.User + ":" + proxy.Pass
			basicAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte(auth))
			req += "Proxy-Authorization: " + basicAuth + "\r\n"
		}
		req += "\r\n"

		if _, err := conn.Write([]byte(req)); err != nil {
			conn.Close()
			return nil, err
		}

		reader := bufio.NewReader(conn)
		respLine, err := reader.ReadString('\n')
		if err != nil {
			conn.Close()
			return nil, err
		}

		if !strings.Contains(respLine, "200") {
			conn.Close()
			return nil, fmt.Errorf("http proxy rejected connection: %s", strings.TrimSpace(respLine))
		}

		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				conn.Close()
				return nil, err
			}
			if line == "\r\n" || line == "\n" {
				break
			}
		}

		return &BufferedConn{Conn: conn, Reader: reader}, nil
	}

	var addrPayload []byte
	var addrType byte

	if ip := std_net.ParseIP(targetHost); ip != nil {
		if ipv4 := ip.To4(); ipv4 != nil {
			addrType = 0x01
			addrPayload = ipv4
		} else {
			addrType = 0x04
			addrPayload = ip.To16()
		}
	} else {
		addrType = 0x03
		domainBytes := []byte(targetHost)
		addrPayload = make([]byte, 0, 1+len(domainBytes))
		addrPayload = append(addrPayload, byte(len(domainBytes)))
		addrPayload = append(addrPayload, domainBytes...)
	}

	req := make([]byte, 0, 4+len(addrPayload)+2)
	req = append(req, 0x05, 0x01, 0x00, addrType)
	req = append(req, addrPayload...)
	portBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(portBuf, targetPort)
	req = append(req, portBuf...)

	if _, err := conn.Write(req); err != nil {
		conn.Close()
		return nil, err
	}

	respHdr := make([]byte, 4)
	if _, err := io.ReadFull(conn, respHdr); err != nil {
		conn.Close()
		return nil, err
	}
	if respHdr[0] != 0x05 || respHdr[1] != 0x00 {
		conn.Close()
		return nil, fmt.Errorf("connection rejected, status: %d", respHdr[1])
	}

	repAddrType := respHdr[3]
	switch repAddrType {
	case 0x01:
		junk := make([]byte, 6)
		if _, err := io.ReadFull(conn, junk); err != nil {
			conn.Close()
			return nil, err
		}
	case 0x03:
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			conn.Close()
			return nil, err
		}
		junk := make([]byte, int(lenBuf[0])+2)
		if _, err := io.ReadFull(conn, junk); err != nil {
			conn.Close()
			return nil, err
		}
	case 0x04:
		junk := make([]byte, 18)
		if _, err := io.ReadFull(conn, junk); err != nil {
			conn.Close()
			return nil, err
		}
	}

	return conn, nil
}

func dialAndEstablishProxy(proxy *ProxyParams, targetHost string, targetPort uint16) (std_net.Conn, error) {
	conn, err := prewarmConnection(proxy)
	if err != nil {
		return nil, err
	}
	return globalPool.finalizeConnection(conn, proxy, targetHost, targetPort)
}

func (c *Client) Process(ctx context.Context, link *transport.Link, dialer internet.Dialer) error {
	outbounds := session.OutboundsFromContext(ctx)
	ob := outbounds[len(outbounds)-1]
	if !ob.Target.IsValid() {
		return errors.New("target not specified.")
	}
	ob.Name = "remnasocks"
	ob.CanSpliceCopy = 2
	destination := ob.Target

	var userEmail string
	if inbound := session.InboundFromContext(ctx); inbound != nil && inbound.User != nil {
		userEmail = inbound.User.Email
	}

	var country string
	if strings.HasPrefix(ob.Tag, "remnasocks-") {
		country = strings.TrimPrefix(ob.Tag, "remnasocks-")
	} else if strings.HasPrefix(ob.Tag, "socks-") {
		country = strings.TrimPrefix(ob.Tag, "socks-")
	}

	allowed, proxyList, err := getUserProxyConfig(userEmail, country)
	if userEmail != "" {
		if err != nil || !allowed || len(proxyList) == 0 {
			return errors.New("routing blocked: no proxy configured for user " + userEmail + " in country " + country)
		}
		if destination.Network == net.Network_UDP {
			return errors.New("UDP over residential proxies is not supported.")
		}

		var activeCandidates []ProxyParams
		var failedCandidates []ProxyParams
		for _, p := range proxyList {
			if GlobalFailures.IsFailed(p.Host, p.Port) {
				failedCandidates = append(failedCandidates, p)
			} else {
				activeCandidates = append(activeCandidates, p)
			}
		}
		candidates := append(activeCandidates, failedCandidates...)

		var upstream std_net.Conn
		var connErr error

		for i := range candidates {
			p := &candidates[i]
			upstream, connErr = globalPool.Get(p, destination.Address.String(), destination.Port.Value())
			if connErr == nil {
				break
			}
			GlobalFailures.MarkFailed(p.Host, p.Port)
		}

		if connErr != nil {
			return errors.New("failed to connect to upstream custom proxy via all candidates").Base(connErr)
		}
		defer upstream.Close()

		p := c.policyManager.ForLevel(0)

		var newCtx context.Context
		var newCancel context.CancelFunc
		if session.TimeoutOnlyFromContext(ctx) {
			newCtx, newCancel = context.WithCancel(context.Background())
		}

		ctx, cancel := context.WithCancel(ctx)
		timer := signal.CancelAfterInactivity(ctx, func() {
			cancel()
			if newCancel != nil {
				newCancel()
			}
		}, p.Timeouts.ConnectionIdle)

		var requestFunc func() error
		var responseFunc func() error

		requestFunc = func() error {
			defer timer.SetTimeout(p.Timeouts.DownlinkOnly)
			return buf.Copy(link.Reader, buf.NewWriter(upstream), buf.UpdateActivity(timer))
		}
		responseFunc = func() error {
			ob.CanSpliceCopy = 1
			defer timer.SetTimeout(p.Timeouts.UplinkOnly)
			return buf.Copy(buf.NewReader(upstream), link.Writer, buf.UpdateActivity(timer))
		}

		if newCtx != nil {
			ctx = newCtx
		}

		responseDonePost := task.OnSuccess(responseFunc, task.Close(link.Writer))
		if err := task.Run(ctx, requestFunc, responseDonePost); err != nil {
			return errors.New("connection ends").Base(err)
		}

		return nil
	}

	return errors.New("remnasocks only supports authenticated users")
}

type FailureTracker struct {
	mu       sync.Mutex
	failures map[string]time.Time
}

var GlobalFailures = &FailureTracker{
	failures: make(map[string]time.Time),
}

func (t *FailureTracker) MarkFailed(host string, port uint16) {
	t.mu.Lock()
	defer t.mu.Unlock()
	key := fmt.Sprintf("%s:%d", host, port)
	t.failures[key] = time.Now()
}

func (t *FailureTracker) IsFailed(host string, port uint16) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	key := fmt.Sprintf("%s:%d", host, port)
	lastFail, ok := t.failures[key]
	if !ok {
		return false
	}
	if time.Since(lastFail) > 10*time.Second {
		delete(t.failures, key)
		return false
	}
	return true
}

func init() {
	common.Must(common.RegisterConfig((*emptypb.Empty)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return NewClient(ctx, config.(*emptypb.Empty))
	}))
}

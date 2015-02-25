package main

import (
	"crypto/tls"
	"errors"
	"flag"
	"github.com/miekg/dns"
	"github.com/rrva/dockerclient"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

func registerShutdownSignalHandlers() {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM, syscall.SIGQUIT)
	for s := range sigChan {
		log.Fatalf("Signal (%s) received, shutting down", s)
	}
}

func matches(s []string, e string) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}

type lookupResponse struct {
	response *string
	err      error
}

type lookupFn func(string) (*string, error)

func lookupWithTimeout(n string, t time.Duration, lookup lookupFn) (*string, error) {

	lookupResponses := make(chan lookupResponse)
	go func(n string) {
		name, err := lookup(n)
		lookupResponses <- lookupResponse{response: name, err: err}
	}(n)

	timeouts := make(chan bool, 1)
	go func() {
		<-time.After(t)
		timeouts <- true
	}()

	for {
		select {
		case r := <-lookupResponses:
			return r.response, r.err
		case <-timeouts:
			return nil, errors.New("Timeout occurred talking to docker")
		}
	}
}

func findContainerNameByIPAddress(n string) (*string, error) {
	containers, err := docker.ListContainers(false, false, "")
	if err != nil {
		return nil, err
	}
	for _, container := range containers {
		info, _ := docker.InspectContainer(container.Id)
		if info.NetworkSettings.IpAddress == n {
			if len(container.Names) > 0 {
				str := container.Names[0][1:]
				return &str, nil
			}
			return nil, nil
		}
	}
	return nil, nil
}

func findContainerIPAddressByName(n string) (*string, error) {
	containers, err := docker.ListContainers(false, false, "")
	if err != nil {
		return nil, err
	}
	for _, container := range containers {
		if matches(container.Names, n) {
			info, err := docker.InspectContainer(container.Id)
			if err != nil {
				return nil, err
			}
			if info != nil {
				return &info.NetworkSettings.IpAddress, nil
			}
		}
	}
	return nil, nil
}

func writeDNSResponse(w dns.ResponseWriter, m *dns.Msg) {
	err := w.WriteMsg(m)
	if err != nil {
		log.Printf("Failed writing DNS response: %s", err)
	}
}

func myselfAsResolverErrorResponse(w dns.ResponseWriter, m *dns.Msg, name string) {
	log.Printf("Oh my! I'm pointing to myself!")
	rr := new(dns.A)
	rr.Hdr = dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 1}
	rr.A = net.ParseIP("0.0.0.0").To4()
	m.Answer = append(m.Answer, rr)
	writeDNSResponse(w, m)
}

func loopbackSanityCheckResponse(w dns.ResponseWriter, req *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(req)

	for _, question := range req.Question {

		if question.Name == "dockerdns.loopbacktest." {
			myselfAsResolverErrorResponse(w, m, question.Name)
			return
		}
	}

	writeDNSResponse(w, m)
}

func localLookupServer(w dns.ResponseWriter, req *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(req)

	for _, question := range req.Question {

		if question.Qtype == dns.TypeA || question.Qtype == dns.TypeAAAA {
			IPAddresses, err := net.LookupHost(strings.TrimSuffix(question.Name, "."))

			if err != nil {
				log.Printf("Local lookup error: %s", err)
				writeDNSResponse(w, m)
				return
			}

			for _, IPAddress := range IPAddresses {
				writeIPAddressResponse(&IPAddress, m, question.Name, question.Qtype)
			}
		}

	}

	writeDNSResponse(w, m)
}

func writeNameResponse(m *dns.Msg, ip string, name *string) {
	rr := new(dns.PTR)
	str := *name + "." + domain + "."
	rr.Hdr = dns.RR_Header{Name: str, Rrtype: dns.TypePTR, Class: dns.ClassINET, Ttl: 1}
	rr.Ptr = str
	m.Answer = append(m.Answer, rr)
}

func writeIPAddressResponse(IPAddress *string, m *dns.Msg, name string, qtype uint16) {
	ip := net.ParseIP(*IPAddress)
	ip4 := ip.To4()
	if ip4 != nil && qtype == dns.TypeA {
		rr := new(dns.A)
		rr.Hdr = dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 1}

		rr.A = ip4
		m.Answer = append(m.Answer, rr)
	} else if ip4 == nil && qtype == dns.TypeAAAA {
		rr := new(dns.AAAA)
		rr.Hdr = dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 1}

		rr.AAAA = ip.To16()
		m.Answer = append(m.Answer, rr)
	}
}

func reverseLookupServer(w dns.ResponseWriter, req *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(req)

	for _, question := range req.Question {

		if question.Qtype != dns.TypePTR {
			continue
		}

		ips := strings.Split(strings.Replace(question.Name, ".in-addr.arpa.", "", 1), ".")

		s := ""
		last := len(ips)
		for i := range ips {
			s = s + ips[last-1-i]
			if i < last-1 {
				s = s + "."
			}
		}

		name, err := lookupWithTimeout(s, 1*time.Second, findContainerNameByIPAddress)

		log.Printf("Reverse lookup %s=%s", s, *name)

		if err != nil {
			log.Printf("Container lookup error: %s", err)
			writeDNSResponse(w, m)
			return
		}

		if name != nil {
			writeNameResponse(m, question.Name, name)
		} else {
			log.Printf("No match found for %s sending empty reply", question.Name)
		}
	}

	writeDNSResponse(w, m)

}

func dockerNameLookupServer(w dns.ResponseWriter, req *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(req)

	for _, question := range req.Question {
		rr := new(dns.A)
		rr.Hdr = dns.RR_Header{Name: question.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 1}

		name := "/" + strings.TrimSuffix(question.Name, "."+domain+".")

		IPAddress, err := lookupWithTimeout(name, 1*time.Second, findContainerIPAddressByName)

		if err != nil {
			log.Printf("Container lookup error: %s", err)
			writeDNSResponse(w, m)
			return
		}

		if IPAddress != nil {
			writeIPAddressResponse(IPAddress, m, question.Name, question.Qtype)
		} else {
			log.Printf("No match found for %s sending empty reply", question.Name)
		}
	}

	writeDNSResponse(w, m)

}

func checkIfResolverIsMyself() {

	IPAddresses, _ := net.LookupHost("dockerdns.loopbacktest")

	if IPAddresses != nil && IPAddresses[0] == "0.0.0.0" {
		log.Fatal("Configuration error detected, I am pointing to myself as resolver, that won't work")
	}

}

func dnsStarted() {
	log.Printf("DNS server started")

	go checkIfResolverIsMyself()
}

func startDNS(addr string, errors chan error) {

	log.Printf("Trying to listen on %s", addr)
	server := &dns.Server{Addr: addr, Net: "udp", NotifyStartedFunc: dnsStarted}

	err := server.ListenAndServe()

	if err != nil {
		errors <- err
	}
}

var docker *dockerclient.DockerClient
var domain string

func newHTTPClient(host string, tlsConfig *tls.Config, timeout time.Duration) (*http.Client, *url.URL, error) {
	u, err := url.Parse(host)
	if err != nil {
		return nil, nil, err
	}

	httpTransport := &http.Transport{
		TLSClientConfig:       tlsConfig,
		ResponseHeaderTimeout: timeout,
	}

	switch u.Scheme {
	default:
		httpTransport.Dial = func(proto, addr string) (net.Conn, error) {
			return net.DialTimeout(proto, addr, timeout)
		}
	case "tcp":
		u.Scheme = "http"
	case "unix":
		socketPath := u.Path
		unixDial := func(proto, addr string) (net.Conn, error) {
			return net.DialTimeout("unix", socketPath, timeout)
		}
		httpTransport.Dial = unixDial
		u.Scheme = "http"
		u.Host = "unix.sock"
		u.Path = ""
	}
	return &http.Client{Transport: httpTransport}, u, nil
}

func main() {

	domain = *flag.String("domain", "dev", "domain")

	defaultDockerHost := os.Getenv("DOCKER_HOST")
	if defaultDockerHost == "" {
		defaultDockerHost = "unix:///var/run/docker.sock"
	}
	var dockerHost = *flag.String("docker-host", defaultDockerHost, "docker host url, or set DOCKER_HOST")
	var listenAddr = flag.String("listen-addr", ":53", "Listen address for DNS")
	var otherLookupsToLocalResolver = *flag.Bool("local-resolver", true, "Perform local gethostbyname queries for other domains")
	flag.Parse()

	var err error
	httpClient, url, err := newHTTPClient(dockerHost, nil, 100*time.Millisecond)
	if err != nil {
		log.Fatalf("Got error %s", err)
	}
	docker, err = dockerclient.NewDockerClientFromHttpClient(url, httpClient, nil)

	_, err = docker.Version()
	if err != nil {
		log.Fatalf("Failed reading docker version: %s specify host with -docker-host", err)
	}

	go registerShutdownSignalHandlers()

	log.Printf("Resolving %s domain against docker container names at %s", domain, dockerHost)
	if otherLookupsToLocalResolver {
		log.Println("Resolving other domains through system resolver")
		dns.HandleFunc(".", localLookupServer)
		dns.HandleFunc("loopbacktest", loopbackSanityCheckResponse)
	}
	dns.HandleFunc(domain, dockerNameLookupServer)
	dns.HandleFunc("arpa", reverseLookupServer)

	dnsListenErrors := make(chan error)
	go startDNS(*listenAddr, dnsListenErrors)
	err = <-dnsListenErrors
	log.Fatalf("Got error %s", err)
}

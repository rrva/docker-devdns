package main

import (
    "flag"
    "github.com/rrva/dockerclient"
    "log"
    "os"
    "strings"
    "github.com/miekg/dns"
    "net"
    "os/signal"
    "syscall"
)


type myDockerClient interface {
    StartMonitorEvents(cb dockerclient.Callback, ec chan error, args ...interface{})
    ListContainers(all bool, size bool, filters string) ([]dockerclient.Container, error)
    InspectContainer(id string) (*dockerclient.ContainerInfo, error)
    Version() (*dockerclient.Version, error)
}


func registerShutdownSignalHandlers() {
    sigChan := make(chan os.Signal, 1)
    signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM, syscall.SIGQUIT)
    for s := range sigChan {
        log.Fatalf("Signal (%s) received, shutting down", s)
    }
}

func cb(event *dockerclient.Event, errors chan error, args ...interface{}) {
    if (event.Status == "start") {
        info, err := docker.InspectContainer(event.Id)
        if err != nil {
            log.Fatalf("Err: %s", err)
        } else {
            name := strings.TrimPrefix(info.Name, "/")
            log.Printf("%s=%s", name, info.NetworkSettings.IpAddress)
            nameCache[name] = info.NetworkSettings.IpAddress
            nameCache[info.NetworkSettings.IpAddress] = name

        }
    }
    if (event.Status == "die") {
        info, err := docker.InspectContainer(event.Id)
        if err != nil {
            log.Fatalf("Err: %s", err)
        } else {
            name := strings.TrimPrefix(info.Name, "/")
            delete(nameCache, name)
            delete(nameCache, info.NetworkSettings.IpAddress)

        }
    }
}


var docker myDockerClient

func refreshEntireCache() {
    log.Printf("Listing all running containers...")
    containers, err := docker.ListContainers(false, false, "")
    if err != nil {
        log.Printf("error listing containers %s", err)
    }
    for _, container := range containers {
        info, _ := docker.InspectContainer(container.Id)
        for _, name := range container.Names {
            name = strings.TrimPrefix(name, "/")
            log.Printf("%s=%s", name, info.NetworkSettings.IpAddress)
            nameCache[name] = info.NetworkSettings.IpAddress
            nameCache[info.NetworkSettings.IpAddress] = name
        }
    }
}

func writeNameResponse(m *dns.Msg, ip string, name *string) {
    rr := new(dns.PTR)
    str := *name + "." + domain + "."
    rr.Hdr = dns.RR_Header{Name: ip, Rrtype: dns.TypePTR, Class: dns.ClassINET, Ttl: 5}
    rr.Ptr = str
    m.Answer = append(m.Answer, rr)
}

func writeIPAddressResponse(IPAddress *string, m *dns.Msg, name string, qtype uint16) {
    ip := net.ParseIP(*IPAddress)
    ip4 := ip.To4()
    if ip4 != nil && qtype == dns.TypeA {
        rr := new(dns.A)
        rr.Hdr = dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 5}

        rr.A = ip4
        m.Answer = append(m.Answer, rr)
    } else if ip4 == nil && qtype == dns.TypeAAAA {
        rr := new(dns.AAAA)
        rr.Hdr = dns.RR_Header{Name: name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 5}

        rr.AAAA = ip.To16()
        m.Answer = append(m.Answer, rr)
    }
}

func inAddrArpaToIPAddress(n string) string {
    ips := strings.Split(strings.Replace(n, ".in-addr.arpa.", "", 1), ".")
    s := ""
    last := len(ips)
    for i := range ips {
        s = s + ips[last-1-i]
        if i < last-1 {
            s = s + "."
        }
    }
    return s
}


func writeDNSResponse(w dns.ResponseWriter, m *dns.Msg) {
    err := w.WriteMsg(m)
    if err != nil {
        log.Printf("Failed writing DNS response: %s", err)
    }
}

func dockerNameLookupServer(w dns.ResponseWriter, req *dns.Msg) {
    m := new(dns.Msg)
    m.SetReply(req)

    for _, question := range req.Question {
        rr := new(dns.A)
        rr.Hdr = dns.RR_Header{Name: question.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 5}
        name := strings.TrimSuffix(question.Name, "."+domain+".")
        IPAddress, exists := nameCache[name]

        if !exists {
            log.Printf("Name not found: %s %s", name, IPAddress)
            writeDNSResponse(w, m)
            return
        }

        writeIPAddressResponse(&IPAddress, m, question.Name, question.Qtype)

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
                m.SetRcode(req, dns.RcodeServerFailure)
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

func reverseLookupServer(w dns.ResponseWriter, req *dns.Msg) {
    m := new(dns.Msg)
    m.SetReply(req)

    for _, question := range req.Question {

        if question.Qtype != dns.TypePTR {
            continue
        }

        ip := inAddrArpaToIPAddress(question.Name)

        name, exists := nameCache[ip]

        if exists {
            writeNameResponse(m, question.Name, &name)
        } else {
            m.SetRcode(req, dns.RcodeRefused)
            log.Printf("No match found for %s sending empty reply", question.Name)
        }
    }

    writeDNSResponse(w, m)

}


func dnsStarted() {
    log.Printf("DNS server started")
    if startedChan != nil {
        startedChan <- true
    }
}

func startDNS(addr string, errors chan error) {

    log.Printf("Trying to listen on %s", addr)
    server := &dns.Server{Addr: addr, Net: "udp", NotifyStartedFunc: dnsStarted}

    err := server.ListenAndServe()

    if err != nil {
        errors <- err
    }
}


func myselfAsResolverErrorResponse(w dns.ResponseWriter, m *dns.Msg, name string) {
    log.Printf("Oh my! I'm pointing to myself!")
    rr := new(dns.A)
    rr.Hdr = dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 5}
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

var domain string
var nameCache map[string]string
var startedChan chan bool

func shutdownOnMonitorErrors(monitorErrors chan error) {
    err := <-monitorErrors
    log.Fatalf("Failed listening to docker events: %s", err)
}

func main() {
    domain := flag.String("domain", "dev", "domain")

    defaultDockerHost := os.Getenv("DOCKER_HOST")
    if defaultDockerHost == "" {
        defaultDockerHost = "tcp://docker:2375"
    }
    var dockerHost = flag.String("docker-host", defaultDockerHost, "docker host url, or set DOCKER_HOST")
    var listenAddr = flag.String("listen-addr", ":5355", "Listen address for DNS")
    var otherLookupsToLocalResolver = *flag.Bool("local-resolver", true, "Perform local gethostbyname queries for other domains")
    flag.Parse()

    log.Printf("Listen addr is %s", *listenAddr)

    log.Printf("Resolving %s domain against docker container names at %s", *domain, *dockerHost)

    var err error

    docker, err = dockerclient.NewDockerClient(*dockerHost, nil)
    if err != nil {
        log.Fatalf("Failed creating docker client: %s", err)
    }
    _, err = docker.Version()
    if err != nil {
        log.Fatalf("Failed reading docker version: %s specify host with -docker-host", err)
    }

    mymain(*listenAddr, otherLookupsToLocalResolver, docker, *domain, nil)
}

func mymain(listenAddr string, otherLookupsToLocalResolver bool, mydocker myDockerClient, mydomain string, started chan bool) {


    docker = mydocker
    domain = mydomain

    startedChan = started
    nameCache = make(map[string]string)


    dns.HandleFunc("in-addr.arpa", reverseLookupServer)


    if otherLookupsToLocalResolver {
        log.Println("Resolving other domains through system resolver")
        dns.HandleFunc(".", localLookupServer)
        dns.HandleFunc("loopbacktest", loopbackSanityCheckResponse)
    }

    dns.HandleFunc(domain, dockerNameLookupServer)


    monitorErrors := make(chan error)
    docker.StartMonitorEvents(cb, monitorErrors)

    dnsListenErrors := make(chan error)

    go startDNS(listenAddr, dnsListenErrors)
    go registerShutdownSignalHandlers()
    go refreshEntireCache()
    go shutdownOnMonitorErrors(monitorErrors)

    err := <-dnsListenErrors

    log.Print(err)
}

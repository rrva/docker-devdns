package main

import (
	"github.com/miekg/dns"
	"github.com/rrva/dockerclient"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"testing"
)

type MyMockedDocker struct {
	mock.Mock
	dockerclient.Callback
}

func (m *MyMockedDocker) StartMonitorEvents(cb dockerclient.Callback, ec chan error, args ...interface{}) {
	m.Callback = cb
}

func (m *MyMockedDocker) ListContainers(all bool, size bool, filters string) ([]dockerclient.Container, error) {
	args := m.Called(all, size, filters)

	return args.Get(0).([]dockerclient.Container), args.Error(1)
}

func (m *MyMockedDocker) InspectContainer(id string) (*dockerclient.ContainerInfo, error) {
	args := m.Called(id)
	return args.Get(0).(*dockerclient.ContainerInfo), args.Error(1)
}

func (m *MyMockedDocker) Version() (*dockerclient.Version, error) {
	return nil, nil
}

var mocker *MyMockedDocker

func init() {

	started := make(chan bool)
	mocker = &MyMockedDocker{}
	containers := make([]dockerclient.Container, 1)
	container := dockerclient.Container{}
	names := make([]string, 1)
	names[0] = "foo1"
	container.Names = names
	container.Id = "idblah"
	containers[0] = container
	mocker.On("ListContainers", false, false, "").Return(containers, nil)

	containerInfo := dockerclient.ContainerInfo{}
	containerInfo.NetworkSettings.IpAddress = "1.2.3.4"
	mocker.On("InspectContainer", container.Id).Return(&containerInfo, nil)

	containerInfo2 := dockerclient.ContainerInfo{}
	containerInfo2.Name = "foo2"
	containerInfo2.NetworkSettings.IpAddress = "2.2.3.4"
	mocker.On("InspectContainer", "dyn1").Return(&containerInfo2, nil)

	go mymain(":5354", true, mocker, "dev", started)

	<-started

}

func dnsQuery(t *testing.T, s string, qtype uint16) *dns.Msg {
	c := new(dns.Client)

	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(s), qtype)
	m.RecursionDesired = true

	r, _, err := c.Exchange(m, "127.0.0.1:5354")
	if err != nil {
		t.Error(err)
	}

	if r.Rcode != dns.RcodeSuccess {
		t.Error("Query unsuccessful")
	}

	if len(r.Answer) == 0 {
		t.Error("No answers")
	}
	return r
}

func Test_dev_container_should_be_resolvable(t *testing.T) {

	r := dnsQuery(t, "foo1.dev", dns.TypeA)
	aa := r.Answer[0].(*dns.A)
	assert.Equal(t, "1.2.3.4", aa.A.String(), "Got wrong reply")
}

func Test_dynamically_added_dev_container_should_be_resolvable(t *testing.T) {

	event := dockerclient.Event{}
	event.Status = "start"
	event.Id = "dyn1"
	mocker.Callback(&event, nil, nil)

	r := dnsQuery(t, "foo2.dev", dns.TypeA)
	aa := r.Answer[0].(*dns.A)
	assert.Equal(t, "2.2.3.4", aa.A.String(), "Got wrong reply")

}

func Test_reverse_lookup_should_give_container_name(t *testing.T) {

	event := dockerclient.Event{}
	event.Status = "start"
	event.Id = "dyn1"
	mocker.Callback(&event, nil, nil)

	r := dnsQuery(t, "4.3.2.1.in-addr.arpa.", dns.TypePTR)

	aa := r.Answer[0].(*dns.PTR)
	assert.Equal(t, "foo1.dev.", aa.Ptr, "Got wrong reply")

}

func Test_resolve_non_container_name_should_give_address(t *testing.T) {

	r := dnsQuery(t, "example.com", dns.TypeA)
	aa := r.Answer[0].(*dns.A)
	assert.Equal(t, "93.184.216.34", aa.A.String(), "Got wrong reply")

}
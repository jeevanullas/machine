package eucalyptus

import (
	"crypto/md5"
	"crypto/rand"
	"fmt"
	"io"
	"io/ioutil"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/codegangsta/cli"
	"github.com/docker/machine/drivers"
	"github.com/docker/machine/drivers/eucalyptus/euca"
	"github.com/docker/machine/log"
	"github.com/docker/machine/provider"
	"github.com/docker/machine/ssh"
	"github.com/docker/machine/state"
	"github.com/docker/machine/utils"
)

const (
	driverName               = "eucalyptus"
	defaultRegion            = "eucalyptus"
	defaultInstanceType      = "m1.large"
	defaultRootSize          = 5
	ipRange                  = "0.0.0.0/0"
	machineSecurityGroupName = "docker-machine"
)

var (
	dockerPort = 2376
	swarmPort  = 3376
)

type Driver struct {
	Id                  string
	AccessKey           string
	SecretKey           string
	SessionToken        string
	Region              string
	AMI                 string
	EC2Endpoint         string
	SSHKeyID            int
	SSHUser             string
	SSHPort             int
	KeyName             string
	InstanceId          string
	InstanceType        string
	IPAddress           string
	PrivateIPAddress    string
	MachineName         string
	SecurityGroupId     string
	SecurityGroupName   string
	ReservationId       string
	IamInstanceProfile  string
	Zone                string
	CaCertPath          string
	PrivateKeyPath      string
	SwarmMaster         bool
	SwarmHost           string
	SwarmDiscovery      string
	storePath           string
	keyPath             string
}

func init() {
	drivers.Register(driverName, &drivers.RegisteredDriver{
		New:            NewDriver,
		GetCreateFlags: GetCreateFlags,
	})
}

func GetCreateFlags() []cli.Flag {
	return []cli.Flag{
		cli.StringFlag{
			Name:   "eucalyptus-access-key",
			Usage:  "Eucalyptus Access Key",
			Value:  "",
			EnvVar: "AWS_ACCESS_KEY_ID",
		},
		cli.StringFlag{
			Name:   "eucalyptus-secret-key",
			Usage:  "Eucalyptus Secret Key",
			Value:  "",
			EnvVar: "AWS_SECRET_ACCESS_KEY",
		},
		cli.StringFlag{
			Name:   "eucalyptus-compute-endpoint",
			Usage:  "Set the endpoint of Eucalyptus",
			Value:  "",
		},
		cli.StringFlag{
			Name:   "eucalyptus-session-token",
			Usage:  "Eucalyptus Session Token",
			Value:  "",
			EnvVar: "AWS_SESSION_TOKEN",
		},
		cli.StringFlag{
			Name:   "eucalyptus-emi",
			Usage:  "Eucalyptus machine image",
			EnvVar: "AWS_AMI",
		},
		cli.StringFlag{
			Name:   "eucalyptus-region",
			Usage:  "Eucalyptus region",
			Value:  defaultRegion,
			EnvVar: "AWS_DEFAULT_REGION",
		},
		cli.StringFlag{
			Name:   "eucalyptus-zone",
			Usage:  "Eucalyptus zone for instance",
			Value:  "",
			EnvVar: "AWS_ZONE",
		},
		cli.StringFlag{
			Name:   "eucalyptus-security-group",
			Usage:  "Eucalyptus security group",
			Value:  "docker-machine",
			EnvVar: "AWS_SECURITY_GROUP",
		},
		cli.StringFlag{
			Name:   "eucalyptus-instance-type",
			Usage:  "Eucalyptus instance type",
			Value:  defaultInstanceType,
			EnvVar: "AWS_INSTANCE_TYPE",
		},
		cli.StringFlag{
			Name:  "eucalyptus-iam-instance-profile",
			Usage: "Eucalyptus IAM Instance Profile",
		},
		cli.StringFlag{
			Name:   "eucalyptus-ssh-user",
			Usage:  "set the name of the ssh user",
			Value:  "ubuntu",
			EnvVar: "AWS_SSH_USER",
		},
	}
}

func NewDriver(machineName string, storePath string, caCert string, privateKey string) (drivers.Driver, error) {
	id := generateId()
	return &Driver{
		Id:             id,
		MachineName:    machineName,
		storePath:      storePath,
		CaCertPath:     caCert,
		PrivateKeyPath: privateKey,
	}, nil
}

func (d *Driver) GetProviderType() provider.ProviderType {
	return provider.Remote
}

func (d *Driver) AuthorizePort(ports []*drivers.Port) error {
	return nil
}

func (d *Driver) DeauthorizePort(ports []*drivers.Port) error {
	return nil
}

func (d *Driver) SetConfigFromFlags(flags drivers.DriverOptions) error {

	d.Region = flags.String("eucalyptus-region")
	d.AccessKey = flags.String("eucalyptus-access-key")
	d.SecretKey = flags.String("eucalyptus-secret-key")
	d.EC2Endpoint = flags.String("eucalyptus-compute-endpoint")
	d.SessionToken = flags.String("eucalyptus-session-token")
	d.AMI = flags.String("eucalyptus-emi") 
	d.InstanceType = flags.String("eucalyptus-instance-type")
	d.SecurityGroupName = flags.String("eucalyptus-security-group")
	zone := flags.String("eucalyptus-zone")
	d.Zone = zone[:]
	d.IamInstanceProfile = flags.String("eucalyptus-iam-instance-profile")
	d.SwarmMaster = flags.Bool("swarm-master")
	d.SwarmHost = flags.String("swarm-host")
	d.SwarmDiscovery = flags.String("swarm-discovery")
	d.SSHUser = flags.String("eucalyptus-ssh-user")
	d.SSHPort = 22

	if d.AccessKey == "" {
		return fmt.Errorf("Eucalyptus driver requires the --eucalyptus-access-key option")
	}

	if d.SecretKey == "" {
		return fmt.Errorf("Eucalyptus driver requires the --eucalyptus-secret-key option")
	}

	if d.isSwarmMaster() {
		u, err := url.Parse(d.SwarmHost)
		if err != nil {
			return fmt.Errorf("error parsing swarm host: %s", err)
		}

		parts := strings.Split(u.Host, ":")
		port, err := strconv.Atoi(parts[1])
		if err != nil {
			return err
		}

		swarmPort = port
	}

	return nil
}

func (d *Driver) GetMachineName() string {
	return d.MachineName
}

func (d *Driver) DriverName() string {
	return driverName
}

func (d *Driver) checkPrereqs() error {
	// check for existing keypair
	key, err := d.getClient().GetKeyPair(d.MachineName)
	if err != nil {
		return err
	}

	if key != nil {
		return fmt.Errorf("There is already a keypair with the name %s.  Please either remove that keypair or use a different machine name.", d.MachineName)
	}

	return nil
}

func (d *Driver) PreCreateCheck() error {
	return d.checkPrereqs()
}

func (d *Driver) instanceIpAvailable() bool {
	ip, err := d.GetIP()
	if err != nil {
		log.Debug(err)
	}
	if ip != "" {
		d.IPAddress = ip
		log.Debugf("Got the IP Address, it's %q", d.IPAddress)
		return true
	}
	return false
}

func (d *Driver) Create() error {
	if err := d.checkPrereqs(); err != nil {
		return err
	}

	log.Infof("Launching instance...")

	if err := d.createKeyPair(); err != nil {
		return fmt.Errorf("unable to create key pair: %s", err)
	}

	if err := d.configureSecurityGroup(d.SecurityGroupName); err != nil {
		return err
	}

	var instance euca.EC2Instance
	inst, err := d.getClient().RunInstance(d.AMI, d.InstanceType, d.Zone, 1, 1, d.SecurityGroupId, d.KeyName, d.IamInstanceProfile)
	if err != nil {
		return fmt.Errorf("Error launching instance: %s", err)
	}
	
	instance = inst

    d.InstanceId = instance.InstanceId

	d.waitForInstance()

	log.Debug("waiting for ip address to become available")
	if err := utils.WaitFor(d.instanceIpAvailable); err != nil {
		return err
	}

    log.Debugf("created instance ID %s, IP address %s, Private IP address %s",
		d.InstanceId,
		d.IPAddress,
		d.PrivateIPAddress,
	)

	log.Debug("Settings tags for instance")
	tags := map[string]string{
		"Name": d.MachineName,
	}

	if err := d.getClient().CreateTags(d.InstanceId, tags); err != nil {
		return err
	}

	return nil
}

func (d *Driver) GetURL() (string, error) {
	ip, err := d.GetIP()
	if err != nil {
		return "", err
	}
	if ip == "" {
		return "", nil
	}
	return fmt.Sprintf("tcp://%s:%d", ip, dockerPort), nil
}

func (d *Driver) GetIP() (string, error) {
	inst, err := d.getInstance()
	if err != nil {
		return "", err
	}

	return inst.IpAddress, nil
}

func (d *Driver) GetState() (state.State, error) {
	inst, err := d.getInstance()
	if err != nil {
		return state.Error, err
	}
	switch inst.InstanceState.Name {
	case "pending":
		return state.Starting, nil
	case "running":
		return state.Running, nil
	case "stopping":
		return state.Stopping, nil
	case "shutting-down":
		return state.Stopping, nil
	case "stopped":
		return state.Stopped, nil
	default:
		return state.Error, nil
	}
	return state.None, nil
}

func (d *Driver) GetSSHHostname() (string, error) {
	// TODO: use @nathanleclaire retry func here (ehazlett)
	return d.GetIP()
}

func (d *Driver) GetSSHPort() (int, error) {
	if d.SSHPort == 0 {
		d.SSHPort = 22
	}

	return d.SSHPort, nil
}

func (d *Driver) GetSSHUsername() string {
	if d.SSHUser == "" {
		d.SSHUser = "ubuntu"
	}

	return d.SSHUser
}

func (d *Driver) Start() error {
	if err := d.getClient().StartInstance(d.InstanceId); err != nil {
		return err
	}

	if err := d.waitForInstance(); err != nil {
		return err
	}

	return nil
}

func (d *Driver) Stop() error {
	if err := d.getClient().StopInstance(d.InstanceId, false); err != nil {
		return err
	}
	return nil
}

func (d *Driver) Remove() error {

	if err := d.terminate(); err != nil {
		return fmt.Errorf("unable to terminate instance: %s", err)
	}

	// remove keypair
	if err := d.deleteKeyPair(); err != nil {
		return fmt.Errorf("unable to remove key pair: %s", err)
	}

	return nil
}

func (d *Driver) Restart() error {
	if err := d.getClient().RestartInstance(d.InstanceId); err != nil {
		return fmt.Errorf("unable to restart instance: %s", err)
	}
	return nil
}

func (d *Driver) Kill() error {
	if err := d.getClient().StopInstance(d.InstanceId, true); err != nil {
		return err
	}
	return nil
}

func (d *Driver) getClient() *euca.EC2 {
	auth := euca.GetAuth(d.AccessKey, d.SecretKey, d.SessionToken)
	return euca.NewEC2(auth, d.EC2Endpoint ,d.Region)
}

func (d *Driver) GetSSHKeyPath() string {
	return filepath.Join(d.storePath, "id_rsa")
}

func (d *Driver) getInstance() (*euca.EC2Instance, error) {
	instance, err := d.getClient().GetInstance(d.InstanceId)
	if err != nil {
		return nil, err
	}

	return &instance, nil
}

func (d *Driver) instanceIsRunning() bool {
	st, err := d.GetState()
	if err != nil {
		log.Debug(err)
	}
	if st == state.Running {
		return true
	}
	return false
}

func (d *Driver) waitForInstance() error {
	if err := utils.WaitFor(d.instanceIsRunning); err != nil {
		return err
	}

	return nil
}

func (d *Driver) createKeyPair() error {

	if err := ssh.GenerateSSHKey(d.GetSSHKeyPath()); err != nil {
		return err
	}

	publicKey, err := ioutil.ReadFile(d.GetSSHKeyPath() + ".pub")
	if err != nil {
		return err
	}

	keyName := d.MachineName

	log.Debugf("creating key pair: %s", keyName)

	if err := d.getClient().ImportKeyPair(keyName, string(publicKey)); err != nil {
		return err
	}

	d.KeyName = keyName
	return nil
}

func (d *Driver) terminate() error {
	if d.InstanceId == "" {
		return fmt.Errorf("unknown instance")
	}

	log.Debugf("terminating instance: %s", d.InstanceId)
	if err := d.getClient().TerminateInstance(d.InstanceId); err != nil {
		return fmt.Errorf("unable to terminate instance: %s", err)
	}

	return nil
}

func (d *Driver) isSwarmMaster() bool {
	return d.SwarmMaster
}

func (d *Driver) securityGroupAvailableFunc(id string) func() bool {
	return func() bool {
		_, err := d.getClient().GetSecurityGroupById(id)
		if err == nil {
			return true
		}
		log.Debug(err)
		return false
	}
}

func (d *Driver) configureSecurityGroup(groupName string) error {
	log.Debugf("configuring security group")

	var securityGroup *euca.SecurityGroup

	groups, err := d.getClient().GetSecurityGroups()
	if err != nil {
		return err
	}

	for _, grp := range groups {
		if grp.GroupName == groupName {
			log.Debugf("found existing security group (%s)", groupName)
			securityGroup = &grp
			break
		}
	}

	// if not found, create
	if securityGroup == nil {
		log.Debugf("creating security group (%s)", groupName)
		group, err := d.getClient().CreateSecurityGroup(groupName, "Docker Machine")
		if err != nil {
			return err
		}
		securityGroup = group
		// wait until created (dat eventual consistency)
		log.Debugf("waiting for group (%s) to become available", group.GroupId)
		if err := utils.WaitFor(d.securityGroupAvailableFunc(group.GroupId)); err != nil {
			return err
		}
	}

	d.SecurityGroupId = securityGroup.GroupId

	perms := d.configureSecurityGroupPermissions(securityGroup)

	if len(perms) != 0 {
		log.Debugf("authorizing group %s with permissions: %v", securityGroup.GroupName, perms)
		if err := d.getClient().AuthorizeSecurityGroup(d.SecurityGroupId, perms); err != nil {
			return err
		}

	}

	return nil
}

func (d *Driver) configureSecurityGroupPermissions(group *euca.SecurityGroup) []euca.IpPermission {
	hasSshPort := false
	hasDockerPort := false
	hasSwarmPort := false
	for _, p := range group.IpPermissions {
		switch p.FromPort {
		case 22:
			hasSshPort = true
		case dockerPort:
			hasDockerPort = true
		case swarmPort:
			hasSwarmPort = true
		}
	}

	perms := []euca.IpPermission{}

	if !hasSshPort {
		perms = append(perms, euca.IpPermission{
			IpProtocol: "tcp",
			FromPort:   22,
			ToPort:     22,
			IpRange:    ipRange,
		})
	}

	if !hasDockerPort {
		perms = append(perms, euca.IpPermission{
			IpProtocol: "tcp",
			FromPort:   dockerPort,
			ToPort:     dockerPort,
			IpRange:    ipRange,
		})
	}

	if !hasSwarmPort && d.SwarmMaster {
		perms = append(perms, euca.IpPermission{
			IpProtocol: "tcp",
			FromPort:   swarmPort,
			ToPort:     swarmPort,
			IpRange:    ipRange,
		})
	}

	log.Debugf("configuring security group authorization for %s", ipRange)

	return perms
}

func (d *Driver) deleteSecurityGroup() error {
	log.Debugf("deleting security group %s", d.SecurityGroupId)

	if err := d.getClient().DeleteSecurityGroup(d.SecurityGroupId); err != nil {
		return err
	}

	return nil
}

func (d *Driver) deleteKeyPair() error {
	log.Debugf("deleting key pair: %s", d.KeyName)

	if err := d.getClient().DeleteKeyPair(d.KeyName); err != nil {
		return err
	}

	return nil
}

func generateId() string {
	rb := make([]byte, 10)
	_, err := rand.Read(rb)
	if err != nil {
		log.Fatalf("unable to generate id: %s", err)
	}

	h := md5.New()
	io.WriteString(h, string(rb))
	return fmt.Sprintf("%x", h.Sum(nil))
}

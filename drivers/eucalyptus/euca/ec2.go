package euca

import (
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strconv"

	awsauth "github.com/smartystreets/go-aws-auth"
)

type (
	EC2 struct {
		Endpoint string
		Auth     Auth
		Region   string
	}

	Instance struct {
		info EC2Instance
	}

	EC2Instance struct {
		InstanceId    string `xml:"instanceId"`
		ImageId       string `xml:"imageId"`
		InstanceState struct {
			Code int    `xml:"code"`
			Name string `xml:"name"`
		} `xml:"instanceState"`
		PrivateDnsName string `xml:"privateDnsName"`
		DnsName        string `xml:"dnsName"`
		Reason         string `xml:"reason"`
		AmiLaunchIndex string `xml:"amiLaunchIndex"`
		ProductCodes   string `xml:"productCodes"`
		InstanceType   string `xml:"instanceType"`
		LaunchTime     string `xml:"launchTime"`
		Placement      struct {
			AvailabilityZone string `xml:"availabilityZone"`
			GroupName        string `xml:"groupName"`
			Tenancy          string `xml:"tenancy"`
		} `xml:"placement"`
		KernelId   string `xml:"kernelId"`
		Monitoring struct {
			State string `xml:"state"`
		} `xml:"monitoring"`
		IpAddress        string `xml:"ipAddress"`
		PrivateIpAddress string `xml:"privateIpAddress"`
		SourceDestCheck  bool   `xml:"sourceDestCheck"`
		GroupSet         []struct {
			GroupId   string `xml:"groupId"`
			GroupName string `xml:"groupName"`
		} `xml:"groupSet"`
		StateReason struct {
			Code    string `xml:"code"`
			Message string `xml:"message"`
		} `xml:"stateReason"`
		Architecture        string `xml:"architecture"`
		RootDeviceType      string `xml:"rootDeviceType"`
		RootDeviceName      string `xml:"rootDeviceName"`
		BlockDeviceMapping  string `xml:"blockDeviceMapping"`
		VirtualizationType  string `xml:"virtualizationType"`
		ClientToken         string `xml:"clientToken"`
		Hypervisor          string `xml:"hypervisor"`
	}

	RunInstancesResponse struct {
		RequestId     string        `xml:"requestId"`
		ReservationId string        `xml:"reservationId"`
		OwnerId       string        `xml:"ownerId"`
		Instances     []EC2Instance `xml:"instancesSet>item"`
	}

)

func newAwsApiResponseError(r http.Response) error {
	var errorResponse ErrorResponse
	if err := getDecodedResponse(r, &errorResponse); err != nil {
		return fmt.Errorf("Error decoding error response: %s", err)
	}
	msg := ""
	for _, e := range errorResponse.Errors {
		msg += fmt.Sprintf("%s\n", e.Message)
	}
	return fmt.Errorf("Non-200 API response: code=%d message=%s", r.StatusCode, msg)
}

func newAwsApiCallError(err error) error {
	return fmt.Errorf("Problem with AWS API call: %s", err)
}

func getDecodedResponse(r http.Response, into interface{}) error {
	defer r.Body.Close()
	if err := xml.NewDecoder(r.Body).Decode(into); err != nil {
		return fmt.Errorf("Error decoding error response: %s", err)
	}
	return nil
}

func NewEC2(auth Auth, endpoint string, region string) *EC2 {
	return &EC2{
		Endpoint: endpoint,
		Auth:     auth,
		Region:   region,
	}
}

func (e *EC2) awsApiCall(v url.Values) (*http.Response, error) {
	v.Set("Version", "2014-06-15")
	client := &http.Client{}
	finalEndpoint := fmt.Sprintf("%s?%s", e.Endpoint, v.Encode())
	req, err := http.NewRequest("GET", finalEndpoint, nil)
	if err != nil {
		return &http.Response{}, fmt.Errorf("error creating request from client")
	}
	req.Header.Add("Content-type", "application/json")

	awsauth.Sign4(req, awsauth.Credentials{
		AccessKeyID:     e.Auth.AccessKey,
		SecretAccessKey: e.Auth.SecretKey,
		SecurityToken:   e.Auth.SessionToken,
	})
	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("client encountered error while doing the request: %s", err.Error())
		return resp, fmt.Errorf("client encountered error while doing the request: %s", err)
	}

	if resp.StatusCode != http.StatusOK {
		return resp, newAwsApiResponseError(*resp)
	}
	return resp, nil
}

func (e *EC2) RunInstance(amiId string, instanceType string, zone string, minCount int, maxCount int, securityGroup string, keyName string, role string) (EC2Instance, error) {
	instance := Instance{}
	v := url.Values{}
	v.Set("Action", "RunInstances")
	v.Set("ImageId", amiId)
	v.Set("Placement.AvailabilityZone", zone)
	v.Set("MinCount", strconv.Itoa(minCount))
	v.Set("MaxCount", strconv.Itoa(maxCount))
	v.Set("KeyName", keyName)
	v.Set("InstanceType", instanceType)
        v.Set("SecurityGroupId.0",securityGroup)

	if len(role) > 0 {
		v.Set("IamInstanceProfile.Name", role)
	}

	resp, err := e.awsApiCall(v)

	if err != nil {
		return instance.info, newAwsApiCallError(err)
	}
	defer resp.Body.Close()

	contents, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return instance.info, fmt.Errorf("Error reading AWS response body")
	}
	unmarshalledResponse := RunInstancesResponse{}
	err = xml.Unmarshal(contents, &unmarshalledResponse)
	if err != nil {
		return instance.info, fmt.Errorf("Error unmarshalling AWS response XML: %s", err)
	}

	instance.info = unmarshalledResponse.Instances[0]
	return instance.info, nil
}

func (e *EC2) DeleteKeyPair(name string) error {
	v := url.Values{}
	v.Set("Action", "DeleteKeyPair")
	v.Set("KeyName", name)

	_, err := e.awsApiCall(v)
	if err != nil {
		return fmt.Errorf("Error making API call to delete keypair :%s", err)
	}
	return nil
}

func (e *EC2) CreateKeyPair(name string) ([]byte, error) {
	v := url.Values{}
	v.Set("Action", "CreateKeyPair")
	v.Set("KeyName", name)
	resp, err := e.awsApiCall(v)
	if err != nil {
		return nil, fmt.Errorf("Error trying API call to create keypair: %s", err)
	}
	defer resp.Body.Close()
	contents, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("Error reading AWS response body")
	}

	unmarshalledResponse := CreateKeyPairResponse{}
	if xml.Unmarshal(contents, &unmarshalledResponse); err != nil {
		return nil, fmt.Errorf("Error unmarshalling AWS response XML: %s", err)
	}

	key := unmarshalledResponse.KeyMaterial

	return key, nil
}

func (e *EC2) ImportKeyPair(name, publicKey string) error {
	keyMaterial := base64.StdEncoding.EncodeToString([]byte(publicKey))

	v := url.Values{}
	v.Set("Action", "ImportKeyPair")
	v.Set("KeyName", name)
	v.Set("PublicKeyMaterial", keyMaterial)

	resp, err := e.awsApiCall(v)
	if err != nil {
		return fmt.Errorf("Error trying API call to create keypair: %s", err)
	}

	defer resp.Body.Close()
	contents, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("Error reading AWS response body")
	}

	unmarshalledResponse := ImportKeyPairResponse{}
	if xml.Unmarshal(contents, &unmarshalledResponse); err != nil {
		return fmt.Errorf("Error unmarshalling AWS response XML: %s", err)
	}

	return nil
}

func (e *EC2) CreateTags(id string, tags map[string]string) error {
	v := url.Values{}
	v.Set("Action", "CreateTags")
	v.Set("ResourceId.1", id)

	counter := 1
	for k, val := range tags {
		v.Set(fmt.Sprintf("Tag.%d.Key", counter), k)
		v.Set(fmt.Sprintf("Tag.%d.Value", counter), val)

		counter += 1
	}

	resp, err := e.awsApiCall(v)
	defer resp.Body.Close()
	if err != nil {
		return err
	}

	createTagsResponse := &CreateTagsResponse{}

	if err := getDecodedResponse(*resp, &createTagsResponse); err != nil {
		return fmt.Errorf("Error decoding create tags response: %s", err)
	}

	return nil
}

func (e *EC2) CreateSecurityGroup(name string, description string) (*SecurityGroup, error) {
	v := url.Values{}
	v.Set("Action", "CreateSecurityGroup")
	v.Set("GroupName", name)
	v.Set("GroupDescription", url.QueryEscape(description))

	resp, err := e.awsApiCall(v)
	defer resp.Body.Close()
	if err != nil {
		// ugly hack since API has no way to check if SG already exists
		if resp.StatusCode == http.StatusBadRequest {
			var errorResponse ErrorResponse
			if err := getDecodedResponse(*resp, &errorResponse); err != nil {
				return nil, fmt.Errorf("Error decoding error response: %s", err)
			}
			if errorResponse.Errors[0].Code == ErrorDuplicateGroup {
				return nil, nil
			}
		}
		return nil, fmt.Errorf("Error making API call to create security group: %s", err)
	}

	createSecurityGroupResponse := CreateSecurityGroupResponse{}

	if err := getDecodedResponse(*resp, &createSecurityGroupResponse); err != nil {
		return nil, fmt.Errorf("Error decoding create security groups response: %s", err)
	}

	group := &SecurityGroup{
		GroupId: createSecurityGroupResponse.GroupId,
	}
	return group, nil
}

func (e *EC2) AuthorizeSecurityGroup(groupId string, permissions []IpPermission) error {
	v := url.Values{}
	v.Set("Action", "AuthorizeSecurityGroupIngress")
	v.Set("GroupId", groupId)

	for index, perm := range permissions {
		n := index + 1 // eucalyptus starts counting from 1 not 0
		v.Set(fmt.Sprintf("IpPermissions.%d.IpProtocol", n), perm.IpProtocol)
		v.Set(fmt.Sprintf("IpPermissions.%d.FromPort", n), strconv.Itoa(perm.FromPort))
		v.Set(fmt.Sprintf("IpPermissions.%d.ToPort", n), strconv.Itoa(perm.ToPort))
		v.Set(fmt.Sprintf("IpPermissions.%d.IpRanges.1.CidrIp", n), perm.IpRange)
	}
	resp, err := e.awsApiCall(v)
	defer resp.Body.Close()
	if err != nil {
		return fmt.Errorf("Error making API call to authorize security group ingress: %s", err)
	}
	return nil
}

func (e *EC2) DeleteSecurityGroup(groupId string) error {
	v := url.Values{}
	v.Set("Action", "DeleteSecurityGroup")
	v.Set("GroupId", groupId)

	resp, err := e.awsApiCall(v)
	defer resp.Body.Close()
	if err != nil {
		return fmt.Errorf("Error making API call to delete security group: %s", err)
	}

	deleteSecurityGroupResponse := DeleteSecurityGroupResponse{}

	if err := getDecodedResponse(*resp, &deleteSecurityGroupResponse); err != nil {
		return fmt.Errorf("Error decoding delete security groups response: %s", err)
	}

	return nil
}

func (e *EC2) GetSecurityGroups() ([]SecurityGroup, error) {
	sgs := []SecurityGroup{}
	resp, err := e.performStandardAction("DescribeSecurityGroups")
	if err != nil {
		return sgs, err
	}
	defer resp.Body.Close()
	contents, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return sgs, fmt.Errorf("Error reading AWS response body: %s", err)
	}

	unmarshalledResponse := DescribeSecurityGroupsResponse{}
	if err = xml.Unmarshal(contents, &unmarshalledResponse); err != nil {
		return sgs, fmt.Errorf("Error unmarshalling AWS response XML: %s", err)
	}

	sgs = unmarshalledResponse.SecurityGroupInfo

	return sgs, nil
}

func (e *EC2) GetSecurityGroupById(id string) (*SecurityGroup, error) {
	groups, err := e.GetSecurityGroups()
	if err != nil {
		return nil, err
	}

	for _, g := range groups {
		if g.GroupId == id {
			return &g, nil
		}
	}
	return nil, nil
}

func (e *EC2) GetKeyPairs() ([]KeyPair, error) {
	keyPairs := []KeyPair{}
	resp, err := e.performStandardAction("DescribeKeyPairs")
	if err != nil {
		return keyPairs, err
	}
	defer resp.Body.Close()
	contents, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return keyPairs, fmt.Errorf("Error reading AWS response body: %s", err)
	}

	unmarshalledResponse := DescribeKeyPairsResponse{}
	if err = xml.Unmarshal(contents, &unmarshalledResponse); err != nil {
		return keyPairs, fmt.Errorf("Error unmarshalling AWS response XML: %s", err)
	}

	keyPairs = unmarshalledResponse.KeySet

	return keyPairs, nil
}

func (e *EC2) GetKeyPair(name string) (*KeyPair, error) {
	keyPairs, err := e.GetKeyPairs()
	if err != nil {
		return nil, err
	}

	for _, key := range keyPairs {
		if key.KeyName == name {
			return &key, nil
		}
	}
	return nil, nil
}

func (e *EC2) GetInstance(instanceId string) (EC2Instance, error) {
	ec2Instance := EC2Instance{}
	resp, err := e.performInstanceAction(instanceId, "DescribeInstances", nil)
	if err != nil {
		return ec2Instance, err
	}
	defer resp.Body.Close()
	contents, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return ec2Instance, fmt.Errorf("Error reading AWS response body: %s", err)
	}

	unmarshalledResponse := DescribeInstancesResponse{}
	if err = xml.Unmarshal(contents, &unmarshalledResponse); err != nil {
		return ec2Instance, fmt.Errorf("Error unmarshalling AWS response XML: %s", err)
	}

	if len(unmarshalledResponse.ReservationSet) > 0 {
		reservationSet := unmarshalledResponse.ReservationSet[0]
		ec2Instance = reservationSet.InstancesSet[0]
	}
	return ec2Instance, nil
}

func (e *EC2) StartInstance(instanceId string) error {
	if _, err := e.performInstanceAction(instanceId, "StartInstances", nil); err != nil {
		return err
	}
	return nil
}

func (e *EC2) RestartInstance(instanceId string) error {
	if _, err := e.performInstanceAction(instanceId, "RebootInstances", nil); err != nil {
		return err
	}
	return nil
}

func (e *EC2) StopInstance(instanceId string, force bool) error {
	vars := make(map[string]string)
	if force {
		vars["Force"] = "1"
	}

	if _, err := e.performInstanceAction(instanceId, "StopInstances", &vars); err != nil {
		return err
	}
	return nil
}

func (e *EC2) TerminateInstance(instanceId string) error {
	if _, err := e.performInstanceAction(instanceId, "TerminateInstances", nil); err != nil {
		return err
	}
	return nil
}

func (e *EC2) performStandardAction(action string) (*http.Response, error) {
	v := url.Values{}
	v.Set("Action", action)
	resp, err := e.awsApiCall(v)
	if err != nil {
		return resp, newAwsApiCallError(err)
	}
	return resp, nil
}

func (e *EC2) performInstanceAction(instanceId, action string, extraVars *map[string]string) (*http.Response, error) {
	v := url.Values{}
	v.Set("Action", action)
	v.Set("InstanceId.1", instanceId)
	if extraVars != nil {
		for k, val := range *extraVars {
			v.Set(k, val)
		}
	}
	resp, err := e.awsApiCall(v)
	if err != nil {
		return resp, newAwsApiCallError(err)
	}
	return resp, nil
}

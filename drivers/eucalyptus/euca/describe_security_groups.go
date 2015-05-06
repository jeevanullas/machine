package euca

type DescribeSecurityGroupsResponse struct {
	RequestId         string          `xml:"requestId"`
	SecurityGroupInfo []SecurityGroup `xml:"securityGroupInfo>item"`
}

package euca

type BlockDeviceMapping struct {
	DeviceName          string
	VirtualName         string
	VolumeSize          int64
	DeleteOnTermination bool
}

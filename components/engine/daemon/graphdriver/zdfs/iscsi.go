package zdfs

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"strings"
	"sync/atomic"
	"time"

	"github.com/rs/xid"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

const (
	hbaNum    = 999999998
	naaPrefix = "naa.18"
)

var (
	processID int
	counter   uint32
)

func init() {
	processID = os.Getpid()
	if err := binary.Read(rand.Reader, binary.BigEndian, &counter); err != nil {
		counter = 0
	}
}

func NewNaaName() string {
	b := make([]byte, 7)
	binary.BigEndian.PutUint32(b, uint32(time.Now().Unix()))
	b[4], b[5] = byte(processID>>8), byte(processID)
	counter := atomic.AddUint32(&counter, 1)
	b[6] = byte(counter)
	return naaPrefix + hex.EncodeToString(b)
}

type DadiIscsiDev struct {
	id  string
	naa string
}

func CreateDeviceAndMount(dir, configPath, mountPoint string) (retErr error) {
	idStr := xid.New().String()
	naaStr := NewNaaName()

	defer func() {
		if retErr != nil {
			logrus.Infof("clear after CreateIscsiDev failed")
			if err := UnmountAndDestoryDev(dir, mountPoint); err != nil {
				logrus.Errorf("DestoryIscsiDev when clear")
			}
		}
	}()

	ioutil.WriteFile(path.Join(dir, "devid"), ([]byte)(idStr), 0666)
	ioutil.WriteFile(path.Join(dir, "devnaa"), ([]byte)(naaStr), 0666)

	devDir := fmt.Sprintf("/sys/kernel/config/target/core/user_%d/dev_%s", hbaNum, idStr)
	err := os.MkdirAll(devDir, 0700)
	if err != nil {
		logrus.Errorf("error create target dir %v", err)
		return err
	}

	err = ioutil.WriteFile(path.Join(devDir, "control"), ([]byte)(fmt.Sprintf("dev_config=%s/%s", "overlaybd", configPath)), 0666)
	if err != nil {
		logrus.Errorf("error write target config %v", err)
		return err
	}

	err = ioutil.WriteFile(path.Join(devDir, "enable"), ([]byte)("1"), 0666)
	if err != nil {
		logrus.Errorf("error write target enable %v", err)
		return err
	}

	loopDir := fmt.Sprintf("/sys/kernel/config/target/loopback/%s", naaStr)
	logrus.Infof("loopback device dir : %s", loopDir)

	err = os.MkdirAll(path.Join(loopDir, "tpgt_1", "lun", "lun_0"), 0700)
	if err != nil {
		logrus.Errorf("error create loopback dir %v", err)
		return err
	}

	err = ioutil.WriteFile(path.Join(loopDir, "tpgt_1", "nexus"), ([]byte)(naaStr), 0666)
	if err != nil {
		logrus.Errorf("error write loopback nexus %v", err)
		return err
	}

	err = os.Symlink(devDir, path.Join(loopDir, "tpgt_1", "lun", "lun_0", "dev_"+idStr))
	if err != nil {
		logrus.Errorf("error create loopback link %v", err)
		return err
	}

	deviceNumber := ""
	for retry := 0; retry < 50; retry++ {
		bytes, err := ioutil.ReadFile(path.Join(loopDir, "tpgt_1", "address"))
		if err != nil {
			logrus.Errorf("error read loopback address %v", err)
			time.Sleep(1 * time.Millisecond)

			continue
		}
		deviceNumber = string(bytes)
		deviceNumber = strings.TrimSuffix(deviceNumber, "\n")
		logrus.Infof("device number found %s", deviceNumber)
		break
	}
	if deviceNumber == "" {
		logrus.Errorf("error get deviceNumver")
		return fmt.Errorf("error get deviceNumber")
	}

	for retry := 0; retry < 50; retry++ {
		devDirs, err := ioutil.ReadDir("/sys/class/scsi_device/" + deviceNumber + ":0/device/block")
		if err != nil {
			logrus.Errorf("error read scsi_device block dir for %s, err: %v", "/sys/class/scsi_device/"+deviceNumber+":0/device/block", err)
			time.Sleep(10 * time.Millisecond)
			continue
		}
		for _, dev := range devDirs {
			device := fmt.Sprintf("/dev/%s", dev.Name())
			logrus.Infof("device found %s", device)
			if err := unix.Mount(device, mountPoint, "ext4", unix.O_RDWR, ""); err != nil {
				logrus.Errorf("error mount %s to %s, err: %v", device, mountPoint, err)
				time.Sleep(10 * time.Millisecond)
				break // retry
			}
			logrus.Infof("success mount %s to %s", device, mountPoint)
			return nil
		}
	}

	return fmt.Errorf("failed to get device and mount for %s", dir)
}

func (di *DadiIscsiDev) UnmountAndDestoryDev(dir, mountPoint string) error {
	idStr, _ := getTrimStringFromFile(path.Join(dir, "devid"))
	naaStr, _ := getTrimStringFromFile(path.Join(dir, "devnaa"))

	err := unix.Unmount(mountPoint, unix.MNT_DETACH)
	if err != nil {
		logrus.Warnf("error umount loopback device %s, err: %v", mountPoint, err)
		// return err
	}

	loopDir := fmt.Sprintf("/sys/kernel/config/target/loopback/%s", naaStr)

	err = os.RemoveAll(path.Join(loopDir, "tpgt_1", "lun", "lun_0", "dev_"+idStr))
	if err != nil {
		logrus.Errorf("error remote loopback link %v", err)
		return err
	}

	err = os.RemoveAll(path.Join(loopDir, "tpgt_1", "lun", "lun_0"))
	if err != nil {
		logrus.Errorf("error remove loopback lun0 %v", err)
		return err
	}

	err = os.RemoveAll(path.Join(loopDir, "tpgt_1"))
	if err != nil {
		logrus.Errorf("error remove loopback tgpt %v", err)
		return err
	}

	err = os.RemoveAll(loopDir)
	if err != nil {
		logrus.Errorf("error remove loopback %v", err)
		return err
	}

	devDir := fmt.Sprintf("/sys/kernel/config/target/core/user_%d/dev_%s", hbaNum, idStr)
	err = os.RemoveAll(devDir)
	if err != nil {
		logrus.Errorf("error remove target %v", err)
		return err
	}
	return nil
}

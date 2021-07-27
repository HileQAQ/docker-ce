package zdfs

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os/exec"
	"strconv"

	// "os"
	"path"
	"strings"

	"github.com/opencontainers/go-digest"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	// "github.com/docker/docker/pkg/fileutils"
	"github.com/docker/docker/pkg/idtools"
)

var mylog *MyLog

type DevConfigLower struct {
	Dir    string        `json:"dir,omitempty"`
	Digest digest.Digest `json:"digest,omitempty"`
	Size   uint64        `json:"size,omitempty"`
}
type DevConfigUpper struct {
	Index string `json:"index"`
	Data  string `json:"data"`
}
type DevConfig struct {
	RepoBlobURL string           `json:"repoBlobUrl"`
	Lowers      []DevConfigLower `json:"lowers"`
	Upper       DevConfigUpper   `json:"upper,omitempty"`
	ResultFile  string           `json:"resultFile"`
}

const (
	overlaybdBaseLayerDir = "/opt/overlaybd/baselayers"
	overlaybdCreate       = "/opt/overlaybd/bin/overlaybd-create"
	dataFile              = ".data_file"  //top layer data file for lsmd
	idxFile               = ".data_index" //top layer index file for lsmd
	iNewFormat            = ".aaaaaaaaaaaaaaaa.lsmt"
	zdfsChecksumFile      = ".checksum_file"
	zdfsOssurlFile        = ".oss_url"
	zdfsOssDataSizeFile   = ".data_size"
	zdfsOssTypeFile       = ".type"
	zdfsMetaDir           = "zdfsmeta"
	zdfsBaseLayer         = "/opt/lsmd/zdfsBaseLayer"
)

func IsZdfsLayerInApplyDiff(idDir, parent, parentDir string) bool {
	var checkDir string
	if parent == "" {
		checkDir = getDiffDir(idDir)
	} else {
		checkDir = getMetaDir(parentDir)
	}

	return hasZdfsFlagFiles(checkDir, true)
}

func ApplyDiff(idDir, parent string, rootUID, rootGID int) error {
	mylog.Infof("LSMD enter ApplyDiff(idDir:%s,..)", idDir)
	defer func() {
		mylog.Infof("LSMD leave ApplyDiff(idDir:%s,..)", idDir)
	}()

	metaDir := getMetaDir(idDir)
	if err := idtools.MkdirAndChown(metaDir, 0755, idtools.Identity{UID: rootUID, GID: rootGID}); err != nil {
		return err
	}
	if err := copyMetaFiles(getDiffDir(idDir), metaDir); err != nil {
		return err
	}

	configJSON := DevConfig{
		Lowers: []DevConfigLower{},
	}
	if parent == "" {
		configJSON.Lowers = append(configJSON.Lowers, DevConfigLower{
			Dir: overlaybdBaseLayerDir,
		})
	} else {
		parentConfJSON, err := loadOverlaybdConfig(parent)
		if err != nil {
			return err
		}
		configJSON.RepoBlobURL = parentConfJSON.RepoBlobURL
		configJSON.Lowers = parentConfJSON.Lowers
	}

	url, err := getTrimStringFromFile(path.Join(metaDir, zdfsOssurlFile))
	if err != nil {
		return err
	}
	idx := strings.LastIndex(url, "/")
	if !strings.HasPrefix(url[idx+1:], "sha256") {
		return fmt.Errorf("Can't parse sha256 from url %s", url)
	}

	str, err := getTrimStringFromFile(path.Join(metaDir, zdfsOssDataSizeFile))
	if err != nil {
		return err
	}
	size, _ := strconv.ParseUint(str, 10, 64)

	if configJSON.RepoBlobURL == "" {
		configJSON.RepoBlobURL = url[0:idx]
	}
	lowerDigest, _ := digest.Parse(url[idx+1:])
	configJSON.Lowers = append(configJSON.Lowers, DevConfigLower{
		Digest: lowerDigest,
		Size:   size,
		Dir:    path.Join(metaDir, zdfsMetaDir),
	})

	return atomicWriteOverlaybdTargetConfig(idDir, &configJSON)
}

func atomicWriteOverlaybdTargetConfig(dir string, configJSON *DevConfig) error {
	data, err := json.Marshal(configJSON)
	if err != nil {
		return errors.Wrapf(err, "failed to marshal %+v configJSON into JSON", configJSON)
	}

	confPath := overlaybdConfPath(dir)
	if err := continuity.AtomicWriteFile(confPath, data, 0600); err != nil {
		return errors.Wrapf(err, "failed to commit the overlaybd config on %s", confPath)
	}
	return nil
}

func loadOverlaybdConfig(dir string) (*DevConfig, error) {
	confPath := overlaybdConfPath(dir)
	data, err := ioutil.ReadFile(confPath)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to read config(path=%s) of snapshot %s", confPath, dir)
	}

	var configJSON DevConfig
	if err := json.Unmarshal(data, &configJSON); err != nil {
		return nil, errors.Wrapf(err, "failed to unmarshal data(%s)", string(data))
	}

	return &configJSON, nil
}

func Create(id, parent, idDir, parentDir string, rootUID, rootGID int) error {
	mylog.Infof("DADI enter Create(id:%s, parent:%s, idDir:%s, parentDir:%s, rootUID:%d, rootGID:%d)", id, parent, idDir, parentDir, rootUID, rootGID)
	defer func() {
		mylog.Infof("DADI leave Create(id:%s)", id)
	}()

	// image layer
	if strings.HasSuffix(id, "-init") == false && strings.HasSuffix(parent, "-init") == false {
		return nil
	}

	// container layer
	metaDir := getMetaDir(idDir)
	if err := idtools.MkdirAndChown(metaDir, 0755, idtools.Identity{UID: rootUID, GID: rootGID}); err != nil {
		return err
	}

	// create rwlayer for init layer
	if strings.HasSuffix(id, "-init") {
		err := createRWLayer(idDir)
		if err != nil {
			return err
		}
		// create config file
		parentConfJSON, err := loadOverlaybdConfig(parentDir)
		if err != nil {
			return err
		}
		var configJSON DevConfig
		configJSON.RepoBlobURL = parentConfJSON.RepoBlobURL
		configJSON.Lowers = parentConfJSON.Lowers
		configJSON.Upper = DevConfigUpper{
			Index: path.Join(metaDir, idxFile),
			Data:  path.Join(metaDir, dataFile),
		}
		configJSON.ResultFile = path.Join(metaDir, "result")
		atomicWriteOverlaybdTargetConfig(idDir, &configJSON)
	}

	return ioutil.WriteFile(path.Join(metaDir, iNewFormat), []byte(" "), 0666)
}

func Get(idDir string) (string, error) {
	mylog.Infof("LSMD enter Get(idDir:%s)", idDir)
	defer func() {
		mylog.Infof("LSMD leave Get(idDir:%s)", idDir)
	}()

	initDir := idDir
	if !strings.HasSuffix(idDir, "-init") {
		initDir = idDir + "-init"
	}
	target := getDadiMerged(initDir)
	if err := idtools.MkdirAndChown(target, 0700, idtools.Identity{UID: rootUID, GID: rootGID}); err != nil {
		return "", err
	}
	err := CreateDeviceAndMount(getMetaDir(initDir), overlaybdConfPath(idDir), target)
	if err != nil {
		return "", err
	}
	return target, nil
}

func Put(idDir string) error {
	mylog.Infof("LSMD enter Put(idDir:%s)", idDir)
	defer func() {
		mylog.Infof("LSMD leave Put(idDir:%s)", idDir)
	}()

	if strings.HasSuffix(idDir, "-init") {
		// do nothing
		return nil
	}

	initDir := idDir + "-init"
	return UnmountAndDestoryDev(getMetaDir(initDir), getDadiMerged(initDir))
}

func createRWLayer(dir string) error {
	cmd := exec.Command("/opt/overlaybd/bin/overlaybd-create", path.Join(dir, dataFile), path.Join(dir, idxFile), "256")
	out, err := cmd.CombinedOutput()
	if err != nil {
		logrus.Errorf("overlaybd-create output: %s, err: %v", out, err)
		return err
	}
	return nil
}

func commit(dir string) error {
	dadiBlob := path.Join(dir, commitFile)
	commitCmd := exec.Command("/opt/overlaybd/bin/overlaybd-commit", path.Join(dir, dataFile), path.Join(dir, idxFile), dadiBlob)
	out, err := commitCmd.CombinedOutput()
	if err != nil {
		logrus.Errorf("overlaybd-commit output: %s, err: %v", out, err)
		return err
	}
	return nil
}

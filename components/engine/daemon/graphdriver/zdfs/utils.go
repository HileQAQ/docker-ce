package zdfs

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"

	"github.com/opencontainers/go-digest"
	"github.com/sirupsen/logrus"
)

var (
	stringIDRegexp = regexp.MustCompile(`^[a-f0-9]{64}(-init)?$`)
	rootDir        string
)

func DADIInit(root string) {
	rootDir = root
}

func getDiffDir(dir string) string {
	return path.Join(dir, "diff")
}

func getDadiMerged(dir string) string {
	return path.Join(dir, "zdfsmerged")
}

func getMetaDir(dir string) string {
	return path.Join(dir, "zdfsmeta")
}

func pathExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func overlaybdConfPath(dir string) string {
	return filepath.Join(dir, zdfsMetaDir, "config.v1.json")
}

func execCmd(str string) error {
	cmd := exec.Command("/bin/bash", "-c", str)
	out, err := cmd.CombinedOutput()
	if err != nil {
		mylog.Errorf("LSMD exec error cmdLind:%s, out:%s, err:%s", str, string(out), err)
	} else {
		mylog.Infof("LSMD exec cmdLind:%s, out:%s", str, string(out))
	}
	return err
}

func copyMetaFiles(srcDir, dstDir string) error {
	files := []string{zdfsOssurlFile, zdfsOssDataSizeFile, zdfsChecksumFile, iNewFormat, zdfsOssTypeFile}
	for _, name := range files {
		data, err := ioutil.ReadFile(path.Join(srcDir, name))
		if err != nil {
			return err
		}
		if err := ioutil.WriteFile(path.Join(dstDir, name), data, 0666); err != nil {
			return err
		}
	}
	return nil
}

// MyLog ...
type MyLog struct {
}

func (my *MyLog) Debugf(format string, v ...interface{}) {
	logrus.Debugf("DEBUG %s", logStr(format, v...))
}

func (my *MyLog) Infof(format string, v ...interface{}) {
	logrus.Infof("INFO %s", logStr(format, v...))
}

func (my *MyLog) Warnf(format string, v ...interface{}) {
	logrus.Warnf("WARN %s", logStr(format, v...))
}

func (my *MyLog) Errorf(format string, v ...interface{}) {
	logrus.Errorf("ERROR %s", logStr(format, v...))
}

func logStr(format string, v ...interface{}) string {
	module := "[DADI]"
	if _, file, line, ok := runtime.Caller(2); ok {
		if i := strings.LastIndex(file, "/"); i > 0 {
			file = file[i+1:]
		}
		return fmt.Sprintf(module+file+":"+strconv.Itoa(line)+" "+format, v...)
	} else {
		return fmt.Sprintf(module+format, v...)
	}
}

func IsNewZdfsLayer(dir string) bool {
	fileNames := []string{iNewFormat, zdfsCommitFile}
	checkPathExist(path.Join(dir, iNewFormat))
	checkPathExist(path.Join(dir, zdfsCommitFile))
	for _, name := range fileNames {
		if !pathExists(path.Join(dir, name)) {
			return false
		}
	}
	return true
}

//Can call this func only after first layer is downloaded and zdfsmeta dir has been created.
func IsZdfsLayer(dir string) bool {
	return hasZdfsFlagFiles(getMetaDir(dir), false)
}

func hasZdfsFlagFiles(dir string, inApplyDiff bool) bool {
	fileNames := []string{iNewFormat}
	if inApplyDiff {
		fileNames = []string{iNewFormat}
	}
	for _, name := range fileNames {
		if !pathExists(path.Join(dir, name)) {
			return false
		}
	}
	return true
}

func getTrimStringFromFile(filePath string) (string, error) {
	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		mylog.Errorf("LSMD ERROR ioutil.ReadFile(%s) err:%s", filePath, err)
		return "", err
	}
	return strings.Trim(string(data), " \n"), nil //Trim函数会把string中首位含有的\n 空格字符都去掉。比如:"\n zxcvg  \n" --> "zxcvg"; " 1233 \n abc \n " --> "1233 \n abc",注意string当中的空格与\n不会去除
}

func GetSha256FromOssurlFile(ossUrlFilePath string) (string, error) {
	url, err := getTrimStringFromFile(ossUrlFilePath)
	if err != nil {
		return "", err
	}
	strs := strings.Split(url, ":")
	if len(strs) < 3 {
		return "", fmt.Errorf("can't parse sha256 from url %s, invalid url", url)
	}

	if !strings.HasSuffix(strs[len(strs)-2], "/sha256") {
		return "", fmt.Errorf("can't parse sha256 from url %s, invalid url", url)
	}

	return strs[len(strs)-1], nil
}

func GetMetaInfo(dir string) (string, string, error) {
	digest, err := GetSha256FromOssurlFile(path.Join(dir, zdfsMetaDir, zdfsOssurlFile))
	if err != nil {
		return "", "", err
	}
	size, err := getTrimStringFromFile(path.Join(dir, zdfsMetaDir, zdfsOssDataSizeFile))
	if err != nil {
		return "", "", err
	}
	return digest, size, nil
}

func moveFiles(srcDir, dstDir string, files []string) error {
	mylog.Infof("enter-> moveFiles(src: %s, dst: %s)", srcDir, dstDir)
	defer func() {
		mylog.Infof("<-leave moveFiles(src: %s, dst: %s)", srcDir, dstDir)
	}()
	for _, name := range files {
		data, err := ioutil.ReadFile(path.Join(srcDir, name))
		if err != nil {
			mylog.Errorf("read error! : %v", err)
			return err
		}
		if err := ioutil.WriteFile(path.Join(dstDir, name), data, 0666); err != nil {
			mylog.Errorf("write error! : %v", err)
			return err
		}
		if err := os.Remove(path.Join(srcDir, name)); err != nil {
			mylog.Errorf("del error! : %v", err)
			return err
		}
		mylog.Infof("move success: %s", name)
	}
	return nil
}

func compress(dir string) (digest.Digest, int64, error) {
	mylog.Infof("enter-> compress(dir: %s)", dir)
	defer func() {
		mylog.Infof("<-leave compress(dir: %s)", dir)
	}()
	dadiBlob := path.Join(dir, zdfsCommitFile)
	compressed := path.Join(dir, zdfsCommitFileComp)
	cmd := exec.Command("/opt/overlaybd/bin/overlaybd-zfile", dadiBlob, compressed)
	out, err := cmd.CombinedOutput()
	if err != nil {
		logrus.Errorf("overlaybd-commit output: %s, err: %v", out, err)
		return "", 0, err
	}
	file, err := os.Open(compressed)
	if err != nil {
		return "", 0, err
	}
	defer file.Close()

	h := sha256.New()
	size, err := io.Copy(h, file)
	if err != nil {
		return "", 0, err
	}
	dgst := digest.NewDigest(digest.SHA256, h)

	return dgst, size, nil
}

// generate .aaaaaaaaaaaaaaaa.lsmt, .oss_url, .type, .checksum, .data_size in idDir/diff
// generate .commit in idDir/meta
func generateCommit(idDir string) (string, error) {
	metaDir := getMetaDir(idDir)
	diffDir := getDiffDir(idDir)
	mylog.Infof("enter-> generateCommit(idDir: %s)", metaDir)
	defer func() {
		mylog.Infof("<-leave generateCommit(idDir: %s)", metaDir)
	}()
	// create .commit
	if err := commit(metaDir); err != nil {
		mylog.Errorf("Create .commit failed")
		return "", err
	}
	// Compress .commit_file.zfile
	dgst, size, err := compress(metaDir)
	if err != nil {
		mylog.Errorf("Compress .commit_file.zfile failed")
		return "", err
	}
	// delete .commit
	if err := os.Remove(path.Join(metaDir, zdfsCommitFile)); err != nil {
		mylog.Errorf("del error! : %v", err)
		return "", err
	}
	// rename .commit
	if err := os.Rename(path.Join(metaDir, zdfsCommitFileComp), path.Join(metaDir, zdfsCommitFile)); err != nil {
		mylog.Errorf("rename failed: %v", err)
		return "", err
	} else {
		mylog.Infof("rename success: %s to %s", path.Join(metaDir, zdfsCommitFileComp), zdfsCommitFile)
	}

	// iNewFormat
	err = ioutil.WriteFile(path.Join(diffDir, iNewFormat), []byte(" "), 0666)
	if err != nil {
		return "", err
	}

	// oss_url
	url := string(dgst)
	mylog.Infof("oss_url: %s", url)
	var ossUrl string
	tmpDir := idDir
	for !pathExists(path.Join(tmpDir, "zdfsmeta", zdfsOssurlFile)) {
		pDir, err := ioutil.ReadFile(path.Join(tmpDir, "parent"))
		if err != nil {
			return "", err
		}
		mylog.Infof("pDir: %s", pDir)
		tmpDir = string(pDir)
	}
	data, err := ioutil.ReadFile(path.Join(tmpDir, "zdfsmeta", zdfsOssurlFile))
	tmp := string(data)
	mylog.Infof("oss_url_t: %s", tmp)
	ossUrl = tmp[:strings.Index(tmp, "sha256:")] + url
	mylog.Infof("ossurl: %s, ossdir: %s", ossUrl, path.Join(diffDir, zdfsOssurlFile))
	err = ioutil.WriteFile(path.Join(diffDir, zdfsOssurlFile), []byte(ossUrl), 0666)
	if err != nil {
		return "", err
	}

	// checksum file
	blob := path.Join(metaDir, zdfsCommitFile)
	cmd := exec.Command("/opt/overlaybd/bin/zchecksum", "generate", "-s 262144", blob, path.Join(diffDir, zdfsChecksumFile))
	output, err := cmd.CombinedOutput()
	if err != nil {
		mylog.Errorf("overlaybd-checksum output: %s, ", string(output))
		return "", err
	}

	// size
	err = ioutil.WriteFile(path.Join(diffDir, zdfsOssDataSizeFile), []byte(strconv.FormatUint(uint64(size), 10)), 0666)
	if err != nil {
		return "", err
	}

	// type
	if err := ioutil.WriteFile(path.Join(diffDir, zdfsOssTypeFile), []byte("oss"), 0666); err != nil {
		return "", err
	}

	return url[7:], nil
}

func GetLayerCacheDir(chainID string) (string, error) {
	dgst := digest.Digest(chainID)
	imgdbDir := path.Join(rootDir, "image", "overlay2", "layerdb")
	layerPath := path.Join(imgdbDir, string(dgst.Algorithm()), dgst.Hex())
	file := path.Join(layerPath, "cache-id")
	logrus.Infof("LSMD GetLayerCacheDir cache-id: %s", file)
	contentBytes, err := ioutil.ReadFile(file)
	if err != nil {
		return "", err
	}
	content := strings.TrimSpace(string(contentBytes))

	if !stringIDRegexp.MatchString(content) {
		return "", errors.New("invalid cache id value")
	}
	logrus.Infof("LSMD GetLayerCacheDir : %s", path.Join(rootDir, "overlay2", content))
	return path.Join(rootDir, "overlay2", content), nil
}

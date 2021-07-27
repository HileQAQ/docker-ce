package zdfs

import (
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"github.com/sirupsen/logrus"
)

func getDiffDir(dir string) string {
	return path.Join(dir, "diff")
}

func getDadiMerged(dir string) string {
	return path.Join(dir, dadiMerged)
}

func getMetaDir(dir string) string {
	return path.Join(dir, dadiMetaDir)
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
	files := []string{zdfsOssurlFile, zdfsOssDataSizeFile, zdfsChecksumFile, iNewFormat}
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

//Can call this func only after first layer is downloaded and zdfsmeta dir has been created.
func IsZdfsLayer(dir string) bool {
	return hasZdfsFlagFiles(getMetaDir(dir), false)
}

func hasZdfsFlagFiles(dir string, inApplyDiff bool) bool {
	fileNames := []string{iNewFormat}
	if inApplyDiff {
		fileNames = []string{iNewFormat, zdfsChecksumFile, zdfsOssurlFile, zdfsOssDataSizeFile, zdfsOssTypeFile}
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

func getSha256FromOssurlFile(ossUrlFilePath string) (string, error) {
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

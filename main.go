package main

import "C"
import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"flag"
	"fmt"
	bpf "github.com/aquasecurity/libbpfgo"
	"github.com/aquasecurity/libbpfgo/helpers"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"
	"unsafe"
)

var secFunc map[string]string
var addrFunc map[uint64]string

func main() {
	// 定义命令行参数
	binaryPath := flag.String("binaryPath", "", "二进制路径")
	// 定义命令行参数
	packageName := flag.String("packageName", "", "包名")
	// 解析命令行参数
	flag.Parse()

	// 输出解析后的值
	fmt.Println("二进制路径:", *binaryPath)
	if *binaryPath == "" || *packageName == "" {
		os.Exit(1)
	}
	secFunc = make(map[string]string)
	addrFunc = make(map[uint64]string)
	os.Remove("./main.bpf.c")
	openFile, err := os.OpenFile("./main.bpf.c", os.O_RDWR|os.O_CREATE, os.ModePerm)
	if err != nil {
		panic(err)
	}
	file, err := ioutil.ReadFile("./template")
	if err != nil {
		panic(err)
	}
	openFile.Write(file)
	symbols := symbol(*binaryPath, *packageName)
	for _, item := range symbols {
		sec, originName := generationSec(item)
		_, err := openFile.WriteString(sec)
		if err != nil {
			panic(err)
		}
		if _, ok := secFunc[item]; ok {
			panic("multi same func")
		}
		secFunc[item] = originName
	}
	openFile.Close()
	cmd := exec.Command("bash", "-c", "make c2bpf")
	// 将命令的输出连接到当前进程的标准输出
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	// 执行命令
	err = cmd.Run()
	if err != nil {
		log.Fatal(err)
	}

	// 加载ebpf程序
	bpfModule, err := bpf.NewModuleFromFile("main.bpf.o")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}
	defer bpfModule.Close()
	bpfModule.BPFLoadObject()
	for oringinName, funcName := range secFunc {
		prog, err := bpfModule.GetProgram(funcName)
		if err != nil {
			fmt.Fprintln(os.Stderr, err, "GetProgram:", oringinName)
			os.Exit(-1)
		}
		offset, err := helpers.SymbolToOffset(*binaryPath, oringinName)
		if err != nil {
			fmt.Fprintln(os.Stderr, err, "SymbolToOffset:", oringinName)
			os.Exit(-1)
		}
		_, err = prog.AttachUprobe(-1, *binaryPath, offset)
		if err != nil {
			fmt.Fprintln(os.Stderr, err, "AttachUprobe:", oringinName)
			os.Exit(-1)
		}
	}
	go func() {
		http.Handle("/", http.FileServer(http.Dir("./dist/")))
		http.ListenAndServe(":3000", nil)
	}()
	hashMap, err := bpfModule.GetMap("hash_map")
	if err != nil {
		panic(err)
	}
	for {
		iterator := hashMap.Iterator()
		for iterator.Next() {
			value, err := hashMap.GetValue(unsafe.Pointer(&iterator.Key()[0]))
			if err != nil {
				panic(err)
			}
			var obj chownEvent
			u := binary.LittleEndian.Uint64(iterator.Key())
			err = binary.Read(bytes.NewBuffer(value), binary.LittleEndian, &obj)
			if err != nil {
				fmt.Printf("failed to decode received data: %s\n", err)
				continue
			}
			comm := (*C.char)(unsafe.Pointer(&obj.Comm))
			fmt.Printf("Pid:%d Time:%d Comm:%s FuncName:%s size:%d\n", obj.Pid, u, C.GoString(comm), addrFunc[obj.FuncAddr], obj.Size)
			err = hashMap.DeleteKey(unsafe.Pointer(&iterator.Key()[0]))
			if err != nil {
				panic(err)
			}
		}
		time.Sleep(time.Second * 1)
	}
	//eventsChannel := make(chan []byte)
	//rb, err := bpfModule.InitRingBuf("sys_enter_rss_maps", eventsChannel)
	//if err != nil {
	//	fmt.Fprintln(os.Stderr, err)
	//	os.Exit(-1)
	//}
	//
	//rb.Start()
	//defer rb.Close()
	//defer rb.Stop()
	//
	//for {
	//	var obj chownEvent
	//	event := <-eventsChannel
	//
	//	err := binary.Read(bytes.NewBuffer(event), binary.LittleEndian, &obj)
	//	if err != nil {
	//		fmt.Printf("failed to decode received data: %s\n", err)
	//		continue
	//	}
	//	comm := (*C.char)(unsafe.Pointer(&obj.Comm))
	//	fmt.Printf("Pid:%d Time:%d Comm:%s FuncName:%x size:%d\n", obj.Pid, obj.Time, C.GoString(comm), obj.FuncAddr, obj.Size)
	//}

}

type chownEvent struct {
	Pid      uint32
	TGid     uint32
	Time     int64
	Size     uint64
	FuncAddr uint64
	Comm     [16]byte
}

func convertToValidCFunctionName(str string) string {
	// 创建正则表达式模式，匹配所有非字母和非数字的字符
	reg := regexp.MustCompile(`[^a-zA-Z0-9]`)

	// 将符号字符替换为相同数量的下划线
	replacedStr := reg.ReplaceAllStringFunc(str, func(match string) string {
		return strings.Repeat("_", len(match))
	})

	return replacedStr
}

func generationSec(funcName string) (string, string) {
	name := convertToValidCFunctionName(funcName)
	sprintf := fmt.Sprintf("SEC(\"uprobe/%s\")\nint %s(struct pt_regs *ctx)\n{\n    return get_rss_stat(ctx);\n}\n", funcName, name)
	return sprintf, name
}

func symbol(binaryPath, projName string) []string {
	res := make([]string, 0)
	f, err := elf.Open(binaryPath)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()

	// 获取符号表
	symbols, err := f.Symbols()
	if err != nil {
		log.Fatal(err)
	}
	// 遍历符号表并打印方法符号
	for _, sym := range symbols {
		if sym.Section == 0x01 && sym.Info == 0x012 {
			if strings.HasPrefix(sym.Name, projName) {
				res = append(res, sym.Name)
				addrFunc[sym.Value] = sym.Name
			}
		}
	}
	return res
}

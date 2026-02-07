//
// (/bin/rm go.{mod,sum}; go mod init example/user/test17; go mod tidy)
// (echo "vet:"; go vet || exit 1; echo "build:"; go build -o test17 *.go; ./test17)
//

package main

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"time"
)

var (
	kubeconfig    = "/home/OpenShift/git/hamzy-installer/ocp-test-mad02/.clusterapi_output/envtest.kubeconfig"
	ptrKubeconfig = &kubeconfig
)

func runPipe(acmdline1 []string, acmdline2 []string) {
	var (
		ctx       context.Context
		cancel    context.CancelFunc
		cmd1      *exec.Cmd
		cmd2      *exec.Cmd
		buffer    bytes.Buffer
		out       []byte
		err       error
	)

	ctx, cancel = context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	fmt.Printf("acmdline1 = %s\n", acmdline1)
	fmt.Printf("acmdline2 = %s\n", acmdline2)

	if len(acmdline1) == 0 {
		panic(fmt.Errorf("runTwoCommands has empty command"))
	} else if len(acmdline1) == 1 {
		cmd1 = exec.CommandContext(ctx, acmdline1[0])
	} else {
		cmd1 = exec.CommandContext(ctx, acmdline1[0], acmdline1[1:]...)
	}

	cmd1.Env = append(
		os.Environ(),
		fmt.Sprintf("KUBECONFIG=%s", *ptrKubeconfig),
	)

	if len(acmdline2) == 0 {
		panic(fmt.Errorf("runTwoCommands has empty command"))
	} else if len(acmdline2) == 1 {
		cmd2 = exec.CommandContext(ctx, acmdline2[0])
	} else {
		cmd2 = exec.CommandContext(ctx, acmdline2[0], acmdline2[1:]...)
	}

	readPipe, writePipe, err := os.Pipe()
	if err != nil {
		panic(fmt.Errorf("Error os.Pipe"))
	}

	defer readPipe.Close()

	cmd1.Stdout = writePipe

	err = cmd1.Start()
	if err != nil {
		panic(fmt.Errorf("Error cmd1.Start"))
	}

	defer cmd1.Wait()

	writePipe.Close()

	cmd2.Stdin = readPipe
	cmd2.Stdout = &buffer
	cmd2.Stderr = &buffer

	cmd2.Run()

	out = buffer.Bytes()

	fmt.Println(string(out))
}

func main() {
	runPipe(
		[]string{ "oc", "get", "ibmpowervscluster", "-n", "openshift-cluster-api-guests", "-o", "json" },
		[]string{ "jq", "-r", ".items[].status.conditions[]" },
	)

if false {
	runPipe(
		[]string{ "echo", "{\"items\": []}" },
		[]string{ "jq", "-r", ".items" },
	)

	runPipe(
		[]string{ "echo", "{\"items\": []}" },
		[]string{ "jq", "-r", ".items.status" },
	)

	runPipe(
		[]string{ "echo", "{\"items\": []}" },
		[]string{ "jq", "-r", ".items.status.conditions[]" },
	)
}
}

module example/user/test9

go 1.21.4

replace github.com/ppc64le-cloud/powervs-utils => /home/OpenShift/git/hamzy-powervs-utils

require (
	github.com/ppc64le-cloud/powervs-utils v0.0.0-00010101000000-000000000000
	github.com/sirupsen/logrus v1.9.3
)

require (
	golang.org/x/sys v0.15.0 // indirect
	k8s.io/apimachinery v0.29.1 // indirect
)

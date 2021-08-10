module github.com/hashicorp/boundary/api

go 1.15

replace github.com/hashicorp/boundary/sdk => ../sdk

require (
	github.com/fatih/structs v1.1.0
	github.com/hashicorp/boundary/sdk v0.0.7-0.20210810184454-a7e681b82392
	github.com/hashicorp/go-cleanhttp v0.5.2
	github.com/hashicorp/go-kms-wrapping/v2 v2.0.0-20210810171353-2a298deaeb2d
	github.com/hashicorp/go-retryablehttp v0.6.8
	github.com/hashicorp/go-rootcerts v1.0.2
	github.com/hashicorp/go-secure-stdlib/parseutil v0.1.1
	github.com/stretchr/testify v1.7.0
	golang.org/x/time v0.0.0-20200630173020-3af7569d3a1e
	google.golang.org/grpc v1.38.0
)

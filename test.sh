export GOARCH=386
go test -v -count=1 ./runtime/...
export GOARCH=amd64
go test -v -count=1 ./runtime/...
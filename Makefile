default: windows

windows:
	export GOOS=windows GOARCH=amd64;go build -ldflags "-s -w" -o offsetfinder.exe main.go
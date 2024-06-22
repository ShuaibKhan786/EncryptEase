# Variables for the build process
GO = go build
GO_FLAGS = -ldflags="-s -w" -o
TARGET = EncryptEase
SOURCE = ./src/main.go

WIN64_TARGET = ./precompiledbin/windows/64bitarch
LINUX64_TARGET = ./precompiledbin/linux/64bitarch
MAC64_TARGET = ./precompiledbin/mac/64bitarch
MACARM_TARGET = ./precompiledbin/mac/armbitarch

# Determine the OS and Architecture
UNAME_S := $(shell uname -s)
UNAME_M := $(shell uname -m)

# Targets for different platforms and architectures
.PHONY: all clean windows linux macos macos_m1

all: windows linux macos macos_m1

# Ensure target directories exist
$(WIN64_TARGET) $(LINUX64_TARGET) $(MAC64_TARGET) $(MACARM_TARGET):
	mkdir -p $@

# Windows 64-bit
windows: $(WIN64_TARGET)
	GOOS=windows GOARCH=amd64 $(GO) $(GO_FLAGS) $(WIN64_TARGET)/$(TARGET).exe $(SOURCE)

# Linux 64-bit
linux: $(LINUX64_TARGET)
	GOOS=linux GOARCH=amd64 $(GO) $(GO_FLAGS) $(LINUX64_TARGET)/$(TARGET) $(SOURCE)

# macOS 64-bit (Intel)
macos: $(MAC64_TARGET)
	GOOS=darwin GOARCH=amd64 $(GO) $(GO_FLAGS) $(MAC64_TARGET)/$(TARGET) $(SOURCE)

# macOS (M1, ARM)
macos_m1: $(MACARM_TARGET)
	GOOS=darwin GOARCH=arm64 $(GO) $(GO_FLAGS) $(MACARM_TARGET)/$(TARGET) $(SOURCE)



# Clean up the build artifacts
clean:
	rm -f $(WIN64_TARGET)/$(TARGET).exe
	rm -f $(LINUX64_TARGET)/$(TARGET)
	rm -f $(MAC64_TARGET)/$(TARGET)
	rm -f $(MACARM_TARGET)/$(TARGET)

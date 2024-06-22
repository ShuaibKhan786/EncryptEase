#!/bin/bash

wrong_cmd() {
    echo "Usage: sh script.sh -build / sh script.sh -prebuild / sh script.sh -upgrade"
    echo -e "\t-build: compile and install"
    echo -e "\t-prebuild: direct install with pre-compiled binary"
    echo -e "\t-upgrade: update to the latest version"
}

check_something_install() {
    if command -v "$1" &> /dev/null; then
        return 0
    else
        return 1
    fi
}

run_build_command() {
    # Create a directory for storing the executable file temporarily
    mkdir -p temp

    # Compile the code into a final executable file
    go build -ldflags="-s -w" -o temp/EncryptEase ./src/main.go

    # Check if the build was successful
    if [ $? -ne 0 ]; then
        echo "Build failed"
        rm -rf temp
        exit 1
    fi

    # Copy the executable file to /usr/local/bin
    sudo cp temp/EncryptEase /usr/local/bin

    # Change the file permission to make it executable
    sudo chmod +x /usr/local/bin/EncryptEase

    rm -rf temp
}

run_prebuild_command() {
    if check_something_install "EncryptEase"; then
        echo -e "\nEncryptEase already installed"
        exit 1
    fi

    os="$(uname -s)"
    arch="$(uname -m)"

    precompiledPath=""

    case $os in 
        "Linux")
            precompiledPath="./precompiledbin/linux/64bitarch/EncryptEase"
            ;;
        "Darwin")
            case $arch in
                "x86_64")
                    precompiledPath="./precompiledbin/mac/64bitarch/EncryptEase"
                    ;;
                "arm64")
                    precompiledPath="./precompiledbin/mac/armbitarch/EncryptEase"
                    ;;
                *)
                    echo -e "\nOther Mac architecture is not supported"
                    exit 1
                ;;
            esac
            ;;
        *)
            echo -e "\nprecompiled install is for  linux and macOS only"
            ;;
    esac

    if [ ! -f "$precompiledPath" ]; then
        echo -e "\nPrecompiled binary not found at $precompiledPath"
        exit 1
    fi

    sudo cp $precompiledPath /usr/local/bin

    sudo chmod +x /usr/local/bin/EncryptEase
}

common_message() {
    echo -e "\nSuccessfully upgraded EncryptEase"
    echo -e "\nRun:\n\tEncryptEase"
}

upgrade_command() {
    if ! check_something_install "EncryptEase"; then
        echo -e "\nEncryptEase is not installed"
        echo "Try a fresh installation:"
        echo -e "\nRun:\n\t./script.sh -build"
        exit 1
    fi

    if check_something_install "go"; then
        echo -e "\nPulling latest code from repository..."
        git pull

        sudo rm /usr/local/bin/EncryptEase

        if [ $? -ne 0 ]; then
            echo -e "\nRemoval failed"
            exit 1
        else
            run_build_command
            common_message
        fi
    else
        echo -e "\nGo is not installed, precompiled implementation coming soon."
    fi
}

# Main script logic
if [ $# -lt 1 ]; then
    wrong_cmd
    exit 1
fi

case "$1" in
    "-build")
        if check_something_install "EncryptEase"; then
            echo -e "\nEncryptEase is already installed"
            exit 1
        fi

        if check_something_install "go"; then
            run_build_command
            common_message
        else
            echo -e "\nGo is not installed"
            exit 1
        fi
        ;;
    "-prebuild")
        run_prebuild_command
        common_message
        ;;
    "-upgrade")
        upgrade_command
        ;;
    *)
        wrong_cmd
        exit 1
        ;;
esac


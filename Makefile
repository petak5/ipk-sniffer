# File: Makefile
# Author: Peter Urgos (xurgos00)
# Date: 25. 4. 2021


all: build-linux

build-linux:
	dotnet publish -r linux-x64 /p:PublishSingleFile=true && cp ./ipk-sniffer/bin/Debug/netcoreapp3.1/linux-x64/publish/ipk-sniffer ./program

build-osx:
	dotnet publish -r osx-x64 /p:PublishSingleFile=true && cp ./ipk-sniffer/bin/Debug/netcoreapp3.1/osx-x64/publish/ipk-sniffer ./program

run:
	cd ./ipk-sniffer && dotnet run

tar:
	tar -cf xurgos00.tar Makefile README manual.pdf ipk-sniffer.sln ipk-sniffer/ipk-sniffer.csproj ipk-sniffer/Program.cs ipk-sniffer/ArgumentsParser.cs ipk-sniffer/Tools.cs

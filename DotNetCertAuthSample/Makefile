VERSION ?= 1.0.0

EZCACertManager.deb: clean build-staging
	dpkg-deb --root-owner-group --build ./staging_folder/ ./$@

build-staging: staging_folder build-app
	mkdir ./$</DEBIAN
	cp ./debian_files/control ./$</DEBIAN

	# Starter script
	mkdir -p ./$</usr/bin
	cp ./debian_files/EZCACertManager.sh ./$</usr/bin/EZCACertManager
	chmod +x ./$</usr/bin/EZCACertManager # set executable permissions to starter script

	# Other files
	mkdir -p ./$</usr/lib/EZCACertManager
	cp -f -a ./out/linux-x64/. ./$</usr/lib/EZCACertManager/ # copies all files from publish dir
	chmod -R a+rX ./$</usr/lib/EZCACertManager/ # set read permissions to all files
	chmod +x ./$</usr/lib/EZCACertManager/EZCACertManager # set executable permissions to main executable

.PHONY: build-app
build-app: out
	dotnet publish "./DotNetCertAuthSample/DotNetCertAuthSample.csproj" \
	  --verbosity quiet \
	  --nologo \
	  --configuration Release \
	  --self-contained true \
	  --framework net10.0 \
	  --runtime linux-x64 \
	  --output "./out/linux-x64" \
	  -p:Version=${VERSION} \

out:
	mkdir $@

staging_folder:
	mkdir $@

.PHONY: clean
clean:
	rm -rf ./EZCACertManager.deb ./out ./staging_folder/

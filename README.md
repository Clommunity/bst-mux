# bst-mux

**BST** is a multiuser backups and file sync service management system based on Syncthing, using Docker and Go.

## Development
BST is built on the [Gorilla-mux](http://www.gorillatoolkit.org/pkg/mux) framework for the web interface and [restangular](https://github.com/mgonto/restangular)

## Installation
__Install Docker__: follow the instructions at [Docker's web site](https://docs.docker.com/installation/).

__Install bst-mux__: clone this repository

__Prepare Docker__: run Dockerfile

__Prepare Directories__
```sh
	mkdir -p /home/syncthing/real
```

__Create synching user__
```sh
	adduser --home /home/syncthing --uid 22000 -g users --disable-password syncthing
```

__Change permisions__
```sh
	chown -R 22000 /home/syncthing
```

__Copy config.xml default__
```sh
	cp res/config.xml.orig /home/syncthing/config.xml
```

__Run bst-mux__
```sh
	go run main.go
```

## Setup

  The first user registed in the system belongs to the administration group (**admin**). Users belonging to this group can create, update and delete other users.

## Debian notes

### Docker installation
To install the latest version of Docker, type the following commands as root:
```
apt-get update; apt-get install curl
curl -sSL https://get.docker.com/ | sh
```
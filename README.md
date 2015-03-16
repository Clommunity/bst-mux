# bst-mux

Multiuser system for SyncThing, using Docker and Go.

## Dev
this version use [Gorilla-mux](http://www.gorillatoolkit.org/pkg/mux) to Router web request, and [restangular](https://github.com/mgonto/restangular) 

## Install

__Install Docker__: You can follow [Docker web site](https://docs.docker.com/installation/).

__Install bst-mux__: TODO

__Prepare Docker__: Execute Dockerfile ?

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

  The first user to registed in system has in admins group, this user can create, update, delete users.

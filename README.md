# bst-mux


Multiuser system for SyncThing, using Docker and Go.

## Dev
this version use [Gorilla-mux](http://www.gorillatoolkit.org/pkg/mux) to Router web request, and [restangular](https://github.com/mgonto/restangular) 

## Install

 * __Install Docker__: You can follow [Docker web site](https://docs.docker.com/installation/).

 * __Install bst-mux__: TODO

 * __Prepare Docker__: Execute Dockerfile ?

 * Prepare Directories
```sh
	mkdir -p /home/syncthing/real
``` 
 * Create synching user
```sh
	adduser --home /home/syncthing --uid 22000 -g users --disable-password syncthing
```
 * Change permisions
```sh
	chown -R 22000 /home/syncthing
``` 
 * Copy config.xml default
```sh
	cp res/config.xml.orig /home/syncthing/config.xml
``` 
 *  Run bst-mux
```sh
	go run main.go
``` 
## Setup

  The first user to registed in system has in admins group, this user can create, update, delete users.

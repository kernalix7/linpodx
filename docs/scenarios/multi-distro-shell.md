# Scenario — Multi-distro shells from one host

linpodx ships per-distro presets so you can drop into Ubuntu, Fedora, or Alpine with
one command — lighter than a VM, native to your desktop session.

## Available distro templates

```console
$ linpodx distro list
NAME       IMAGE                                 SIZE    DEFAULT_SHELL
ubuntu     docker.io/library/ubuntu:24.04        77MB    bash
fedora     registry.fedoraproject.org/fedora:40  189MB   bash
alpine     docker.io/library/alpine:3.19         8MB     ash
arch       docker.io/library/archlinux:base      414MB   bash
```

## 1. Spin up an ephemeral Ubuntu shell

```console
$ linpodx distro run ubuntu --rm
ubuntu@distro-ubuntu-9f2c:/# cat /etc/os-release
NAME="Ubuntu"
VERSION="24.04 LTS (Noble Numbat)"
...
ubuntu@distro-ubuntu-9f2c:/# apt list --installed 2>/dev/null | wc -l
98
ubuntu@distro-ubuntu-9f2c:/# exit
```

The `--rm` flag removes the container on exit. State (apt installs, files in `/home`)
is gone.

## 2. Persist a Fedora shell across sessions

```console
$ linpodx distro run fedora --name fedora-dev --persist
[fedora@distro-fedora-dev /]$ sudo dnf install -y vim git
...
Installed:
  vim-9.1.349-1.fc40.x86_64  git-2.45.2-1.fc40.x86_64
[fedora@distro-fedora-dev /]$ exit

$ linpodx distro shell fedora-dev   # later
[fedora@distro-fedora-dev /]$ which vim
/usr/bin/vim
```

`--persist` allocates a writable rootfs that survives `exit`. Resumed via
`linpodx distro shell <name>`.

## 3. Drop into Alpine for a 5-second test

```console
$ linpodx distro run alpine --rm -- sh -c 'wget -qO- ifconfig.me; echo'
203.0.113.42
```

The `--` separator passes the rest to the container's entrypoint. No interactive
shell is allocated.

## 4. List what's running

```console
$ linpodx ps
ID         NAME                       IMAGE             STATE     UPTIME
9f2c8a1c   distro-ubuntu-9f2c         ubuntu:24.04      exited    7m
4d11abef   distro-fedora-dev          fedora:40         running   2h
```

## 5. Mount your host project into the distro

```console
$ linpodx distro run ubuntu --rm \
    --mount type=bind,src=$HOME/projects/demo,dst=/work,ro \
    -- ls -la /work
total 32
drwxr-xr-x 5 1000 1000 4096 May  9 12:34 .
drwxr-xr-x 1 root root 4096 May 10 09:00 ..
drwxr-xr-x 8 1000 1000 4096 May  8 10:01 .git
-rw-r--r-- 1 1000 1000  421 May  8 10:01 README.md
-rw-r--r-- 1 1000 1000  830 May  9 12:34 Cargo.toml
drwxr-xr-x 2 1000 1000 4096 May  8 10:01 src
```

## 6. With systemd inside (Ubuntu / Fedora only)

```console
$ linpodx distro run fedora --name fedora-systemd --persist --systemd
[+] booting systemd inside container...
[fedora@distro-fedora-systemd /]$ systemctl --version
systemd 255 (255.4-1.fc40)
[fedora@distro-fedora-systemd /]$ sudo systemctl start nginx
[fedora@distro-fedora-systemd /]$ curl -s localhost:80 | head -1
<!DOCTYPE html>
```

`--systemd` enables the cgroup delegation Podman needs to pid-1 systemd cleanly. Not
supported by Alpine (no systemd in upstream).

## 7. Clean up

```console
$ linpodx distro rm fedora-dev
removed: fedora-dev
$ linpodx distro prune --exited
pruned: 1 container, freed 12MB
```

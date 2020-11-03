# tm - testbed manager
[![Build Status](https://travis-ci.org/micchie/tm.svg?branch=master)](https://travis-ci.org/micchie/tm)

## Installation
Assuming the group is set to the users of tm:
```
sudo cp tm.py /usr/local/bin/tm
sudo chmod 754 /usr/local/bin/tm
sudo mkdir /usr/local/tm
sudo chmod 775 /usr/local/tm
```

In Ubuntu 18.04
```
sudo cp tm-cleanup.* /lib/systemd/system/
```
In Ubuntu 20.04
```
sudo cp tm-cleanup.* /usr/lib/systemd/system/
```
```
sudo systemctl enable tm-cleanup.timer
sudo systemctl start tm-cleanup.timer
systemctl start list-timers
```
In the UNIT and ACTIVATES rows, tm-cleanup.timer and tm-cleanup.service should
appear, respectively.

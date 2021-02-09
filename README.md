# RouterSploit - Exploitation Framework for Embedded Devices

[![Python 3.6](https://img.shields.io/badge/Python-3.6-yellow.svg)](http://www.python.org/download/)
[![Build Status](https://travis-ci.org/threat9/routersploit.svg?branch=master)](https://travis-ci.org/threat9/routersploit)

The RouterSploit Framework is an open-source exploitation framework dedicated to embedded devices.

[![asciicast](https://asciinema.org/a/180370.png)](https://asciinema.org/a/180370)

It consists of various modules that aid penetration testing operations:

* exploits - modules that take advantage of identified vulnerabilities
* creds - modules designed to test credentials against network services
* scanners - modules that check if a target is vulnerable to any exploit
* payloads - modules that are responsible for generating payloads for various architectures and injection points
* generic - modules that perform generic attacks 

# Installation

## Requirements

Required:
* future
* requests
* paramiko
* pysnmp
* pycrypto

Optional:
* bluepy - Bluetooth low energy 

## Installation on Kali Linux

```
apt-get install python3-pip
git clone https://www.github.com/threat9/routersploit
cd routersploit
python3 -m pip install -r requirements.txt
python3 rsf.py
```

Bluetooth Low Energy support:
```
apt-get install libglib2.0-dev
python3 -m pip install bluepy
python3 rsf.py
```

## Installation on Ubuntu 20.04

```
sudo apt-get install git python3-pip
git clone https://github.com/threat9/routersploit
cd routersploit
python3 -m pip install -r requirements.txt
python3 rsf.py
```

Bluetooth Low Energy support:

```
sudo apt-get install libglib2.0-dev
python3 -m pip install bluepy
python3 rsf.py
```

## Installation on Ubuntu 18.04 & 17.10

```
sudo add-apt-repository universe
sudo apt-get install git python3-pip
git clone https://www.github.com/threat9/routersploit
cd routersploit
python3 -m pip install setuptools
python3 -m pip install -r requirements.txt
python3 rsf.py
```

Bluetooth Low Energy support:
```
apt-get install libglib2.0-dev
python3 -m pip install bluepy
python3 rsf.py
```


## Installation on OSX

```
git clone https://www.github.com/threat9/routersploit
cd routersploit
sudo python3 -m pip install -r requirements.txt
python3 rsf.py
```

## Running on Docker

```
git clone https://www.github.com/threat9/routersploit
cd routersploit
docker build -t routersploit .
docker run -it --rm routersploit
```

# Update

Update RouterSploit Framework often. The project is under heavy development and new modules are shipped almost every day.

```
cd routersploit
git pull
```

# Build your own
To our surprise, people started to fork 
[routersploit](https://github.com/threat9/routersploit) not because they were 
interested in the security of embedded devices but simply because they want to 
leverage our interactive shell logic and build their tools using similar 
concept. All these years they must have said: _"There must be a better way!"_ 
and they were completely right, the better way is called 
[_Riposte_](https://github.com/fwkz/riposte).

[_Riposte_](https://github.com/fwkz/riposte) allows you to easily wrap your 
application inside a tailored interactive shell. Common chores regarding 
building REPLs was factored out and being taken care of so you can 
focus on specific domain logic of your application.
# License

The RouterSploit Framework is under a BSD license.
Please see [LICENSE](LICENSE) for more details.

# Acknowledgments
* [riposte](https://github.com/fwkz/riposte)

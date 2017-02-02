# Udacity Full-Stack Nanodegree
## Project: Item Catalog

## Overview

This project implements a web application that provides a list of items within a variety of categories and integrates third-party user authorization and authentication.

## How to Run

You must have have Python, Vagrant and VirtualBox installed. This project uses a congfigured Vagrant virtual machine which has the "Flask" server installed.

Clone the repository and navigate to the directory inside your terminal and issue the following commands:

```bash
$ cd catalog
$ vagrant up
$ vagrant ssh
```

When the virtual machine is done booting up change to the shared directory by running the following commands:

```bash
$ cd /vagrant/catalog
$ python project.py
```

You should see the server is running:

Then navigate to localhost:5000 in you browser to view the web application.

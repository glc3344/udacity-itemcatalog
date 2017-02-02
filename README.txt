# Udacity Full-Stack Nanodegree
## Project: Item Catalog

## Overview

This prohect implements a web application that provides a list of items within a variety of categories and integrates third-party user registration and authentication.

## How to Run

You must have have Python, Vagrant and VirtualBox installed. This project uses a pre-congfigured Vagrant virtual machine which has the [Flask](http://flask.pocoo.org/) server installed.

```bash
$ cd catalog
$ vagrant up
$ vagrant ssh
```

Within the virtual machine change in to the shared directory by running

```bash
$ cd /vagrant/catalog
$ python project
```

Then navigate to localhost:5000 in you browser.
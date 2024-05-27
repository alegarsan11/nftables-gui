# nftables-gui

[![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=alegarsan11_nftables-gui&metric=alert_status)](https://sonarcloud.io/summary/new_code?id=alegarsan11_nftables-gui)

This repository is used to develop a web interface that enables the configuration of nftables through a graphical user interface.

## Requirements
To use this project, you need to install `python3-nftables` and `python3-hug`. For proper functioning, it's necessary to run the parsing file as an administrator.

## Default User Credentials
The default user credentials are as follows:
- Username: default
- Password: defaultpassword

## Running the Project
To run the project, follow these steps:

1. Grant permissions to the `run.sh` file: 

    `sudo chmod +x run.sh`

2. Execute the run.sh file. This file is used to run the project:

    `sudo ./run.sh`

3. To kill all processes:

    `sudo killall python`

### Deploying the Apache Server
To deploy an Apache server, use the build.sh file:
1. Grant permissions to the build.sh file:

    `sudo chmod +x build.sh`

2. Execute the build.sh file:

    `sudo ./build.sh`

### Testing and Coverage
To run the tests and generate coverage reports, use the following commands:
- Execute the test files (in the nftables-frontend folder):

    `python -m pytest`

- Execute coverage:

    `python -m pytest --cov`

- Generate a coverage report:

    `python -m pytest --cov --cov-report=html`

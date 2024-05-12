# nftables-gui
This is a repository to develop an web interface to enble configuration of nftables via GUI.

To use this project, you need to install `python3-nftables` and `python3-hug` additionally. For proper functioning, it's necessary to run the parsing file as an administrator.

The default user credentials are as follows:
Username: default
Password: defaultpassword

To run the project:
- Grant permissions:
`sudo chmod +x run.sh`
- Execute the file:
`sudo ./run.sh`

- Execute the test files:
`python -m pytest` (On the nftables-frontend folder)
- Execute coverage:
`python -m pytest --cov`
- Generate report of coverage
`python -m pytest --cov --cov-report=html`

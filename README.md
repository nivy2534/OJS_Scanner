Hello.
This is the image version of open journal system

To install this, please visit https://hub.docker.com/r/pkpofficial/ojs
Or, follow this step
```
git clone https://github.com/pkp/containers.git journalName && cd journalName
rm docs templates -Rf                               # Delete folders that are not useful in production
vim .env                         					# Set environment variables as you wish (ojs version, ports, url...)
source .env && wget "https://github.com/pkp/${PKP_TOOL}/raw/${PKP_VERSION}/config.TEMPLATE.inc.php" -O ./volumes/config/pkp.config.inc.php
sudo chown 33:33 ./volumes -R && sudo chown 999:999 ./volumes/db -R	# Ensure folders got the propper permissions
docker compose up -d
# Visit your new site and complete the installation as usual (Read about DB access credentials below, in step 5).
```
Before you follow this step, plase ensure you have git installed.

Caution!

We recommended to install this via wsl on any distro you have for windows for easy installation. Note that the distro should be integrated to your docker desktop.
To change to any other ojs version, open .env file and change the ```PKP_VERSION``` to your liked version.

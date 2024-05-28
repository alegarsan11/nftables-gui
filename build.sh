#!/bin/bash

# Configuración de Matplotlib
export MPLCONFIGDIR=/tmp/matplotlib
sudo mkdir -p $MPLCONFIGDIR
sudo chown www-data:www-data $MPLCONFIGDIR
sudo chmod 777 $MPLCONFIGDIR

# Instalación de dependencias
sudo apt-get install -y libfreetype6-dev libxft-dev apache2
sleep 5
# Copiar la aplicación
sudo cp -r nftables-frontend /usr/share

# Instalación y configuración de Apache con WSGI
sudo apt-get install -y libapache2-mod-wsgi-py3
sleep 5
sudo a2enmod wsgi

# Configuración del sitio de Apache
sudo cp nftables-frontend/nftables-config.conf /etc/apache2/sites-available/nftables-config.conf
sudo a2ensite nftables-config.conf

# Ajuste de permisos
sudo chmod 664 /usr/share/nftables-frontend/instance/nftables.db
sudo chown www-data:www-data /usr/share/nftables-frontend/instance/nftables.db
sudo chown -R www-data:www-data /usr/share/nftables-frontend
sudo chmod -R 775 /usr/share/nftables-frontend
sudo chmod -R 775 /usr/share/nftables-frontend/instance
sudo chmod -R 775 /usr/share/nftables-frontend/static
sudo chown -R www-data:www-data /usr/share/nftables-frontend/static

# Reiniciar Apache
sudo systemctl restart apache2

# Iniciar el parser de nftables
cd nftables-parser
sudo hug -f main.py 

#! /bin/bash

sudo git clone https://github.com/alegarsan11/nftables-gui.git /var/www/flask

# Variables
PROJECT_DIR=/var/www/flask/nftables-frontend
PROJECT_NAME=nftables-gui
WSGI_FILE=wsgi.py
VENV_DIR=$PROJECT_DIR/venv
PYTHON_VERSION=python3.8

# Actualizar los repositorios de paquetes
sudo apt update

# Instalar Apache y el módulo mod_wsgi para Python 3 si no están instalados
sudo apt install -y apache2 libapache2-mod-wsgi-py3

# Crear un archivo WSGI para que Apache pueda interactuar con la aplicación Flask
cat <<EOT > $PROJECT_DIR/$WSGI_FILE
import sys
import logging

# Configurar el logging
logging.basicConfig(stream=sys.stderr)

# Añadir el directorio del proyecto al path
sys.path.insert(0, "$PROJECT_DIR")

from app import app as application  # Ajusta según tu archivo principal de Flask
EOT

# Configurar Apache para servir la aplicación Flask
sudo tee /etc/apache2/sites-available/$PROJECT_NAME.conf > /dev/null <<EOT
<VirtualHost *:80>
    ServerName localhost

    WSGIDaemonProcess $PROJECT_NAME python-path=$VENV_DIR/lib/$PYTHON_VERSION/site-packages
    WSGIScriptAlias / $PROJECT_DIR/$WSGI_FILE

    <Directory $PROJECT_DIR>
        Require all granted
    </Directory>

    Alias /static $PROJECT_DIR/static
    <Directory $PROJECT_DIR/static/>
        Require all granted
    </Directory>

    ErrorLog \${APACHE_LOG_DIR}/$PROJECT_NAME_error.log
    CustomLog \${APACHE_LOG_DIR}/$PROJECT_NAME_access.log combined
</VirtualHost>
EOT

# Actualizar los repositorios de paquetes
sudo apt update

# Instalar Apache y el módulo mod_wsgi para Python 3 si no están instalados
sudo apt install -y apache2 libapache2-mod-wsgi-py3

# Habilitar el sitio y el módulo wsgi
sudo a2ensite $PROJECT_NAME.conf
sudo a2enmod wsgi
#Reiniciar Apache para aplicar los cambios
sudo systemctl restart apache2

echo "La aplicación Flask ahora debería estar disponible en http://localhost"
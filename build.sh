#!/bin/bash

# Configuración de Matplotlib
export MPLCONFIGDIR=/tmp/matplotlib
sudo mkdir -p $MPLCONFIGDIR
sudo chown www-data:www-data $MPLCONFIGDIR
sudo chmod 777 $MPLCONFIGDIR
sudo pip install -r requirements.txt
# Instalación de dependencias
sudo apt-get install libfreetype6-dev 
sudo apt-get install libxft-dev apache2

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
sudo a2dissite 000-default.conf

# Ajuste de permisos
sudo touch /usr/share/nftables-frontend/instance/nftables.db
sudo chmod 664 /usr/share/nftables-frontend/instance/nftables.db
sudo chown www-data:www-data /usr/share/nftables-frontend/instance/nftables.db
sudo chown -R www-data:www-data /usr/share/nftables-frontend
sudo chmod -R 775 /usr/share/nftables-frontend
sudo chmod -R 775 /usr/share/nftables-frontend/instance
sudo chmod -R 775 /usr/share/nftables-frontend/static
sudo chown -R www-data:www-data /usr/share/nftables-frontend/static
FICHERO="/etc/apache2/sites-available/000-default.conf"

if [ -f "$FICHERO" ]; then
    rm "$FICHERO"
    echo "El fichero $FICHERO ha sido eliminado."
else
    echo "El fichero $FICHERO no existe."
fi
FICHERO="/etc/apache2/sites-enabled/000-default.conf"

if [ -f "$FICHERO" ]; then
    rm "$FICHERO"
    echo "El fichero $FICHERO ha sido eliminado."
else
    echo "El fichero $FICHERO no existe."
fi

ARCHIVO="/etc/apache2/ports.conf"

# Línea a añadir
LINEA="Listen 8080"

# Comprobar si la línea ya existe en el archivo
if ! grep -qF "$LINEA" "$ARCHIVO"; then
    # Añadir la línea al final del archivo
    echo "$LINEA" | sudo tee -a "$ARCHIVO" > /dev/null
    echo "Línea añadida: $LINEA"
else
    echo "La línea ya existe en el archivo: $LINEA"
fi

# Reiniciar Apache
sudo systemctl restart apache2

# Iniciar el parser de nftables
cd nftables-parser
sudo hug -f main.py 

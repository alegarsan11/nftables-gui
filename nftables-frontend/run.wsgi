import os
import sys
import matplotlib
matplotlib.use('Agg')  # Configurar el backend de Matplotlib

# Establece la variable de entorno MPLCONFIGDIR
os.environ['MPLCONFIGDIR'] = '/tmp/matplotlib'

# Añade tu aplicación al path de Python
sys.path.insert(0,'/usr/share/nftables-frontend')

# Importa tu aplicación
from app import app as application
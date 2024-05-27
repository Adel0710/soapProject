# Utiliser une image de base avec Python 3.10
FROM python:3.10

# Définir le répertoire de travail
WORKDIR /app

# Copier le fichier des dépendances dans l'image
COPY requirements.txt /app/

# Installer les dépendances Python
RUN pip install --no-cache-dir -r requirements.txt

# Copier tout le contenu du répertoire actuel dans /app
COPY . /app/

# Définir la commande par défaut pour exécuter l'application
CMD ["python", "src/manage.py", "runserver", "0.0.0.0:8000"]


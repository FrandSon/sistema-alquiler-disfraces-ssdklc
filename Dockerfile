# Imagen base oficial, ligera y auditable
FROM python:3.12-slim


# Evitar que Python escriba archivos .pyc y forzar logs en tiempo real para auditoría (RS-14)
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=5000


# Instalar dependencias mínimas del sistema para compilación y diagnóstico de red
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq5 \
    && rm -rf /var/lib/apt/lists/*


# Crear grupo y usuario de mínimo privilegio (Seguridad por Diseño - No Root)
RUN groupadd -r atelier_group && useradd -r -g atelier_group -d /app -s /sbin/nologin atelier_user


# Definir directorio de trabajo
WORKDIR /app


# Copiar e instalar dependencias primero para aprovechar la caché de capas de Docker
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt


# Copiar las capas separadas de Frontend y Backend (RNF-01)
COPY frontend/ /app/frontend/
COPY backend/ /app/backend/


# Entregar la propiedad de los archivos al usuario no privilegiado
RUN chown -R atelier_user:atelier_group /app


# Cambiar al usuario sin privilegios antes de iniciar el servidor
USER atelier_user


# Documentar el puerto interno del contenedor
EXPOSE 5000


# Ejecutar con Gunicorn enlazando a 0.0.0.0:${PORT} (compatible con Docker local y Render.com)
CMD ["sh", "-c", "gunicorn --chdir backend --preload -w 2 -b 0.0.0.0:${PORT:-5000} app:app"]


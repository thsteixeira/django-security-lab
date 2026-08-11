FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# B6 (tier-3 containment): run as a non-root user so a lab that reaches real
# code/command execution (command injection, deserialization) cannot act as root
# inside the container. /app stays root-owned and world-readable on purpose — an
# exploit can read the lab code but not overwrite it. A lab that must write at
# runtime (e.g. Lab 04's upload dir) creates and chowns its own writable path.
RUN useradd --create-home --uid 10001 labuser

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Writable data area for labs that must write at runtime — e.g. Lab 04's uploads/
# directory and its off-limits flag file. /app stays root-owned (read-only to the
# app user); /data is labuser's.
RUN mkdir -p /data && chown labuser:labuser /data

# Drop root for everything that runs at container runtime (migrate, seed, tests,
# runserver). pip install above ran as root, so the packages are in the shared
# system site-packages and remain importable by labuser.
USER labuser

EXPOSE 8000

CMD ["python", "manage.py", "runserver", "0.0.0.0:8000"]

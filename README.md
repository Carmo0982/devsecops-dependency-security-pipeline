

# DevSecOps: Dependency Security Pipeline

Sistema de análisis de dependencias seguras integrado en un pipeline DevSecOps para detectar automáticamente vulnerabilidades en las dependencias de una aplicación Python antes de que el software sea desplegado.

## Tabla de Contenidos

- [Descripción General](#descripción-general)
- [Estructura del Proyecto](#estructura-del-proyecto)
- [Requisitos Previos](#requisitos-previos)
- [Inicio Rapido](#inicio-rapido)
- [Instalación](#instalación)
- [Backend API](#backend-api)
- [Frontend Demo](#frontend-demo)
- [Scanner CLI](#scanner-cli)
- [Pipeline CI/CD](#pipeline-cicd)
- [Pruebas del Sistema](#pruebas-del-sistema)
- [Comandos Rapidos](#comandos-rapidos)

## Descripción General

Este proyecto implementa un sistema automatizado de análisis de vulnerabilidades en dependencias de software. Utiliza la herramienta `safety` para escanear archivos `requirements.txt` y detectar CVEs (Common Vulnerabilities and Exposures) conocidos en las librerías utilizadas.

### Características Principales

- API REST para escaneo de dependencias
- Frontend web para consumir la API de escaneo
- Scanner CLI para ejecución local
- Integración principal con GitHub Actions
- Detección temprana de vulnerabilidades
- Bloqueo automático del pipeline si se encuentran vulnerabilidades críticas
- Reportes detallados en formato texto y JSON

## Estructura del Proyecto
devsecops-dependency-security-pipeline/
├── backend/
│ ├── app_simple.py # API REST simple para escaneo de dependencias
│ └── app/ # Backend modular reutilizable
├── frontend/
│ ├── index.html # Interfaz web del prototipo
│ ├── styles.css # Estilos de la interfaz
│ └── app.js # Llamadas a la API y render de resultados
├── scanner-cli/
│ └── scan.py # Scanner CLI para ejecución local
├── .github/
│ └── workflows/
│   └── security-scan.yml # Workflow principal de GitHub Actions
└── README.md

## Requisitos Previos

- Python 3.12 o superior
- pip (gestor de paquetes de Python)
- Git (opcional, para control de versiones)
- Acceso a internet para instalar dependencias

## Inicio Rapido

Se usan 2 terminales: una para backend y otra para frontend.

1. Terminal 1: backend API (puerto 5001)

```bash
source .venv/bin/activate
python -m pip install -r backend/requirements.txt
cd backend
python app_simple.py
```

2. Terminal 2: frontend estatico (puerto 5500)

```bash
source .venv/bin/activate
cd frontend
python3 -m http.server 5500
```

3. Abrir en navegador

```text
Frontend: http://localhost:5500
Backend API: http://localhost:5001
Health check: http://localhost:5001/health
```

4. Prueba minima (opcional)

```bash
curl -F "file=@backend/test.txt" http://localhost:5001/scan
```

Esperado: respuesta HTTP 422 con `"status": "failed"` cuando el archivo tiene dependencias vulnerables.

## Frontend Demo

El frontend del prototipo vive en `frontend/` y se conecta al backend Flask por HTTP.

### Ejecutar en local

1. Levantar backend:

```bash
cd backend
python app_simple.py
```

2. En otra terminal, levantar servidor estatico para el frontend:

```bash
cd frontend
python3 -m http.server 5500
```

3. Abrir en el navegador:

```text
http://localhost:5500
```

4. Verificar que la Base URL de la UI sea:

```text
http://localhost:5001
```


## Pipeline CI/CD

Pipeline principal en GitHub Actions:

- `/.github/workflows/security-scan.yml`

## Pruebas del Sistema

Prueba API con archivo vulnerable:

```bash
curl -F "file=@backend/test.txt" http://localhost:5001/scan
```

Resultado esperado:

- `HTTP 422`
- `"status": "failed"`
- lista de vulnerabilidades

Prueba de salud:

```bash
curl http://localhost:5001/health
```

Resultado esperado:

- `HTTP 200`
- `"status": "ok"`

## Comandos Rapidos

Backend:

```bash
source .venv/bin/activate
cd backend
python app_simple.py
```

Frontend:

```bash
source .venv/bin/activate
cd frontend
python3 -m http.server 5500
```

Abrir en navegador:

```text
Frontend: http://localhost:5500
Backend: http://localhost:5001
```
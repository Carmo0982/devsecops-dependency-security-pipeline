

# DevSecOps: Dependency Security Pipeline

Sistema de análisis de dependencias seguras integrado en un pipeline DevSecOps para detectar automáticamente vulnerabilidades en las dependencias de una aplicación Python antes de que el software sea desplegado.

## Tabla de Contenidos

- [Descripción General](#descripción-general)
- [Estructura del Proyecto](#estructura-del-proyecto)
- [Requisitos Previos](#requisitos-previos)
- [Instalación](#instalación)
- [Backend API](#backend-api)
- [Scanner CLI](#scanner-cli)
- [Pipeline CI/CD](#pipeline-cicd)
- [Pruebas del Sistema](#pruebas-del-sistema)
- [Ejemplos de Uso](#ejemplos-de-uso)
- [Integración con Proyectos Existentes](#integración-con-proyectos-existentes)
- [Flujo de Trabajo](#flujo-de-trabajo)
- [Solución de Problemas](#solución-de-problemas)
- [Comandos Rápidos](#comandos-rápidos)

## Descripción General

Este proyecto implementa un sistema automatizado de análisis de vulnerabilidades en dependencias de software. Utiliza la herramienta `safety` para escanear archivos `requirements.txt` y detectar CVEs (Common Vulnerabilities and Exposures) conocidos en las librerías utilizadas.

### Características Principales

- API REST para escaneo de dependencias
- Scanner CLI para ejecución local
- Integración con GitHub Actions, GitLab CI/CD y Jenkins
- Detección temprana de vulnerabilidades
- Bloqueo automático del pipeline si se encuentran vulnerabilidades críticas
- Reportes detallados en formato texto y JSON

## Estructura del Proyecto
devsecops-dependency-security-pipeline/
├── backend/
│ ├── app_simple.py # API REST para escaneo de dependencias
│ └── test.txt # Archivo de prueba con dependencias vulnerables
├── scanner-cli/
│ └── scan.py # Scanner CLI para ejecución local
├── pipeline/
│ ├── .github/workflows/
│ │ └── security-scan.yml # GitHub Actions workflow
│ ├── .gitlab-ci.yml # GitLab CI/CD pipeline
│ └── jenkins/
│ └── Jenkinsfile # Jenkins pipeline
└── README.md

text

## Requisitos Previos

- Python 3.12 o superior
- pip (gestor de paquetes de Python)
- Git (opcional, para control de versiones)
- Acceso a internet para instalar dependencias

## Instalación

### 1. Clonar el repositorio

```bash
git clone https://github.com/tu-usuario/devsecops-dependency-security-pipeline.git
cd devsecops-dependency-security-pipeline
2. Crear y activar entorno virtual
Windows:

powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
Linux/Mac:

bash
python3 -m venv venv
source venv/bin/activate
3. Instalar dependencias
bash
pip install safety==2.3.5 flask==2.3.3 flask-cors==4.0.0
Backend API
Iniciar el servidor
bash
cd backend
python app_simple.py
El servidor se iniciará en http://localhost:5000

Endpoints disponibles
Método	Endpoint	Descripción
GET	/health	Verificar estado del servidor
GET	/scan-example	Escanear ejemplo vulnerable
GET	/scan-local	Escanear test.txt de la carpeta backend
POST	/scan	Subir y escanear archivo requirements.txt
Respuestas de la API
Respuesta exitosa sin vulnerabilidades:

json
{
  "status": "passed",
  "total_count": 0,
  "vulnerabilities": []
}
Respuesta con vulnerabilidades:

json
{
  "status": "failed",
  "total_count": 59,
  "vulnerabilities": [
    {
      "package": "requests",
      "version": "2.20.0",
      "cve": "58755",
      "severity": null,
      "description": ""
    }
  ]
}
Scanner CLI
El scanner CLI permite ejecutar análisis de dependencias directamente desde la línea de comandos.

Ubicarse en el directorio del scanner
bash
cd scanner-cli
Comandos disponibles
Comando	Descripción
python scan.py <archivo>	Escanear y mostrar reporte
python scan.py <archivo> --json	Escanear con salida JSON
python scan.py <archivo> --fail-on-vuln	Escanear y fallar si hay vulnerabilidades
Ejemplos de uso
Escanear archivo y mostrar reporte:

bash
python scan.py ../backend/test.txt
Escanear con salida JSON:

bash
python scan.py ../backend/test.txt --json
Escanear y fallar si hay vulnerabilidades:

bash
python scan.py ../backend/test.txt --fail-on-vuln
Verificar código de salida
Windows PowerShell:

powershell
echo $LASTEXITCODE
Linux/Mac:

bash
echo $?
0 = Sin vulnerabilidades (éxito)

1 = Vulnerabilidades encontradas (fallo)

Ejemplo de salida del scanner
text
============================================================
REPORTE DE SEGURIDAD DE DEPENDENCIAS
============================================================
Archivo escaneado: ../backend/test.txt
Fecha: 2026-04-05 21:36:08
------------------------------------------------------------
Se encontraron 59 vulnerabilidades:

1. Paquete: requests
   Version: 2.20.0
   CVE: 58755
   Severidad: No especificada

2. Paquete: requests
   Version: 2.20.0
   CVE: 77680
   Severidad: No especificada

3. Paquete: django
   Version: 2.2.10
   CVE: 49733
   Severidad: No especificada

------------------------------------------------------------
Estado: FAILED - El pipeline debe BLOQUEARSE
Recomendacion: Actualizar las dependencias vulnerables
============================================================
Pipeline CI/CD
GitHub Actions
El workflow se ejecuta automáticamente cuando:

Se hace push a las ramas main o develop

Se crea un pull request hacia main

Se ejecuta manualmente desde GitHub

Archivo: .github/workflows/security-scan.yml

Estructura del workflow:

yaml
name: Security Scan - Dependency Check
on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]
  workflow_dispatch:
jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout code
      - name: Setup Python
      - name: Install safety
      - name: Find requirements files
      - name: Scan dependencies
      - name: Upload scan report
GitLab CI/CD
Archivo: .gitlab-ci.yml

El pipeline incluye las etapas:

security-scan - Escaneo de dependencias

build - Construcción de la aplicación

deploy - Despliegue a producción

Características:

Cache de pip para acelerar ejecuciones

Reportes de vulnerabilidades en formato JSON

Ejecución automática en merge requests

Jenkins Pipeline
Archivo: jenkins/Jenkinsfile

Características:

Pipeline declarativo

Escaneo automático de todos los requirements.txt

Fallo del pipeline si se encuentran vulnerabilidades

Notificaciones de éxito/fallo

Pruebas del Sistema
Prueba 1: Escanear archivo vulnerable
El archivo backend/test.txt contiene dependencias vulnerables:

text
flask==1.0.2
requests==2.20.0
django==2.2.10
Ejecutar el escaneo:

bash
cd scanner-cli
python scan.py ../backend/test.txt
Resultado esperado: FAILED con 59 vulnerabilidades encontradas

Prueba 2: Escanear archivo seguro
Crear un archivo sin vulnerabilidades:

bash
echo "flask==2.3.0" > safe.txt
python scan.py safe.txt
Resultado esperado: PASSED sin vulnerabilidades

Prueba 3: Probar el backend API
Iniciar el servidor:

bash
cd backend
python app_simple.py
En otra terminal, probar los endpoints:

bash
curl http://localhost:5000/health
curl http://localhost:5000/scan-example
curl http://localhost:5000/scan-local
Prueba 4: Verificar código de salida
bash
python scan.py ../backend/test.txt --fail-on-vuln
echo $LASTEXITCODE  # Debe mostrar 1
Ejemplos de Uso
Ejemplo 1: Escanear requirements.txt de un proyecto existente
bash
cp /ruta/de/tu/proyecto/requirements.txt backend/
cd scanner-cli
python scan.py ../backend/requirements.txt
Ejemplo 2: Usar la API para escanear desde otro programa
python
import requests

url = "http://localhost:5000/scan"
files = {"file": open("requirements.txt", "rb")}
response = requests.post(url, files=files)
print(response.json())
Ejemplo 3: Integrar en script de CI/CD local
bash
#!/bin/bash
cd scanner-cli
python scan.py ../backend/requirements.txt --json
if [ $? -eq 1 ]; then
    echo "Vulnerabilidades encontradas. Deteniendo despliegue."
    exit 1
fi
echo "Sin vulnerabilidades. Continuando despliegue."
Integración con Proyectos Existentes
Opción 1: Usar solo el scanner CLI
Copiar scanner-cli/scan.py a tu proyecto

Instalar safety: pip install safety

Ejecutar: python scan.py requirements.txt

Opción 2: Usar la API
Copiar la carpeta backend/ a tu proyecto

Instalar dependencias: pip install -r backend/requirements.txt

Iniciar servidor: python backend/app_simple.py

Enviar peticiones POST al endpoint /scan

Opción 3: Integrar pipeline CI/CD
GitHub Actions:

Copiar .github/workflows/security-scan.yml a tu repositorio

Commit y push

El workflow se ejecutará automáticamente

GitLab CI:

Copiar .gitlab-ci.yml a la raíz de tu repositorio

Commit y push

El pipeline se ejecutará en cada commit

Jenkins:

Copiar jenkins/Jenkinsfile a tu repositorio

Configurar un pipeline multibranch en Jenkins

El pipeline se ejecutará automáticamente
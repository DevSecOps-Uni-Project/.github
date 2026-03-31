import os
import json
import google.generativeai as genai
import sys

# 1. Configuración de la IA
# Usamos la clave que guardaste en los Secrets del repo
API_KEY = os.environ.get("GEMINI_API_KEY")
if not API_KEY:
    print("❌ Error: GEMINI_API_KEY no encontrada en el entorno.")
    sys.exit(1)

genai.configure(api_key=API_KEY)
# Usamos 1.5-flash por su gran ventana de contexto y rapidez
model = genai.GenerativeModel('gemini-1.5-flash')

def parse_sarif(file_path):
    """Extrae hallazgos de archivos SARIF (CodeQL/Snyk/Semgrep)"""
    try:
        with open(file_path, 'r') as f:
            data = json.load(f)
        findings = []
        for run in data.get('runs', []):
            for result in run.get('results', []):
                # Solo nos interesan errores o advertencias serias
                level = result.get('level', 'warning')
                if level in ['error', 'warning']:
                    msg = result.get('message', {}).get('text', 'Sin descripción')
                    rule_id = result.get('ruleId', 'N/A')
                    locations = result.get('locations', [])
                    file_info = "Desconocido"
                    line_info = "N/A"
                    
                    if locations:
                        phys_loc = locations[0].get('physicalLocation', {})
                        file_info = phys_loc.get('artifactLocation', {}).get('uri', 'Desconocido')
                        line_info = phys_loc.get('region', {}).get('startLine', 'N/A')
                    
                    findings.append({
                        "herramienta": run.get('tool', {}).get('driver', {}).get('name', 'Herramienta SARIF'),
                        "regla": rule_id,
                        "archivo": file_info,
                        "linea": line_info,
                        "descripcion": msg
                    })
        return findings
    except Exception as e:
        return [f"Error parseando SARIF {file_path}: {str(e)}"]

def parse_json_generic(file_path):
    """Lectura simple para archivos JSON genéricos (Trivy/Snyk JSON)"""
    try:
        with open(file_path, 'r') as f:
            return json.load(f)
    except Exception as e:
        return {"error": f"No se pudo leer {file_path}: {str(e)}"}

def main():
    results_dir = 'all-results' # Carpeta donde el pipeline descarga los artefactos
    all_context = []

    print(f"--- Iniciando Auditoría IA en {results_dir} ---")

    if not os.path.exists(results_dir):
        print(f"❌ Directorio {results_dir} no encontrado.")
        sys.exit(1)

    # 2. Recolectar datos de todas las herramientas
    for root, dirs, files in os.walk(results_dir):
        for file in files:
            path = os.path.join(root, file)
            if file.endswith('.sarif'):
                all_context.append({"origen": file, "hallazgos": parse_sarif(path)})
            elif file.endswith('.json'):
                # Para JSON grandes (como Snyk), intentamos resumir o enviar directo
                all_context.append({"origen": file, "hallazgos": parse_json_generic(path)})

    # 3. Construir el Prompt Maestro para Autorremediación
    prompt = """
    Eres un Arquitecto Senior de DevSecOps con especialidad en Análisis de Riesgos. Tu misión es auditar los reportes de seguridad y proponer remediaciones automáticas para el proyecto "Backend_IDS" (Java 21 / Spring Boot).

    ### 1. MAPEO DE HERRAMIENTAS Y VALOR
    Para cada herramienta analizada, explica brevemente:
    - **Propósito**: Qué evita en este pipeline (ej. Inyecciones, librerías obsoletas, misconfigurations).
    - **Beneficio**: Qué valor aporta a la gobernanza del proyecto.

    ### 2. CLASIFICACIÓN DE RIESGO (TRIAGE)
    Ordena todos los hallazgos de **MAYOR A MENOR CRITICIDAD**.
    Para determinar la prioridad, usa la fórmula: **Riesgo = Probabilidad x Impacto**.
    - **Impacto**: Gravedad del daño si se explota (ej. Exfiltración de datos, ejecución remota).
    - **Vulnerabilidad**: Facilidad con la que un atacante puede explotar el fallo.

    ### 3. PROTOCOLO DE AUTORREMEDIACIÓN "MÍNIMAMENTE INVASIVA"
    Procesa los hallazgos por bloques en este orden de prioridad:

    #### BLOQUE A: Críticos y Altos (Secretos y Código - SAST)
    - **Análisis**: Ubicación (Archivo:Línea), Fragmento Inseguro y Explicación del Riesgo.
    - **Remediación**: Proporciona el código corregido. 
    - **REGLA DE ORO**: La corrección debe ser **lo menos invasiva posible**. Mantén la lógica de negocio intacta, cambia solo la función o el patrón vulnerable (ej. usa PreparedStatement en lugar de concatenar, pero no reescribas todo el Controller).

    #### BLOQUE B: Dependencias y Cadena de Suministro (SCA - Snyk)
    - Lista las 2 vulnerabilidades Críticas y 9 Altas detectadas.
    - Indica la versión exacta a actualizar en el `pom.xml`.

    #### BLOQUE C: Infraestructura y Contenedores (Trivy)
    - Corrige el hallazgo Crítico detectado en la imagen.
    - Prioriza cambios en el Dockerfile que no aumenten el tamaño de la imagen innecesariamente.

    ### 4. FORMATO DE SALIDA
    - Usa **Tablas de Riesgo** (ID, Gravedad, Archivo, Impacto).
    - Usa **Bloques de Código** con comentarios `// CORRECCIÓN APLICADA` para que el desarrollador identifique el cambio.
    - Finaliza con un **Veredicto de Gobernanza**: "APROBADO CON CAMBIOS" o "RECHAZADO".
    """

    # 4. Generar reporte con Gemini
    try:
        print("🤖 Enviando datos a Gemini 1.5 Flash...")
        response = model.generate_content(prompt)
        
        report_path = "REPORTE_IA_SEGURIDAD.md"
        with open(report_path, "w", encoding="utf-8") as f:
            f.write(response.text)
        
        print(f"✅ Reporte generado exitosamente: {report_path}")

    except Exception as e:
        print(f"❌ Error llamando a la API de Gemini: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()
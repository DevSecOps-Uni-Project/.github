import os
import json
import google.generativeai as genai
import sys

# 1. Configuración de la IA
API_KEY = os.environ.get("GEMINI_API_KEY")
if not API_KEY:
    print("❌ Error: GEMINI_API_KEY no encontrada en el entorno.")
    sys.exit(1)

genai.configure(api_key=API_KEY)
model = genai.GenerativeModel('gemini-1.5-flash')

def parse_sarif(file_path):
    """Extrae hallazgos de archivos SARIF (CodeQL/Snyk/Semgrep)"""
    try:
        with open(file_path, 'r') as f:
            data = json.load(f)
        findings = []
        for run in data.get('runs', []):
            for result in run.get('results', []):
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
        print(f"⚠️ Error parseando SARIF {file_path}: {e}")
        return []

def parse_json_generic(file_path):
    """Lectura simple para archivos JSON genéricos"""
    try:
        with open(file_path, 'r') as f:
            return json.load(f)
    except Exception as e:
        print(f"⚠️ Error leyendo JSON {file_path}: {e}")
        return {}

def main():
    results_dir = 'all-results'
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
                all_context.append({"origen": file, "hallazgos": parse_json_generic(path)})

    # 3. Construir el Prompt Maestro con la DATA INYECTADA
    prompt_instrucciones = """
    Eres un Arquitecto Senior de DevSecOps. Tu misión es auditar los reportes y proponer remediaciones para "Backend_IDS" (Java 21 / Spring Boot).

    ### INSTRUCCIONES DE GOBERNANZA:
    1. Si detectas fallos CRÍTICOS o ALTOS sin corrección trivial, el veredicto debe ser "RECHAZADO".
    2. Proporciona código corregido con el comentario // CORRECCIÓN APLICADA.
    3. Usa tablas para resumir riesgos (Probabilidad x Impacto).

    ### DATOS DE SEGURIDAD DETECTADOS:
    """
    
    # Convertimos los hallazgos en texto para el prompt
    datos_hallazgos = json.dumps(all_context, indent=2)
    prompt_final = prompt_instrucciones + datos_hallazgos

    # 4. Generar reporte con Gemini
    try:
        print("🤖 Enviando hallazgos a Gemini 1.5 Flash...")
        response = model.generate_content(prompt_final)
        reporte_texto = response.text
        
        report_path = "REPORTE_IA_SEGURIDAD.md"
        with open(report_path, "w", encoding="utf-8") as f:
            f.write(reporte_texto)
        
        print(f"✅ Reporte generado: {report_path}")

        # 5. LÓGICA BLOQUEANTE (EXIT CODE)
        # Si la IA determina que el riesgo es demasiado alto, fallamos el pipeline.
        if "RECHAZADO" in reporte_texto.upper() or "CRÍTICO" in reporte_texto.upper():
            print("❌ GOBERNANZA: Se han detectado riesgos inaceptables. Bloqueando pipeline.")
            sys.exit(1)
        else:
            print("✅ GOBERNANZA: El código cumple con los estándares mínimos.")
            sys.exit(0)

    except Exception as e:
        print(f"⚠️ Error en la API de Gemini o el Triage: {str(e)}")
        print("Continuando sin auditoría IA para no bloquear el desarrollo.")
        sys.exit(0)

if __name__ == "__main__":
    main()
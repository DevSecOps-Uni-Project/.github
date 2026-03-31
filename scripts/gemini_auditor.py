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
# Aseguramos que usamos el modelo correcto y compatible
model = genai.GenerativeModel('gemini-1.5-flash')

def parse_sarif(file_path):
    """Extrae hallazgos de archivos SARIF (CodeQL/Snyk/Semgrep)"""
    try:
        with open(file_path, 'r') as f:
            data = json.load(f)
        findings = []
        for run in data.get('runs', []):
            tool_name = run.get('tool', {}).get('driver', {}).get('name', 'Herramienta')
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
                        "herramienta": tool_name,
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
    """Lectura robusta para JSON estándar y JSON Lines (Trufflehog/Trivy)"""
    try:
        with open(file_path, 'r') as f:
            content = f.read().strip()
            if not content:
                return []
            
            # Intento 1: JSON Estándar (Array o Dict)
            try:
                return json.loads(content)
            except json.JSONDecodeError:
                # Intento 2: JSON Lines (un objeto por línea, común en scanners de seguridad)
                f.seek(0)
                return [json.loads(line) for line in f if line.strip()]
    except Exception as e:
        print(f"⚠️ Error leyendo JSON {file_path}: {e}")
        return {"error": str(e)}

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
            # Evitamos procesar archivos vacíos o de logs
            if os.path.getsize(path) == 0:
                continue
                
            if file.endswith('.sarif'):
                res = parse_sarif(path)
                if res: all_context.append({"origen": file, "hallazgos": res})
            elif file.endswith('.json'):
                res = parse_json_generic(path)
                if res: all_context.append({"origen": file, "hallazgos": res})

    if not all_context:
        print("✅ No se encontraron hallazgos para analizar.")
        sys.exit(0)

    # 3. Construir el Prompt Maestro
    prompt_final = f"""
    Eres un Arquitecto Senior de DevSecOps. Analiza estos reportes de seguridad para el proyecto "Backend_IDS" (Java 21 / Spring Boot).

    ### INSTRUCCIONES:
    1. Si hay fallos CRÍTICOS (especialmente secretos expuestos), el veredicto es "RECHAZADO".
    2. Proporciona bloques de código con // CORRECCIÓN APLICADA.
    3. Resume en una tabla: ID, Gravedad, Archivo, Impacto.

    ### REPORTES DETECTADOS:
    {json.dumps(all_context, indent=2)}
    """

    # 4. Generar reporte con Gemini
    try:
        print(f"🤖 Enviando {len(all_context)} reportes a Gemini 1.5 Flash...")
        # Usamos contents para asegurar compatibilidad con versiones de API
        response = model.generate_content(prompt_final)
        
        if not response.text:
            raise Exception("Gemini devolvió una respuesta vacía.")

        reporte_texto = response.text
        
        with open("REPORTE_IA_SEGURIDAD.md", "w", encoding="utf-8") as f:
            f.write(reporte_texto)
        
        print("✅ Reporte generado: REPORTE_IA_SEGURIDAD.md")

        # 5. Lógica de bloqueo
        reducido = reporte_texto.upper()
        if "RECHAZADO" in reducido or "CRÍTICO" in reducido or "CRITICAL" in reducido:
            print("❌ GOBERNANZA: Riesgos altos detectados.")
            sys.exit(1)
        
        sys.exit(0)

    except Exception as e:
        print(f"⚠️ Error en la fase de IA: {str(e)}")
        # No bloqueamos el pipeline si la IA falla (opcional)
        sys.exit(0)

if __name__ == "__main__":
    main()
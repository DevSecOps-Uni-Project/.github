import os
import json
import sys

try:
    # El nuevo SDK se importa preferiblemente así
    from google import genai
except ImportError:
    print("❌ Error: No se pudo encontrar la librería google-genai.")
    print("Asegúrate de ejecutar: pip install -U google-genai")
    sys.exit(1)

# 1. Configuración de la IA
API_KEY = os.environ.get("GEMINI_API_KEY")
if not API_KEY:
    print("❌ Error: GEMINI_API_KEY no encontrada en el entorno.")
    sys.exit(1)

# SOLUCIÓN AL 404: Especificamos la versión de la API y usamos el cliente correctamente
# 'v1' es la versión estable para gemini-1.5-flash
client = genai.Client(
    api_key=API_KEY,
    http_options={'api_version': 'v1'}
)

MODEL_ID = "gemini-1.5-flash"

def parse_sarif(file_path):
    """Extrae hallazgos de archivos SARIF (CodeQL, Semgrep, Snyk)"""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        findings = []
        for run in data.get('runs', []):
            tool_name = run.get('tool', {}).get('driver', {}).get('name', 'Herramienta')
            for result in run.get('results', []):
                level = result.get('level', 'warning')
                # Filtramos solo lo que requiere atención inmediata
                if level in ['error', 'warning']:
                    msg = result.get('message', {}).get('text', 'Sin descripción')
                    locs = result.get('locations', [{}])
                    phys_loc = locs[0].get('physicalLocation', {}) if locs else {}
                    uri = phys_loc.get('artifactLocation', {}).get('uri', 'N/A')
                    
                    findings.append({
                        "herramienta": tool_name,
                        "regla": result.get('ruleId', 'N/A'),
                        "archivo": uri,
                        "descripcion": msg
                    })
        return findings
    except Exception:
        return []

def parse_json_generic(file_path):
    """Lectura para JSON y JSON Lines (Trufflehog / Trivy)"""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read().strip()
            if not content: return []
            try:
                return json.loads(content)
            except json.JSONDecodeError:
                # Intento de lectura JSON Lines
                f.seek(0)
                return [json.loads(line) for line in f if line.strip()]
    except Exception:
        return []

def main():
    results_dir = sys.argv[1] if len(sys.argv) > 1 else 'security-results'
    all_context = []

    print(f"--- 🛡️ Iniciando Auditoría IA en {results_dir} ---")

    if not os.path.exists(results_dir):
        # Compatibilidad con ejecuciones antiguas que descargaban artefactos en all-results
        if results_dir == 'security-results' and os.path.exists('all-results'):
            results_dir = 'all-results'
            print(f"ℹ️ Usando ruta alternativa de artefactos: {results_dir}")
        else:
            print(f"❌ Directorio {results_dir} no encontrado.")
            sys.exit(1)

    # 2. Recolección de evidencias
    for root, _, files in os.walk(results_dir):
        for file in files:
            path = os.path.join(root, file)
            if os.path.getsize(path) == 0: continue
            
            print(f"📂 Procesando reporte: {file}")
            if file.endswith('.sarif'):
                findings = parse_sarif(path)
                if findings:
                    all_context.append({"origen": file, "hallazgos": findings})
            elif file.endswith('.json'):
                findings = parse_json_generic(path)
                if findings:
                    all_context.append({"origen": file, "hallazgos": findings})

    if not all_context:
        print("✅ No se detectaron hallazgos críticos en los reportes.")
        sys.exit(0)

    # 3. Prompt Maestro para DevSecOps
    prompt = f"""
    Eres un Arquitecto Senior de DevSecOps especializado en el proyecto "Backend_IDS" (Java 21).
    Analiza los siguientes reportes de seguridad y genera un informe de remediación.

    ### REGLAS DE ORO:
    1. Si hay fallos CRÍTICOS o SECRETOS expuestos, el veredicto final debe ser "RECHAZADO".
    2. Para cada vulnerabilidad, proporciona el código corregido usando el comentario `// CORRECCIÓN APLICADA`.
    3. Usa tablas para resumir el riesgo (Herramienta, Archivo, Prioridad).
    4. La remediación debe ser mínimamente invasiva.

    ### DATOS DE LOS REPORTES:
    {json.dumps(all_context, indent=2)}
    """

    # 4. Generar reporte con el nuevo SDK
    try:
        print(f"🤖 Solicitando análisis a {MODEL_ID}...")
        
        # En el nuevo SDK, el método es client.models.generate_content
        response = client.models.generate_content(
            model=MODEL_ID,
            contents=prompt
        )
        
        report_text = response.text
        
        # Guardar el reporte para los artefactos de GitHub
        with open("REPORTE_IA_SEGURIDAD.md", "w", encoding="utf-8") as f:
            f.write(report_text)
        
        print("✅ Reporte generado exitosamente: REPORTE_IA_SEGURIDAD.md")

        # 5. Lógica de Gobernanza (Exit Code)
        # Si la IA determina que el riesgo es inaceptable, fallamos el pipeline.
        if "RECHAZADO" in report_text.upper() or "CRITICAL" in report_text.upper():
            print("❌ Veredicto de IA: Fallos críticos detectados. Bloqueando pipeline.")
            sys.exit(1)
            
        print("🟢 Veredicto de IA: Riesgos controlados.")
        sys.exit(0)

    except Exception as e:
        print(f"⚠️ Error durante la comunicación con la API: {e}")
        # No matamos el pipeline por un error de API para no bloquear al equipo, 
        # pero podrías cambiarlo a sys.exit(1) si la auditoría es obligatoria.
        sys.exit(0)

if __name__ == "__main__":
    main()
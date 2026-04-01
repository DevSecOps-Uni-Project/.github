import os
import json
import sys

try:
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

# IMPORTANTE: Usamos v1beta porque los modelos Flash suelen estar primero ahí en AI Studio
client = genai.Client(
    api_key=API_KEY,
    http_options={'api_version': 'v1beta'}
)

# Lista refinada: gemini-2.0-flash ya es estable en la mayoría de regiones de AI Studio
DEFAULT_MODEL_CANDIDATES = [
    "gemini-2.0-flash", 
    "gemini-1.5-flash",
    "gemini-1.5-flash-latest"
]


def _is_truthy(value):
    return str(value).strip().lower() in ("1", "true", "yes", "on")

def _normalize_model_name(name):
    if not name:
        return ""
    return name.replace("models/", "").strip()

def resolve_model_id():
    """Resuelve el modelo a usar con prioridad: variable de entorno -> defaults."""
    env_model = _normalize_model_name(os.environ.get("GEMINI_MODEL", ""))
    if env_model:
        return env_model
    return DEFAULT_MODEL_CANDIDATES[0]

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
                f.seek(0)
                return [json.loads(line) for line in f if line.strip()]
    except Exception:
        return []

def main():
    results_dir = sys.argv[1] if len(sys.argv) > 1 else 'security-results'
    fail_on_api_error = _is_truthy(os.environ.get("IA_FAIL_ON_API_ERROR", "false"))
    all_context = []

    print(f"--- 🛡️ Iniciando Auditoría IA en {results_dir} ---")

    if not os.path.exists(results_dir):
        if results_dir == 'security-results' and os.path.exists('all-results'):
            results_dir = 'all-results'
            print(f"ℹ️ Usando ruta alternativa: {results_dir}")
        else:
            print(f"❌ Directorio {results_dir} no encontrado.")
            sys.exit(1)

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

    prompt = f"""
    Eres un Arquitecto Senior de DevSecOps especializado en el proyecto "Backend_IDS" (Java 21).
    Analiza los siguientes reportes de seguridad y genera un informe de remediación en MARKDOWN.

    ### REGLAS DE ORO:
    1. Si hay fallos CRÍTICOS o SECRETOS expuestos, el veredicto final debe ser "VEREDICTO: RECHAZADO".
    2. Proporciona el código corregido usando el comentario `// CORRECCIÓN APLICADA`.
    3. Usa tablas para resumir el riesgo.
    4. Responde en ESPAÑOL.

    ### DATOS DE LOS REPORTES:
    {json.dumps(all_context, indent=2)}
    """

    selected_model = resolve_model_id()

    try:
        print(f"🤖 Solicitando análisis a {selected_model}...")
        response = client.models.generate_content(
            model=selected_model,
            contents=prompt
        )
        
        report_text = response.text
        with open("REPORTE_IA_SEGURIDAD.md", "w", encoding="utf-8") as f:
            f.write(report_text)
        
        print("✅ Reporte generado exitosamente.")

        # Lógica de salida
        if "RECHAZADO" in report_text.upper() or "CRITICAL" in report_text.upper():
            print("❌ Veredicto de IA: Fallos críticos detectados.")
            sys.exit(1)
            
        print("🟢 Veredicto de IA: Riesgos controlados.")
        sys.exit(0)

    except Exception as e:
        print(f"⚠️ Error con {selected_model}: {e}. Intentando fallback...")
        for fallback in DEFAULT_MODEL_CANDIDATES:
            if fallback == selected_model: continue
            try:
                print(f"ℹ️ Reintentando con: {fallback}")
                response = client.models.generate_content(model=fallback, contents=prompt)
                report_text = response.text
                with open("REPORTE_IA_SEGURIDAD.md", "w", encoding="utf-8") as f:
                    f.write(report_text)
                print(f"✅ Logrado con {fallback}")

                if "RECHAZADO" in report_text.upper() or "CRITICAL" in report_text.upper():
                    print("❌ Veredicto de IA: Fallos críticos detectados.")
                    sys.exit(1)

                sys.exit(0)
            except Exception as fallback_error:
                print(f"⚠️ Falló fallback {fallback}: {fallback_error}")
                continue
        
        print("❌ Todos los modelos fallaron.")
        if fail_on_api_error:
            print("❌ IA_FAIL_ON_API_ERROR=true: bloqueando pipeline por error de IA.")
            sys.exit(1)

        print("⚠️ IA_FAIL_ON_API_ERROR=false: no se bloquea el pipeline por caída de IA.")
        sys.exit(0)

if __name__ == "__main__":
    main()
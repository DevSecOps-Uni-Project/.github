import os
import json
from google import genai # Importación del nuevo SDK
import sys

# 1. Configuración de la IA con el nuevo SDK
API_KEY = os.environ.get("GEMINI_API_KEY")
if not API_KEY:
    print("❌ Error: GEMINI_API_KEY no encontrada.")
    sys.exit(1)

# Inicializamos el cliente moderno
client = genai.Client(api_key=API_KEY)
MODEL_ID = "gemini-1.5-flash"

def parse_sarif(file_path):
    """Extrae hallazgos de archivos SARIF"""
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
                    findings.append({
                        "herramienta": tool_name,
                        "regla": result.get('ruleId', 'N/A'),
                        "archivo": result.get('locations', [{}])[0].get('physicalLocation', {}).get('artifactLocation', {}).get('uri', 'N/A'),
                        "descripcion": msg
                    })
        return findings
    except Exception as e:
        return []

def parse_json_generic(file_path):
    """Lectura para JSON y JSON Lines (Trufflehog)"""
    try:
        with open(file_path, 'r') as f:
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
    results_dir = 'all-results'
    all_context = []

    print(f"--- Iniciando Auditoría IA en {results_dir} ---")

    if not os.path.exists(results_dir):
        print(f"❌ Directorio {results_dir} no encontrado.")
        sys.exit(1)

    # Recolectar archivos
    for root, _, files in os.walk(results_dir):
        for file in files:
            path = os.path.join(root, file)
            if os.path.getsize(path) == 0: continue
            
            print(f"📂 Procesando: {file}") # Para que sepas cuáles son los 9 reportes
            if file.endswith('.sarif'):
                all_context.append({"origen": file, "hallazgos": parse_sarif(path)})
            elif file.endswith('.json'):
                all_context.append({"origen": file, "hallazgos": parse_json_generic(path)})

    if not all_context:
        print("✅ No hay hallazgos que analizar.")
        sys.exit(0)

    # 3. Prompt Maestro
    prompt = f"""
    Eres un Arquitecto Senior de DevSecOps. Analiza estos reportes de seguridad para "Backend_IDS".
    
    INSTRUCCIONES:
    1. Si hay fallos CRÍTICOS, el veredicto es "RECHAZADO".
    2. Proporciona código corregido con // CORRECCIÓN APLICADA.
    
    REPORTES:
    {json.dumps(all_context, indent=2)}
    """

    # 4. Generar reporte con el nuevo método
    try:
        print(f"🤖 Enviando datos a {MODEL_ID}...")
        response = client.models.generate_content(
            model=MODEL_ID,
            contents=prompt
        )
        
        report_text = response.text
        with open("REPORTE_IA_SEGURIDAD.md", "w", encoding="utf-8") as f:
            f.write(report_text)
        
        print("✅ Reporte generado exitosamente.")

        # Lógica de salida
        if "RECHAZADO" in report_text.upper() or "CRITICAL" in report_text.upper():
            sys.exit(1)
        sys.exit(0)

    except Exception as e:
        print(f"⚠️ Error en API: {e}")
        sys.exit(0)

if __name__ == "__main__":
    main()
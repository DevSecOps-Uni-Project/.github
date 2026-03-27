import json
import os
import sys
from anthropic import Anthropic

class SecurityNormalizer:
    def __init__(self, results_dir='security-results'):
        self.results_dir = results_dir
        self.findings = {
            "1_secrets": [],      # TruffleHog
            "2_dependencies": [], # Snyk
            "3_sast": [],         # Semgrep
            "4_containers": [],   # Trivy (Añadido)
            "5_dast": []          # ZAP
        }
    
    def load_json(self, filename):
    ruta_archivo = os.path.join(self.results_dir, filename)
    if not os.path.exists(ruta_archivo):
        return None
    
    try:
        with open(ruta_archivo, 'r', encoding='utf-8') as f:
            content = f.read().strip()
            
            # Intento 1: JSON puro
            try:
                return json.loads(content)
            except json.JSONDecodeError:
                hallazgos = []
                f.seek(0)
                for linea in f:
                    linea = linea.strip()
                    if linea.startswith('{'):
                        try:
                            hallazgos.append(json.loads(linea))
                        except: continue
                return hallazgos if hallazgos else None
    except Exception as e:
        print(f"⚠️ Error cargando {filename}: {str(e)}")
        return None


    def process_trufflehog(self, filename='trufflehog-results.json'):
        data = self.load_json(filename)
        if not data: return
        events = data if isinstance(data, list) else [data]
        for event in events:
            # Validar que sea un hallazgo real y no un log
            if not isinstance(event, dict) or 'DetectorName' not in event: continue
            
            source_inc = event.get('SourceMetadata', {}).get('Data', {}).get('Git', {})
            self.findings["1_secrets"].append({
                "tool": "TruffleHog",
                "type": f"Credential Leak ({event.get('DetectorName')})",
                "file": source_inc.get('file', 'N/A'),
                "line": source_inc.get('line', 'N/A'),
                "severity": "CRITICAL"
            })

    def process_snyk(self, filename='snyk-results.json'):
        data = self.load_json(filename)
        if not data: return
        reports = data if isinstance(data, list) else [data]
        for report in reports:
            # Snyk puede devolver un error en el JSON si no se autenticó
            if 'error' in report and not report.get('vulnerabilities'): continue
            
            for v in report.get('vulnerabilities', []):
                if v.get('severity') in ['critical', 'high']:
                    self.findings["2_dependencies"].append({
                        "tool": "Snyk",
                        "package": v.get('packageName'),
                        "vulnerability": v.get('title'),
                        "severity": v.get('severity').upper(),
                        "fix": v.get('fixedIn', 'Update available')
                    })

    def process_semgrep(self, filename='semgrep-results.json'):
        data = self.load_json(filename)
        if not data: return
        # Maneja tanto JSON de Semgrep como SARIF
        results = data.get('results', []) if 'results' in data else []
        if not results and 'runs' in data: # Es SARIF
            for run in data.get('runs', []):
                for res in run.get('results', []):
                    results.append(res)

        for result in results:
            extra = result.get('extra', {})
            # Filtrar solo crítico/alto
            sev = extra.get('severity', result.get('level', '')).upper()
            if sev in ['ERROR', 'HIGH', 'CRITICAL']:
                self.findings["3_sast"].append({
                    "tool": "Semgrep",
                    "rule": result.get('check_id') or result.get('ruleId'),
                    "file": result.get('path') or result.get('locations', [{}])[0].get('physicalLocation', {}).get('artifactLocation', {}).get('uri'),
                    "severity": sev,
                    "message": extra.get('message') or result.get('message', {}).get('text')
                })

    def process_trivy(self, filename='trivy-results.json'):
        """Procesa hallazgos de contenedores (Trivy) detectados en Code Scanning"""
        data = self.load_json(filename)
        if not data: return
        
        results = data.get('Results', [])
        for res in results:
            for v in res.get('Vulnerabilities', []):
                if v.get('Severity') in ['CRITICAL', 'HIGH']:
                    self.findings["4_containers"].append({
                        "tool": "Trivy",
                        "library": v.get('PkgName'),
                        "vulnerability": v.get('VulnerabilityID'),
                        "severity": v.get('Severity'),
                        "installed": v.get('InstalledVersion'),
                        "fixed": v.get('FixedVersion', 'N/A')
                    })

    def process_zap(self, filename='zap-results.json'):
        data = self.load_json(filename)
        if not data: return
        for site in data.get('site', []):
            for alert in site.get('alerts', []):
                if alert.get('riskcode') in ['3', '2']: 
                    self.findings["5_dast"].append({
                        "tool": "ZAP",
                        "alert": alert.get('alert'),
                        "risk": alert.get('riskdesc'),
                        "solution": alert.get('solution')
                    })

    def get_priority_phase(self):
        # Define el orden de importancia del bloqueo
        order = ["1_secrets", "2_dependencies", "3_sast", "4_containers", "5_dast"]
        for phase in order:
            if self.findings[phase]:
                return phase, self.findings[phase]
        return None, []

    def call_claude_ai(self, phase, issues):
        api_key = os.environ.get("CLAUDE_API_KEY")
        if not api_key: return "❌ Error: API Key de Claude no configurada."

        client = Anthropic(api_key=api_key)
        
        prompt = f"""Actúa como un experto en DevSecOps Senior. 
        Analiza estos hallazgos críticos de la fase: {phase}.
        
        Genera un informe en Markdown:
        1. Resumen del riesgo para el negocio.
        2. Tabla de hallazgos (Herramienta, Severidad, Ubicación).
        3. Instrucciones técnicas de remediación con ejemplos de 'Código Seguro'.
        
        DATOS TÉCNICOS:
        {json.dumps(issues, indent=2)}
        """

        try:
            response = client.messages.create(
                model="claude-3-5-sonnet-20240620",
                max_tokens=2500,
                temperature=0,
                messages=[{"role": "user", "content": prompt}]
            )
            return response.content[0].text
        except Exception as e:
            return f"❌ Error en Claude: {str(e)}"

def main():
    # Directorio donde se descargan los artefactos en el pipeline
    results_path = sys.argv[1] if len(sys.argv) > 1 else 'security-results'
    normalizer = SecurityNormalizer(results_path)
    
    # 1. Recolección de datos
    normalizer.process_trufflehog()
    normalizer.process_snyk()
    normalizer.process_semgrep()
    normalizer.process_trivy()
    normalizer.process_zap()

    # 2. Triaje: ¿Hay algo crítico?
    phase, issues = normalizer.get_priority_phase()

    summary_path = os.getenv('GITHUB_STEP_SUMMARY')
    
    if not phase:
        msg = "✅ **PROYECTO APROBADO**: No se detectaron vulnerabilidades críticas ni altas en el escaneo actual."
        if summary_path:
            with open(summary_path, 'a') as f: f.write(f"\n# 🤖 AI Security Mentor\n{msg}")
        print(msg)
        sys.exit(0)

    # 3. Explicación de la IA
    print(f"🚀 Hallazgos encontrados en {phase}. Consultando al Mentor de IA...")
    report = normalizer.call_claude_ai(phase, issues)

    if summary_path:
        with open(summary_path, 'a', encoding='utf-8') as f:
            f.write(f"\n# 🤖 Reporte de Auditoría IA\n")
            f.write(f"## 🚨 Bloqueo en Fase: {phase.upper()}\n")
            f.write(report)
            f.write("\n\n---\n*Reporte generado automáticamente basado en el análisis de herramientas estáticas y dinámicas.*")

    print(f"\n❌ Pipeline bloqueado por política de seguridad en: {phase}")
    sys.exit(1)

if __name__ == "__main__":
    main()
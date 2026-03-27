import json
import os
import sys
from anthropic import Anthropic

class SecurityNormalizer:
    def __init__(self):
        self.findings = {
            "1_secrets": [],      # Fase 1: TruffleHog
            "2_dependencies": [], # Fase 2: Snyk
            "3_sast": [],         # Fase 3: Semgrep
            "4_dast": []          # Fase 4: ZAP
        }
    
    # CORRECCIÓN: Añadido 'self' y lógica para archivos JSON y JSONL
    def load_json(self, ruta_archivo):
        if not os.path.exists(ruta_archivo):
            return None
        
        hallazgos = []
        try:
            with open(ruta_archivo, 'r', encoding='utf-8') as f:
                content = f.read().strip()
                if not content: return None
                
                # Intentamos cargar como JSON único primero (Snyk/Semgrep)
                try:
                    return json.loads(content)
                except json.JSONDecodeError:
                    # Si falla, procesamos línea por línea (TruffleHog/JSONL)
                    f.seek(0)
                    for linea in f:
                        if linea.strip():
                            hallazgos.append(json.loads(linea))
                    return hallazgos
        except Exception as e:
            print(f"⚠️ Error cargando {ruta_archivo}: {str(e)}")
            return None

    def process_trufflehog(self, path='trufflehog-results.json'):
        data = self.load_json(path)
        if not data: return
        # TruffleHog puede venir como lista o eventos sueltos
        events = data if isinstance(data, list) else [data]
        for event in events:
            # Estructura específica de TruffleHog
            detector = event.get('DetectorName', 'Unknown')
            # Navegamos por el dict de forma segura
            source_inc = event.get('SourceMetadata', {}).get('Data', {}).get('Git', {})
            if not source_inc: continue
            
            self.findings["1_secrets"].append({
                "tool": "TruffleHog",
                "type": f"Credential Leak ({detector})",
                "file": source_inc.get('file', 'N/A'),
                "line": source_inc.get('line', 'N/A'),
                "severity": "CRITICAL",
                "remediation": "Revocar credencial, rotar y usar GitHub Secrets."
            })

    def process_snyk(self, path='snyk-results.json'):
        data = self.load_json(path)
        if not data: return
        # Snyk a veces devuelve una lista de proyectos o un objeto único
        reports = data if isinstance(data, list) else [data]
        for report in reports:
            for v in report.get('vulnerabilities', []):
                if v.get('severity') in ['critical', 'high']:
                    self.findings["2_dependencies"].append({
                        "tool": "Snyk",
                        "package": v.get('packageName'),
                        "vulnerability": v.get('title'),
                        "severity": v.get('severity').upper(),
                        "fix_version": v.get('fixedIn', 'Update available'),
                        "id": v.get('id')
                    })

    def process_semgrep(self, path='semgrep-results.sarif'):
        data = self.load_json(path)
        if not data: return
        for run in data.get('runs', []):
            for result in run.get('results', []):
                # En SARIF, 'error' suele ser crítico
                if result.get('level') in ['error', 'warning']:
                    loc = result.get('locations', [{}])[0].get('physicalLocation', {})
                    self.findings["3_sast"].append({
                        "tool": "Semgrep",
                        "rule": result.get('ruleId'),
                        "file": loc.get('artifactLocation', {}).get('uri'),
                        "line": loc.get('region', {}).get('startLine'),
                        "message": result.get('message', {}).get('text')
                    })

    def process_zap(self, path='zap-results.json'):
        data = self.load_json(path)
        if not data: return
        for site in data.get('site', []):
            for alert in site.get('alerts', []):
                if alert.get('riskcode') in ['3', '2']: 
                    self.findings["4_dast"].append({
                        "tool": "ZAP",
                        "alert": alert.get('alert'),
                        "risk": alert.get('riskdesc'),
                        "solution": alert.get('solution')
                    })

    def get_priority_phase(self):
        # El orden aquí define qué fase detiene el pipeline primero
        for phase in ["1_secrets", "2_dependencies", "3_sast", "4_dast"]:
            if self.findings[phase]:
                return phase, self.findings[phase]
        return None, []

    def call_claude_ai(self, phase, issues):
        api_key = os.environ.get("CLAUDE_API_KEY")
        if not api_key: return "❌ Error: API Key de Claude no configurada."

        client = Anthropic(api_key=api_key)
        
        prompt = f"""Actúa como un experto en DevSecOps Senior. 
        Analiza los hallazgos de seguridad de la fase: {phase}.
        
        Genera un informe en Markdown que incluya:
        1. Riesgo de cada hallazgo.
        2. Ubicación exacta (archivo/línea).
        3. Guía de remediación con ejemplos de Código Vulnerable vs Código Seguro (Antes/Después).
        
        DATOS:
        {json.dumps(issues, indent=2)}
        """

        try:
            response = client.messages.create(
                model="claude-3-5-sonnet-20240620",
                max_tokens=3000,
                temperature=0,
                messages=[{"role": "user", "content": prompt}]
            )
            return response.content[0].text
        except Exception as e:
            return f"❌ Error llamando a Claude: {str(e)}"

def main():
    normalizer = SecurityNormalizer()
    
    # Procesar archivos
    normalizer.process_trufflehog()
    normalizer.process_snyk()
    normalizer.process_semgrep()
    normalizer.process_zap()

    phase, issues = normalizer.get_priority_phase()

    summary_path = os.getenv('GITHUB_STEP_SUMMARY')
    
    if not phase:
        msg = "✅ **PROYECTO APROBADO**: No se encontraron vulnerabilidades críticas en ninguna fase."
        if summary_path:
            with open(summary_path, 'a') as f: f.write(f"\n# 🤖 Reporte de IA\n{msg}")
        print(msg)
        sys.exit(0)

    print(f"🚀 Generando reporte de IA para {phase}...")
    report = normalizer.call_claude_ai(phase, issues)

    if summary_path:
        with open(summary_path, 'a', encoding='utf-8') as f:
            f.write(f"\n# 🤖 Reporte de Gobernanza e IA\n")
            f.write(f"## 🚨 Fase Bloqueante: {phase.replace('_', ' ').upper()}\n")
            f.write(report)
            f.write("\n\n---\n_Analizado por Claude 3.5 Sonnet_")

    print(f"\n❌ Pipeline detenido por vulnerabilidades en {phase}.")
    sys.exit(1)

if __name__ == "__main__":
    main()
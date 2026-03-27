import json
import os
import sys
from anthropic import Anthropic

class SecurityNormalizer:
    def __init__(self):
        # Estructura jerárquica: Solo se atiende una fase a la vez
        self.findings = {
            "1_secrets": [],      # Fase 1: Credenciales (TruffleHog)
            "2_dependencies": [], # Fase 2: Librerías (Snyk/Trivy)
            "3_sast": [],         # Fase 3: Código Estático (Semgrep/CodeQL)
            "4_dast": []          # Fase 4: Aplicación en vivo (ZAP)
        }

    def load_json(self, path):
        if not os.path.exists(path): return None
        try:
            with open(path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            print(f"⚠️ Error cargando {path}: {e}")
            return None

    # --- PROCESADORES DE HERRAMIENTAS ---

    def process_trufflehog(self, path='trufflehog-results.json'):
        data = self.load_json(path)
        if not data: return
        events = data if isinstance(data, list) else [data]
        for event in events:
            detector = event.get('DetectorName', 'Unknown')
            meta = event.get('SourceMetadata', {}).get('Data', {}).get('Git', {})
            self.findings["1_secrets"].append({
                "tool": "TruffleHog",
                "type": f"Credential Leak ({detector})",
                "file": meta.get('file', 'N/A'),
                "line": meta.get('line', 'N/A'),
                "severity": "CRITICAL",
                "remediation": "Revocar credencial, rotar y usar GitHub Secrets."
            })

    def process_snyk(self, path='snyk-results.json'):
        data = self.load_json(path)
        if not data: return
        reports = data if isinstance(data, list) else [data]
        for report in reports:
            for v in report.get('vulnerabilities', []):
                if v.get('severity') in ['critical', 'high']:
                    self.findings["2_dependencies"].append({
                        "tool": "Snyk",
                        "package": v.get('packageName'),
                        "vulnerability": v.get('title'),
                        "severity": v.get('severity').upper(),
                        "fix_version": v.get('fixedIn', 'Update to latest'),
                        "id": v.get('id')
                    })

    def process_semgrep(self, path='semgrep-results.sarif'):
        data = self.load_json(path)
        if not data: return
        for run in data.get('runs', []):
            for result in run.get('results', []):
                if result.get('level') == 'error':
                    loc = result.get('locations', [{}])[0].get('physicalLocation', {})
                    self.findings["3_sast"].append({
                        "tool": "Semgrep",
                        "rule": result.get('ruleId'),
                        "file": loc.get('artifactLocation', {}).get('uri'),
                        "line": loc.get('region', {}).get('startLine'),
                        "message": result.get('message', {}).get('text')
                    })

    def process_zap(self, path='zap-results.json'):
        # Implementación simplificada para ZAP
        data = self.load_json(path)
        if not data: return
        for site in data.get('site', []):
            for alert in site.get('alerts', []):
                if alert.get('riskcode') in ['3', '2']: # High/Medium
                    self.findings["4_dast"].append({
                        "tool": "ZAP",
                        "alert": alert.get('alert'),
                        "risk": alert.get('riskdesc'),
                        "solution": alert.get('solution')
                    })

    # --- LÓGICA DE TRIAGE E IA ---

    def get_priority_phase(self):
        for phase in ["1_secrets", "2_dependencies", "3_sast", "4_dast"]:
            if self.findings[phase]:
                return phase, self.findings[phase]
        return None, []

    def call_claude_ai(self, phase, issues):
        api_key = os.environ.get("CLAUDE_API_KEY")
        if not api_key: return "❌ Error: API Key de Claude no configurada."

        client = Anthropic(api_key=api_key)
        
        prompt = f"""Actúa como un experto en DevSecOps de nivel Senior. 
        Analiza los siguientes hallazgos de seguridad detectados en la fase: {phase}.
        
        Tu tarea es generar un informe detallado en Markdown para el desarrollador.
        REQUISITOS:
        1. Explica brevemente el riesgo de cada hallazgo.
        2. Indica la ubicación exacta (archivo/línea).
        3. Proporciona una guía de remediación clara.
        4. MUY IMPORTANTE: Incluye un ejemplo de código vulnerable y cómo debería quedar corregido (Antes/Después).
        
        HALLAZGOS:
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
    
    # Recolectar datos
    normalizer.process_trufflehog()
    normalizer.process_snyk()
    normalizer.process_semgrep()
    normalizer.process_zap()

    # Identificar la fase más urgente
    phase, issues = normalizer.get_priority_phase()

    if not phase:
        print("✅ PROYECTO APROBADO: No se encontraron vulnerabilidades críticas.")
        sys.exit(0)

    # Generar Reporte con IA
    print(f"🚀 Iniciando Triage de IA para la fase: {phase}")
    report = normalizer.call_claude_ai(phase, issues)

    # Escribir en el Summary de GitHub Actions
    summary_path = os.getenv('GITHUB_STEP_SUMMARY')
    if summary_path:
        with open(summary_path, 'a', encoding='utf-8') as f:
            f.write(f"\n# 🤖 Reporte de Gobernanza e IA\n")
            f.write(f"## Fase bloqueante: {phase.replace('_', ' ').upper()}\n")
            f.write(report)
            f.write("\n\n---\n_Reporte generado automáticamente por Claude 3.5 Sonnet_")

    print(f"\n❌ Pipeline detenido en la fase {phase}. Revisa el Summary de la ejecución.")
    sys.exit(1)

if __name__ == "__main__":
    main()
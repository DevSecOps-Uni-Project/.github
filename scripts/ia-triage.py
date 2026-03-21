import json
import os
import sys
import re

def load_json_safely(file_path):
    """Carga archivos JSON/SARIF manejando errores de formato."""
    if not os.path.exists(file_path):
        return None
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read().strip()
            if not content: return None
            # Intento de parseo estándar
            try:
                return json.loads(content)
            except json.JSONDecodeError:
                # Intento de rescate si el JSON tiene texto extra al inicio/final
                match = re.search(r'({[\s\S]*})', content)
                if match:
                    return json.loads(match.group(1))
            return None
    except Exception as e:
        print(f"⚠️ Error procesando {file_path}: {e}")
        return None

def analyze_zap_html(file_path):
    """Analiza el reporte HTML de ZAP buscando patrones de riesgo."""
    if not os.path.exists(file_path):
        return 0, []
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            html = f.read()
            # ZAP usa clases CSS 'risk-3' para Alto y 'risk-2' para Medio
            high_alerts = len(re.findall(r'class="risk-3"', html))
            med_alerts = len(re.findall(r'class="risk-2"', html))
            
            alerts = []
            if high_alerts > 0: alerts.append(f"🔥 DAST (ZAP): {high_alerts} alertas de RIESGO ALTO.")
            if med_alerts > 0: alerts.append(f"⚠️ DAST (ZAP): {med_alerts} alertas de RIESGO MEDIO.")
            
            return (high_alerts + med_alerts), alerts
    except Exception as e:
        print(f"⚠️ Error analizando ZAP HTML: {e}")
        return 0, []

def analyze_all():
    print("\n" + "="*55)
    print("🤖 IA SECURITY TRIAGE REPORT - PROYECTO IDS")
    print("Estándar: SARIF Compliance | Java 21 LTS")
    repo_name = os.getenv('GITHUB_REPOSITORY', 'Proyecto Local')
    print(f"📌 Target: {repo_name}")
    print("="*55 + "\n")
    
    total_critical = 0
    summary = []

    # 1. SAST (Semgrep)
    semgrep_data = load_json_safely('semgrep-results.sarif')
    if semgrep_data:
        runs = semgrep_data.get('runs', [])
        if runs:
            results = runs[0].get('results', [])
            s_crit = [r for r in results if r.get('level') == 'error']
            if s_crit:
                total_critical += len(s_crit)
                summary.append(f"🔍 SAST (Semgrep): {len(s_crit)} fallos críticos en lógica.")

    # 2. SCA (Snyk)
    snyk_data = load_json_safely('snyk-results.json')
    if snyk_data:
        vulns = snyk_data if isinstance(snyk_data, list) else snyk_data.get('vulnerabilities', [])
        # Si es lista (multiple scans), aplanamos
        if isinstance(snyk_data, list):
            vulns = [v for item in snyk_data for v in item.get('vulnerabilities', [])]
        
        sn_crit = [v for v in vulns if v.get('severity') in ['critical', 'high']]
        if sn_crit:
            total_critical += len(sn_crit)
            summary.append(f"📦 SCA (Snyk): {len(sn_crit)} vulnerabilidades en dependencias.")

    # 3. CONTAINER (Trivy)
    trivy_data = load_json_safely('trivy-results.sarif')
    if trivy_data:
        runs = trivy_data.get('runs', [])
        if runs:
            results = runs[0].get('results', [])
            t_crit = len([r for r in results if r.get('level') in ['error']])
            if t_crit > 0:
                total_critical += t_crit
                summary.append(f"🐳 Container (Trivy): {t_crit} riesgos detectados en la imagen.")

    # 4. DAST (ZAP)
    zap_count, zap_summary = analyze_zap_html('zap-results.html')
    if zap_count > 0:
        total_critical += zap_count
        summary.extend(zap_summary)
    else:
        # Verificamos si al menos el archivo existe aunque no tenga alertas
        if os.path.exists('zap-results.html'):
            summary.append("✅ DAST (ZAP): Sin riesgos críticos detectados.")
        else:
            summary.append("⚪ DAST (ZAP): Reporte no disponible.")

    # --- SALIDA ---
    print("\n" + "-"*40)
    print("📊 RESUMEN EJECUTIVO DE GOBERNANZA:")
    if not summary:
        print("   ✅ No se encontraron vulnerabilidades.")
    else:
        for item in summary:
            print(f"   - {item}")
    print("-"*40)

    if total_critical > 0:
        print(f"\n❌ DECISIÓN IA: RECHAZADO (Blocked)")
        print(f"Motivo: {total_critical} hallazgos de riesgo acumulados.")
        sys.exit(1) 
    else:
        print("\n✅ DECISIÓN IA: APROBADO (Passed)")
        sys.exit(0)

if __name__ == "__main__":
    analyze_all()
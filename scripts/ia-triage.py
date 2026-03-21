import json
import os
import sys
import re

def load_json_safely(file_path):
    """Carga archivos JSON/SARIF manejando errores de formato y archivos vacíos."""
    if not os.path.exists(file_path):
        return None
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read().strip()
            if not content: 
                return None
            try:
                return json.loads(content)
            except json.JSONDecodeError:
                # Intento de rescate para JSON malformados por logs de consola
                match = re.search(r'({[\s\S]*})', content)
                if match:
                    return json.loads(match.group(1))
            return None
    except Exception as e:
        print(f"⚠️ Error procesando {file_path}: {e}")
        return None

def analyze_zap_html(file_path):
    """Extrae alertas del reporte HTML de ZAP usando selectores de clase CSS."""
    if not os.path.exists(file_path):
        return 0, []
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            html = f.read()
            # ZAP estándar usa class="risk-3" para High y risk-2 para Medium
            high_alerts = len(re.findall(r'class="risk-3"', html))
            med_alerts = len(re.findall(r'class="risk-2"', html))
            
            alerts = []
            if high_alerts > 0: 
                alerts.append(f"🔥 DAST (ZAP): {high_alerts} alertas de RIESGO ALTO.")
            if med_alerts > 0: 
                alerts.append(f"⚠️ DAST (ZAP): {med_alerts} alertas de RIESGO MEDIO.")
            
            return (high_alerts + med_alerts), alerts
    except Exception as e:
        print(f"⚠️ Error analizando ZAP HTML: {e}")
        return 0, []

def analyze_all():
    print("\n" + "="*60)
    print("🤖 IA SECURITY TRIAGE REPORT - PROYECTO IDS")
    print("Estándar: SARIF & SCA Compliance | Java 21 LTS")
    repo_name = os.getenv('GITHUB_REPOSITORY', 'Proyecto Local')
    print(f"📌 Target: {repo_name}")
    print("="*60 + "\n")
    
    total_critical = 0
    summary = []

    # 1. SAST (Semgrep)
    semgrep_data = load_json_safely('semgrep-results.sarif')
    if semgrep_data:
        runs = semgrep_data.get('runs', [])
        if runs:
            results = runs[0].get('results', [])
            # En SARIF 'error' equivale a crítico/bloqueante
            s_crit = [r for r in results if r.get('level') == 'error']
            if s_crit:
                total_critical += len(s_crit)
                summary.append(f"🔍 SAST (Semgrep): {len(s_crit)} fallos críticos en código.")

    # 2. SCA (Snyk) - LOGICA PARA TUS 9 RIESGOS (2C/7H)
    snyk_data = load_json_safely('snyk-results.json')
    if snyk_data:
        # Aplanamos si Snyk devuelve una lista de múltiples escaneos
        reports = snyk_data if isinstance(snyk_data, list) else [snyk_data]
        sn_count = 0
        
        for report in reports:
            vulns = report.get('vulnerabilities', [])
            # Filtramos exactamente por los niveles que bloquean el pipeline
            findings = [v for v in vulns if v.get('severity') in ['critical', 'high']]
            sn_count += len(findings)
        
        if sn_count > 0:
            total_critical += sn_count
            summary.append(f"📦 SCA (Snyk): {sn_count} vulnerabilidades críticas/altas en dependencias.")

    # 3. CONTAINER (Trivy)
    trivy_data = load_json_safely('trivy-results.sarif')
    if trivy_data:
        runs = trivy_data.get('runs', [])
        if runs:
            results = runs[0].get('results', [])
            t_crit = len([r for r in results if r.get('level') in ['error']])
            if t_crit > 0:
                total_critical += t_crit
                summary.append(f"🐳 Container (Trivy): {t_crit} vulnerabilidades en la imagen Docker.")

    # 4. DAST (ZAP)
    zap_count, zap_summary = analyze_zap_html('zap-results.html')
    if zap_count > 0:
        total_critical += zap_count
        summary.extend(zap_summary)
    else:
        if os.path.exists('zap-results.html'):
            summary.append("✅ DAST (ZAP): No se detectaron riesgos activos en la URL.")
        else:
            summary.append("⚪ DAST (ZAP): Reporte no disponible o vacío.")

    # --- RESUMEN FINAL ---
    print("\n" + "-"*45)
    print("📊 RESUMEN DE GOBERNANZA:")
    if not summary:
        print("   ✅ No se encontraron vulnerabilidades pendientes.")
    else:
        for item in summary:
            print(f"   - {item}")
    print("-" * 45)

    if total_critical > 0:
        print(f"\n❌ DECISIÓN IA: RECHAZADO (Blocked)")
        print(f"Motivo: Se han acumulado {total_critical} hallazgos de seguridad no permitidos.")
        print("Acción: Corrija las dependencias (Snyk) o la lógica de código antes de reintentar.\n")
        sys.exit(1) 
    else:
        print("\n✅ DECISIÓN IA: APROBADO (Passed)")
        print("Gobernanza cumplida satisfactoriamente.\n")
        sys.exit(0)

if __name__ == "__main__":
    analyze_all()
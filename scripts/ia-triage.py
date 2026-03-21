import json
import os
import sys
import re

def load_json_safely(file_path):
    """
    Carga archivos JSON manejando múltiples objetos secuenciales (NDJSON/Concatenated JSON).
    Esto soluciona el error: 'Extra data: line ... column ...'
    """
    if not os.path.exists(file_path):
        return None
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read().strip()
            if not content: return None
            
            results = []
            decoder = json.JSONDecoder()
            pos = 0
            # Intentamos decodificar todos los objetos JSON presentes en el archivo
            while pos < len(content):
                try:
                    # Eliminar espacios/saltos de línea antes de cada objeto
                    content = content.lstrip()
                    if not content: break
                    
                    obj, pos = decoder.raw_decode(content)
                    results.append(obj)
                    content = content[pos:].lstrip()
                    pos = 0 # Reiniciamos pos porque estamos recortando el string
                except json.JSONDecodeError:
                    break
            
            return results if results else None
    except Exception as e:
        print(f"⚠️ Error procesando {file_path}: {e}")
        return None

def _extract_zap_summary_count(html, label):
    """Extrae el conteo numérico de la tabla Summary of Alerts (High/Medium)."""
    patterns = [
        rf'<td[^>]*>\s*{label}\s*: ?\s*</td>\s*<td[^>]*>\s*(\d+)\s*</td>',
        rf'<th[^>]*>\s*{label}\s*: ?\s*</th>\s*<td[^>]*>\s*(\d+)\s*</td>'
    ]
    for pattern in patterns:
        match = re.search(pattern, html, flags=re.IGNORECASE | re.DOTALL)
        if match:
            return int(match.group(1))
    return 0

def analyze_zap_html(file_path):
    """Analiza el reporte HTML de ZAP usando la tabla de Summary of Alerts."""
    if not os.path.exists(file_path):
        return 0, []
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            html = f.read()
            high = _extract_zap_summary_count(html, 'High')
            med = _extract_zap_summary_count(html, 'Medium')

            alerts = []
            if high > 0:
                alerts.append(f"🔥 DAST (ZAP): {high} alertas de RIESGO ALTO.")
            if med > 0:
                alerts.append(f"⚠️ DAST (ZAP): {med} alertas de RIESGO MEDIO.")
            return (high + med), alerts
    except Exception:
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
        # Semgrep suele ser un solo objeto SARIF
        report = semgrep_data[0] if isinstance(semgrep_data, list) else semgrep_data
        try:
            results = report.get('runs', [{}])[0].get('results', [])
            s_crit = [r for r in results if r.get('level') == 'error']
            if s_crit:
                total_critical += len(s_crit)
                summary.append(f"🔍 SAST (Semgrep): {len(s_crit)} fallos críticos.")
        except: pass

    # 2. SCA (Snyk) - LOGICA PARA LOS 9 RIESGOS (2C/7H)
    snyk_results = load_json_safely('snyk-results.json')
    if snyk_results:
        sn_count = 0
        # Iteramos sobre todos los objetos JSON encontrados (por si escaneó varios archivos)
        for report in snyk_results:
            vulns = report.get('vulnerabilities', [])
            findings = [v for v in vulns if v.get('severity') in ['critical', 'high']]
            sn_count += len(findings)
        
        if sn_count > 0:
            total_critical += sn_count
            summary.append(f"📦 SCA (Snyk): {sn_count} vulnerabilidades críticas/altas.")

    # 3. CONTAINER (Trivy)
    trivy_data = load_json_safely('trivy-results.sarif')
    if trivy_data:
        report = trivy_data[0] if isinstance(trivy_data, list) else trivy_data
        try:
            results = report.get('runs', [{}])[0].get('results', [])
            t_crit = len([r for r in results if r.get('level') == 'error'])
            if t_crit > 0:
                total_critical += t_crit
                summary.append(f"🐳 Container (Trivy): {t_crit} riesgos en imagen.")
        except: pass

    # 4. DAST (ZAP)
    zap_count, zap_summary = analyze_zap_html('zap-results.html')
    if zap_count > 0:
        total_critical += zap_count
        summary.extend(zap_summary)
    else:
        status = "✅ Sin riesgos" if os.path.exists('zap-results.html') else "⚪ No disponible"
        summary.append(f"DAST (ZAP): {status}")

    # --- SALIDA ---
    print("\n" + "-"*45)
    print("📊 RESUMEN DE GOBERNANZA:")
    for item in summary:
        print(f"   - {item}")
    print("-" * 45)

    if total_critical > 0:
        print(f"\n❌ DECISIÓN IA: RECHAZADO (Blocked)")
        print(f"Motivo: {total_critical} hallazgos de seguridad acumulados.")
        sys.exit(1) 
    else:
        print("\n✅ DECISIÓN IA: APROBADO (Passed)")
        sys.exit(0)

if __name__ == "__main__":
    analyze_all()
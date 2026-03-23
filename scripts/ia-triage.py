import json
import os
import sys
import re

def load_json_safely(file_path):
    """Carga archivos JSON manejando múltiples objetos secuenciales."""
    if not os.path.exists(file_path):
        return None
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read().strip()
            if not content: return None
            
            results = []
            decoder = json.JSONDecoder()
            pos = 0
            while pos < len(content):
                try:
                    content = content.lstrip()
                    if not content: break
                    obj, pos = decoder.raw_decode(content)
                    results.append(obj)
                    content = content[pos:].lstrip()
                    pos = 0 
                except json.JSONDecodeError:
                    break
            return results if results else None
    except Exception as e:
        print(f"⚠️ Error procesando {file_path}: {e}")
        return None

def _extract_zap_summary_count(html, label):
    """Extrae el conteo numérico de la tabla Summary of Alerts."""
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
    """Analiza el reporte HTML de ZAP."""
    if not os.path.exists(file_path):
        return 0, []
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            html = f.read()
            high = _extract_zap_summary_count(html, 'High')
            med = _extract_zap_summary_count(html, 'Medium')
            alerts = []
            if high > 0: alerts.append(f"🔥 DAST (ZAP): {high} alertas de RIESGO ALTO.")
            if med > 0: alerts.append(f"⚠️ DAST (ZAP): {med} alertas de RIESGO MEDIO.")
            return (high + med), alerts
    except Exception:
        return 0, []

def write_to_github_summary(total_critical, summary):
    """Escribe el veredicto de la IA en el resumen de la ejecución de GitHub."""
    summary_path = os.getenv('GITHUB_STEP_SUMMARY')
    if summary_path:
        with open(summary_path, 'a', encoding='utf-8') as f:
            f.write("## 🤖 Reporte de Triage de IA (Gobernanza)\n")
            status = "❌ **RECHAZADO**" if total_critical > 0 else "✅ **APROBADO**"
            f.write(f"### Estado Final: {status}\n\n")
            f.write("| Herramienta | Hallazgos detectados |\n")
            f.write("| :--- | :--- |\n")
            for item in summary:
                # Formatear cada item como fila de tabla
                parts = item.split(':')
                tool = parts[0] if len(parts) > 0 else "Herramienta"
                desc = parts[1].strip() if len(parts) > 1 else item
                f.write(f"| {tool} | {desc} |\n")
            
            if total_critical > 0:
                f.write(f"\n> [!CAUTION]\n> Se detuvo el pipeline debido a **{total_critical}** vulnerabilidades críticas o altas.")

def analyze_all():
    print("\n" + "="*60)
    print("🤖 IA SECURITY TRIAGE REPORT - PROYECTO IDS")
    repo_name = os.getenv('GITHUB_REPOSITORY', 'Proyecto Local')
    print(f"📌 Target: {repo_name}")
    print("="*60 + "\n")
    
    total_critical = 0
    summary = []

    # 1. SAST (Semgrep)
    semgrep_data = load_json_safely('semgrep-results.sarif')
    if semgrep_data:
        report = semgrep_data[0] if isinstance(semgrep_data, list) else semgrep_data
        try:
            results = report.get('runs', [{}])[0].get('results', [])
            s_crit = [r for r in results if r.get('level') == 'error']
            if s_crit:
                total_critical += len(s_crit)
                summary.append(f"🔍 SAST (Semgrep): {len(s_crit)} fallos críticos.")
        except: pass

    # 2. SCA (Snyk)
    snyk_results = load_json_safely('snyk-results.json')
    if snyk_results:
        sn_count = 0
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
        summary.append(f"🕸️ DAST (ZAP): ✅ Sin riesgos detectados.")

    # --- SALIDA CONSOLA ---
    print("📊 RESUMEN:")
    for item in summary: print(f"   - {item}")

    # --- SALIDA GITHUB ACTIONS ---
    write_to_github_summary(total_critical, summary)

    if total_critical > 0:
        print(f"\n❌ DECISIÓN IA: RECHAZADO")
        sys.exit(1) 
    else:
        print("\n✅ DECISIÓN IA: APROBADO")
        sys.exit(0)

if __name__ == "__main__":
    analyze_all()
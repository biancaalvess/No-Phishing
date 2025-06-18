import json
from datetime import datetime
from typing import Dict, List, Any
import os

class ReportGenerator:
    def __init__(self):
        self.reports_dir = "reports"
        self._ensure_reports_directory()
    
    def _ensure_reports_directory(self):
        """Garante que o diretório de relatórios existe"""
        if not os.path.exists(self.reports_dir):
            os.makedirs(self.reports_dir)
    
    def generate_detailed_report(self, analysis_result: Dict[str, Any]) -> str:
        """Gera relatório detalhado da análise"""
        report_lines = []
        
        # Cabeçalho
        report_lines.append("=" * 80)
        report_lines.append("🛡️  RELATÓRIO DE ANÁLISE DE SEGURANÇA")
        report_lines.append("=" * 80)
        report_lines.append(f"Data/Hora: {analysis_result.get('timestamp', 'N/A')}")
        report_lines.append(f"Tipo de Análise: {analysis_result.get('type', 'N/A').upper()}")
        report_lines.append("")
        
        # Resumo Executivo
        report_lines.append("📊 RESUMO EXECUTIVO")
        report_lines.append("-" * 40)
        report_lines.append(f"Nível de Risco: {analysis_result.get('risk_level', 'N/A')}")
        report_lines.append(f"Score de Risco: {analysis_result.get('risk_score', 0):.1f}/100")
        
        # Adiciona emoji baseado no risco
        risk_level = analysis_result.get('risk_level', '')
        if risk_level == 'CRÍTICO':
            report_lines.append("Status: 🚨 PERIGO IMINENTE")
        elif risk_level == 'ALTO':
            report_lines.append("Status: ⚠️ ALTO RISCO")
        elif risk_level == 'MÉDIO':
            report_lines.append("Status: ⚡ RISCO MODERADO")
        elif risk_level == 'BAIXO':
            report_lines.append("Status: ✅ BAIXO RISCO")
        else:
            report_lines.append("Status: ℹ️ RISCO MÍNIMO")
        
        report_lines.append("")
        
        # Recomendações
        recommendations = analysis_result.get('recommendations', [])
        if recommendations:
            report_lines.append("💡 RECOMENDAÇÕES PRIORITÁRIAS")
            report_lines.append("-" * 40)
            for i, rec in enumerate(recommendations, 1):
                report_lines.append(f"{i}. {rec}")
            report_lines.append("")
        
        # Análise específica por tipo
        if analysis_result.get('type') == 'email':
            report_lines.extend(self._generate_email_analysis_section(analysis_result))
        elif analysis_result.get('type') == 'url':
            report_lines.extend(self._generate_url_analysis_section(analysis_result))
        
        # Rodapé
        report_lines.append("=" * 80)
        report_lines.append("Relatório gerado pelo Sistema de Detecção de Phishing")
        report_lines.append(f"Versão 1.0 - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report_lines.append("=" * 80)
        
        return "\n".join(report_lines)
    
    def _generate_email_analysis_section(self, analysis_result: Dict[str, Any]) -> List[str]:
        """Gera seção específica para análise de email"""
        lines = []
        
        # Análise de Conteúdo
        content_analysis = analysis_result.get('content_analysis', {})
        lines.append("📧 ANÁLISE DE CONTEÚDO")
        lines.append("-" * 40)
        lines.append(f"Score de Urgência: {content_analysis.get('urgency_score', 0):.1f}/40")
        lines.append(f"Score Social Engineering: {content_analysis.get('social_score', 0):.1f}/30")
        lines.append(f"Score Credenciais: {content_analysis.get('credential_score', 0):.1f}/30")
        lines.append(f"Score Formatação: {content_analysis.get('formatting_score', 0):.1f}/20")
        
        if content_analysis.get('urgency_detected'):
            lines.append("⚠️ Táticas de urgência detectadas")
        if content_analysis.get('social_engineering_detected'):
            lines.append("🎭 Engenharia social detectada")
        if content_analysis.get('requests_credentials'):
            lines.append("🔐 Solicitação de credenciais detectada")
        
        lines.append("")
        
        # Análise do Remetente
        sender_analysis = analysis_result.get('sender_analysis', {})
        if sender_analysis:
            lines.append("👤 ANÁLISE DO REMETENTE")
            lines.append("-" * 40)
            lines.append(f"Domínio: {sender_analysis.get('domain', 'N/A')}")
            lines.append(f"Score de Risco: {sender_analysis.get('risk_score', 0):.1f}/100")
            
            issues = sender_analysis.get('issues', [])
            if issues:
                lines.append("Problemas identificados:")
                for issue in issues:
                    lines.append(f"  • {issue}")
            lines.append("")
        
        # URLs Encontradas
        urls_found = analysis_result.get('urls_found', 0)
        if urls_found > 0:
            lines.append(f"🔗 ANÁLISE DE URLs ({urls_found} encontradas)")
            lines.append("-" * 40)
            
            url_analyses = analysis_result.get('url_analyses', [])
            for i, url_analysis in enumerate(url_analyses, 1):
                lines.append(f"URL {i}: {url_analysis.get('url', 'N/A')[:60]}...")
                lines.append(f"  Risco: {url_analysis.get('risk_level', 'N/A')} ({url_analysis.get('risk_score', 0):.1f}/100)")
                
                url_flags = []
                structure_analysis = url_analysis.get('structure_analysis', {})
                if structure_analysis.get('suspicious_domain'):
                    url_flags.append("Domínio suspeito")
                if structure_analysis.get('url_shortener'):
                    url_flags.append("URL encurtada")
                
                if url_flags:
                    lines.append(f"  Flags: {', '.join(url_flags)}")
                lines.append("")
        
        # Predição ML
        ml_prediction = analysis_result.get('ml_prediction', {})
        if ml_prediction:
            lines.append("🤖 ANÁLISE DE MACHINE LEARNING")
            lines.append("-" * 40)
            lines.append(f"Classificação: {ml_prediction.get('classification', 'N/A')}")
            lines.append(f"Confiança: {ml_prediction.get('confidence', 0):.1%}")
            lines.append(f"Score ML: {ml_prediction.get('risk_score', 0):.1f}/100")
            lines.append("")
        
        return lines
    
    def _generate_url_analysis_section(self, analysis_result: Dict[str, Any]) -> List[str]:
        """Gera seção específica para análise de URL"""
        lines = []
        
        lines.append(f"🌐 URL ANALISADA: {analysis_result.get('url', 'N/A')}")
        lines.append("")
        
        # Análise Estrutural
        structure_analysis = analysis_result.get('structure_analysis', {})
        lines.append("🏗️ ANÁLISE ESTRUTURAL")
        lines.append("-" * 40)
        lines.append(f"Domínio: {structure_analysis.get('domain', 'N/A')}")
        lines.append(f"Protocolo: {structure_analysis.get('protocol', 'N/A')}")
        lines.append(f"Subdomínios: {structure_analysis.get('subdomain_count', 0)}")
        
        flags = structure_analysis.get('flags', [])
        if flags:
            lines.append("Problemas estruturais:")
            for flag in flags:
                lines.append(f"  • {flag}")
        lines.append("")
        
        # Análise de Domínio
        domain_analysis = analysis_result.get('domain_analysis', {})
        if domain_analysis:
            lines.append("🏷️ ANÁLISE DE DOMÍNIO")
            lines.append("-" * 40)
            lines.append(f"Idade estimada: {domain_analysis.get('estimated_age_days', 0)} dias")
            lines.append(f"Spoofing detectado: {'Sim' if domain_analysis.get('spoofing_detected') else 'Não'}")
            lines.append(f"Homógrafo detectado: {'Sim' if domain_analysis.get('homograph_detected') else 'Não'}")
            
            domain_flags = domain_analysis.get('flags', [])
            if domain_flags:
                lines.append("Problemas de domínio:")
                for flag in domain_flags:
                    lines.append(f"  • {flag}")
            lines.append("")
        
        # Análise de Reputação
        reputation_analysis = analysis_result.get('reputation_analysis', {})
        if reputation_analysis:
            lines.append("🛡️ ANÁLISE DE REPUTAÇÃO")
            lines.append("-" * 40)
            lines.append(f"Score de Reputação: {reputation_analysis.get('risk_score', 0):.1f}/100")
            lines.append(f"Em lista negra: {'Sim' if reputation_analysis.get('is_blacklisted') else 'Não'}")
            
            threats = reputation_analysis.get('threats_found', [])
            if threats:
                lines.append("Ameaças identificadas:")
                for threat in threats:
                    lines.append(f"  • {threat}")
            
            sources = reputation_analysis.get('sources', [])
            if sources:
                lines.append(f"Fontes consultadas: {', '.join(sources)}")
            lines.append("")
        
        # Predição ML
        ml_prediction = analysis_result.get('ml_prediction', {})
        if ml_prediction:
            lines.append("🤖 ANÁLISE DE MACHINE LEARNING")
            lines.append("-" * 40)
            lines.append(f"Classificação: {ml_prediction.get('classification', 'N/A')}")
            lines.append(f"Confiança: {ml_prediction.get('confidence', 0):.1%}")
            lines.append(f"Score ML: {ml_prediction.get('risk_score', 0):.1f}/100")
            lines.append("")
        
        return lines
    
    def save_report(self, analysis_result: Dict[str, Any], filename: str = None) -> str:
        """Salva relatório em arquivo"""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            analysis_type = analysis_result.get('type', 'analysis')
            filename = f"{analysis_type}_report_{timestamp}.txt"
        
        filepath = os.path.join(self.reports_dir, filename)
        report_content = self.generate_detailed_report(analysis_result)
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(report_content)
        
        return filepath
    
    def save_json_report(self, analysis_result: Dict[str, Any], filename: str = None) -> str:
        """Salva relatório em formato JSON"""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            analysis_type = analysis_result.get('type', 'analysis')
            filename = f"{analysis_type}_report_{timestamp}.json"
        
        filepath = os.path.join(self.reports_dir, filename)
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(analysis_result, f, indent=2, ensure_ascii=False)
        
        return filepath
    
    def generate_summary_report(self, analyses: List[Dict[str, Any]]) -> str:
        """Gera relatório resumo de múltiplas análises"""
        if not analyses:
            return "Nenhuma análise para gerar relatório."
        
        lines = []
        lines.append("=" * 80)
        lines.append("📊 RELATÓRIO RESUMO DE ANÁLISES")
        lines.append("=" * 80)
        lines.append(f"Total de análises: {len(analyses)}")
        lines.append(f"Período: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append("")
        
        # Estatísticas gerais
        email_count = sum(1 for a in analyses if a.get('type') == 'email')
        url_count = sum(1 for a in analyses if a.get('type') == 'url')
        
        lines.append("📈 ESTATÍSTICAS GERAIS")
        lines.append("-" * 40)
        lines.append(f"Emails analisados: {email_count}")
        lines.append(f"URLs analisadas: {url_count}")
        lines.append("")
        
        # Distribuição de riscos
        risk_distribution = {}
        for analysis in analyses:
            risk_level = analysis.get('risk_level', 'DESCONHECIDO')
            risk_distribution[risk_level] = risk_distribution.get(risk_level, 0) + 1
        
        lines.append("⚠️ DISTRIBUIÇÃO DE RISCOS")
        lines.append("-" * 40)
        for risk_level, count in sorted(risk_distribution.items()):
            percentage = (count / len(analyses)) * 100
            lines.append(f"{risk_level}: {count} ({percentage:.1f}%)")
        lines.append("")
        
        # Top ameaças
        high_risk_analyses = [a for a in analyses if a.get('risk_score', 0) >= 60]
        if high_risk_analyses:
            lines.append("🚨 ANÁLISES DE ALTO RISCO")
            lines.append("-" * 40)
            for i, analysis in enumerate(high_risk_analyses[:5], 1):
                analysis_type = analysis.get('type', 'N/A')
                risk_score = analysis.get('risk_score', 0)
                timestamp = analysis.get('timestamp', 'N/A')
                
                if analysis_type == 'email':
                    identifier = f"Email de {analysis.get('sender_analysis', {}).get('domain', 'N/A')}"
                else:
                    identifier = f"URL: {analysis.get('url', 'N/A')[:50]}..."
                
                lines.append(f"{i}. {identifier}")
                lines.append(f"   Risco: {risk_score:.1f}/100 - {timestamp}")
            lines.append("")
        
        # Recomendações gerais
        lines.append("💡 RECOMENDAÇÕES GERAIS")
        lines.append("-" * 40)
        
        critical_count = risk_distribution.get('CRÍTICO', 0)
        high_count = risk_distribution.get('ALTO', 0)
        
        if critical_count > 0:
            lines.append(f"🚨 {critical_count} análises críticas requerem ação imediata")
        if high_count > 0:
            lines.append(f"⚠️ {high_count} análises de alto risco precisam de atenção")
        
        lines.append("📚 Mantenha treinamento de segurança atualizado")
        lines.append("🔄 Execute análises regulares de segurança")
        lines.append("📊 Monitore tendências de ameaças")
        
        lines.append("")
        lines.append("=" * 80)
        lines.append("Relatório gerado pelo Sistema de Detecção de Phishing")
        lines.append("=" * 80)
        
        return "\n".join(lines)

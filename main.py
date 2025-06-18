import asyncio
import json
from datetime import datetime
from typing import Dict, List, Any
from email_analyzer import EmailAnalyzer
from url_analyzer import URLAnalyzer
from ml_classifier import MLClassifier
from reputation_checker import ReputationChecker
from report_generator import ReportGenerator

class PhishingDetector:
    def __init__(self):
        self.email_analyzer = EmailAnalyzer()
        self.url_analyzer = URLAnalyzer()
        self.ml_classifier = MLClassifier()
        self.reputation_checker = ReputationChecker()
        self.report_generator = ReportGenerator()
        
    async def analyze_email(self, email_content: str, sender: str = None, subject: str = None) -> Dict[str, Any]:
        """Analisa um email completo para detectar phishing"""
        print(f"🔍 Analisando email...")
        
        # Análises paralelas
        tasks = [
            self.email_analyzer.analyze_content(email_content),
            self.email_analyzer.analyze_sender(sender) if sender else asyncio.sleep(0),
            self.email_analyzer.analyze_subject(subject) if subject else asyncio.sleep(0),
            self.ml_classifier.classify_email(email_content),
        ]
        
        results = await asyncio.gather(*tasks)
        content_analysis = results[0]
        sender_analysis = results[1] if sender else {}
        subject_analysis = results[2] if subject else {}
        ml_prediction = results[3]
        
        # URLs encontradas no email
        urls = self.email_analyzer.extract_urls(email_content)
        url_analyses = []
        
        for url in urls[:5]:  # Limita a 5 URLs para performance
            url_analysis = await self.analyze_url(url)
            url_analyses.append(url_analysis)
        
        # Calcula score final
        final_score = self._calculate_email_score(
            content_analysis, sender_analysis, subject_analysis, 
            ml_prediction, url_analyses
        )
        
        result = {
            'type': 'email',
            'timestamp': datetime.now().isoformat(),
            'risk_score': final_score,
            'risk_level': self._get_risk_level(final_score),
            'content_analysis': content_analysis,
            'sender_analysis': sender_analysis,
            'subject_analysis': subject_analysis,
            'ml_prediction': ml_prediction,
            'urls_found': len(urls),
            'url_analyses': url_analyses,
            'recommendations': self._get_email_recommendations(final_score, content_analysis)
        }
        
        print(f"✅ Análise concluída - Risco: {result['risk_level']} ({final_score:.1f}/100)")
        return result
    
    async def analyze_url(self, url: str) -> Dict[str, Any]:
        """Analisa uma URL para detectar phishing"""
        print(f"🌐 Analisando URL: {url[:50]}...")
        
        # Análises paralelas
        tasks = [
            self.url_analyzer.analyze_structure(url),
            self.url_analyzer.analyze_domain(url),
            self.reputation_checker.check_url_reputation(url),
            self.ml_classifier.classify_url(url)
        ]
        
        results = await asyncio.gather(*tasks)
        structure_analysis = results[0]
        domain_analysis = results[1]
        reputation_analysis = results[2]
        ml_prediction = results[3]
        
        # Calcula score final
        final_score = self._calculate_url_score(
            structure_analysis, domain_analysis, reputation_analysis, ml_prediction
        )
        
        result = {
            'type': 'url',
            'url': url,
            'timestamp': datetime.now().isoformat(),
            'risk_score': final_score,
            'risk_level': self._get_risk_level(final_score),
            'structure_analysis': structure_analysis,
            'domain_analysis': domain_analysis,
            'reputation_analysis': reputation_analysis,
            'ml_prediction': ml_prediction,
            'recommendations': self._get_url_recommendations(final_score, structure_analysis)
        }
        
        print(f"✅ URL analisada - Risco: {result['risk_level']} ({final_score:.1f}/100)")
        return result
    
    def _calculate_email_score(self, content_analysis, sender_analysis, 
                              subject_analysis, ml_prediction, url_analyses) -> float:
        """Calcula score de risco do email (0-100)"""
        score = 0
        
        # Análise de conteúdo (40% do peso)
        score += content_analysis.get('risk_score', 0) * 0.4
        
        # Análise do remetente (25% do peso)
        if sender_analysis:
            score += sender_analysis.get('risk_score', 0) * 0.25
        
        # Análise do assunto (15% do peso)
        if subject_analysis:
            score += subject_analysis.get('risk_score', 0) * 0.15
        
        # Predição ML (10% do peso)
        score += ml_prediction.get('risk_score', 0) * 0.1
        
        # URLs suspeitas (10% do peso)
        if url_analyses:
            avg_url_score = sum(ua['risk_score'] for ua in url_analyses) / len(url_analyses)
            score += avg_url_score * 0.1
        
        return min(score, 100)
    
    def _calculate_url_score(self, structure_analysis, domain_analysis, 
                            reputation_analysis, ml_prediction) -> float:
        """Calcula score de risco da URL (0-100)"""
        score = 0
        
        # Análise estrutural (30% do peso)
        score += structure_analysis.get('risk_score', 0) * 0.3
        
        # Análise de domínio (30% do peso)
        score += domain_analysis.get('risk_score', 0) * 0.3
        
        # Reputação (25% do peso)
        score += reputation_analysis.get('risk_score', 0) * 0.25
        
        # Predição ML (15% do peso)
        score += ml_prediction.get('risk_score', 0) * 0.15
        
        return min(score, 100)
    
    def _get_risk_level(self, score: float) -> str:
        """Converte score numérico em nível de risco"""
        if score >= 80:
            return "CRÍTICO"
        elif score >= 60:
            return "ALTO"
        elif score >= 40:
            return "MÉDIO"
        elif score >= 20:
            return "BAIXO"
        else:
            return "MÍNIMO"
    
    def _get_email_recommendations(self, score: float, content_analysis: Dict) -> List[str]:
        """Gera recomendações baseadas na análise do email"""
        recommendations = []
        
        if score >= 60:
            recommendations.append("🚨 NÃO clique em links ou baixe anexos")
            recommendations.append("🚨 NÃO forneça informações pessoais")
            recommendations.append("📧 Marque como spam/phishing")
        
        if content_analysis.get('urgency_detected'):
            recommendations.append("⚠️ Email usa táticas de urgência - seja cauteloso")
        
        if content_analysis.get('suspicious_links'):
            recommendations.append("🔗 Links suspeitos detectados - não clique")
        
        if content_analysis.get('requests_credentials'):
            recommendations.append("🔐 Nunca forneça senhas por email")
        
        return recommendations
    
    def _get_url_recommendations(self, score: float, structure_analysis: Dict) -> List[str]:
        """Gera recomendações baseadas na análise da URL"""
        recommendations = []
        
        if score >= 60:
            recommendations.append("🚨 NÃO acesse esta URL")
            recommendations.append("🛡️ Use proteção antivírus atualizada")
        
        if structure_analysis.get('suspicious_domain'):
            recommendations.append("🌐 Domínio suspeito - verifique a legitimidade")
        
        if structure_analysis.get('url_shortener'):
            recommendations.append("🔗 URL encurtada - destino desconhecido")
        
        return recommendations

# Exemplo de uso
async def main():
    detector = PhishingDetector()
    
    # Teste com email suspeito
    email_suspeito = """
    Urgente! Sua conta será suspensa em 24 horas!
    
    Prezado cliente,
    
    Detectamos atividade suspeita em sua conta bancária. Para evitar o bloqueio,
    clique IMEDIATAMENTE no link abaixo e confirme seus dados:
    
    https://banco-seguro-verificacao.tk/login
    
    Caso não faça a verificação em 24 horas, sua conta será PERMANENTEMENTE suspensa!
    
    Atenciosamente,
    Equipe de Segurança
    """
    
    print("=" * 60)
    print("🛡️  SISTEMA DE DETECÇÃO DE PHISHING")
    print("=" * 60)
    
    # Analisa email
    resultado_email = await detector.analyze_email(
        email_content=email_suspeito,
        sender="seguranca@banco-falso.com",
        subject="URGENTE: Confirme sua conta em 24h"
    )
    
    print("\n📊 RELATÓRIO DE ANÁLISE:")
    print(f"Tipo: {resultado_email['type'].upper()}")
    print(f"Nível de Risco: {resultado_email['risk_level']}")
    print(f"Score: {resultado_email['risk_score']:.1f}/100")
    print(f"URLs encontradas: {resultado_email['urls_found']}")
    
    print("\n💡 RECOMENDAÇÕES:")
    for rec in resultado_email['recommendations']:
        print(f"  {rec}")
    
    # Teste com URL suspeita
    print("\n" + "=" * 60)
    url_suspeita = "https://banco-seguro-verificacao.tk/login"
    resultado_url = await detector.analyze_url(url_suspeita)
    
    print(f"\n📊 ANÁLISE DA URL:")
    print(f"URL: {resultado_url['url']}")
    print(f"Nível de Risco: {resultado_url['risk_level']}")
    print(f"Score: {resultado_url['risk_score']:.1f}/100")
    
    print("\n💡 RECOMENDAÇÕES:")
    for rec in resultado_url['recommendations']:
        print(f"  {rec}")

if __name__ == "__main__":
    asyncio.run(main())

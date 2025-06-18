import re
import asyncio
from typing import Dict, List, Any
import hashlib
from collections import Counter

class MLClassifier:
    def __init__(self):
        # Features para classificação de emails
        self.email_features = {
            'urgency_words': ['urgente', 'imediato', 'agora', 'expire', 'último'],
            'credential_words': ['senha', 'login', 'cpf', 'cartão', 'dados'],
            'social_words': ['parabéns', 'ganhou', 'prêmio', 'grátis', 'sorteio'],
            'threat_words': ['suspenso', 'bloqueado', 'cancelado', 'removido'],
            'action_words': ['clique', 'acesse', 'confirme', 'verifique', 'atualize']
        }
        
        # Features para classificação de URLs
        self.url_features = {
            'suspicious_tlds': ['.tk', '.ml', '.ga', '.cf', '.click'],
            'phishing_words': ['secure', 'verify', 'login', 'account', 'update'],
            'brand_words': ['bank', 'paypal', 'amazon', 'google', 'microsoft']
        }
        
        # Pesos dos features (simulando modelo treinado)
        self.email_weights = {
            'urgency_score': 0.25,
            'credential_score': 0.30,
            'social_score': 0.15,
            'threat_score': 0.20,
            'action_score': 0.10
        }
        
        self.url_weights = {
            'tld_score': 0.30,
            'phishing_score': 0.25,
            'brand_score': 0.20,
            'structure_score': 0.25
        }
    
    async def classify_email(self, email_content: str) -> Dict[str, Any]:
        """Classifica email usando features de ML"""
        content_lower = email_content.lower()
        
        # Extrai features
        features = self._extract_email_features(content_lower)
        
        # Calcula scores
        urgency_score = self._calculate_feature_score(content_lower, self.email_features['urgency_words'])
        credential_score = self._calculate_feature_score(content_lower, self.email_features['credential_words'])
        social_score = self._calculate_feature_score(content_lower, self.email_features['social_words'])
        threat_score = self._calculate_feature_score(content_lower, self.email_features['threat_words'])
        action_score = self._calculate_feature_score(content_lower, self.email_features['action_words'])
        
        # Aplica pesos (simulando modelo ML)
        weighted_score = (
            urgency_score * self.email_weights['urgency_score'] +
            credential_score * self.email_weights['credential_score'] +
            social_score * self.email_weights['social_score'] +
            threat_score * self.email_weights['threat_score'] +
            action_score * self.email_weights['action_score']
        )
        
        # Normaliza para 0-100
        risk_score = min(weighted_score * 2, 100)
        
        # Determina classificação
        if risk_score >= 70:
            classification = "PHISHING"
            confidence = 0.9
        elif risk_score >= 50:
            classification = "SUSPEITO"
            confidence = 0.7
        elif risk_score >= 30:
            classification = "DUVIDOSO"
            confidence = 0.5
        else:
            classification = "LEGÍTIMO"
            confidence = 0.8
        
        return {
            'risk_score': risk_score,
            'classification': classification,
            'confidence': confidence,
            'features': features,
            'feature_scores': {
                'urgency': urgency_score,
                'credential': credential_score,
                'social': social_score,
                'threat': threat_score,
                'action': action_score
            }
        }
    
    async def classify_url(self, url: str) -> Dict[str, Any]:
        """Classifica URL usando features de ML"""
        url_lower = url.lower()
        
        # Extrai features
        features = self._extract_url_features(url_lower)
        
        # Calcula scores
        tld_score = self._calculate_tld_score(url_lower)
        phishing_score = self._calculate_feature_score(url_lower, self.url_features['phishing_words'])
        brand_score = self._calculate_feature_score(url_lower, self.url_features['brand_words'])
        structure_score = self._calculate_structure_score(url_lower)
        
        # Aplica pesos
        weighted_score = (
            tld_score * self.url_weights['tld_score'] +
            phishing_score * self.url_weights['phishing_score'] +
            brand_score * self.url_weights['brand_score'] +
            structure_score * self.url_weights['structure_score']
        )
        
        # Normaliza para 0-100
        risk_score = min(weighted_score * 1.5, 100)
        
        # Determina classificação
        if risk_score >= 75:
            classification = "MALICIOSA"
            confidence = 0.9
        elif risk_score >= 55:
            classification = "SUSPEITA"
            confidence = 0.75
        elif risk_score >= 35:
            classification = "DUVIDOSA"
            confidence = 0.6
        else:
            classification = "SEGURA"
            confidence = 0.8
        
        return {
            'risk_score': risk_score,
            'classification': classification,
            'confidence': confidence,
            'features': features,
            'feature_scores': {
                'tld': tld_score,
                'phishing': phishing_score,
                'brand': brand_score,
                'structure': structure_score
            }
        }
    
    def _extract_email_features(self, content: str) -> Dict[str, Any]:
        """Extrai features do email para ML"""
        return {
            'length': len(content),
            'word_count': len(content.split()),
            'exclamation_count': content.count('!'),
            'question_count': content.count('?'),
            'caps_ratio': sum(1 for c in content if c.isupper()) / max(len(content), 1),
            'digit_ratio': sum(1 for c in content if c.isdigit()) / max(len(content), 1),
            'url_count': len(re.findall(r'https?://[^\s]+', content)),
            'email_count': len(re.findall(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', content))
        }
    
    def _extract_url_features(self, url: str) -> Dict[str, Any]:
        """Extrai features da URL para ML"""
        return {
            'length': len(url),
            'subdomain_count': url.count('.') - 1,
            'hyphen_count': url.count('-'),
            'digit_count': sum(1 for c in url if c.isdigit()),
            'special_char_count': sum(1 for c in url if c in '@%&=?#'),
            'has_ip': bool(re.search(r'\d+\.\d+\.\d+\.\d+', url)),
            'has_port': ':' in url and url.count(':') > 1
        }
    
    def _calculate_feature_score(self, text: str, keywords: List[str]) -> float:
        """Calcula score baseado na presença de palavras-chave"""
        score = 0
        for keyword in keywords:
            count = text.count(keyword)
            score += count * 10  # 10 pontos por ocorrência
        return min(score, 50)  # Máximo 50 pontos
    
    def _calculate_tld_score(self, url: str) -> float:
        """Calcula score baseado no TLD"""
        score = 0
        for tld in self.url_features['suspicious_tlds']:
            if tld in url:
                score += 30
        return min(score, 50)
    
    def _calculate_structure_score(self, url: str) -> float:
        """Calcula score baseado na estrutura da URL"""
        score = 0
        
        # URL muito longa
        if len(url) > 100:
            score += 15
        
        # Muitos subdomínios
        if url.count('.') > 4:
            score += 20
        
        # Muitos hífens
        if url.count('-') > 3:
            score += 15
        
        # Caracteres especiais excessivos
        special_chars = sum(1 for c in url if c in '@%&=?#')
        if special_chars > 5:
            score += 20
        
        # Uso de IP
        if re.search(r'\d+\.\d+\.\d+\.\d+', url):
            score += 25
        
        return min(score, 50)
    
    def generate_feature_importance(self) -> Dict[str, float]:
        """Gera importância dos features (simulado)"""
        return {
            'email_features': {
                'urgency_words': 0.25,
                'credential_requests': 0.30,
                'social_engineering': 0.15,
                'threat_language': 0.20,
                'call_to_action': 0.10
            },
            'url_features': {
                'suspicious_tld': 0.30,
                'phishing_keywords': 0.25,
                'brand_impersonation': 0.20,
                'structural_anomalies': 0.25
            }
        }

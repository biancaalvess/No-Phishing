import asyncio
import hashlib
from typing import Dict, List, Any
from urllib.parse import urlparse
import json

class ReputationChecker:
    def __init__(self):
        # Simulação de bases de dados de reputação
        self.blacklisted_domains = {
            'phishing-site.tk', 'fake-bank.ml', 'scam-alert.ga',
            'malware-host.cf', 'suspicious-login.click'
        }
        
        self.suspicious_patterns = [
            'secure-bank', 'verify-account', 'update-info',
            'confirm-identity', 'urgent-action', 'suspended-account'
        ]
        
        # Simulação de feeds de threat intelligence
        self.threat_feeds = {
            'phishing_urls': [
                'phishing-example.com/login',
                'fake-paypal.tk/secure',
                'bank-verification.ml/update'
            ],
            'malware_domains': [
                'malware-host.cf',
                'trojan-download.tk',
                'virus-site.ml'
            ]
        }
        
        # Cache para evitar consultas repetidas
        self.reputation_cache = {}
    
    async def check_url_reputation(self, url: str) -> Dict[str, Any]:
        """Verifica reputação de uma URL"""
        # Verifica cache primeiro
        url_hash = hashlib.md5(url.encode()).hexdigest()
        if url_hash in self.reputation_cache:
            return self.reputation_cache[url_hash]
        
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            full_path = f"{domain}{parsed.path}"
            
            risk_score = 0
            threats_found = []
            sources = []
            
            # Verifica listas negras
            blacklist_result = await self._check_blacklists(domain, full_path)
            risk_score += blacklist_result['score']
            threats_found.extend(blacklist_result['threats'])
            sources.extend(blacklist_result['sources'])
            
            # Verifica feeds de threat intelligence
            threat_intel_result = await self._check_threat_intelligence(url, domain)
            risk_score += threat_intel_result['score']
            threats_found.extend(threat_intel_result['threats'])
            sources.extend(threat_intel_result['sources'])
            
            # Verifica padrões suspeitos
            pattern_result = await self._check_suspicious_patterns(url)
            risk_score += pattern_result['score']
            threats_found.extend(pattern_result['threats'])
            
            # Verifica histórico de domínio (simulado)
            history_result = await self._check_domain_history(domain)
            risk_score += history_result['score']
            threats_found.extend(history_result['threats'])
            
            result = {
                'risk_score': min(risk_score, 100),
                'threats_found': threats_found,
                'sources': list(set(sources)),
                'is_blacklisted': blacklist_result['score'] > 0,
                'threat_categories': self._categorize_threats(threats_found),
                'last_checked': self._get_current_timestamp()
            }
            
            # Armazena no cache
            self.reputation_cache[url_hash] = result
            
            return result
            
        except Exception as e:
            return {
                'risk_score': 25,
                'threats_found': [f'Erro na verificação: {str(e)}'],
                'sources': [],
                'is_blacklisted': False,
                'threat_categories': ['error'],
                'last_checked': self._get_current_timestamp()
            }
    
    async def check_domain_reputation(self, domain: str) -> Dict[str, Any]:
        """Verifica reputação específica de um domínio"""
        domain = domain.lower()
        
        risk_score = 0
        reputation_data = {
            'domain': domain,
            'risk_score': 0,
            'categories': [],
            'last_seen_threats': [],
            'registration_info': {},
            'dns_info': {}
        }
        
        # Verifica se está em listas negras
        if domain in self.blacklisted_domains:
            risk_score += 50
            reputation_data['categories'].append('blacklisted')
        
        # Verifica padrões suspeitos no domínio
        for pattern in self.suspicious_patterns:
            if pattern in domain:
                risk_score += 15
                reputation_data['categories'].append('suspicious_pattern')
        
        # Simula verificação de idade do domínio
        domain_age = await self._get_domain_age(domain)
        if domain_age < 30:  # Domínio muito novo
            risk_score += 20
            reputation_data['categories'].append('new_domain')
        
        # Simula verificação de SSL
        ssl_info = await self._check_ssl_certificate(domain)
        if not ssl_info['valid']:
            risk_score += 15
            reputation_data['categories'].append('invalid_ssl')
        
        reputation_data['risk_score'] = min(risk_score, 100)
        reputation_data['registration_info'] = {'estimated_age_days': domain_age}
        reputation_data['dns_info'] = ssl_info
        
        return reputation_data
    
    async def _check_blacklists(self, domain: str, full_path: str) -> Dict[str, Any]:
        """Verifica listas negras conhecidas"""
        score = 0
        threats = []
        sources = []
        
        # Verifica domínio em blacklist
        if domain in self.blacklisted_domains:
            score += 50
            threats.append(f'Domínio {domain} em lista negra')
            sources.append('Internal Blacklist')
        
        # Verifica URL completa em feeds de phishing
        for phishing_url in self.threat_feeds['phishing_urls']:
            if phishing_url in full_path:
                score += 40
                threats.append(f'URL corresponde a padrão de phishing conhecido')
                sources.append('Phishing Feed')
        
        # Verifica domínio em feeds de malware
        if domain in self.threat_feeds['malware_domains']:
            score += 60
            threats.append(f'Domínio {domain} associado a malware')
            sources.append('Malware Feed')
        
        return {
            'score': score,
            'threats': threats,
            'sources': sources
        }
    
    async def _check_threat_intelligence(self, url: str, domain: str) -> Dict[str, Any]:
        """Verifica feeds de threat intelligence"""
        score = 0
        threats = []
        sources = []
        
        # Simula consulta a feeds de threat intelligence
        # Em implementação real, consultaria APIs como VirusTotal, URLVoid, etc.
        
        # Verifica padrões conhecidos de campanhas de phishing
        phishing_campaigns = [
            'banking-phish-2024', 'paypal-scam-wave', 'crypto-theft-campaign'
        ]
        
        for campaign in phishing_campaigns:
            if any(keyword in url.lower() for keyword in campaign.split('-')):
                score += 25
                threats.append(f'URL pode estar relacionada à campanha: {campaign}')
                sources.append('Threat Intelligence')
        
        # Simula verificação de reputação de IP (se aplicável)
        if self._is_ip_in_url(url):
            score += 30
            threats.append('URL usa endereço IP em vez de domínio')
            sources.append('IP Reputation')
        
        return {
            'score': score,
            'threats': threats,
            'sources': sources
        }
    
    async def _check_suspicious_patterns(self, url: str) -> Dict[str, Any]:
        """Verifica padrões suspeitos na URL"""
        score = 0
        threats = []
        
        url_lower = url.lower()
        
        # Padrões comuns de phishing
        phishing_patterns = [
            'secure-login', 'verify-account', 'update-payment',
            'confirm-identity', 'urgent-action', 'suspended-notice'
        ]
        
        for pattern in phishing_patterns:
            if pattern in url_lower:
                score += 15
                threats.append(f'Padrão suspeito detectado: {pattern}')
        
        # URLs com muitos redirecionamentos (simulado)
        if 'redirect' in url_lower or 'goto' in url_lower:
            score += 20
            threats.append('URL contém redirecionamento suspeito')
        
        # URLs com encoding suspeito
        if '%' in url and url.count('%') > 3:
            score += 15
            threats.append('URL contém encoding suspeito')
        
        return {
            'score': score,
            'threats': threats
        }
    
    async def _check_domain_history(self, domain: str) -> Dict[str, Any]:
        """Verifica histórico do domínio"""
        score = 0
        threats = []
        
        # Simula verificação de histórico
        # Em implementação real, consultaria bases de dados históricas
        
        # Domínios com histórico de abuse
        abuse_history = ['previous-scam.tk', 'old-phishing.ml']
        if domain in abuse_history:
            score += 35
            threats.append('Domínio com histórico de atividades maliciosas')
        
        # Verifica se domínio foi registrado recentemente
        # (simulado baseado em TLD)
        suspicious_tlds = ['.tk', '.ml', '.ga', '.cf']
        if any(domain.endswith(tld) for tld in suspicious_tlds):
            score += 20
            threats.append('Domínio usa TLD frequentemente associado a abuse')
        
        return {
            'score': score,
            'threats': threats
        }
    
    async def _get_domain_age(self, domain: str) -> int:
        """Simula obtenção da idade do domínio"""
        # Em implementação real, consultaria WHOIS
        # Por agora, simula baseado em características
        
        if any(domain.endswith(tld) for tld in ['.tk', '.ml', '.ga', '.cf']):
            return 15  # TLDs suspeitos tendem a ser novos
        
        if len(domain) > 20:
            return 30  # Domínios muito longos podem ser novos
        
        return 180  # Padrão: ~6 meses
    
    async def _check_ssl_certificate(self, domain: str) -> Dict[str, Any]:
        """Simula verificação de certificado SSL"""
        # Em implementação real, verificaria o certificado SSL
        
        # Simula baseado em características do domínio
        suspicious_tlds = ['.tk', '.ml', '.ga', '.cf']
        
        if any(domain.endswith(tld) for tld in suspicious_tlds):
            return {
                'valid': False,
                'issuer': 'Unknown',
                'expires_soon': True,
                'self_signed': True
            }
        
        return {
            'valid': True,
            'issuer': 'Let\'s Encrypt',
            'expires_soon': False,
            'self_signed': False
        }
    
    def _is_ip_in_url(self, url: str) -> bool:
        """Verifica se URL contém endereço IP"""
        import re
        ip_pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
        return bool(re.search(ip_pattern, url))
    
    def _categorize_threats(self, threats: List[str]) -> List[str]:
        """Categoriza as ameaças encontradas"""
        categories = set()
        
        for threat in threats:
            threat_lower = threat.lower()
            
            if any(word in threat_lower for word in ['phishing', 'fake', 'scam']):
                categories.add('phishing')
            
            if any(word in threat_lower for word in ['malware', 'virus', 'trojan']):
                categories.add('malware')
            
            if any(word in threat_lower for word in ['blacklist', 'blocked']):
                categories.add('blacklisted')
            
            if any(word in threat_lower for word in ['suspicious', 'pattern']):
                categories.add('suspicious')
        
        return list(categories) if categories else ['unknown']
    
    def _get_current_timestamp(self) -> str:
        """Retorna timestamp atual"""
        from datetime import datetime
        return datetime.now().isoformat()
    
    def get_reputation_summary(self) -> Dict[str, Any]:
        """Retorna resumo das verificações de reputação"""
        total_checks = len(self.reputation_cache)
        high_risk = sum(1 for result in self.reputation_cache.values() 
                       if result['risk_score'] >= 60)
        
        return {
            'total_checks': total_checks,
            'high_risk_found': high_risk,
            'cache_size': total_checks,
            'threat_categories': self._get_threat_category_stats()
        }
    
    def _get_threat_category_stats(self) -> Dict[str, int]:
        """Estatísticas das categorias de ameaças"""
        category_counts = {}
        
        for result in self.reputation_cache.values():
            for category in result.get('threat_categories', []):
                category_counts[category] = category_counts.get(category, 0) + 1
        
        return category_counts

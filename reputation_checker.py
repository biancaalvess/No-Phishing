import asyncio
import hashlib
from typing import Dict, List, Any
from urllib.parse import urlparse
import json
import os
import re
import aiohttp
from dotenv import load_dotenv

# Carrega variáveis de ambiente do arquivo .env
load_dotenv()

class ReputationChecker:
    def __init__(self):
        # Carrega chaves de API do ambiente
        self.virustotal_api_key = os.getenv('VIRUSTOTAL_API_KEY', '')
        self.google_safebrowsing_api_key = os.getenv('GOOGLE_SAFEBROWSING_API_KEY', '')
        self.phishtank_api_key = os.getenv('PHISHTANK_API_KEY', '')
        self.urlscan_api_key = os.getenv('URLSCAN_API_KEY', '')
        self.abuseipdb_api_key = os.getenv('ABUSEIPDB_API_KEY', '')
        
        # Simulação de bases de dados de reputação (fallback)
        self.blacklisted_domains = {
            'phishing-site.tk', 'fake-bank.ml', 'scam-alert.ga',
            'malware-host.cf', 'suspicious-login.click'
        }
        
        self.suspicious_patterns = [
            'secure-bank', 'verify-account', 'update-info',
            'confirm-identity', 'urgent-action', 'suspended-account'
        ]
        
        # Cache para evitar consultas repetidas
        self.reputation_cache = {}
    
    async def check_url_reputation(self, url: str) -> Dict[str, Any]:
        """Verifica reputação de uma URL usando APIs reais"""
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
            
            # Executa verificações em paralelo (quando possível)
            results = await asyncio.gather(
                self._check_virustotal(url),
                self._check_google_safebrowsing(url),
                self._check_phishtank(url),
                self._check_urlscan(url),
                self._check_blacklists(domain, full_path),
                self._check_suspicious_patterns(url),
                self._check_domain_history(domain),
                return_exceptions=True
            )
            
            # Processa resultados
            for result in results:
                if isinstance(result, dict):
                    risk_score += result.get('score', 0)
                    threats_found.extend(result.get('threats', []))
                    sources.extend(result.get('sources', []))
            
            result = {
                'risk_score': min(risk_score, 100),
                'threats_found': threats_found,
                'sources': list(set(sources)),
                'is_blacklisted': risk_score > 50,
                'threat_categories': self._categorize_threats(threats_found),
                'last_checked': self._get_current_timestamp(),
                'apis_used': [s for s in sources if any(api in s for api in ['VirusTotal', 'Google', 'PhishTank', 'URLScan'])]
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
    
    async def _check_virustotal(self, url: str) -> Dict[str, Any]:
        """Verifica URL no VirusTotal (70+ antivírus)"""
        if not self.virustotal_api_key:
            return {'score': 0, 'threats': [], 'sources': []}
        
        try:
            # Hash da URL para VirusTotal
            url_hash = hashlib.sha256(url.encode()).hexdigest()
            
            async with aiohttp.ClientSession() as session:
                # Primeiro, tenta obter o report existente
                headers = {'x-apikey': self.virustotal_api_key}
                report_url = f'https://www.virustotal.com/api/v3/urls/{url_hash}'
                
                async with session.get(report_url, headers=headers, timeout=aiohttp.ClientTimeout(total=10)) as response:
                    if response.status == 200:
                        data = await response.json()
                        attributes = data.get('data', {}).get('attributes', {})
                        
                        # Conta quantos antivírus detectaram como malicioso
                        last_analysis_stats = attributes.get('last_analysis_stats', {})
                        malicious_count = last_analysis_stats.get('malicious', 0)
                        suspicious_count = last_analysis_stats.get('suspicious', 0)
                        
                        if malicious_count > 0 or suspicious_count > 0:
                            score = min(malicious_count * 15 + suspicious_count * 5, 100)
                            return {
                                'score': score,
                                'threats': [f'Detectado por {malicious_count} antivírus como malicioso'],
                                'sources': ['VirusTotal']
                            }
                    elif response.status == 404:
                        # URL não está no banco, pode submeter para análise
                        # Por enquanto, retorna score baixo
                        return {'score': 0, 'threats': [], 'sources': []}
        
        except Exception as e:
            # Em caso de erro, não aumenta o score (fallback silencioso)
            pass
        
        return {'score': 0, 'threats': [], 'sources': []}
    
    async def _check_google_safebrowsing(self, url: str) -> Dict[str, Any]:
        """Verifica URL no Google Safe Browsing (mesma tecnologia do Chrome)"""
        if not self.google_safebrowsing_api_key:
            return {'score': 0, 'threats': [], 'sources': []}
        
        try:
            async with aiohttp.ClientSession() as session:
                api_url = f'https://safebrowsing.googleapis.com/v4/threatMatches:find?key={self.google_safebrowsing_api_key}'
                
                payload = {
                    'client': {
                        'clientId': 'no-phishing',
                        'clientVersion': '1.0.0'
                    },
                    'threatInfo': {
                        'threatTypes': ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE'],
                        'platformTypes': ['ANY_PLATFORM'],
                        'threatEntryTypes': ['URL'],
                        'threatEntries': [{'url': url}]
                    }
                }
                
                async with session.post(api_url, json=payload, timeout=aiohttp.ClientTimeout(total=10)) as response:
                    if response.status == 200:
                        data = await response.json()
                        
                        if 'matches' in data and len(data['matches']) > 0:
                            threat_types = [match.get('threatType', '') for match in data['matches']]
                            score = 90 if 'SOCIAL_ENGINEERING' in threat_types else 70
                            
                            return {
                                'score': score,
                                'threats': [f'Google Safe Browsing detectou: {", ".join(threat_types)}'],
                                'sources': ['Google Safe Browsing']
                            }
        
        except Exception as e:
            pass
        
        return {'score': 0, 'threats': [], 'sources': []}
    
    async def _check_phishtank(self, url: str) -> Dict[str, Any]:
        """Verifica URL no PhishTank (banco de dados colaborativo de phishing)"""
        if not self.phishtank_api_key:
            return {'score': 0, 'threats': [], 'sources': []}
        
        try:
            # PhishTank requer hash MD5 da URL
            url_hash = hashlib.md5(url.encode()).hexdigest()
            
            async with aiohttp.ClientSession() as session:
                api_url = f'https://checkurl.phishtank.com/checkurl/'
                headers = {'User-Agent': 'No-Phishing/1.0'}
                data = {
                    'url': url,
                    'format': 'json',
                    'app_key': self.phishtank_api_key
                }
                
                async with session.post(api_url, data=data, headers=headers, timeout=aiohttp.ClientTimeout(total=10)) as response:
                    if response.status == 200:
                        result = await response.json()
                        
                        if result.get('results', {}).get('in_database'):
                            phish_details = result.get('results', {})
                            verified = phish_details.get('verified', 'no')
                            
                            if verified == 'yes':
                                return {
                                    'score': 95,
                                    'threats': ['URL confirmada como phishing no PhishTank'],
                                    'sources': ['PhishTank']
                                }
                            else:
                                return {
                                    'score': 60,
                                    'threats': ['URL reportada como phishing no PhishTank (não verificado)'],
                                    'sources': ['PhishTank']
                                }
        
        except Exception as e:
            pass
        
        return {'score': 0, 'threats': [], 'sources': []}
    
    async def _check_urlscan(self, url: str) -> Dict[str, Any]:
        """Verifica URL no URLScan.io (análise técnica detalhada)"""
        if not self.urlscan_api_key:
            return {'score': 0, 'threats': [], 'sources': []}
        
        try:
            async with aiohttp.ClientSession() as session:
                # Primeiro, verifica se já existe um scan
                search_url = f'https://urlscan.io/api/v1/search/?q=url:{url}'
                headers = {'API-Key': self.urlscan_api_key} if self.urlscan_api_key else {}
                
                async with session.get(search_url, headers=headers, timeout=aiohttp.ClientTimeout(total=10)) as response:
                    if response.status == 200:
                        data = await response.json()
                        results = data.get('results', [])
                        
                        if results:
                            # Pega o resultado mais recente
                            latest = results[0]
                            verdict = latest.get('verdicts', {})
                            
                            if verdict.get('overall', {}).get('malicious'):
                                score = 85
                                threats = ['URLScan detectou atividade maliciosa']
                                
                                # Adiciona detalhes técnicos se disponíveis
                                if 'ip' in latest:
                                    threats.append(f'IP do servidor: {latest.get("ip")}')
                                
                                return {
                                    'score': score,
                                    'threats': threats,
                                    'sources': ['URLScan.io']
                                }
        
        except Exception as e:
            pass
        
        return {'score': 0, 'threats': [], 'sources': []}
    
    async def _check_abuseipdb(self, ip: str) -> Dict[str, Any]:
        """Verifica IP no AbuseIPDB (reputação de endereços IP)"""
        if not self.abuseipdb_api_key:
            return {'score': 0, 'threats': [], 'sources': []}
        
        try:
            async with aiohttp.ClientSession() as session:
                api_url = 'https://api.abuseipdb.com/api/v2/check'
                headers = {
                    'Key': self.abuseipdb_api_key,
                    'Accept': 'application/json'
                }
                params = {
                    'ipAddress': ip,
                    'maxAgeInDays': 90,
                    'verbose': ''
                }
                
                async with session.get(api_url, headers=headers, params=params, timeout=aiohttp.ClientTimeout(total=10)) as response:
                    if response.status == 200:
                        data = await response.json()
                        result = data.get('data', {})
                        
                        abuse_confidence = result.get('abuseConfidencePercentage', 0)
                        
                        if abuse_confidence > 50:
                            score = min(abuse_confidence, 100)
                            return {
                                'score': score,
                                'threats': [f'IP com {abuse_confidence}% de confiança de abuso'],
                                'sources': ['AbuseIPDB']
                            }
        
        except Exception as e:
            pass
        
        return {'score': 0, 'threats': [], 'sources': []}
    
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
        """Verifica listas negras locais (fallback)"""
        score = 0
        threats = []
        sources = []
        
        # Verifica domínio em blacklist
        if domain in self.blacklisted_domains:
            score += 50
            threats.append(f'Domínio {domain} em lista negra local')
            sources.append('Internal Blacklist')
        
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
        
        # URLs com muitos redirecionamentos
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
        if any(domain.endswith(tld) for tld in ['.tk', '.ml', '.ga', '.cf']):
            return 15  # TLDs suspeitos tendem a ser novos
        
        if len(domain) > 20:
            return 30  # Domínios muito longos podem ser novos
        
        return 180  # Padrão: ~6 meses
    
    async def _check_ssl_certificate(self, domain: str) -> Dict[str, Any]:
        """Simula verificação de certificado SSL"""
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

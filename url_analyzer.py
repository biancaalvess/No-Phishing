import re
import asyncio
from typing import Dict, List, Any
from urllib.parse import urlparse, parse_qs
import socket
import ssl

class URLAnalyzer:
    def __init__(self):
        # TLDs suspeitos
        self.suspicious_tlds = [
            '.tk', '.ml', '.ga', '.cf', '.click', '.download', '.zip',
            '.review', '.country', '.kim', '.cricket', '.science'
        ]
        
        # Palavras suspeitas em URLs
        self.suspicious_keywords = [
            'secure', 'verify', 'update', 'confirm', 'login', 'account',
            'bank', 'paypal', 'amazon', 'microsoft', 'google', 'apple',
            'security', 'suspended', 'locked', 'urgent'
        ]
        
        # URL shorteners conhecidos
        self.url_shorteners = [
            'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly',
            'short.link', 'tiny.cc', 'is.gd', 'buff.ly'
        ]
        
        # Domínios legítimos para comparação
        self.legitimate_domains = {
            'banking': ['bancodobrasil.com.br', 'itau.com.br', 'bradesco.com.br', 'caixa.gov.br'],
            'tech': ['google.com', 'microsoft.com', 'apple.com', 'amazon.com'],
            'social': ['facebook.com', 'instagram.com', 'twitter.com', 'linkedin.com']
        }
    
    async def analyze_structure(self, url: str) -> Dict[str, Any]:
        """Analisa a estrutura da URL"""
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            path = parsed.path.lower()
            query = parsed.query.lower()
            
            risk_score = 0
            flags = []
            
            # Verifica protocolo
            if parsed.scheme == 'http':
                risk_score += 15
                flags.append('Protocolo HTTP inseguro')
            
            # Verifica IP em vez de domínio
            if self._is_ip_address(domain):
                risk_score += 30
                flags.append('Usa endereço IP em vez de domínio')
            
            # Verifica TLD suspeito
            if any(domain.endswith(tld) for tld in self.suspicious_tlds):
                risk_score += 25
                flags.append('TLD suspeito')
            
            # Verifica URL shortener
            if any(shortener in domain for shortener in self.url_shorteners):
                risk_score += 20
                flags.append('URL encurtada')
            
            # Verifica subdomínios excessivos
            subdomain_count = domain.count('.') - 1
            if subdomain_count > 3:
                risk_score += 15
                flags.append('Muitos subdomínios')
            
            # Verifica caracteres suspeitos
            if self._has_suspicious_chars(url):
                risk_score += 20
                flags.append('Caracteres suspeitos')
            
            # Verifica palavras-chave suspeitas
            suspicious_words_found = [word for word in self.suspicious_keywords 
                                    if word in domain or word in path]
            if suspicious_words_found:
                risk_score += len(suspicious_words_found) * 5
                flags.append(f'Palavras suspeitas: {", ".join(suspicious_words_found)}')
            
            # Verifica parâmetros suspeitos
            if self._has_suspicious_params(query):
                risk_score += 15
                flags.append('Parâmetros suspeitos')
            
            return {
                'risk_score': min(risk_score, 100),
                'flags': flags,
                'domain': domain,
                'protocol': parsed.scheme,
                'subdomain_count': subdomain_count,
                'suspicious_domain': risk_score > 30,
                'url_shortener': any(shortener in domain for shortener in self.url_shorteners)
            }
            
        except Exception as e:
            return {
                'risk_score': 50,
                'flags': [f'Erro ao analisar URL: {str(e)}'],
                'domain': '',
                'protocol': '',
                'subdomain_count': 0,
                'suspicious_domain': True,
                'url_shortener': False
            }
    
    async def analyze_domain(self, url: str) -> Dict[str, Any]:
        """Analisa o domínio da URL"""
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            
            risk_score = 0
            flags = []
            
            # Verifica spoofing de domínios conhecidos
            spoofing_result = self._check_domain_spoofing(domain)
            if spoofing_result['is_spoofing']:
                risk_score += 40
                flags.append(f'Possível spoofing de: {spoofing_result["target_domain"]}')
            
            # Verifica homógrafos (caracteres similares)
            if self._has_homograph_attack(domain):
                risk_score += 35
                flags.append('Possível ataque homógrafo')
            
            # Verifica idade do domínio (simulado)
            domain_age = await self._estimate_domain_age(domain)
            if domain_age < 30:  # Domínio muito novo
                risk_score += 25
                flags.append('Domínio muito recente')
            
            # Verifica reputação do domínio
            reputation_score = await self._check_domain_reputation(domain)
            risk_score += reputation_score
            if reputation_score > 20:
                flags.append('Domínio com má reputação')
            
            return {
                'risk_score': min(risk_score, 100),
                'flags': flags,
                'domain': domain,
                'estimated_age_days': domain_age,
                'spoofing_detected': spoofing_result['is_spoofing'],
                'homograph_detected': self._has_homograph_attack(domain)
            }
            
        except Exception as e:
            return {
                'risk_score': 30,
                'flags': [f'Erro ao analisar domínio: {str(e)}'],
                'domain': '',
                'estimated_age_days': 0,
                'spoofing_detected': False,
                'homograph_detected': False
            }
    
    def _is_ip_address(self, domain: str) -> bool:
        """Verifica se é um endereço IP"""
        ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        return bool(re.match(ip_pattern, domain))
    
    def _has_suspicious_chars(self, url: str) -> bool:
        """Verifica caracteres suspeitos na URL"""
        # Caracteres de confusão
        suspicious_chars = ['%', '@', '-', '_']
        char_count = sum(url.count(char) for char in suspicious_chars)
        
        # Muitos hífens ou underscores
        if url.count('-') > 5 or url.count('_') > 3:
            return True
        
        # Encoding suspeito
        if '%' in url and url.count('%') > 3:
            return True
        
        # Caracteres não ASCII
        try:
            url.encode('ascii')
        except UnicodeEncodeError:
            return True
        
        return False
    
    def _has_suspicious_params(self, query: str) -> bool:
        """Verifica parâmetros suspeitos"""
        suspicious_params = ['redirect', 'url', 'goto', 'next', 'continue', 'return']
        return any(param in query for param in suspicious_params)
    
    def _check_domain_spoofing(self, domain: str) -> Dict[str, Any]:
        """Verifica spoofing de domínios conhecidos"""
        for category, domains in self.legitimate_domains.items():
            for legit_domain in domains:
                # Verifica variações comuns
                variations = [
                    legit_domain.replace('o', '0'),
                    legit_domain.replace('i', '1'),
                    legit_domain.replace('e', '3'),
                    legit_domain.replace('a', '@'),
                    legit_domain.replace('.com', '.co'),
                    legit_domain.replace('.com.br', '.com'),
                    'secure-' + legit_domain,
                    legit_domain.replace('.', '-') + '.com',
                    legit_domain.replace('www.', 'wwww.'),
                ]
                
                if domain in variations or self._calculate_similarity(domain, legit_domain) > 0.8:
                    return {
                        'is_spoofing': True,
                        'target_domain': legit_domain,
                        'category': category
                    }
        
        return {'is_spoofing': False, 'target_domain': '', 'category': ''}
    
    def _has_homograph_attack(self, domain: str) -> bool:
        """Detecta ataques homógrafos (caracteres similares)"""
        # Caracteres que podem ser confundidos
        confusing_chars = {
            'a': ['а', 'α'], 'e': ['е', 'ε'], 'o': ['о', 'ο'], 
            'p': ['р', 'ρ'], 'c': ['с', 'ϲ'], 'x': ['х', 'χ']
        }
        
        for char in domain:
            for latin_char, similar_chars in confusing_chars.items():
                if char in similar_chars:
                    return True
        
        return False
    
    async def _estimate_domain_age(self, domain: str) -> int:
        """Estima a idade do domínio (simulado)"""
        # Em uma implementação real, usaria APIs como WHOIS
        # Por agora, simula baseado em características do domínio
        
        # Domínios com números aleatórios tendem a ser mais novos
        if re.search(r'\d{3,}', domain):
            return 5
        
        # Domínios com TLDs suspeitos tendem a ser novos
        if any(domain.endswith(tld) for tld in self.suspicious_tlds):
            return 10
        
        # Domínios muito longos podem ser novos
        if len(domain) > 20:
            return 15
        
        # Simulação padrão
        return 180  # ~6 meses
    
    async def _check_domain_reputation(self, domain: str) -> float:
        """Verifica reputação do domínio (simulado)"""
        # Em uma implementação real, consultaria bases de dados de reputação
        risk_score = 0
        
        # Domínios em listas negras conhecidas (simulado)
        blacklisted_patterns = ['phishing', 'scam', 'fake', 'malware']
        if any(pattern in domain for pattern in blacklisted_patterns):
            risk_score += 50
        
        # Domínios com padrões suspeitos
        if re.search(r'[0-9]{3,}', domain):  # Muitos números
            risk_score += 15
        
        if domain.count('-') > 3:  # Muitos hífens
            risk_score += 10
        
        return min(risk_score, 50)
    
    def _calculate_similarity(self, str1: str, str2: str) -> float:
        """Calcula similaridade entre duas strings"""
        # Implementação simples de distância de Levenshtein normalizada
        def levenshtein_distance(s1, s2):
            if len(s1) < len(s2):
                return levenshtein_distance(s2, s1)
            
            if len(s2) == 0:
                return len(s1)
            
            previous_row = list(range(len(s2) + 1))
            for i, c1 in enumerate(s1):
                current_row = [i + 1]
                for j, c2 in enumerate(s2):
                    insertions = previous_row[j + 1] + 1
                    deletions = current_row[j] + 1
                    substitutions = previous_row[j] + (c1 != c2)
                    current_row.append(min(insertions, deletions, substitutions))
                previous_row = current_row
            
            return previous_row[-1]
        
        max_len = max(len(str1), len(str2))
        if max_len == 0:
            return 1.0
        
        distance = levenshtein_distance(str1, str2)
        return 1 - (distance / max_len)

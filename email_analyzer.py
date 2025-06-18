import re
import asyncio
from typing import Dict, List, Any
from urllib.parse import urlparse
import base64

class EmailAnalyzer:
    def __init__(self):
        # Palavras-chave de urgência/pressão
        self.urgency_keywords = [
            'urgente', 'imediatamente', 'agora', 'expire', 'suspenso', 'bloqueado',
            'verificar', 'confirmar', 'atualizar', 'validar', '24 horas', 'prazo',
            'último aviso', 'ação necessária', 'conta bloqueada', 'acesso negado'
        ]
        
        # Palavras-chave de engenharia social
        self.social_engineering_keywords = [
            'parabéns', 'ganhou', 'prêmio', 'sorteio', 'grátis', 'oferta especial',
            'desconto', 'promoção', 'limitado', 'exclusivo', 'clique aqui',
            'cadastre-se', 'registre-se', 'aprovado', 'selecionado'
        ]
        
        # Palavras relacionadas a credenciais
        self.credential_keywords = [
            'senha', 'login', 'usuário', 'cpf', 'rg', 'cartão', 'conta',
            'dados pessoais', 'informações', 'confirme', 'verifique'
        ]
        
        # Domínios legítimos conhecidos
        self.legitimate_domains = [
            'gmail.com', 'outlook.com', 'yahoo.com', 'hotmail.com',
            'bancodobrasil.com.br', 'itau.com.br', 'bradesco.com.br',
            'caixa.gov.br', 'santander.com.br'
        ]
    
    async def analyze_content(self, content: str) -> Dict[str, Any]:
        """Analisa o conteúdo do email"""
        content_lower = content.lower()
        
        # Detecta urgência
        urgency_score = self._calculate_urgency_score(content_lower)
        
        # Detecta engenharia social
        social_score = self._calculate_social_engineering_score(content_lower)
        
        # Detecta solicitação de credenciais
        credential_score = self._calculate_credential_request_score(content_lower)
        
        # Analisa formatação suspeita
        formatting_score = self._analyze_formatting(content)
        
        # Detecta links suspeitos
        suspicious_links = self._detect_suspicious_links(content)
        
        # Score final (0-100)
        risk_score = min(
            (urgency_score + social_score + credential_score + 
             formatting_score + len(suspicious_links) * 10), 100
        )
        
        return {
            'risk_score': risk_score,
            'urgency_detected': urgency_score > 20,
            'social_engineering_detected': social_score > 15,
            'requests_credentials': credential_score > 10,
            'suspicious_formatting': formatting_score > 15,
            'suspicious_links': suspicious_links,
            'urgency_score': urgency_score,
            'social_score': social_score,
            'credential_score': credential_score,
            'formatting_score': formatting_score
        }
    
    async def analyze_sender(self, sender: str) -> Dict[str, Any]:
        """Analisa o remetente do email"""
        if not sender:
            return {'risk_score': 0}
        
        sender_lower = sender.lower()
        risk_score = 0
        issues = []
        
        # Verifica domínio suspeito
        try:
            domain = sender.split('@')[1] if '@' in sender else ''
            
            # Domínios com TLDs suspeitos
            suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.click', '.download']
            if any(domain.endswith(tld) for tld in suspicious_tlds):
                risk_score += 30
                issues.append('TLD suspeito')
            
            # Domínios que imitam bancos/serviços
            if self._is_domain_spoofing(domain):
                risk_score += 40
                issues.append('Possível spoofing de domínio')
            
            # Domínios muito novos ou com caracteres suspeitos
            if self._has_suspicious_characters(domain):
                risk_score += 20
                issues.append('Caracteres suspeitos no domínio')
                
        except:
            risk_score += 10
            issues.append('Formato de email inválido')
        
        return {
            'risk_score': min(risk_score, 100),
            'issues': issues,
            'domain': domain if '@' in sender else '',
            'is_suspicious': risk_score > 30
        }
    
    async def analyze_subject(self, subject: str) -> Dict[str, Any]:
        """Analisa o assunto do email"""
        if not subject:
            return {'risk_score': 0}
        
        subject_lower = subject.lower()
        risk_score = 0
        flags = []
        
        # Urgência no assunto
        urgency_words = ['urgente', 'imediato', 'expire', 'último']
        if any(word in subject_lower for word in urgency_words):
            risk_score += 25
            flags.append('Urgência detectada')
        
        # Uso excessivo de maiúsculas
        if sum(1 for c in subject if c.isupper()) > len(subject) * 0.5:
            risk_score += 15
            flags.append('Excesso de maiúsculas')
        
        # Caracteres especiais excessivos
        special_chars = sum(1 for c in subject if c in '!@#$%^&*()[]{}')
        if special_chars > 3:
            risk_score += 10
            flags.append('Muitos caracteres especiais')
        
        # Palavras de engenharia social
        social_words = ['parabéns', 'ganhou', 'prêmio', 'grátis']
        if any(word in subject_lower for word in social_words):
            risk_score += 20
            flags.append('Engenharia social')
        
        return {
            'risk_score': min(risk_score, 100),
            'flags': flags,
            'has_urgency': any(word in subject_lower for word in urgency_words),
            'excessive_caps': sum(1 for c in subject if c.isupper()) > len(subject) * 0.5
        }
    
    def extract_urls(self, content: str) -> List[str]:
        """Extrai URLs do conteúdo do email"""
        url_pattern = r'https?://[^\s<>"\']+|www\.[^\s<>"\']+|[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}[^\s<>"\']*'
        urls = re.findall(url_pattern, content)
        
        # Limpa e valida URLs
        clean_urls = []
        for url in urls:
            if not url.startswith(('http://', 'https://')):
                if url.startswith('www.'):
                    url = 'http://' + url
                else:
                    url = 'http://' + url
            clean_urls.append(url)
        
        return clean_urls
    
    def _calculate_urgency_score(self, content: str) -> float:
        """Calcula score de urgência (0-40)"""
        score = 0
        for keyword in self.urgency_keywords:
            if keyword in content:
                score += 5
        return min(score, 40)
    
    def _calculate_social_engineering_score(self, content: str) -> float:
        """Calcula score de engenharia social (0-30)"""
        score = 0
        for keyword in self.social_engineering_keywords:
            if keyword in content:
                score += 3
        return min(score, 30)
    
    def _calculate_credential_request_score(self, content: str) -> float:
        """Calcula score de solicitação de credenciais (0-30)"""
        score = 0
        for keyword in self.credential_keywords:
            if keyword in content:
                score += 4
        return min(score, 30)
    
    def _analyze_formatting(self, content: str) -> float:
        """Analisa formatação suspeita (0-20)"""
        score = 0
        
        # Excesso de maiúsculas
        caps_ratio = sum(1 for c in content if c.isupper()) / max(len(content), 1)
        if caps_ratio > 0.3:
            score += 10
        
        # Excesso de pontuação
        punct_ratio = sum(1 for c in content if c in '!?.,;:') / max(len(content), 1)
        if punct_ratio > 0.1:
            score += 5
        
        # HTML suspeito (tentativa de ocultar conteúdo)
        if '<script>' in content.lower() or 'javascript:' in content.lower():
            score += 15
        
        return min(score, 20)
    
    def _detect_suspicious_links(self, content: str) -> List[str]:
        """Detecta links suspeitos"""
        urls = self.extract_urls(content)
        suspicious = []
        
        for url in urls:
            try:
                parsed = urlparse(url)
                domain = parsed.netloc.lower()
                
                # URL encurtadores
                shorteners = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly']
                if any(short in domain for short in shorteners):
                    suspicious.append(url)
                    continue
                
                # Domínios com TLDs suspeitos
                suspicious_tlds = ['.tk', '.ml', '.ga', '.cf']
                if any(domain.endswith(tld) for tld in suspicious_tlds):
                    suspicious.append(url)
                    continue
                
                # IPs em vez de domínios
                if re.match(r'\d+\.\d+\.\d+\.\d+', domain):
                    suspicious.append(url)
                    continue
                    
            except:
                suspicious.append(url)
        
        return suspicious
    
    def _is_domain_spoofing(self, domain: str) -> bool:
        """Verifica se o domínio pode ser spoofing"""
        # Verifica similaridade com domínios legítimos
        for legit_domain in self.legitimate_domains:
            # Substitições comuns
            variations = [
                legit_domain.replace('o', '0'),
                legit_domain.replace('i', '1'),
                legit_domain.replace('e', '3'),
                legit_domain.replace('.com', '.co'),
                legit_domain.replace('.com.br', '.com'),
                'secure-' + legit_domain,
                legit_domain.replace('.', '-'),
            ]
            
            if domain in variations:
                return True
        
        return False
    
    def _has_suspicious_characters(self, domain: str) -> bool:
        """Verifica caracteres suspeitos no domínio"""
        # Hífens excessivos
        if domain.count('-') > 3:
            return True
        
        # Números excessivos
        if sum(1 for c in domain if c.isdigit()) > len(domain) * 0.3:
            return True
        
        # Caracteres não ASCII
        try:
            domain.encode('ascii')
        except UnicodeEncodeError:
            return True
        
        return False

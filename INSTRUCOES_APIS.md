# 🔐 Instruções para Configurar APIs de Segurança

Este documento explica como obter e configurar as chaves de API gratuitas que tornam o No-Phishing ainda mais poderoso.

## 📋 APIs Disponíveis

### 1. VirusTotal API ⭐ **RECOMENDADO**

**O que faz:** Verifica se uma URL foi reportada como maliciosa por mais de 70 antivírus diferentes.

**Plano Gratuito:**
- 4 requisições por minuto
- 500 requisições por dia
- Totalmente gratuito

**Como obter:**
1. Acesse https://www.virustotal.com/gui/join-us
2. Crie uma conta gratuita
3. Após fazer login, vá em "API Key" no menu superior
4. Copie sua chave de API

**Documentação:** https://developers.virustotal.com/reference

---

### 2. Google Safe Browsing API ⭐ **RECOMENDADO**

**O que faz:** A mesma tecnologia que o Chrome usa para exibir a tela vermelha de "Site Perigoso".

**Plano Gratuito:**
- Gratuito para uso não comercial
- Limites generosos

**Como obter:**
1. Acesse https://console.cloud.google.com/
2. Crie um novo projeto (ou selecione um existente)
3. No menu lateral, vá em "APIs & Services" > "Library"
4. Procure por "Safe Browsing API" e clique em "Enable"
5. Vá em "APIs & Services" > "Credentials"
6. Clique em "Create Credentials" > "API Key"
7. Copie a chave gerada

**Documentação:** https://developers.google.com/safe-browsing

---

### 3. PhishTank API

**O que faz:** Banco de dados colaborativo (crowdsourced) específico para phishing.

**Plano Gratuito:**
- Totalmente gratuito e ilimitado
- Requer registro para evitar rate-limits agressivos

**Como obter:**
1. Acesse https://www.phishtank.com/
2. Clique em "Sign Up" e crie uma conta gratuita
3. Após fazer login, vá em "API" no menu
4. Gere uma chave de API
5. Copie a chave

**Documentação:** https://www.phishtank.com/api_info.php

---

### 4. URLScan.io API

**O que faz:** Não apenas diz se é perigoso, mas fornece detalhes técnicos do site (IP, tecnologias usadas, captura de tela).

**Plano Gratuito:**
- Limite para usuários não autenticados
- Limite maior para usuários registrados

**Como obter:**
1. Acesse https://urlscan.io/
2. Clique em "Sign Up" e crie uma conta gratuita
3. Após fazer login, vá em "Settings" > "API Key"
4. Gere uma nova chave de API
5. Copie a chave

**Documentação:** https://urlscan.io/docs/api/

---

### 5. AbuseIPDB API

**O que faz:** Verifica se o endereço IP do servidor tem histórico de atividades maliciosas (spam, ataques, etc.).

**Plano Gratuito:**
- Até 1.000 verificações por dia
- Totalmente gratuito

**Como obter:**
1. Acesse https://www.abuseipdb.com/
2. Clique em "Sign Up" e crie uma conta gratuita
3. Após fazer login, vá em "API" no menu
4. Gere uma chave de API
5. Copie a chave

**Documentação:** https://www.abuseipdb.com/api

---

## 🚀 Como Configurar

### Passo 1: Copiar o arquivo de exemplo

```bash
cp .env.example .env
```

### Passo 2: Editar o arquivo .env

Abra o arquivo `.env` e preencha as chaves que você obteve:

```env
VIRUSTOTAL_API_KEY=sua_chave_aqui
GOOGLE_SAFEBROWSING_API_KEY=sua_chave_aqui
PHISHTANK_API_KEY=sua_chave_aqui
URLSCAN_API_KEY=sua_chave_aqui
ABUSEIPDB_API_KEY=sua_chave_aqui
```

### Passo 3: Testar

Execute o sistema e verifique se as APIs estão funcionando. O sistema funciona mesmo sem todas as chaves configuradas - ele simplesmente usará análise local quando uma API não estiver disponível.

---

## ⚠️ Importante

- **Todas as APIs são opcionais.** O sistema funciona perfeitamente sem elas, usando análise local.
- **Não compartilhe suas chaves de API** publicamente.
- **Para produção no Vercel:** Configure as variáveis de ambiente nas configurações do projeto no Vercel Dashboard.

---

## 🎯 Recomendações

Para começar, recomendamos configurar pelo menos:

1. **VirusTotal** - Mais fácil de obter e muito eficaz
2. **Google Safe Browsing** - Usa a mesma tecnologia do Chrome

Essas duas APIs já fornecem uma cobertura excelente contra ameaças conhecidas.

---

## 📊 Comparação de APIs

| API | Dificuldade | Eficácia | Limite Gratuito |
|-----|-------------|----------|-----------------|
| VirusTotal | ⭐ Fácil | ⭐⭐⭐⭐⭐ | 500/dia |
| Google Safe Browsing | ⭐⭐ Média | ⭐⭐⭐⭐⭐ | Generoso |
| PhishTank | ⭐ Fácil | ⭐⭐⭐⭐ | Ilimitado |
| URLScan.io | ⭐⭐ Média | ⭐⭐⭐⭐ | Limitado |
| AbuseIPDB | ⭐ Fácil | ⭐⭐⭐ | 1000/dia |

---

## 🆘 Problemas Comuns

### "API Key inválida"
- Verifique se copiou a chave completa
- Certifique-se de que não há espaços extras
- Algumas APIs podem levar alguns minutos para ativar após a criação

### "Rate limit exceeded"
- Você atingiu o limite de requisições
- Aguarde alguns minutos ou considere fazer upgrade do plano

### "API não está funcionando"
- O sistema continuará funcionando com análise local
- Verifique se a chave está correta no arquivo .env
- Algumas APIs podem estar temporariamente indisponíveis

---

## 📝 Notas Finais

O No-Phishing foi projetado para funcionar de forma híbrida:
- **Com APIs:** Análise mais precisa e atualizada
- **Sem APIs:** Análise local baseada em Machine Learning e padrões

Ambas as abordagens são eficazes, mas as APIs adicionam uma camada extra de proteção contra ameaças conhecidas globalmente.


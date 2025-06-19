from flask import Flask, render_template, request, jsonify
import logging
from datetime import datetime
import os
import re
from urllib.parse import urlparse

# Configuração de logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.secret_key = 'sua-chave-secreta-aqui'

# Lista de domínios conhecidamente seguros
DOMINIOS_SEGUROS = {
    'nubank.com.br', 'itau.com.br', 'bradesco.com.br', 'bancodobrasil.com.br',
    'bb.com.br', 'caixa.gov.br', 'santander.com.br', 'paypal.com',
    'google.com', 'microsoft.com', 'amazon.com', 'gov.br', 'mercadopago.com.br',
    'picpay.com', 'inter.co', 'original.com.br', 'c6bank.com.br',
    'facebook.com', 'instagram.com', 'whatsapp.com', 'youtube.com',
    'gmail.com', 'outlook.com', 'hotmail.com', 'yahoo.com'
}

# Lista de domínios maliciosos conhecidos (atualizada manualmente)
DOMINIOS_MALICIOSOS = {
    'banco-seguro-verificacao.tk', 'itau-verificacao.ml', 'nubank-update.ga',
    'bradesco-secure.cf', 'caixa-verificar.tk', 'santander-login.ml',
    'paypal-secure.ga', 'mercadopago-verify.cf', 'picpay-update.tk',
    'bb-verificacao.ml', 'inter-secure.ga', 'original-verify.cf'
}

# MARCAS CRÍTICAS - Qualquer imitação é EXTREMAMENTE perigosa
MARCAS_CRITICAS = {
    'nubank': {
        'oficial': 'nubank.com.br',
        'categoria': 'banco',
        'risco_imitacao': 95,
        'variacoes': ['nubbank', 'nuubank', 'nubanck', 'nubankk', 'nubank2024', 'nubankapp', 'nubankbr', 'nubanksecure', 'securenubank', 'nu-bank', 'nubank-br']
    },
    'itau': {
        'oficial': 'itau.com.br', 
        'categoria': 'banco',
        'risco_imitacao': 95,
        'variacoes': ['itauu', 'itaau', 'itaubank', 'itausecure', 'itauoficial', 'itaubr', 'secureitau', 'itau-unibanco', 'itaucard']
    },
    'bradesco': {
        'oficial': 'bradesco.com.br',
        'categoria': 'banco', 
        'risco_imitacao': 95,
        'variacoes': ['bradescobank', 'bradescoo', 'braadesco', 'bradescosecure', 'bradescooficial', 'bradescobr', 'bradesco-bank']
    },
    'bancodobrasil': {
        'oficial': 'bancodobrasil.com.br',
        'categoria': 'banco',
        'risco_imitacao': 95,
        'variacoes': ['bb', 'bancobrasil', 'bancobrasiloficial', 'bancodobrasilsecure', 'bbbank', 'banco-brasil', 'bb-bank']
    },
    'caixa': {
        'oficial': 'caixa.gov.br',
        'categoria': 'banco',
        'risco_imitacao': 95,
        'variacoes': ['caiixa', 'caixaa', 'caixabank', 'caixasecure', 'caixaoficial', 'caixabr', 'caixaeconomica', 'caixa-economica']
    },
    'santander': {
        'oficial': 'santander.com.br',
        'categoria': 'banco',
        'risco_imitacao': 95,
        'variacoes': ['santanderr', 'santanderbank', 'santandersecure', 'santanderoficial', 'santanderbr', 'santander-bank']
    },
    'paypal': {
        'oficial': 'paypal.com',
        'categoria': 'pagamento',
        'risco_imitacao': 90,
        'variacoes': ['paypall', 'paypaall', 'paypalsecure', 'paypaloficial', 'paypalbr', 'pay-pal']
    },
    'mercadopago': {
        'oficial': 'mercadopago.com.br',
        'categoria': 'pagamento',
        'risco_imitacao': 90,
        'variacoes': ['mercadopagoo', 'mercadopaago', 'mercadopagosecure', 'mercadopagooficial', 'mercado-pago']
    },
    'picpay': {
        'oficial': 'picpay.com',
        'categoria': 'pagamento',
        'risco_imitacao': 90,
        'variacoes': ['picpayy', 'piicpay', 'picpaysecure', 'picpayoficial', 'picpaybr', 'pic-pay']
    },
    'inter': {
        'oficial': 'inter.co',
        'categoria': 'banco',
        'risco_imitacao': 90,
        'variacoes': ['interbank', 'intersecure', 'interoficial', 'interbr', 'banco-inter']
    }
}

# TLDs EXTREMAMENTE SUSPEITOS
TLDS_PERIGOSOS = {
    '.tk': 95, '.ml': 95, '.ga': 95, '.cf': 95,
    '.click': 80, '.download': 85, '.zip': 90,
    '.review': 75, '.country': 70, '.kim': 70,
    '.cricket': 75, '.science': 70, '.top': 65,
    '.work': 60, '.date': 70, '.stream': 75
}

# Palavras suspeitas categorizadas
PALAVRAS_URGENCIA = [
    'urgente', 'imediatamente', 'agora', 'expire', 'último', 'prazo',
    'suspenso', 'bloqueado', 'cancelado', 'removido', 'desativado',
    'último aviso', 'ação necessária', 'conta bloqueada', 'acesso negado',
    'tempo limitado', 'oferta expira', 'válido até', 'apenas hoje'
]

PALAVRAS_ENGENHARIA_SOCIAL = [
    'parabéns', 'ganhou', 'prêmio', 'sorteio', 'grátis', 'oferta especial',
    'desconto', 'promoção', 'limitado', 'exclusivo', 'selecionado',
    'aprovado', 'contemplado', 'beneficiado', 'escolhido', 'vencedor'
]

PALAVRAS_CREDENCIAIS = [
    'senha', 'login', 'usuário', 'cpf', 'rg', 'cartão', 'conta',
    'dados pessoais', 'informações', 'confirme', 'verifique', 'atualize',
    'validar', 'autenticar', 'token', 'código', 'pin', 'chave'
]

PALAVRAS_ACAO = [
    'clique aqui', 'acesse agora', 'baixe', 'instale', 'cadastre-se',
    'registre-se', 'faça login', 'entre', 'confirme', 'verifique',
    'atualize', 'renove', 'ative', 'desbloqueie'
]

# GOLPES DE ENGENHARIA SOCIAL E PROPOSTAS FRAUDULENTAS
PALAVRAS_GOLPES_COLABORACAO = [
    'colaboração', 'parceria', 'freelancer', 'upwork', 'fiverr', 'freelance',
    'conta suspensa', 'conta bloqueada', 'mudança de endereço', 'verificação de identidade',
    'criar uma conta', 'compartilhe comigo', 'usar sua conta', 'empresas de ponta',
    'dividir lucro', 'ganhar dinheiro', 'receita', 'colaboração de longo prazo',
    'trabalhar juntos', 'gerar receita', 'lucrar', 'ganhos', 'projetos de desenvolvimento'
]

PALAVRAS_PROMESSAS_FINANCEIRAS = [
    'ganhar pelo menos', 'mil por semana', 'muito bem', 'ótimos ganhos',
    'dinheiro fácil', 'renda extra', 'trabalho em casa', 'sem experiência',
    'apenas algumas horas', 'pouco tempo', 'máximo 2 a 3 horas',
    'geralmente menos', 'sem esforço', 'garantido'
]

PALAVRAS_SOLICITACOES_SUSPEITAS = [
    'criar uma conta', 'compartilhar conta', 'usar minha conta', 'emprestar conta',
    'preciso da sua ajuda', 'você pode me ajudar', 'sua função é',
    'permitir usar', 'participar das videoconferências', 'se preparar com respostas',
    'só me candidatarei', 'conversarei com os clientes', 'usar seu nome',
    'fingir ser você', 'representar você'
]

PALAVRAS_MANIPULACAO_PSICOLOGICA = [
    'vi você no github', 'procurando alguém', 'desenvolvedor experiente',
    'anos de experiência', 'infelizmente', 'repentinamente', 'permanentemente',
    'espero que', 'aguardo resposta positiva', 'o que você acha',
    'aberto a negociações', 'se nossa colaboração', 'bem-sucedida',
    'atenciosamente', 'respeitosamente'
]

PADROES_GOLPES_TECNICOS = [
    r'\b\d+\s*anos?\s*de\s*experiência\b',  # "10 anos de experiência"
    r'\b\d+\s*mil\s*por\s*semana\b',        # "2 mil por semana"
    r'\b\d+%\s*da\s*receita\b',             # "10% da receita"
    r'\b\d+\s*a\s*\d+\s*horas?\s*por\s*semana\b',  # "2 a 3 horas por semana"
    r'\bR?\$?\s*\d+[.,]?\d*\s*(mil|k|reais?|dólares?)\b',  # valores monetários
]

def criar_estrutura_arquivos():
    """Cria a estrutura de pastas e arquivos necessários"""
    # Cria diretórios
    os.makedirs('templates', exist_ok=True)
    os.makedirs('static', exist_ok=True)
    
    
@app.route('/')
def index():
    """Página principal"""
    return render_template('index.html')

@app.route('/verificar', methods=['POST'])
def verificar_mensagem():
    """Endpoint para verificar mensagens/URLs - SISTEMA 100% LOCAL"""
    try:
        data = request.get_json()
        
        if not data or 'mensagem' not in data:
            return jsonify({'erro': 'Mensagem não fornecida'}), 400
        
        mensagem = data['mensagem'].strip()
        
        if not mensagem:
            return jsonify({'erro': 'Mensagem vazia'}), 400
        
        logger.info(f" ANÁLISE LOCAL: {mensagem[:100]}...")
        
        # ANÁLISE COMPLETA LOCAL
        resultado = analisar_local(mensagem)
        
        logger.warning(f" RESULTADO: {resultado['nivel_risco_texto']} - Score: {resultado['score_risco']}")
        
        return jsonify(resultado)
        
    except Exception as e:
        logger.error(f" ERRO na análise: {str(e)}")
        return jsonify({
            'score_risco': 90,
            'nivel_risco': 'danger',
            'nivel_risco_texto': 'ERRO',
            'palavras_suspeitas': [],
            'dominios_suspeitos': [f"ERRO NA ANÁLISE: {str(e)}"],
            'recomendacoes': [
                " ERRO NO SISTEMA - Seja cauteloso",
                " Não insira dados pessoais até verificar manualmente"
            ]
        }), 200

def extrair_urls(texto):
    """Extrai todas as URLs do texto"""
    url_pattern = r'https?://[^\s<>"\']+|www\.[^\s<>"\']+|[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}[^\s<>"\']*'
    urls = re.findall(url_pattern, texto)
    
    # Limpa e normaliza URLs
    urls_limpas = []
    for url in urls:
        if not url.startswith(('http://', 'https://')):
            if url.startswith('www.'):
                url = 'http://' + url
            else:
                url = 'http://' + url
        urls_limpas.append(url)
    
    return urls_limpas

def extrair_dominio(url):
    """Extrai domínio de uma URL"""
    try:
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        parsed = urlparse(url)
        return parsed.netloc.lower()
    except:
        return url.lower()

def detectar_imitacao_marca(dominio):
    """Detecta imitações de marcas críticas"""
    dominio_limpo = dominio.lower()
    nome_base = dominio_limpo.split('.')[0]
    
    imitacoes_encontradas = []
    score_total = 0
    
    for marca, info in MARCAS_CRITICAS.items():
        marca_lower = marca.lower()
        
        # Verificação exata da marca no domínio
        if marca_lower in nome_base and dominio_limpo != info['oficial']:
            score_total = info['risco_imitacao']
            imitacoes_encontradas.append({
                'tipo': 'IMITAÇÃO DETECTADA',
                'marca_imitada': marca.upper(),
                'dominio_oficial': info['oficial'],
                'dominio_suspeito': dominio_limpo,
                'categoria': info['categoria'],
                'risco': info['risco_imitacao']
            })
        
        # Verificação de variações conhecidas
        if nome_base in info['variacoes']:
            score_total = max(score_total, info['risco_imitacao'])
            imitacoes_encontradas.append({
                'tipo': 'VARIAÇÃO PERIGOSA',
                'marca_imitada': marca.upper(),
                'dominio_oficial': info['oficial'],
                'dominio_suspeito': dominio_limpo,
                'categoria': info['categoria'],
                'risco': info['risco_imitacao']
            })
    
    return {
        'score': score_total,
        'imitacoes': imitacoes_encontradas,
        'is_imitacao': len(imitacoes_encontradas) > 0
    }

def verificar_tld_perigoso(dominio):
    """Verifica TLDs perigosos"""
    dominio_limpo = dominio.lower()
    
    for tld, risco in TLDS_PERIGOSOS.items():
        if dominio_limpo.endswith(tld):
            return {
                'is_perigoso': True,
                'tld': tld,
                'risco': risco,
                'motivo': f"TLD {tld} frequentemente usado para phishing"
            }
    
    return {'is_perigoso': False, 'risco': 0}

def analisar_palavras_suspeitas(texto):
    """Analisa palavras suspeitas no texto incluindo golpes de engenharia social"""
    texto_lower = texto.lower()
    palavras_encontradas = []
    score_total = 0
    
    # Verifica palavras de urgência
    for palavra in PALAVRAS_URGENCIA:
        if palavra in texto_lower:
            palavras_encontradas.append(f"URGÊNCIA: {palavra}")
            score_total += 15
    
    # Verifica engenharia social tradicional
    for palavra in PALAVRAS_ENGENHARIA_SOCIAL:
        if palavra in texto_lower:
            palavras_encontradas.append(f"ENG. SOCIAL: {palavra}")
            score_total += 10
    
    # Verifica solicitação de credenciais
    for palavra in PALAVRAS_CREDENCIAIS:
        if palavra in texto_lower:
            palavras_encontradas.append(f"CREDENCIAIS: {palavra}")
            score_total += 20
    
    # Verifica chamadas para ação
    for palavra in PALAVRAS_ACAO:
        if palavra in texto_lower:
            palavras_encontradas.append(f"AÇÃO: {palavra}")
            score_total += 8
    
    # NOVA: Verifica golpes de colaboração/freelancer
    for palavra in PALAVRAS_GOLPES_COLABORACAO:
        if palavra in texto_lower:
            palavras_encontradas.append(f"GOLPE COLABORAÇÃO: {palavra}")
            score_total += 25  # Score alto para este tipo de golpe
    
    # NOVA: Verifica promessas financeiras suspeitas
    for palavra in PALAVRAS_PROMESSAS_FINANCEIRAS:
        if palavra in texto_lower:
            palavras_encontradas.append(f"PROMESSA FINANCEIRA: {palavra}")
            score_total += 20
    
    # NOVA: Verifica solicitações suspeitas
    for palavra in PALAVRAS_SOLICITACOES_SUSPEITAS:
        if palavra in texto_lower:
            palavras_encontradas.append(f"SOLICITAÇÃO SUSPEITA: {palavra}")
            score_total += 30  # Score muito alto
    
    # NOVA: Verifica manipulação psicológica
    for palavra in PALAVRAS_MANIPULACAO_PSICOLOGICA:
        if palavra in texto_lower:
            palavras_encontradas.append(f"MANIPULAÇÃO: {palavra}")
            score_total += 12
    
    # NOVA: Verifica padrões técnicos suspeitos
    for padrao in PADROES_GOLPES_TECNICOS:
        matches = re.findall(padrao, texto_lower)
        for match in matches:
            if isinstance(match, tuple):
                match = ' '.join(match)
            palavras_encontradas.append(f"PADRÃO SUSPEITO: {match}")
            score_total += 15
    
    return {
        'palavras': palavras_encontradas,
        'score': min(score_total, 90)  # Aumentei o máximo para 90
    }

def detectar_golpe_colaboracao(texto):
    """Detecta especificamente golpes de colaboração/freelancer"""
    texto_lower = texto.lower()
    
    # Indicadores específicos de golpes de colaboração
    indicadores_criticos = [
        'criar uma conta',
        'compartilhar conta',
        'usar sua conta',
        'conta suspensa',
        'preciso da sua ajuda',
        'dividir lucro',
        'usar seu nome',
        'participar das videoconferências'
    ]
    
    indicadores_encontrados = []
    score_golpe = 0
    
    for indicador in indicadores_criticos:
        if indicador in texto_lower:
            indicadores_encontrados.append(indicador)
            score_golpe += 35  # Score muito alto para cada indicador
    
    # Padrões específicos
    padroes_criticos = [
        r'conta.*suspensa.*devido.*mudança',
        r'criar.*conta.*seu.*nome',
        r'compartilh.*conta.*comigo',
        r'dividir.*lucro.*colaboração',
        r'ganhar.*mil.*semana',
        r'apenas.*horas.*semana'
    ]
    
    for padrao in padroes_criticos:
        if re.search(padrao, texto_lower):
            indicadores_encontrados.append(f"PADRÃO CRÍTICO: {padrao}")
            score_golpe += 40
    
    return {
        'is_golpe_colaboracao': len(indicadores_encontrados) >= 2,
        'score': min(score_golpe, 95),
        'indicadores': indicadores_encontrados
    }

def analisar_local(mensagem):
    """ANÁLISE COMPLETA 100% LOCAL"""
    
    # Extrai URLs da mensagem
    urls = extrair_urls(mensagem)
    
    score_risco = 0
    dominios_suspeitos = []
    palavras_suspeitas = []
    
    # ANÁLISE DE PALAVRAS SUSPEITAS
    analise_palavras = analisar_palavras_suspeitas(mensagem)
    palavras_suspeitas = analise_palavras['palavras']
    score_risco += analise_palavras['score']

    # NOVA: DETECÇÃO ESPECÍFICA DE GOLPES DE COLABORAÇÃO
    golpe_colaboracao = detectar_golpe_colaboracao(mensagem)
    if golpe_colaboracao['is_golpe_colaboracao']:
        score_risco += golpe_colaboracao['score']
        dominios_suspeitos.append("🚨 GOLPE DE COLABORAÇÃO/FREELANCER DETECTADO")
        for indicador in golpe_colaboracao['indicadores']:
            dominios_suspeitos.append(f"⚠️ INDICADOR: {indicador}")
    
    # ANÁLISE DE DOMÍNIOS
    for url in urls:
        dominio = extrair_dominio(url)
        
        # Verifica se é domínio seguro conhecido
        if dominio in DOMINIOS_SEGUROS:
            continue  # Domínio seguro, não adiciona risco
        
        # Verifica se é domínio malicioso conhecido
        if dominio in DOMINIOS_MALICIOSOS:
            score_risco += 95
            dominios_suspeitos.append(f"🚨 DOMÍNIO MALICIOSO CONHECIDO: {dominio}")
            continue
        
        # Verifica imitação de marcas
        imitacao_result = detectar_imitacao_marca(dominio)
        if imitacao_result['is_imitacao']:
            score_risco += imitacao_result['score']
            for imitacao in imitacao_result['imitacoes']:
                dominios_suspeitos.append(
                    f" {imitacao['tipo']}: {imitacao['dominio_suspeito']} "
                    f"imita {imitacao['marca_imitada']} (oficial: {imitacao['dominio_oficial']})"
                )
        
        # Verifica TLD perigoso
        tld_result = verificar_tld_perigoso(dominio)
        if tld_result['is_perigoso']:
            score_risco += tld_result['risco']
            dominios_suspeitos.append(f"🚩 TLD PERIGOSO: {dominio} - {tld_result['motivo']}")
        
        # Verifica padrões suspeitos
        if re.search(r'\d+\.\d+\.\d+\.\d+', dominio):
            score_risco += 40
            dominios_suspeitos.append(f"🚨 USA IP: {dominio} (em vez de nome de domínio)")
        
        if len(dominio.split('.')) > 4:
            score_risco += 20
            dominios_suspeitos.append(f"⚠️ MUITOS SUBDOMÍNIOS: {dominio}")
        
        # Se não é conhecido como seguro, adiciona risco base
        if not any([imitacao_result['is_imitacao'], tld_result['is_perigoso'], 
                   re.search(r'\d+\.\d+\.\d+\.\d+', dominio)]):
            score_risco += 15
            dominios_suspeitos.append(f"⚠️ DOMÍNIO DESCONHECIDO: {dominio}")
    
    # ANÁLISE DE PADRÕES GERAIS
    mensagem_lower = mensagem.lower()
    
    # Excesso de maiúsculas
    caps_ratio = sum(1 for c in mensagem if c.isupper()) / max(len(mensagem), 1)
    if caps_ratio > 0.3:
        score_risco += 15
        palavras_suspeitas.append("EXCESSO DE MAIÚSCULAS")
    
    # Excesso de pontuação
    punct_count = sum(1 for c in mensagem if c in '!?.,;:')
    if punct_count > len(mensagem) * 0.1:
        score_risco += 10
        palavras_suspeitas.append("EXCESSO DE PONTUAÇÃO")
    
    # Números de telefone ou códigos suspeitos
    if re.search(r'\b\d{10,11}\b', mensagem):
        score_risco += 10
        palavras_suspeitas.append("NÚMERO DE TELEFONE")
    
    # Limita score máximo
    score_risco = min(score_risco, 100)
    
    # DETERMINA NÍVEL DE RISCO
    if score_risco >= 80 or golpe_colaboracao['is_golpe_colaboracao']:
        nivel_risco = 'danger'
        nivel_risco_texto = 'CRÍTICO'
        recomendacoes = [
            " GOLPE DETECTADO - NÃO RESPONDA A ESTA MENSAGEM",
            " NUNCA compartilhe contas ou dados pessoais",
            " NUNCA crie contas para terceiros usarem",
            " Desconfie de promessas de dinheiro fácil",
            " Golpes de 'colaboração' são muito comuns",
            " Reporte este golpe às autoridades se necessário"
        ]
    elif score_risco >= 60:
        nivel_risco = 'danger'
        nivel_risco_texto = 'ALTO'
        recomendacoes = [
            " ALTO RISCO - Seja extremamente cauteloso",
            "Verifique se é realmente da empresa oficial",
            " NÃO clique em links ou baixe arquivos",
            " Entre em contato com a empresa por canais oficiais"
        ]
    elif score_risco >= 40:
        nivel_risco = 'warning'
        nivel_risco_texto = 'MÉDIO'
        recomendacoes = [
            " CUIDADO - Esta mensagem tem elementos suspeitos",
            " Confirme a legitimidade antes de prosseguir",
            " Evite inserir dados sensíveis",
            " Em caso de dúvida, contate a empresa diretamente"
        ]
    elif score_risco >= 20:
        nivel_risco = 'warning'
        nivel_risco_texto = 'BAIXO'
        recomendacoes = [
            " ATENÇÃO - Alguns elementos podem ser suspeitos",
            " Sempre verifique a legitimidade de mensagens",
            " Mantenha cuidado com dados pessoais"
        ]
    else:
        nivel_risco = 'safe'
        nivel_risco_texto = 'SEGURO'
        recomendacoes = [
            " Mensagem aparenta ser segura",
            " Mesmo assim, sempre mantenha cuidado com dados pessoais",
            " Verifique sempre a legitimidade de sites antes de inserir dados"
        ]
    
    return {
        'score_risco': score_risco,
        'nivel_risco': nivel_risco,
        'nivel_risco_texto': nivel_risco_texto,
        'palavras_suspeitas': palavras_suspeitas,
        'dominios_suspeitos': dominios_suspeitos,
        'recomendacoes': recomendacoes,
        'detalhes': {
            'tipo_analise': 'local_completa',
            'timestamp': datetime.now().isoformat(),
            'urls_encontradas': len(urls),
            'dominios_analisados': [extrair_dominio(url) for url in urls]
        }
    }

@app.route('/health')
def health_check():
    """Health check do sistema"""
    return jsonify({
        'status': 'ok',
        'modo': 'LOCAL_COMPLETO',
        'dominios_seguros': len(DOMINIOS_SEGUROS),
        'dominios_maliciosos': len(DOMINIOS_MALICIOSOS),
        'marcas_protegidas': len(MARCAS_CRITICAS),
        'tlds_perigosos': len(TLDS_PERIGOSOS),
        'timestamp': datetime.now().isoformat()
    })

@app.errorhandler(404)
def not_found(error):
    logger.warning(f"Página não encontrada: {request.path}")
    return jsonify({'erro': 'Página não encontrada'}), 404

@app.errorhandler(500)
def internal_error(error):
    logger.error(f"Erro interno: {str(error)}")
    return jsonify({'erro': 'Erro interno do servidor'}), 500

if __name__ == '__main__':
    # Cria estrutura de arquivos automaticamente
    criar_estrutura_arquivos()
    
    logger.warning(" SISTEMA INICIADO EM MODO 100% LOCAL")
    logger.warning(" PRIORIDADE MÁXIMA: PROTEÇÃO DO USUÁRIO")
    logger.info(" Sistema completamente independente - SEM APIs externas")
    logger.info("Estrutura de arquivos criada automaticamente")
    logger.info(f" Protegendo contra {len(MARCAS_CRITICAS)} marcas críticas")
    logger.info(f" Detectando {len(TLDS_PERIGOSOS)} TLDs perigosos")
    
    app.run(debug=True, host='127.0.0.1', port=5000)

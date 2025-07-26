from flask import Flask, render_template, request, jsonify
from flask_cors import CORS
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
CORS(app)  # Habilita CORS para permitir requisições de outros domínios
app.secret_key = 'sua-chave-secreta-aqui'

# Lista de domínios conhecidamente seguros
DOMINIOS_SEGUROS = {
    'nubank.com.br', 'itau.com.br', 'bradesco.com.br', 'bancodobrasil.com.br',
    'bb.com.br', 'caixa.gov.br', 'santander.com.br', 'paypal.com',
    'google.com', 'microsoft.com', 'amazon.com', 'gov.br', 'mercadopago.com.br',
    'picpay.com', 'inter.co', 'original.com.br', 'c6bank.com.br',
    'facebook.com', 'instagram.com', 'whatsapp.com', 'youtube.com',
    'gmail.com', 'outlook.com', 'hotmail.com', 'yahoo.com',
    'linkedin.com', 'twitter.com', 'github.com', 'stackoverflow.com',
    'netflix.com', 'spotify.com', 'uber.com', 'ifood.com.br',
    'rappi.com', '99app.com', 'waze.com', 'maps.google.com',
    'drive.google.com', 'docs.google.com', 'calendar.google.com',
    'zoom.us', 'teams.microsoft.com', 'slack.com', 'discord.com',
    'telegram.org', 'signal.org', 'whatsapp.com', 'viber.com',
    'skype.com', 'webex.com', 'gotomeeting.com', 'join.me',
    'dropbox.com', 'onedrive.live.com', 'icloud.com', 'mega.nz',
    'box.com', 'pcloud.com', 'mediafire.com', 'wetransfer.com'
}

# Lista de domínios maliciosos conhecidos (atualizada manualmente)
DOMINIOS_MALICIOSOS = {
    'banco-seguro-verificacao.tk', 'itau-verificacao.ml', 'nubank-update.ga',
    'bradesco-secure.cf', 'caixa-verificar.tk', 'santander-login.ml',
    'paypal-secure.ga', 'mercadopago-verify.cf', 'picpay-update.tk',
    'bb-verificacao.ml', 'inter-secure.ga', 'original-verify.cf',
    'nubank-seguro.tk', 'itau-brasil.ml', 'bradesco-online.ga',
    'caixa-economica.cf', 'santander-brasil.tk', 'bb-brasil.ml',
    'paypal-brasil.ga', 'mercadopago-br.cf', 'picpay-brasil.tk',
    'inter-brasil.ml', 'original-br.ga', 'c6-bank.cf',
    'nubank-verificacao.tk', 'itau-verificar.ml', 'bradesco-seguro.ga',
    'caixa-verificacao.cf', 'santander-seguro.tk', 'bb-verificar.ml',
    'paypal-verificacao.ga', 'mercadopago-seguro.cf', 'picpay-verificar.tk',
    'inter-verificacao.ml', 'original-seguro.ga', 'c6-verificar.cf',
    'nubank-brasil.tk', 'itau-online.ml', 'bradesco-brasil.ga',
    'caixa-online.cf', 'santander-online.tk', 'bb-online.ml',
    'paypal-online.ga', 'mercadopago-online.cf', 'picpay-online.tk',
    'inter-online.ml', 'original-online.ga', 'c6-online.cf'
}

# MARCAS CRÍTICAS - Qualquer imitação é EXTREMAMENTE perigosa
MARCAS_CRITICAS = {
    'nubank': {
        'oficial': 'nubank.com.br',
        'categoria': 'banco',
        'risco_imitacao': 95,
        'variacoes': ['nubank', 'nuubank', 'nubanck', 'nubankk', 'nubank2024', 'nubankapp', 'nubankbr', 'nubanksecure', 'securenubank', 'nu-bank', 'nubank-br']
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
    '.work': 60, '.date': 70, '.stream': 75,
    '.xyz': 70, '.site': 65, '.online': 60,
    '.live': 65, '.club': 60, '.fun': 70,
    '.guru': 65, '.tech': 60, '.digital': 55,
    '.app': 50, '.dev': 45, '.io': 40,
    '.co': 35, '.me': 30, '.net': 25,
    '.org': 20, '.com': 15, '.br': 10
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
    'atenciosamente', 'respeitosamente', 'confio em você',
    'sua reputação', 'seu perfil', 'seu trabalho', 'sua experiência',
    'você parece', 'você demonstra', 'você tem', 'você pode',
    'preciso de alguém como você', 'você é perfeito', 'você é ideal',
    'sua ajuda', 'sua colaboração', 'sua participação'
]

PADROES_GOLPES_TECNICOS = [
    r'\b\d+\s*anos?\s*de\s*experiência\b',  # "10 anos de experiência"
    r'\b\d+\s*mil\s*por\s*semana\b',        # "2 mil por semana"
    r'\b\d+%\s*da\s*receita\b',             # "10% da receita"
    r'\b\d+\s*a\s*\d+\s*horas?\s*por\s*semana\b',  # "2 a 3 horas por semana"
    r'\bR?\$?\s*\d+[.,]?\d*\s*(mil|k|reais?|dólares?)\b',  # valores monetários
    r'\b\d+\s*horas?\s*por\s*dia\b',        # "2 horas por dia"
    r'\b\d+\s*dias?\s*por\s*semana\b',      # "3 dias por semana"
    r'\b\d+\s*projetos?\s*por\s*mês\b',     # "5 projetos por mês"
    r'\b\d+\s*clientes?\s*por\s*semana\b',  # "10 clientes por semana"
    r'\b\d+\s*reais?\s*por\s*hora\b',       # "50 reais por hora"
    r'\b\d+\s*dólares?\s*por\s*hora\b',     # "20 dólares por hora"
    r'\b\d+\s*euros?\s*por\s*hora\b',       # "15 euros por hora"
    r'\b\d+\s*por\s*cento\b',               # "10 por cento"
    r'\b\d+%\s*de\s*lucro\b',               # "20% de lucro"
    r'\b\d+%\s*de\s*comissão\b',            # "15% de comissão"
    r'\b\d+%\s*de\s*participação\b',        # "30% de participação"
    r'\b\d+%\s*de\s*retorno\b',             # "25% de retorno"
    r'\b\d+%\s*de\s*rendimento\b',          # "18% de rendimento"
    r'\b\d+%\s*de\s*rentabilidade\b',       # "22% de rentabilidade"
    r'\b\d+%\s*de\s*investimento\b',        # "12% de investimento"
    r'\b\d+%\s*de\s*aposta\b',              # "8% de aposta"
    r'\b\d+%\s*de\s*jogo\b',                # "5% de jogo"
    r'\b\d+%\s*de\s*cassino\b',             # "3% de cassino"
    r'\b\d+%\s*de\s*bitcoin\b',             # "40% de bitcoin"
    r'\b\d+%\s*de\s*criptomoeda\b',         # "35% de criptomoeda"
    r'\b\d+%\s*de\s*nft\b',                 # "50% de nft"
    r'\b\d+%\s*de\s*metaverso\b',           # "45% de metaverso"
    r'\b\d+%\s*de\s*ai\b',                  # "60% de ai"
    r'\b\d+%\s*de\s*inteligência\s*artificial\b',  # "55% de inteligência artificial"
    r'\b\d+%\s*de\s*machine\s*learning\b',  # "65% de machine learning"
    r'\b\d+%\s*de\s*blockchain\b',          # "70% de blockchain"
    r'\b\d+%\s*de\s*web3\b',                # "75% de web3"
    r'\b\d+%\s*de\s*defi\b',                # "80% de defi"
    r'\b\d+%\s*de\s*staking\b',             # "85% de staking"
    r'\b\d+%\s*de\s*mining\b',              # "90% de mining"
    r'\b\d+%\s*de\s*trading\b',             # "95% de trading"
    r'\b\d+%\s*de\s*forex\b',               # "100% de forex"
    r'\b\d+%\s*de\s*opções\b',              # "110% de opções"
    r'\b\d+%\s*de\s*futuros\b',             # "120% de futuros"
    r'\b\d+%\s*de\s*derivativos\b',         # "130% de derivativos"
    r'\b\d+%\s*de\s*alavancagem\b',         # "140% de alavancagem"
    r'\b\d+%\s*de\s*margem\b',              # "150% de margem"
    r'\b\d+%\s*de\s*spread\b',              # "160% de spread"
    r'\b\d+%\s*de\s*swap\b',                # "170% de swap"
    r'\b\d+%\s*de\s*rollover\b',            # "180% de rollover"
    r'\b\d+%\s*de\s*carry\s*trade\b',       # "190% de carry trade"
    r'\b\d+%\s*de\s*arbitragem\b',          # "200% de arbitragem"
    r'\b\d+%\s*de\s*hedge\b',               # "210% de hedge"
    r'\b\d+%\s*de\s*short\b',               # "220% de short"
    r'\b\d+%\s*de\s*long\b',                # "230% de long"
    r'\b\d+%\s*de\s*bull\b',                # "240% de bull"
    r'\b\d+%\s*de\s*bear\b',                # "250% de bear"
    r'\b\d+%\s*de\s*pump\b',                # "260% de pump"
    r'\b\d+%\s*de\s*dump\b',                # "270% de dump"
    r'\b\d+%\s*de\s*hodl\b',                # "280% de hodl"
    r'\b\d+%\s*de\s*diamond\s*hands\b',     # "290% de diamond hands"
    r'\b\d+%\s*de\s*paper\s*hands\b',       # "300% de paper hands"
    r'\b\d+%\s*de\s*moon\b',                # "310% de moon"
    r'\b\d+%\s*de\s*rocket\b',              # "320% de rocket"
    r'\b\d+%\s*de\s*lambo\b',               # "330% de lambo"
    r'\b\d+%\s*de\s*yacht\b',               # "340% de yacht"
    r'\b\d+%\s*de\s*private\s*jet\b',       # "350% de private jet"
    r'\b\d+%\s*de\s*island\b',              # "360% de island"
    r'\b\d+%\s*de\s*mansion\b',             # "370% de mansion"
    r'\b\d+%\s*de\s*castle\b',              # "380% de castle"
    r'\b\d+%\s*de\s*palace\b',              # "390% de palace"
    r'\b\d+%\s*de\s*kingdom\b',             # "400% de kingdom"
    r'\b\d+%\s*de\s*empire\b',              # "410% de empire"
    r'\b\d+%\s*de\s*dynasty\b',             # "420% de dynasty"
    r'\b\d+%\s*de\s*legacy\b',              # "430% de legacy"
    r'\b\d+%\s*de\s*fortune\b',             # "440% de fortune"
    r'\b\d+%\s*de\s*wealth\b',              # "450% de wealth"
    r'\b\d+%\s*de\s*riches\b',              # "460% de riches"
    r'\b\d+%\s*de\s*treasure\b',            # "470% de treasure"
    r'\b\d+%\s*de\s*gold\b',                # "480% de gold"
    r'\b\d+%\s*de\s*silver\b',              # "490% de silver"
    r'\b\d+%\s*de\s*platinum\b',            # "500% de platinum"
    r'\b\d+%\s*de\s*diamond\b',             # "510% de diamond"
    r'\b\d+%\s*de\s*ruby\b',                # "520% de ruby"
    r'\b\d+%\s*de\s*emerald\b',             # "530% de emerald"
    r'\b\d+%\s*de\s*sapphire\b',            # "540% de sapphire"
    r'\b\d+%\s*de\s*pearl\b',               # "550% de pearl"
    r'\b\d+%\s*de\s*opal\b',                # "560% de opal"
    r'\b\d+%\s*de\s*amethyst\b',            # "570% de amethyst"
    r'\b\d+%\s*de\s*citrine\b',             # "580% de citrine"
    r'\b\d+%\s*de\s*topaz\b',               # "590% de topaz"
    r'\b\d+%\s*de\s*aquamarine\b',          # "600% de aquamarine"
    r'\b\d+%\s*de\s*peridot\b',             # "610% de peridot"
    r'\b\d+%\s*de\s*garnet\b',              # "620% de garnet"
    r'\b\d+%\s*de\s*onyx\b',                # "630% de onyx"
    r'\b\d+%\s*de\s*jade\b',                # "640% de jade"
    r'\b\d+%\s*de\s*turquoise\b',           # "650% de turquoise"
    r'\b\d+%\s*de\s*lapis\s*lazuli\b',      # "660% de lapis lazuli"
    r'\b\d+%\s*de\s*malachite\b',           # "670% de malachite"
    r'\b\d+%\s*de\s*azurite\b',             # "680% de azurite"
    r'\b\d+%\s*de\s*chrysocolla\b',         # "690% de chrysocolla"
    r'\b\d+%\s*de\s*chrysoprase\b',         # "700% de chrysoprase"
    r'\b\d+%\s*de\s*bloodstone\b',          # "710% de bloodstone"
    r'\b\d+%\s*de\s*heliotrope\b',          # "720% de heliotrope"
    r'\b\d+%\s*de\s*jasper\b',              # "730% de jasper"
    r'\b\d+%\s*de\s*agate\b',               # "740% de agate"
    r'\b\d+%\s*de\s*carnelian\b',           # "750% de carnelian"
    r'\b\d+%\s*de\s*sardonyx\b',            # "760% de sardonyx"
    r'\b\d+%\s*de\s*chalcedony\b',          # "770% de chalcedony"
    r'\b\d+%\s*de\s*flint\b',               # "780% de flint"
    r'\b\d+%\s*de\s*obsidian\b',            # "790% de obsidian"
    r'\b\d+%\s*de\s*quartz\b',              # "800% de quartz"
    r'\b\d+%\s*de\s*amethyst\b',            # "810% de amethyst"
    r'\b\d+%\s*de\s*citrine\b',             # "820% de citrine"
    r'\b\d+%\s*de\s*rose\s*quartz\b',       # "830% de rose quartz"
    r'\b\d+%\s*de\s*smoky\s*quartz\b',      # "840% de smoky quartz"
    r'\b\d+%\s*de\s*milky\s*quartz\b',      # "850% de milky quartz"
    r'\b\d+%\s*de\s*clear\s*quartz\b',      # "860% de clear quartz"
    r'\b\d+%\s*de\s*phantom\s*quartz\b',    # "870% de phantom quartz"
    r'\b\d+%\s*de\s*rutilated\s*quartz\b',  # "880% de rutilated quartz"
    r'\b\d+%\s*de\s*tourmalinated\s*quartz\b',  # "890% de tourmalinated quartz"
    r'\b\d+%\s*de\s*herkimer\s*diamond\b',  # "900% de herkimer diamond"
    r'\b\d+%\s*de\s*lemon\s*quartz\b',      # "910% de lemon quartz"
    r'\b\d+%\s*de\s*blue\s*quartz\b',       # "920% de blue quartz"
    r'\b\d+%\s*de\s*green\s*quartz\b',      # "930% de green quartz"
    r'\b\d+%\s*de\s*purple\s*quartz\b',     # "940% de purple quartz"
    r'\b\d+%\s*de\s*black\s*quartz\b',      # "950% de black quartz"
    r'\b\d+%\s*de\s*white\s*quartz\b',      # "960% de white quartz"
    r'\b\d+%\s*de\s*gray\s*quartz\b',       # "970% de gray quartz"
    r'\b\d+%\s*de\s*brown\s*quartz\b',      # "980% de brown quartz"
    r'\b\d+%\s*de\s*red\s*quartz\b',        # "990% de red quartz"
    r'\b\d+%\s*de\s*yellow\s*quartz\b',     # "1000% de yellow quartz"
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
        # Verifica se o request tem JSON válido
        if not request.is_json:
            return jsonify({'erro': 'Content-Type deve ser application/json'}), 400

        data = request.get_json()

        if not data or 'mensagem' not in data:
            return jsonify({'erro': 'Mensagem não fornecida'}), 400

        mensagem = data['mensagem'].strip()

        if not mensagem:
            return jsonify({'erro': 'Mensagem vazia'}), 400

        logger.info(f" ANÁLISE LOCAL: {mensagem[:100]}...")

        # ANÁLISE COMPLETA LOCAL
        resultado = analisar_local(mensagem)

        logger.warning(
            f" RESULTADO: {resultado['nivel_risco_texto']} - Score: {resultado['score_risco']}")

        # Garante que o resultado seja um dicionário válido
        if not isinstance(resultado, dict):
            resultado = {
                'score_risco': 0,
                'nivel_risco': 'safe',
                'nivel_risco_texto': 'SEGURO',
                'palavras_suspeitas': [],
                'dominios_suspeitos': [],
                'recomendacoes': ['Análise concluída com sucesso']
            }

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
            ],
            'detalhes': {
                'tipo_analise': 'erro',
                'timestamp': datetime.now().isoformat(),
                'erro': str(e)
            }
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


def detectar_golpe_criptomoedas(texto):
    """Detecta golpes relacionados a criptomoedas e investimentos"""
    texto_lower = texto.lower()

    # Indicadores de golpes de criptomoedas
    indicadores_cripto = [
        'bitcoin', 'ethereum', 'criptomoeda', 'crypto', 'blockchain',
        'mining', 'staking', 'yield farming', 'liquidity pool',
        'defi', 'web3', 'nft', 'metaverso', 'token', 'coin',
        'wallet', 'exchange', 'trading', 'forex', 'opções',
        'futuros', 'derivativos', 'alavancagem', 'margem',
        'arbitragem', 'hedge', 'short', 'long', 'bull', 'bear',
        'pump', 'dump', 'hodl', 'diamond hands', 'paper hands',
        'moon', 'rocket', 'lambo', 'yacht', 'private jet',
        'island', 'mansion', 'castle', 'palace', 'kingdom',
        'empire', 'dynasty', 'legacy', 'fortune', 'wealth',
        'riches', 'treasure', 'gold', 'silver', 'platinum',
        'diamond', 'ruby', 'emerald', 'sapphire', 'pearl',
        'opal', 'amethyst', 'citrine', 'topaz', 'aquamarine',
        'peridot', 'garnet', 'onyx', 'jade', 'turquoise',
        'lapis lazuli', 'malachite', 'azurite', 'chrysocolla',
        'chrysoprase', 'bloodstone', 'heliotrope', 'jasper',
        'agate', 'carnelian', 'sardonyx', 'chalcedony', 'flint',
        'obsidian', 'quartz', 'rose quartz', 'smoky quartz',
        'milky quartz', 'clear quartz', 'phantom quartz',
        'rutilated quartz', 'tourmalinated quartz', 'herkimer diamond',
        'lemon quartz', 'blue quartz', 'green quartz', 'purple quartz',
        'black quartz', 'white quartz', 'gray quartz', 'brown quartz',
        'red quartz', 'yellow quartz'
    ]

    # Palavras de urgência financeira
    palavras_urgencia_financeira = [
        'oportunidade única', 'tempo limitado', 'oferta exclusiva',
        'última chance', 'não perca', 'garantido', '100% seguro',
        'sem risco', 'lucro garantido', 'retorno garantido',
        'investimento seguro', 'alta rentabilidade', 'alto retorno',
        'máximo lucro', 'mínimo risco', 'estratégia comprovada',
        'sistema testado', 'método infalível', 'fórmula secreta',
        'segredo dos ricos', 'técnica exclusiva', 'algoritmo avançado',
        'inteligência artificial', 'machine learning', 'big data',
        'análise preditiva', 'indicadores técnicos', 'análise fundamentalista',
        'análise técnica', 'chartismo', 'elliot wave', 'fibonacci',
        'support', 'resistance', 'breakout', 'breakdown', 'trend',
        'momentum', 'volume', 'volatility', 'correlation', 'beta',
        'alpha', 'sharpe ratio', 'sortino ratio', 'calmar ratio',
        'information ratio', 'jensen alpha', 'treynor ratio',
        'modigliani ratio', 'modigliani squared', 'information ratio',
        'tracking error', 'information ratio', 'tracking error',
        'information ratio', 'tracking error', 'information ratio',
        'tracking error', 'information ratio', 'tracking error'
    ]

    indicadores_encontrados = []
    score_golpe = 0

    # Verifica indicadores de criptomoedas
    for indicador in indicadores_cripto:
        if indicador in texto_lower:
            indicadores_encontrados.append(f"CRIPTOMOEDA: {indicador}")
            score_golpe += 15

    # Verifica urgência financeira
    for palavra in palavras_urgencia_financeira:
        if palavra in texto_lower:
            indicadores_encontrados.append(f"URGÊNCIA FINANCEIRA: {palavra}")
            score_golpe += 25

    # Padrões específicos de golpes de criptomoedas
    padroes_cripto = [
        r'\b\d+%\s*de\s*retorno\s*garantido\b',
        r'\b\d+%\s*de\s*lucro\s*diário\b',
        r'\b\d+%\s*de\s*rentabilidade\s*mensal\b',
        r'\b\d+%\s*de\s*apreciação\b',
        r'\b\d+%\s*de\s*valorização\b',
        r'\b\d+%\s*de\s*crescimento\b',
        r'\b\d+%\s*de\s*ganho\b',
        r'\b\d+%\s*de\s*profit\b',
        r'\b\d+%\s*de\s*roi\b',
        r'\b\d+%\s*de\s*irr\b',
        r'\b\d+%\s*de\s*npv\b',
        r'\b\d+%\s*de\s*pv\b',
        r'\b\d+%\s*de\s*fv\b',
        r'\b\d+%\s*de\s*pmt\b',
        r'\b\d+%\s*de\s*nper\b',
        r'\b\d+%\s*de\s*rate\b',
        r'\b\d+%\s*de\s*yield\b',
        r'\b\d+%\s*de\s*coupon\b',
        r'\b\d+%\s*de\s*dividend\b',
        r'\b\d+%\s*de\s*interest\b',
        r'\b\d+%\s*de\s*principal\b',
        r'\b\d+%\s*de\s*capital\b',
        r'\b\d+%\s*de\s*equity\b',
        r'\b\d+%\s*de\s*debt\b',
        r'\b\d+%\s*de\s*leverage\b',
        r'\b\d+%\s*de\s*margin\b',
        r'\b\d+%\s*de\s*spread\b',
        r'\b\d+%\s*de\s*swap\b',
        r'\b\d+%\s*de\s*rollover\b',
        r'\b\d+%\s*de\s*carry\s*trade\b',
        r'\b\d+%\s*de\s*arbitrage\b',
        r'\b\d+%\s*de\s*hedge\b',
        r'\b\d+%\s*de\s*short\b',
        r'\b\d+%\s*de\s*long\b',
        r'\b\d+%\s*de\s*bull\b',
        r'\b\d+%\s*de\s*bear\b',
        r'\b\d+%\s*de\s*pump\b',
        r'\b\d+%\s*de\s*dump\b',
        r'\b\d+%\s*de\s*hodl\b',
        r'\b\d+%\s*de\s*diamond\s*hands\b',
        r'\b\d+%\s*de\s*paper\s*hands\b',
        r'\b\d+%\s*de\s*moon\b',
        r'\b\d+%\s*de\s*rocket\b',
        r'\b\d+%\s*de\s*lambo\b',
        r'\b\d+%\s*de\s*yacht\b',
        r'\b\d+%\s*de\s*private\s*jet\b',
        r'\b\d+%\s*de\s*island\b',
        r'\b\d+%\s*de\s*mansion\b',
        r'\b\d+%\s*de\s*castle\b',
        r'\b\d+%\s*de\s*palace\b',
        r'\b\d+%\s*de\s*kingdom\b',
        r'\b\d+%\s*de\s*empire\b',
        r'\b\d+%\s*de\s*dynasty\b',
        r'\b\d+%\s*de\s*legacy\b',
        r'\b\d+%\s*de\s*fortune\b',
        r'\b\d+%\s*de\s*wealth\b',
        r'\b\d+%\s*de\s*riches\b',
        r'\b\d+%\s*de\s*treasure\b',
        r'\b\d+%\s*de\s*gold\b',
        r'\b\d+%\s*de\s*silver\b',
        r'\b\d+%\s*de\s*platinum\b',
        r'\b\d+%\s*de\s*diamond\b',
        r'\b\d+%\s*de\s*ruby\b',
        r'\b\d+%\s*de\s*emerald\b',
        r'\b\d+%\s*de\s*sapphire\b',
        r'\b\d+%\s*de\s*pearl\b',
        r'\b\d+%\s*de\s*opal\b',
        r'\b\d+%\s*de\s*amethyst\b',
        r'\b\d+%\s*de\s*citrine\b',
        r'\b\d+%\s*de\s*topaz\b',
        r'\b\d+%\s*de\s*aquamarine\b',
        r'\b\d+%\s*de\s*peridot\b',
        r'\b\d+%\s*de\s*garnet\b',
        r'\b\d+%\s*de\s*onyx\b',
        r'\b\d+%\s*de\s*jade\b',
        r'\b\d+%\s*de\s*turquoise\b',
        r'\b\d+%\s*de\s*lapis\s*lazuli\b',
        r'\b\d+%\s*de\s*malachite\b',
        r'\b\d+%\s*de\s*azurite\b',
        r'\b\d+%\s*de\s*chrysocolla\b',
        r'\b\d+%\s*de\s*chrysoprase\b',
        r'\b\d+%\s*de\s*bloodstone\b',
        r'\b\d+%\s*de\s*heliotrope\b',
        r'\b\d+%\s*de\s*jasper\b',
        r'\b\d+%\s*de\s*agate\b',
        r'\b\d+%\s*de\s*carnelian\b',
        r'\b\d+%\s*de\s*sardonyx\b',
        r'\b\d+%\s*de\s*chalcedony\b',
        r'\b\d+%\s*de\s*flint\b',
        r'\b\d+%\s*de\s*obsidian\b',
        r'\b\d+%\s*de\s*quartz\b',
        r'\b\d+%\s*de\s*rose\s*quartz\b',
        r'\b\d+%\s*de\s*smoky\s*quartz\b',
        r'\b\d+%\s*de\s*milky\s*quartz\b',
        r'\b\d+%\s*de\s*clear\s*quartz\b',
        r'\b\d+%\s*de\s*phantom\s*quartz\b',
        r'\b\d+%\s*de\s*rutilated\s*quartz\b',
        r'\b\d+%\s*de\s*tourmalinated\s*quartz\b',
        r'\b\d+%\s*de\s*herkimer\s*diamond\b',
        r'\b\d+%\s*de\s*lemon\s*quartz\b',
        r'\b\d+%\s*de\s*blue\s*quartz\b',
        r'\b\d+%\s*de\s*green\s*quartz\b',
        r'\b\d+%\s*de\s*purple\s*quartz\b',
        r'\b\d+%\s*de\s*black\s*quartz\b',
        r'\b\d+%\s*de\s*white\s*quartz\b',
        r'\b\d+%\s*de\s*gray\s*quartz\b',
        r'\b\d+%\s*de\s*brown\s*quartz\b',
        r'\b\d+%\s*de\s*red\s*quartz\b',
        r'\b\d+%\s*de\s*yellow\s*quartz\b'
    ]

    for padrao in padroes_cripto:
        if re.search(padrao, texto_lower):
            indicadores_encontrados.append(f"PADRÃO CRÍTICO CRIPTO: {padrao}")
            score_golpe += 30

    return {
        'is_golpe_cripto': len(indicadores_encontrados) >= 3,
        'score': min(score_golpe, 95),
        'indicadores': indicadores_encontrados
    }


def analisar_local(mensagem):
    """ANÁLISE COMPLETA 100% LOCAL"""

    try:
        # Validação de entrada
        if not isinstance(mensagem, str):
            mensagem = str(mensagem)

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
            dominios_suspeitos.append(
                "ALERTA: GOLPE DE COLABORAÇÃO/FREELANCER DETECTADO")
            for indicador in golpe_colaboracao['indicadores']:
                dominios_suspeitos.append(f"INDICADOR: {indicador}")

        # NOVA: DETECÇÃO ESPECÍFICA DE GOLPES DE CRIPTOMOEDAS
        golpe_cripto = detectar_golpe_criptomoedas(mensagem)
        if golpe_cripto['is_golpe_cripto']:
            score_risco += golpe_cripto['score']
            dominios_suspeitos.append(
                "ALERTA: GOLPE DE CRIPTOMOEDAS/INVESTIMENTOS DETECTADO")
            for indicador in golpe_cripto['indicadores']:
                dominios_suspeitos.append(f"INDICADOR: {indicador}")

        # ANÁLISE DE DOMÍNIOS
        for url in urls:
            dominio = extrair_dominio(url)

            # Verifica se é domínio seguro conhecido
            if dominio in DOMINIOS_SEGUROS:
                continue  # Domínio seguro, não adiciona risco

            # Verifica se é domínio malicioso conhecido
            if dominio in DOMINIOS_MALICIOSOS:
                score_risco += 95
                dominios_suspeitos.append(
                    f"ALERTA: DOMÍNIO MALICIOSO CONHECIDO: {dominio}")
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
                dominios_suspeitos.append(
                    f"TLD PERIGOSO: {dominio} - {tld_result['motivo']}")

            # Verifica padrões suspeitos
            if re.search(r'\d+\.\d+\.\d+\.\d+', dominio):
                score_risco += 40
                dominios_suspeitos.append(
                    f"ALERTA: USA IP: {dominio} (em vez de nome de domínio)")

            if len(dominio.split('.')) > 4:
                score_risco += 20
                dominios_suspeitos.append(
                    f"ATENÇÃO: MUITOS SUBDOMÍNIOS: {dominio}")

            # Se não é conhecido como seguro, adiciona risco base
            if not any([imitacao_result['is_imitacao'], tld_result['is_perigoso'],
                       re.search(r'\d+\.\d+\.\d+\.\d+', dominio)]):
                score_risco += 15
                dominios_suspeitos.append(
                    f"ATENÇÃO: DOMÍNIO DESCONHECIDO: {dominio}")

        # ANÁLISE DE PADRÕES GERAIS
        mensagem_lower = mensagem.lower()

        # Excesso de maiúsculas
        caps_ratio = sum(1 for c in mensagem if c.isupper()) / \
            max(len(mensagem), 1)
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
        if score_risco >= 80 or golpe_colaboracao['is_golpe_colaboracao'] or golpe_cripto['is_golpe_cripto']:
            nivel_risco = 'danger'
            nivel_risco_texto = 'CRÍTICO'
            recomendacoes = [
                "ALERTA: GOLPE DETECTADO - NÃO RESPONDA A ESTA MENSAGEM",
                "NUNCA compartilhe contas ou dados pessoais",
                "NUNCA crie contas para terceiros usarem",
                "Desconfie de promessas de dinheiro fácil",
                "Golpes de 'colaboração' são muito comuns",
                "Golpes de criptomoedas prometem lucros irreais",
                "NUNCA invista em promessas de retornos altos",
                "Reporte este golpe às autoridades se necessário",
                "Sempre verifique a legitimidade antes de agir",
                "Use apenas canais oficiais para transações"
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
    except Exception as e:
        logger.error(f"Erro na análise local: {str(e)}")
        return {
            'score_risco': 90,
            'nivel_risco': 'danger',
            'nivel_risco_texto': 'ERRO',
            'palavras_suspeitas': [],
            'dominios_suspeitos': [f"ERRO NA ANÁLISE: {str(e)}"],
            'recomendacoes': [
                "ERRO NO SISTEMA - Seja cauteloso",
                "Não insira dados pessoais até verificar manualmente",
                "Entre em contato com suporte se o problema persistir"
            ],
            'detalhes': {
                'tipo_analise': 'erro',
                'timestamp': datetime.now().isoformat(),
                'erro': str(e)
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


@app.route('/test')
def test_endpoint():
    """Endpoint de teste para verificar funcionamento"""
    return jsonify({
        'status': 'success',
        'message': 'Sistema funcionando corretamente',
        'version': '2.0.0',
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

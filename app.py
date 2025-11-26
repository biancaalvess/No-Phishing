from flask import Flask, render_template, request, jsonify
from flask_cors import CORS
import logging
from datetime import datetime
import asyncio

# Importando os módulos inteligentes (que já estão nos seus arquivos)
from ml_classifier import MLClassifier
from email_analyzer import EmailAnalyzer
from url_analyzer import URLAnalyzer
from reputation_checker import ReputationChecker

# Configuração de logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

app = Flask(__name__)
CORS(app)  # Habilita CORS para permitir requisições de outros domínios
app.secret_key = 'sua-chave-secreta-aqui'

# Inicializando a "IA" e os analisadores
# Isso carrega as classes dos arquivos ml_classifier.py, etc.
ml_classifier = MLClassifier()
email_analyzer = EmailAnalyzer()
url_analyzer = URLAnalyzer()
reputation_checker = ReputationChecker()

# Função auxiliar para executar código assíncrono em rotas síncronas do Flask


def run_async(coro):
    """Executa uma corrotina assíncrona em uma rota síncrona do Flask"""
    try:
        loop = asyncio.get_event_loop()
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
    return loop.run_until_complete(coro)


@app.route('/')
def index():
    """Página principal"""
    return render_template('index.html')


@app.route('/verificar', methods=['POST'])
def verificar_mensagem():
    """
    Endpoint INTELIGENTE que usa os módulos avançados (ML, Reputation, etc.)
    """
    try:
        if not request.is_json:
            return jsonify({'erro': 'Content-Type deve ser application/json'}), 400

        data = request.get_json()
        mensagem = data.get('mensagem', '').strip()

        if not mensagem:
            return jsonify({'erro': 'Mensagem vazia'}), 400

        logger.info(
            f"🔍 Iniciando análise inteligente para: {mensagem[:50]}...")

        # Função assíncrona interna para fazer todas as análises
        async def analisar_mensagem():
            # 1. Classificação via "IA" (MLClassifier)
            # O ml_classifier.py usa pesos e lógica avançada localmente (Grátis)
            ml_result = await ml_classifier.classify_email(mensagem)

            # 2. Análise de conteúdo (EmailAnalyzer)
            content_result = await email_analyzer.analyze_content(mensagem)

            # 3. Análise de URLs (se houver)
            urls = email_analyzer.extract_urls(mensagem)
            url_details = []
            max_url_score = 0

            for url in urls[:3]:  # Analisa as 3 primeiras URLs para não demorar
                # Análise paralela de estrutura e reputação da URL
                struct_res, rep_res, url_ml = await asyncio.gather(
                    url_analyzer.analyze_structure(url),
                    reputation_checker.check_url_reputation(url),
                    ml_classifier.classify_url(url)
                )

                # Calcula risco da URL
                url_risk = max(
                    struct_res.get('risk_score', 0),
                    rep_res.get('risk_score', 0),
                    url_ml.get('risk_score', 0)
                )
                max_url_score = max(max_url_score, url_risk)

                url_details.append({
                    'url': url,
                    'risco': url_risk,
                    'problemas': struct_res.get('flags', []) + rep_res.get('threats_found', [])
                })

            # --- CÁLCULO FINAL DO SCORE ---
            # Combina a "IA", análise de texto e URLs
            score_final = 0

            # Pesos:
            # ML (IA) = 30%
            # Análise de Texto (Urgência/Engenharia Social) = 40%
            # URLs Maliciosas = 30%

            score_ml = ml_result.get('risk_score', 0)
            score_content = content_result.get('risk_score', 0)

            score_final = (score_ml * 0.3) + \
                (score_content * 0.4) + (max_url_score * 0.3)

            # Ajustes finos
            if max_url_score > 90:
                # URL perigosa sobe o risco total
                score_final = max(score_final, 95)

            score_final = min(round(score_final), 100)

            # Determina nível de risco e texto
            nivel_risco = 'safe'
            texto_risco = 'SEGURO'
            if score_final >= 80:
                nivel_risco = 'danger'
                texto_risco = 'CRÍTICO'
            elif score_final >= 60:
                nivel_risco = 'danger'
                texto_risco = 'ALTO'
            elif score_final >= 40:
                nivel_risco = 'warning'
                texto_risco = 'MÉDIO'

            # Prepara as recomendações baseadas na IA
            recomendacoes = []
            if score_final > 40:
                recomendacoes.append(
                    "⚠️ Cuidado: Nosso sistema inteligente detectou padrões suspeitos.")
            if ml_result.get('feature_scores', {}).get('urgency', 0) > 10:
                recomendacoes.append(
                    "🕒 Atenção: A mensagem tenta criar senso de urgência falso.")
            if ml_result.get('feature_scores', {}).get('credential', 0) > 10:
                recomendacoes.append(
                    "🔒 Alerta: Pedido de senha ou dados sensíveis detectado.")
            if not recomendacoes:
                recomendacoes.append(
                    "✅ Nenhuma ameaça óbvia detectada, mas mantenha a atenção.")

            # Monta resposta compatível com seu front-end
            response_data = {
                'score_risco': score_final,
                'nivel_risco': nivel_risco,
                'nivel_risco_texto': texto_risco,
                'palavras_suspeitas': content_result.get('urgency_keywords_found', []) +
                [f"Padrão ML: {ml_result.get('classification', '')}"],
                'dominios_suspeitos': [u['url'] for u in url_details if u['risco'] > 50],
                'recomendacoes': recomendacoes,
                'detalhes': {
                    'tipo_analise': 'IA_HIBRIDA_LOCAL',  # Mostra que usou a IA
                    'ml_confidence': f"{ml_result.get('confidence', 0)*100:.1f}%",
                    'urls_analisadas': len(urls)
                }
            }

            return response_data

        # Executa a análise assíncrona
        resultado = run_async(analisar_mensagem())

        logger.info(
            f"✅ Resultado: {resultado['nivel_risco_texto']} - Score: {resultado['score_risco']}")

        return jsonify(resultado)

    except Exception as e:
        logger.error(f"❌ Erro na análise: {str(e)}")
        # Fallback simples em caso de erro
        return jsonify({
            'score_risco': 0,
            'nivel_risco': 'warning',
            'nivel_risco_texto': 'ERRO',
            'recomendacoes': ['Houve um erro interno na análise inteligente. Tente novamente.']
        }), 500


@app.route('/health')
def health_check():
    """Health check do sistema"""
    return jsonify({
        'status': 'ok',
        'modo': 'IA_ATIVADA',
        'timestamp': datetime.now().isoformat()
    })


@app.route('/test')
def test_endpoint():
    """Endpoint de teste para verificar funcionamento"""
    return jsonify({
        'status': 'success',
        'message': 'Sistema funcionando corretamente',
        'version': '3.0.0 - IA Ativada',
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


# Removemos a criação de arquivos para evitar erros no Vercel
# As pastas templates e static já devem estar no Git
if __name__ == '__main__':
    logger.info("🚀 SISTEMA INICIADO COM IA ATIVADA")
    logger.info(
        "✅ Módulos avançados carregados: ML, Email Analyzer, URL Analyzer, Reputation Checker")
    logger.info("🌐 Sistema compatível com Vercel Serverless")
    app.run(debug=True, host='127.0.0.1', port=5000)

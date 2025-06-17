import re
import tldextract
import requests
import json
from flask import Flask, render_template_string, request, jsonify, render_template
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

# Lista de domínios legítimos (unificada)
DOMINIOS_LEGITIMOS = [
    "itau.com.br", "bradesco.com.br", "santander.com.br", "bancodobrasil.com.br", "caixa.gov.br",
    "mercadolivre.com.br", "google.com", "google.com.br", "facebook.com", "facebook.com.br",
    "microsoft.com", "instagram.com", "whatsapp.com", "github.com", "linkedin.com", "twitter.com",
    "x.com", "nubank.com.br", "picpay.com", "inter.co", "c6bank.com.br", "bancooriginal.com.br",
    "neon.com.br", "pagseguro.uol.com.br", "bmg.com.br", "sicredi.com.br", "sicoob.com.br",
    "btgpactual.com", "xp.com.br", "americanas.com.br", "submarino.com.br", "magazineluiza.com.br",
    "mercado_pago.com.br", "mercadopago.com.br", "shopee.com.br", "amazon.com", "amazon.com.br",
    "aliexpress.com", "casasbahia.com.br", "pontofrio.com.br", "kabum.com.br", "netshoes.com.br",
    "tiktok.com", "spotify.com", "telegram.org", "discord.com", "pinterest.com", "snapchat.com",
    "reddit.com", "zoom.us", "ifood.com.br", "uber.com", "99app.com", "airbnb.com", "hotmart.com",
    "sympla.com.br", "eventbrite.com", "canva.com", "apple.com", "icloud.com", "dropbox.com",
    "adobe.com", "wix.com", "wordpress.com", "notion.so", "openai.com", "gupy.com", "indeed.com"
]

# Variáveis globais para carregar uma vez
palavras_suspeitas_carregadas = []
urls_suspeitas_carregadas = []

carregado = False

@app.before_request
def carregar_dados():
    global carregado, palavras_suspeitas_carregadas, urls_suspeitas_carregadas
    if not carregado:
        carregado = True

    if not palavras_suspeitas_carregadas:
        palavras_suspeitas_carregadas = processar_palavras_suspeitas_arquivo()
        print(f"Palavras suspeitas carregadas: {len(palavras_suspeitas_carregadas)}")

    if not urls_suspeitas_carregadas:
        urls_suspeitas_carregadas = obter_urls_suspeitas_do_urlhaus()
        if not urls_suspeitas_carregadas:
            try:
                with open('urls_suspeitas.txt', 'r', encoding="utf-8") as f:
                    urls_suspeitas_carregadas = f.read().splitlines()
                print(f"URLs suspeitas carregadas do arquivo fallback: {len(urls_suspeitas_carregadas)}")
            except FileNotFoundError:
                print("Arquivo 'urls_suspeitas.txt' não encontrado, não carregou URLs suspeitas.")

@app.route('/')
def index():
    with open('index.html', 'r', encoding='utf-8') as f:
        page = f.read()
    return render_template_string(page)

@app.route('/analisar', methods=['POST'])
def analisar():
    mensagem = request.form.get('mensagem', '')
    if not mensagem.strip():
        return render_template('resultado.html', erro="Por favor, insira uma mensagem para análise.", suspeitas=[], dominios_suspeitos=[], mensagem="")

    suspeitas = analisar_mensagens(mensagem, palavras_suspeitas_carregadas)
    links = detectar_links(mensagem)
    dominios_suspeitos = verificar_urls_suspeitas(links, urls_suspeitas_carregadas, DOMINIOS_LEGITIMOS)

    return render_template('resultado.html', suspeitas=suspeitas, dominios_suspeitos=dominios_suspeitos, mensagem=mensagem, erro=None)

@app.route('/verificar', methods=['POST'])
def verificar_api():
    data = request.get_json()
    mensagem = data.get('mensagem', '') if data else ''

    if not mensagem:
        return jsonify({"erro": "Mensagem não fornecida"}), 400

    suspeitas = analisar_mensagens(mensagem, palavras_suspeitas_carregadas)
    links = detectar_links(mensagem)
    dominios_suspeitos = verificar_urls_suspeitas(links, urls_suspeitas_carregadas, DOMINIOS_LEGITIMOS)

    e_golpe = bool(suspeitas or dominios_suspeitos)

    resposta = {
        "e_golpe": e_golpe,
        "palavras_suspeitas": suspeitas,
        "dominios_suspeitos": dominios_suspeitos,
        "mensagem_original": mensagem
    }
    return jsonify(resposta)

@app.errorhandler(404)
def page_not_found(e):
    return "Página não encontrada", 404

@app.errorhandler(500)
def server_error(e):
    return "Erro interno do servidor", 500

# --- Funções auxiliares unificadas abaixo ---

def distancia_levenshtein(s1, s2):
    if len(s1) < len(s2):
        return distancia_levenshtein(s2, s1)
    if len(s2) == 0:
        return len(s1)
    linha_anterior = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        linha_atual = [i + 1]
        for j, c2 in enumerate(s2):
            insercoes = linha_anterior[j + 1] + 1
            delecoes = linha_atual[j] + 1
            substituicoes = linha_anterior[j] + (c1 != c2)
            linha_atual.append(min(insercoes, delecoes, substituicoes))
        linha_anterior = linha_atual
    return linha_anterior[-1]

def processar_palavras_suspeitas_arquivo():
    try:
        with open('phishing-keywords.txt', 'r', encoding="utf-8") as arquivo:
            palavras = arquivo.read().splitlines()
        return palavras
    except FileNotFoundError:
        print("Aviso: O arquivo 'phishing-keywords.txt' não foi encontrado.")
        return []

def obter_urls_suspeitas_do_urlhaus():
    url = "https://urlhaus-api.abuse.ch/v1/urls/recent/"
    headers = {"User-Agent": "PhishingDetector/1.0 (npmstartteste@gmail.com)"}

    try:
        print("Tentando obter URLs suspeitas do URLhaus...")
        response = requests.get(url, headers=headers, timeout=30)
        response.raise_for_status()
        data = response.json()
        urls = [item['url'] for item in data.get('urls', []) if 'url' in item]
        print(f"Obtidas {len(urls)} URLs suspeitas do URLhaus.")
        return urls
    except requests.exceptions.RequestException as e:
        print(f"Erro ao obter URLs do URLhaus: {e}")
        return []
    except json.JSONDecodeError:
        print("Erro de JSON na resposta do URLhaus.")
        return []

def analisar_mensagens(mensagem, palavras_suspeitas):
    mensagem = mensagem.lower()
    encontradas = []
    for palavra in palavras_suspeitas:
        if re.search(rf'\b{re.escape(palavra)}\b', mensagem):
            encontradas.append(palavra)
    return encontradas

def detectar_links(mensagem):
    padrao_url = r'https?://[\w\.-]+\.[a-zA-Z]{2,}(?:/[^\s]*)?|\bwww\.[\w\.-]+\.[a-zA-Z]{2,}(?:/[^\s]*)?'
    return re.findall(padrao_url, mensagem.lower())

def extrair_dominio_completo(link):
    extraido = tldextract.extract(link)
    partes = [p for p in [extraido.subdomain, extraido.domain, extraido.suffix] if p]
    return '.'.join(partes)

def verificar_urls_suspeitas(links, lista_suspeita, dominios_legitimos):
    dominios_suspeitos_encontrados = []
    lista_suspeita_set = set(lista_suspeita)
    dominios_legitimos_set = set(dominios_legitimos)

    for link in links:
        dominio_completo = extrair_dominio_completo(link)
        extraido = tldextract.extract(link)
        nome_dominio_atual = extraido.domain.lower()
        sufixo_atual = extraido.suffix.lower()

        # Se domínio completo está explicitamente na lista suspeita
        if dominio_completo in lista_suspeita_set:
            dominios_suspeitos_encontrados.append(dominio_completo)
            continue

        # Checar se domínio termina com algum domínio suspeito conhecido (exemplo subdomínio malicioso)
        for suspeito_base in lista_suspeita_set:
            if dominio_completo.endswith(suspeito_base) and len(dominio_completo) > len(suspeito_base):
                dominios_suspeitos_encontrados.append(dominio_completo)
                break

        # Checar domínios muito parecidos com domínios legítimos usando Levenshtein e outras heurísticas
        for legit_dominio_completo in dominios_legitimos_set:
            legit_ext = tldextract.extract(legit_dominio_completo)
            nome_dominio_legitimo = legit_ext.domain.lower()
            sufixo_legitimo = legit_ext.suffix.lower()

            # Só comparar domínios com mesmo sufixo (ex: ambos .com, .com.br)
            if sufixo_atual != sufixo_legitimo:
                continue

            distancia = distancia_levenshtein(nome_dominio_atual, nome_dominio_legitimo)

            # Ajuste: considerar como suspeito se distância 1 ou 2 e nomes razoavelmente curtos (evita falsos positivos)
            if distancia == 1 or (distancia == 2 and len(nome_dominio_legitimo) >= 5):
                dominios_suspeitos_encontrados.append(dominio_completo)
                break

            # Detecta repetições estranhas de caracteres (exemplo "gooogle")
            for char in set(nome_dominio_atual):
                if nome_dominio_atual.count(char) > nome_dominio_legitimo.count(char) + 1:
                    dominios_suspeitos_encontrados.append(dominio_completo)
                    break

            # Se nome do domínio contém nome legítimo mas com caracteres extras estranhos (ex: login-google)
            if nome_dominio_legitimo in nome_dominio_atual and nome_dominio_atual != nome_dominio_legitimo:
                if '-' in nome_dominio_atual or '_' in nome_dominio_atual:
                    dominios_suspeitos_encontrados.append(dominio_completo)
                    break

                # Se o domínio tem caracteres repetidos demais e tamanho próximo do legítimo
                if any(nome_dominio_atual.count(c) > 2 for c in set(nome_dominio_atual)) and \
                   abs(len(nome_dominio_atual) - len(nome_dominio_legitimo)) <= 2:
                    dominios_suspeitos_encontrados.append(dominio_completo)
                    break

                adicoes_phishing_comuns = ["login", "seguranca", "fatura", "atualiza", "verify", "secure", "bank", "premios", "rewards", "promo", "app", "online", "acesso", "cliente"]
                if any(add in nome_dominio_atual for add in adicoes_phishing_comuns):
                    dominios_suspeitos_encontrados.append(dominio_completo)
                    break

        # Subdomínio suspeito
        if extraido.subdomain and extraido.subdomain.lower() != 'www':
            palavras_chave_subdominio_suspeito = ["login", "seguranca", "fatura", "acesso", "confirmar", "atualizar", "premios", "ganho", "secure", "verify", "suporte", "app", "online", "portal"]
            if any(palavra in extraido.subdomain.lower() for palavra in palavras_chave_subdominio_suspeito):
                dominios_suspeitos_encontrados.append(dominio_completo)

    return list(set(dominios_suspeitos_encontrados))

if __name__ == '__main__':
    app.run(debug=True, port=5000)

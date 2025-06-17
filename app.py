from flask import Flask, request, jsonify
from flask_cors import CORS 
import re
import tldextract
import requests
import json
import main

from main import (
    analisar_mensagens,
    detectar_links,
    verificar_urls_suspeitas,
    processar_palavras_suspeitas_arquivo
)

DOMINIOS_LEGITIMOS = [
    "itau.com.br",
    "bradesco.com.br",
    "santander.com.br",
    "bancodobrasil.com.br",
    "caixa.gov.br",
    "mercadolivre.com.br",
    "google.com",
    "google.com.br",
    "facebook.com",
    "facebook.com.br",
    "microsoft.com",
    "instagram.com",
    "whatsapp.com"
]

app = Flask(__name__)
CORS(app) 

palavras_suspeitas_carregadas = []
urls_suspeitas_carregadas = []

# Carregar os dados uma vez quando a aplicação Flask inicia
@app.before_request
def carregar_dados():
    global palavras_suspeitas_carregadas, urls_suspeitas_carregadas
    if not palavras_suspeitas_carregadas: 
        print("A carregar palavras suspeitas...")
        palavras_suspeitas_carregadas = main.processar_palavras_suspeitas_arquivo()
    
    if not urls_suspeitas_carregadas: 
        print("A carregar URLs suspeitas da API ou fallback...")
        urls_suspeitas_carregadas = main.obter_urls_suspeitas_do_urlhaus()
        if not urls_suspeitas_carregadas:
            print("Tentando carregar URLs suspeitas de 'urls_suspeitas.txt' como fallback.")
            try:
                with open('urls_suspeitas.txt', 'r', encoding="utf-8") as f:
                    urls_suspeitas_carregadas = f.read().splitlines()
                if urls_suspeitas_carregadas:
                    print(f"Carregadas {len(urls_suspeitas_carregadas)} URLs suspeitas de 'urls_suspeitas.txt'.")
                else:
                    print("O arquivo 'urls_suspeitas.txt' está vazio ou não pôde ser lido.")
            except FileNotFoundError:
                print("Erro: O arquivo 'urls_suspeitas.txt' não foi encontrado. Nenhuma URL suspeita será verificada via arquivo.")
                urls_suspeitas_carregadas = []

    if not palavras_suspeitas_carregadas and not urls_suspeitas_carregadas:
        print("AVISO: Nenhuma lista de palavras ou URLs suspeitas foi carregada. A detecção pode não ser eficaz.")


@app.route('/verificar', methods=['POST'])
def verificar_mensagem():
    data = request.get_json()
    mensagem = data.get('mensagem', '')

    if not mensagem:
        return jsonify({"erro": "Mensagem não fornecida"}), 400

    suspeitas = main.analisar_mensagens(mensagem, palavras_suspeitas_carregadas)
    links = main.detectar_links(mensagem)
    dominios_suspeitos = main.verificar_urls_suspeitas(links, urls_suspeitas_carregadas, DOMINIOS_LEGITIMOS)

    e_golpe = bool(suspeitas or dominios_suspeitos)

    resposta = {
        "e_golpe": e_golpe,
        "palavras_suspeitas": suspeitas,
        "dominios_suspeitos": dominios_suspeitos,
        "mensagem_original": mensagem
    }
    return jsonify(resposta)

@app.route('/')
def index():
    return "API do Detector de Phishing está a funcionar!"

if __name__ == '__main__':
    app.run(debug=True, port=5000) 
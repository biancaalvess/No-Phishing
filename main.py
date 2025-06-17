import re
import tldextract
import requests
import json
import time

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
        print("Aviso: O arquivo 'phishing-keywords.txt' não foi encontrado. As palavras suspeitas não serão verificadas via arquivo.")
        return []

def obter_urls_suspeitas_do_urlhaus():
    url = "https://urlhaus.abuse.ch/downloads/json/"
    headers = {"User-Agent": "PhishingDetector/1.0 (npmstartteste@gmail.com)"}

    try:
        print("Tentando obter URLs suspeitas do URLhaus...")
        response = requests.get(url, headers=headers, timeout=30)
        response.raise_for_status()

        data = response.json()
        urls = [item['url'] for item in data['data'] if 'url' in item]

        print(f"Obtidas {len(urls)} URLs suspeitas do URLhaus.")
        return urls
    except requests.exceptions.Timeout:
        print("Erro: Tempo limite excedido ao conectar com a API do URLhaus. Verifique sua conexão.")
        return []
    except requests.exceptions.RequestException as e:
        print(f"Erro de requisição ao buscar URLs do URLhaus: {e}")
        print("Verifique sua conexão com a internet ou se o serviço URLhaus está disponível.")
        return []
    except json.JSONDecodeError as e:
        print(f"Erro de decodificação JSON da API do URLhaus: {e}")
        print(f"Conteúdo recebido (primeiros 500 chars): '{response.text[:500]}'")
        print("Isso geralmente indica que a API não retornou JSON válido.")
        return []
    except KeyError:
        print("Erro: Estrutura JSON inesperada da API do URLhaus. A chave 'data' não foi encontrada.")
        return []

def analisar_mensagens(mensagem, palavras_suspeitas):
    mensagem = mensagem.lower()
    encontradas = []

    for palavra in palavras_suspeitas:
        if re.search(rf'\b{re.escape(palavra)}\b', mensagem):
            encontradas.append(palavra)
    return encontradas

def detectar_links(mensagem):
    padrao_url = r'(?:https?://|www\.)?[\w\.-]+\.[a-zA-Z]{2,}(?:/[^\s]*)?'
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
        nome_dominio_atual = extraido.domain
        sufixo_atual = extraido.suffix

        # 1. Verificação na lista de URLs suspeitas (do URLhaus ou arquivo)
        if dominio_completo in lista_suspeita_set:
            dominios_suspeitos_encontrados.append(dominio_completo)
            continue

        # 2. Verificação de subdomínios maliciosos (e.g., login.malicioso.com)
        for suspeito_base in lista_suspeita_set:
            if dominio_completo.endswith(suspeito_base) and len(dominio_completo) > len(suspeito_base):
                dominios_suspeitos_encontrados.append(dominio_completo)
                break

        # 3. Verificação de typosquatting e subdomínios suspeitos
        for legit_dominio_completo in dominios_legitimos_set:
            legit_ext = tldextract.extract(legit_dominio_completo)
            nome_dominio_legitimo = legit_ext.domain
            sufixo_legitimo = legit_ext.suffix

            distancia = distancia_levenshtein(nome_dominio_atual, nome_dominio_legitimo)
            if distancia > 0 and (distancia == 1 or (distancia == 2 and len(nome_dominio_legitimo) > 6)):
                dominios_suspeitos_encontrados.append(dominio_completo)
                break
            
            if any(nome_dominio_atual.count(char) > nome_dominio_legitimo.count(char) for char in set(nome_dominio_atual)):
                dominios_suspeitos_encontrados.append(dominio_completo)
                break

                # Detecção de Typosquatting por Adição/Substituição de Caracteres e Hífen/Underscore
            if nome_dominio_legitimo in nome_dominio_atual and nome_dominio_atual != nome_dominio_legitimo:
                    if '-' in nome_dominio_atual or '_' in nome_dominio_atual:
                        dominios_suspeitos_encontrados.append(dominio_completo)
                        break
                    if any(nome_dominio_atual.count(char) > 2 for char in set(nome_dominio_atual)) and \
                       abs(len(nome_dominio_atual) - len(nome_dominio_legitimo)) <= 2:
                        dominios_suspeitos_encontrados.append(dominio_completo)
                        break
                    adicoes_phishing_comuns = ["login", "seguranca", "fatura", "atualiza", "verify", "secure", "bank", "premios", "rewards", "promo", "app", "online", "acesso", "cliente"]
                    if any(add in nome_dominio_atual for add in adicoes_phishing_comuns):
                        dominios_suspeitos_encontrados.append(dominio_completo)
                        break

        # 4. Detecção de Subdomínios Suspeitos (mesmo que o domínio principal não seja um typosquatting)
        if extraido.subdomain and extraido.subdomain.lower() != 'www':
            palavras_chave_subdominio_suspeito = ["login", "seguranca", "fatura", "acesso", "confirmar", "atualizar", "premios", "ganho", "secure", "verify", "suporte", "app", "online", "portal"]
            if any(palavra in extraido.subdomain for palavra in palavras_chave_subdominio_suspeito):
                dominios_suspeitos_encontrados.append(dominio_completo)

    return list(set(dominios_suspeitos_encontrados))

if __name__ == '__main__':
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
        "whatsapp.com",
        "github.com",
        "linkedin.com",
        "twitter.com",
        "x.com",
        "nubank.com.br",
        "picpay.com",
        "inter.co",
        "c6bank.com.br",
        "bancooriginal.com.br",
        "neon.com.br",
        "pagseguro.uol.com.br",
        "bmg.com.br",
        "sicredi.com.br",
        "sicoob.com.br",
        "btgpactual.com",
        "xp.com.br",
        "americanas.com.br",
        "submarino.com.br",
        "magazineluiza.com.br",
        "mercado_pago.com.br",
        "mercadopago.com.br",
        "shopee.com.br",
        "amazon.com",
        "amazon.com.br",
        "aliexpress.com",
        "casasbahia.com.br",
        "pontofrio.com.br",
        "kabum.com.br",
        "netshoes.com.br",
        "tiktok.com",
        "spotify.com",
        "telegram.org",
        "discord.com",
        "pinterest.com",
        "snapchat.com",
        "reddit.com",
        "zoom.us",
        "ifood.com.br",
        "uber.com",
        "99app.com",
        "airbnb.com",
        "hotmart.com",
        "sympla.com.br",
        "eventbrite.com",
        "canva.com",
        "apple.com",
        "icloud.com",
        "dropbox.com",
        "adobe.com",
        "wix.com",
        "wordpress.com",
        "notion.so",
        "openai.com",
        "gupy.com",
        "indeed.com"
    ]

    palavras_suspeitas = processar_palavras_suspeitas_arquivo()
    urls_suspeitas = obter_urls_suspeitas_do_urlhaus()

    if not urls_suspeitas:
        print("\nNão foi possível carregar URLs suspeitas da API do URLhaus. Tentando carregar de 'urls_suspeitas.txt' como fallback.")
        try:
            with open('urls_suspeitas.txt', 'r', encoding="utf-8") as f:
                urls_suspeitas = f.read().splitlines()
            if urls_suspeitas:
                print(f"Carregadas {len(urls_suspeitas)} URLs suspeitas de 'urls_suspeitas.txt'.")
            else:
                print("O arquivo 'urls_suspeitas.txt' está vazio ou não pôde ser lido. A verificação de URLs será limitada.")
        except FileNotFoundError:
            print("Erro: O arquivo 'urls_suspeitas.txt' não foi encontrado. Nenhuma URL suspeita será verificada via arquivo.")
            urls_suspeitas = []

    if not palavras_suspeitas and not urls_suspeitas:
        print("\nNão foi possível carregar nenhuma lista de palavras ou URLs suspeitas. O programa não pode verificar efetivamente.")
        print("Certifique-se de ter 'phishing-keywords.txt' e/ou que a conexão com URLhaus esteja a funcionar.")
    else:
        print("\n--- Analisador de Phishing ---")
        print("Digite ou cole a mensagem para ser verificada (para sair, digite 'sair'):")

        while True:
            mensagem = input("> ")
            if mensagem.lower() == 'sair':
                break

            suspeitas = analisar_mensagens(mensagem, palavras_suspeitas)
            links = detectar_links(mensagem)
            dominios_suspeitos_encontrados = verificar_urls_suspeitas(links, urls_suspeitas, DOMINIOS_LEGITIMOS)

            if suspeitas or dominios_suspeitos_encontrados:
                print("\n---")
                print("❗ **ALERTA: Possível golpe detetado!**")
                print("---")
                if suspeitas:
                    print("Palavras suspeitas encontradas:")
                    for palavra in suspeitas:
                        print(f" - **{palavra}**")
                if dominios_suspeitos_encontrados:
                    print("\nDomínios suspeitos encontrados:")
                    for dominio in dominios_suspeitos_encontrados:
                        print(f" - **{dominio}**")
            else:
                print("\n---")
                print("✅ Nenhum indício forte de golpe encontrado nesta mensagem. Mantenha-se atento!")
                print("---")
            print("\nDigite outra mensagem ou 'sair' para encerrar:")
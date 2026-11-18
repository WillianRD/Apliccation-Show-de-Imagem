"""Sistema unificado: rastreio de cargas (SSW) + consulta de CNPJ + dashboard do Mercado Livre.

Páginas:
  /            -> menu, rastreio por NF-e e consulta de CNPJ
  /dashboard   -> dashboard do Mercado Livre

APIs:
  - POST /api/rastrear-publico  -> rastreamento público do SSW (CNPJ + NF-e)
  - POST /api/consultar-cnpj    -> dados cadastrais via publica.cnpj.ws
  - /api/ml/*, /ml/*            -> Mercado Livre (ver ml.py)

Uso (PowerShell):
    pip install -r requirements.txt
    copy .env.example .env      # e preencha ML_APP_ID e ML_SECRET
    python app.py
    # abra http://127.0.0.1:5000
"""
import os
import re
import time

import requests
from bs4 import BeautifulSoup
from flask import Flask, Response, request

import ml  # carrega o .env e define o blueprint do Mercado Livre
import jamef  # login e rastreio da JAMEF

BASE = os.path.dirname(os.path.abspath(__file__))
SSW_PUBLICO_URL = "https://ssw.inf.br/app/tracking/{cnpj}/{codigo}/"
CNPJ_WS_URL = "https://publica.cnpj.ws/cnpj/{cnpj}"
HEADERS = {"User-Agent": "Mozilla/5.0 (rastreio-ssw local)"}

app = Flask(__name__)
# Usado só para o "state" do login OAuth. Se não definir FLASK_SECRET, vale até reiniciar o app.
app.secret_key = os.environ.get("FLASK_SECRET") or os.urandom(24)
app.register_blueprint(ml.bp)
app.register_blueprint(jamef.bp)


def _pagina(nome):
    with open(os.path.join(BASE, nome), encoding="utf-8") as f:
        return Response(f.read(), mimetype="text/html")


@app.get("/")
def index():
    return _pagina("rastreio-ssw.html")


@app.get("/dashboard")
def dashboard():
    return _pagina("dashboard.html")


# ---------- Rastreamento público (CNPJ + NF-e) ----------
DATA_INICIO = re.compile(r"^\d{2}/\d{2}/\d{2,4}")


def _texto(el):
    return re.sub(r"\s+", " ", el.get_text(" ", strip=True)).strip()


def _decodificar(conteudo):
    try:
        return conteudo.decode("utf-8")
    except UnicodeDecodeError:
        return conteudo.decode("latin-1")


def extrair_eventos(html):
    """Lê as linhas de evento: 3 colunas (data/hora, unidade, situação).

    Considera qualquer linha cuja primeira coluna comece com uma data, o que
    dispensa depender de linhas pares/ímpares ou de linhas separadoras.
    """
    soup = BeautifulSoup(html, "html.parser")
    eventos = []
    for tr in soup.find_all("tr"):
        tds = tr.find_all("td", recursive=False)
        if len(tds) != 3:
            continue
        data_hora = _texto(tds[0])
        if not DATA_INICIO.match(data_hora):
            continue

        partes = re.split(r"<br\s*/?>", tds[1].decode_contents(), flags=re.I)
        partes = [_texto(BeautifulSoup(p, "html.parser")) for p in partes]
        partes = [p for p in partes if p]
        cidade = partes[0] if partes else ""
        unidade = partes[1] if len(partes) > 1 else ""

        negrito = tds[2].find("b")
        detalhe = tds[2].select_one(".tdb")
        titulo = _texto(negrito) if negrito else ""
        if detalhe:
            descricao = _texto(detalhe)
        else:
            # sem a classe .tdb: descrição é o texto da coluna sem o título
            completo = _texto(tds[2])
            descricao = completo[len(titulo):].strip() if completo.startswith(titulo) else completo
        if not (cidade or unidade) or not (titulo or descricao):
            continue
        eventos.append(
            {
                "data_hora": data_hora,
                "cidade": cidade,
                "unidade": unidade,
                "status": titulo,
                "descricao": descricao,
            }
        )
    return eventos


def extrair_carga(html):
    """Dados do cabeçalho e do rodapé (melhor esforço, só o que for encontrado)."""
    texto = _texto(BeautifulSoup(html, "html.parser"))
    padroes = {
        "remetente": r"Remetente:\s*(.+?)\s+Destinat\S+rio:",
        "destinatario": r"Destinat\S+rio:\s*(.+?)\s+N Coleta:",
        "coleta": r"N Coleta:\s*(.*?)\s+N Fiscal:",
        "nota_fiscal": r"N Fiscal:\s*(.*?)\s+N Pedido:",
        "pedido": r"N Pedido:\s*(.*?)\s+Data/Hora",
        "transportadora": r"mercadoria:\s*(.+?)\s+E-mail:",
        "email": r"E-mail:\s*(\S+)",
        "telefone": r"Telefone:\s*(\(?\d[\d\s)\-]*\d)",
    }
    carga = {}
    for campo, padrao in padroes.items():
        m = re.search(padrao, texto)
        if m and m.group(1).strip():
            carga[campo] = m.group(1).strip()
    return carga


@app.post("/api/rastrear-publico")
def rastrear_publico():
    dados = request.get_json(silent=True) or {}
    cnpj = re.sub(r"\D", "", str(dados.get("cnpj", "")))
    codigo = re.sub(r"\D", "", str(dados.get("chave_nfe") or dados.get("nro_nf") or ""))
    if len(cnpj) != 14 or not codigo:
        return {"sucesso": False, "mensagem": "Informe CNPJ (14 dígitos) e NF-e."}, 400

    url = SSW_PUBLICO_URL.format(cnpj=cnpj, codigo=codigo)
    try:
        r = requests.get(url, headers=HEADERS, timeout=20)
    except requests.RequestException as e:
        return {"sucesso": False, "mensagem": "Falha ao consultar o SSW", "detalhe": str(e)}, 502
    if r.status_code == 404:
        return {"sucesso": False, "mensagem": "Documento não localizado", "url": url}
    if r.status_code != 200:
        return {
            "sucesso": False,
            "mensagem": "O SSW respondeu HTTP %d" % r.status_code,
            "url": url,
        }, 502

    html = _decodificar(r.content)
    eventos = extrair_eventos(html)
    if not eventos:
        trecho = _texto(BeautifulSoup(html, "html.parser"))[:300]
        return {
            "sucesso": False,
            "mensagem": "Nenhum evento de rastreamento encontrado",
            "url": url,
            "trecho": trecho,
        }
    resposta = {"sucesso": True, "url": url, "eventos": eventos}
    carga = extrair_carga(html)
    if carga:
        resposta["carga"] = carga
    return resposta


# ---------- Consulta de CNPJ (publica.cnpj.ws) ----------
# A API pública permite ~3 consultas por minuto. O cache evita gastar a cota
# quando o mesmo CNPJ é consultado de novo em pouco tempo.
CNPJ_CACHE = {}
CNPJ_CACHE_TTL = 600  # segundos


HEADERS_CNPJ = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                  "(KHTML, like Gecko) Chrome/124.0 Safari/537.36",
    "Accept": "application/json",
}


def _buscar_cnpj(cnpj):
    cnpj = re.sub(r"\D", "", str(cnpj or ""))
    if len(cnpj) != 14:
        return {"mensagem": "Informe um CNPJ com 14 dígitos.", "recebido": cnpj}, 400

    agora = time.time()
    em_cache = CNPJ_CACHE.get(cnpj)
    if em_cache and agora - em_cache[0] < CNPJ_CACHE_TTL:
        return em_cache[1]

    url = CNPJ_WS_URL.format(cnpj=cnpj)
    try:
        r = requests.get(url, headers=HEADERS_CNPJ, timeout=20)
    except requests.RequestException as e:
        return {"mensagem": "Falha ao consultar a CNPJ.ws", "detalhe": str(e), "url": url}, 502

    if r.status_code == 404:
        return {
            "mensagem": "A CNPJ.ws respondeu 404 (CNPJ não encontrado).",
            "url": url,
            "resposta": r.text[:300],
        }, 404
    if r.status_code == 429:
        return {
            "mensagem": "Limite da API atingido (3 consultas por minuto). Aguarde um pouco e tente de novo.",
            "url": url,
        }, 429
    if r.status_code != 200:
        return {
            "mensagem": "A CNPJ.ws respondeu HTTP %d" % r.status_code,
            "url": url,
            "resposta": r.text[:300],
        }, 502

    try:
        resultado = r.json()
    except ValueError:
        return {"mensagem": "Resposta inválida da CNPJ.ws.", "url": url}, 502

    CNPJ_CACHE[cnpj] = (agora, resultado)
    return resultado


@app.post("/api/consultar-cnpj")
def consultar_cnpj():
    dados = request.get_json(silent=True) or {}
    return _buscar_cnpj(dados.get("cnpj"))


@app.get("/api/consultar-cnpj/<cnpj>")
def consultar_cnpj_get(cnpj):
    """Atalho para testar no navegador: /api/consultar-cnpj/04340772000123"""
    return _buscar_cnpj(cnpj)


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000)
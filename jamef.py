"""Integração com a API da JAMEF: login (token JWT) e rastreio por NF.

Regras da JAMEF que este módulo respeita:
- o token vale 1 hora e é enviado em "Authorization: Bearer <token>";
- o login tem limite de 1 requisição por minuto por IP (erro 429 se passar).
  Por isso o token fica guardado no ml.db e é reutilizado, inclusive depois de
  reiniciar o app. O login só é refeito quando o token vence.

Configuração (arquivo .env, ao lado do app.py):
    JAMEF_USUARIO=...            # e-mail cadastrado no Portal Developers (campo "username")
    JAMEF_SENHA=...              # senha do portal (campo "password")
    JAMEF_AMBIENTE=homologacao   # ou producao (precisa de aprovação no portal)

Ajustes que dependem da documentação da JAMEF (todos opcionais):
    JAMEF_CAMPO_USUARIO=username           # nome do campo de usuário no corpo do /login
    JAMEF_CAMPO_SENHA=password             # nome do campo de senha no corpo do /login
    JAMEF_LOGIN_PATH=/auth/v1/login
    JAMEF_RASTREIO_METODO=GET
    JAMEF_RASTREIO_PATH=/consulta/v1/rastreamento     # padrão da documentação
    JAMEF_RASTREIO_QUERY=documentoRemetente={cnpj}&numeroNotaFiscal={nf}   # {nf} e {cnpj} são substituídos
    JAMEF_RASTREIO_BODY={"nf":"{nf}"}      # só para POST
"""
import base64
import json
import math
import os
import re
import threading
import time
from datetime import datetime, timezone
from urllib.parse import parse_qsl

import requests
from flask import Blueprint, jsonify, request

import ml

ml._carregar_env()

HOSTS = {"homologacao": "https://api-qa.jamef.com.br", "producao": "https://api.jamef.com.br"}
INTERVALO_LOGIN = 60  # segundos: limite da JAMEF (1 login por minuto por IP)

_lock = threading.Lock()
_lock_req = threading.Lock()
_ultima_req = [0.0]
INTERVALO_REQ = 2.1  # a API de rastreamento permite 1 requisição a cada 2 segundos
bp = Blueprint("jamef", __name__)


class JamefError(Exception):
    def __init__(self, mensagem, status=502):
        super().__init__(mensagem)
        self.mensagem = mensagem
        self.status = status


def _cfg():
    amb = (os.environ.get("JAMEF_AMBIENTE") or "homologacao").strip().lower()
    if amb not in HOSTS:
        amb = "homologacao"
    env = os.environ.get
    return {
        "ambiente": amb,
        "host": HOSTS[amb],
        "usuario": env("JAMEF_USUARIO", ""),
        "senha": env("JAMEF_SENHA", ""),
        "campo_usuario": env("JAMEF_CAMPO_USUARIO", "username"),
        "campo_senha": env("JAMEF_CAMPO_SENHA", "password"),
        "login_path": env("JAMEF_LOGIN_PATH", "/auth/v1/login"),
        "rastreio_metodo": (env("JAMEF_RASTREIO_METODO", "GET") or "GET").upper(),
        "rastreio_path": env("JAMEF_RASTREIO_PATH", "/consulta/v1/rastreamento"),
        "rastreio_query": env("JAMEF_RASTREIO_QUERY", "documentoRemetente={cnpj}&numeroNotaFiscal={nf}"),
        "rastreio_body": env("JAMEF_RASTREIO_BODY", ""),
    }


# ---------------------------------------------------------------- token guardado
def _con():
    con = ml._db()
    con.execute(
        "CREATE TABLE IF NOT EXISTS jamef_token ("
        "ambiente TEXT PRIMARY KEY, token TEXT, expira REAL, ultimo_login REAL)"
    )
    return con


def _ler(amb):
    con = _con()
    try:
        row = con.execute("SELECT * FROM jamef_token WHERE ambiente = ?", (amb,)).fetchone()
        return dict(row) if row else None
    finally:
        con.close()


def _gravar(amb, token, expira, ultimo_login):
    con = _con()
    try:
        con.execute(
            "INSERT OR REPLACE INTO jamef_token (ambiente, token, expira, ultimo_login) VALUES (?, ?, ?, ?)",
            (amb, token, expira, ultimo_login),
        )
        con.commit()
    finally:
        con.close()


def _invalidar(amb):
    t = _ler(amb)
    if t:
        _gravar(amb, t["token"], 0, t["ultimo_login"])


# ---------------------------------------------------------------- login
CHAVES_TOKEN = ("token", "access_token", "accesstoken", "jwt", "bearer", "id_token")


def _achar_token(d, nivel=0):
    """Procura o token na resposta, inclusive dentro de listas (a JAMEF devolve em dado[0].accessToken)."""
    if nivel > 4:
        return None
    if isinstance(d, dict):
        for k, v in d.items():
            if k.lower() in CHAVES_TOKEN and isinstance(v, str) and len(v) > 20:
                return v
        itens = list(d.values())
    elif isinstance(d, list):
        itens = d[:5]
    else:
        return None
    for v in itens:
        t = _achar_token(v, nivel + 1)
        if t:
            return t
    return None


def _achar_validade(d, nivel=0):
    """Segundos de validade informados pela JAMEF (expiresIn), se vierem na resposta."""
    if nivel > 4:
        return None
    if isinstance(d, dict):
        for k, v in d.items():
            if k.lower() in ("expiresin", "expires_in") and isinstance(v, (int, float)) and v > 0:
                return float(v)
        itens = list(d.values())
    elif isinstance(d, list):
        itens = d[:5]
    else:
        return None
    for v in itens:
        r = _achar_validade(v, nivel + 1)
        if r:
            return r
    return None


def _jwt_exp(token):
    try:
        p = token.split(".")[1]
        p += "=" * (-len(p) % 4)
        return float(json.loads(base64.urlsafe_b64decode(p)).get("exp"))
    except Exception:
        return None


def _mensagem(r):
    try:
        d = r.json()
    except ValueError:
        return (r.text or "")[:200]
    if isinstance(d, dict):
        partes = [str(d[k]) for k in ("mensagem", "message", "error", "erro", "detail") if d.get(k)][:1]
        erros = d.get("erros")
        if isinstance(erros, list):  # formato de erro da JAMEF: erros[].detalhes
            partes += [str(e["detalhes"]) for e in erros[:2] if isinstance(e, dict) and e.get("detalhes")]
        if partes:
            return " — ".join(partes)[:300]
    return str(d)[:300]


def _login():
    """Devolve um token válido, reaproveitando o guardado. Só faz login se vencido."""
    with _lock:
        c = _cfg()
        amb = c["ambiente"]
        t = _ler(amb)
        agora = time.time()
        if t and t["token"] and t["expira"] > agora + 30:
            return t["token"]
        if not (c["usuario"] and c["senha"]):
            raise JamefError("Configure JAMEF_USUARIO e JAMEF_SENHA no arquivo .env e reinicie o app.py.", 501)
        espera = INTERVALO_LOGIN - (agora - (t["ultimo_login"] if t else 0))
        if espera > 0:
            raise JamefError(
                "A JAMEF permite 1 login por minuto. Aguarde %d segundos e tente de novo." % math.ceil(espera), 429
            )
        # registra a tentativa antes de chamar: a JAMEF conta toda requisição de login, deu certo ou não
        _gravar(amb, t["token"] if t else None, 0, agora)
        try:
            r = requests.post(
                c["host"] + c["login_path"],
                json={c["campo_usuario"]: c["usuario"], c["campo_senha"]: c["senha"]},
                headers={"Accept": "application/json"},
                timeout=30,
            )
        except requests.RequestException as e:
            raise JamefError("Falha de rede ao autenticar na JAMEF: %s" % e, 502)
        if r.status_code == 429:
            raise JamefError("A JAMEF recusou o login por excesso de tentativas (429). Aguarde 1 minuto.", 429)
        if r.status_code not in (200, 201):
            if r.status_code in (401, 403):
                motivo, codigo = "usuário ou senha recusados", 401
            elif r.status_code in (400, 422):
                motivo = (
                    "a JAMEF não aceitou o corpo do login; confira os nomes dos campos no login-request "
                    "da documentação (JAMEF_CAMPO_USUARIO e JAMEF_CAMPO_SENHA no .env)"
                )
                codigo = 400
            else:
                motivo, codigo = "erro no servidor da JAMEF", 502
            raise JamefError(
                "Falha no login da JAMEF (HTTP %d, %s): %s" % (r.status_code, motivo, _mensagem(r)), codigo
            )
        try:
            dados = r.json()
        except ValueError:
            dados = None
        token = _achar_token(dados)
        if not token:
            raise JamefError("A JAMEF respondeu ao login, mas não encontrei o token na resposta. Confira o login-response na documentação.", 502)
        validade = _achar_validade(dados)
        if validade:
            expira = agora + min(validade, 3600) - 60
        else:
            expira = min(_jwt_exp(token) or (agora + 3600), agora + 3600) - 60
        _gravar(amb, token, expira, agora)
        return token


# ---------------------------------------------------------------- chamadas autenticadas
def _chamar(metodo, caminho, params=None, corpo=None):
    c = _cfg()
    r = None
    for tentativa in range(2):
        token = _login()
        with _lock_req:  # respeita 1 requisição a cada 2 segundos
            falta = INTERVALO_REQ - (time.time() - _ultima_req[0])
            if falta > 0:
                time.sleep(falta)
            _ultima_req[0] = time.time()
        try:
            r = requests.request(
                metodo,
                c["host"] + caminho,
                params=params,
                json=corpo,
                headers={"Authorization": "Bearer " + token, "Accept": "application/json"},
                timeout=30,
            )
        except requests.RequestException as e:
            raise JamefError("Falha de rede ao falar com a JAMEF: %s" % e, 502)
        if r.status_code == 401 and tentativa == 0:
            _invalidar(c["ambiente"])  # token recusado: força novo login (respeitando 1 por minuto)
            continue
        break
    if r.status_code == 404 or (r.status_code == 422 and "nenhum registro" in _mensagem(r).lower()):
        return None  # a JAMEF responde 422 "Nenhum registro foi localizado" quando a NF não existe
    if r.status_code == 429:
        raise JamefError("Limite de requisições da JAMEF atingido (429). Tente de novo em instantes.", 429)
    if r.status_code >= 400:
        raise JamefError("A JAMEF respondeu HTTP %d: %s" % (r.status_code, _mensagem(r)), 502 if r.status_code >= 500 else r.status_code)
    try:
        return r.json()
    except ValueError:
        raise JamefError("A JAMEF devolveu uma resposta que não é JSON.", 502)


# ---------------------------------------------------------------- rastreio
def _listas(d, nivel=0):
    """Todas as listas de objetos dentro da resposta."""
    saida = []
    if isinstance(d, list):
        if d and all(isinstance(x, dict) for x in d):
            saida.append(d)
        if nivel < 4:
            for x in d[:50]:
                saida += _listas(x, nivel + 1)
    elif isinstance(d, dict) and nivel < 4:
        for v in d.values():
            saida += _listas(v, nivel + 1)
    return saida


CAMPOS_DATA = ("data", "date", "dt", "hora", "time", "hr")


def _chave(d, padroes, excluir=()):
    """Valor do primeiro campo cujo nome contém um dos padrões (na ordem dos padrões)."""
    for p in padroes:
        for k, v in d.items():
            kl = str(k).lower()
            if p in kl and not any(x in kl for x in excluir) and isinstance(v, (str, int, float)) and str(v).strip():
                return str(v).strip()
    return ""


def _ts(texto):
    t = (texto or "").strip().replace("Z", "+00:00")
    for f in ("%d/%m/%Y %H:%M:%S", "%d/%m/%Y %H:%M", "%d/%m/%Y", "%d/%m/%y %H:%M"):
        try:
            return datetime.strptime(t, f).replace(tzinfo=timezone.utc).timestamp()
        except ValueError:
            pass
    try:
        d = datetime.fromisoformat(t)
        return (d if d.tzinfo else d.replace(tzinfo=timezone.utc)).timestamp()
    except ValueError:
        return None


def _normalizar(dados):
    """Procura a lista de ocorrências na resposta e converte para o formato do SSW.

    Reconhece os campos pelo nome (data, ocorrência/status, cidade/unidade). Se a
    JAMEF usar nomes muito diferentes, devolve lista vazia e a mensagem pede ajuste."""
    melhor, pontos = None, 0
    for lst in _listas(dados):
        p = sum(
            1 for e in lst
            if _chave(e, ("data", "date", "dt"))
            and _chave(e, ("status", "situac", "ocorr", "evento", "descr"), CAMPOS_DATA)
        )
        if p > pontos:
            melhor, pontos = lst, p
    eventos = []
    for e in melhor or []:
        data = _chave(e, ("data", "date", "dt"))
        hora = _chave(e, ("hora", "time", "hr"))
        if hora and hora not in data:
            data = (data + " " + hora).strip()
        status = _chave(e, ("status", "situac", "ocorr", "evento", "descr"), CAMPOS_DATA)
        descricao = _chave(e, ("obs", "detalhe", "mensagem", "descr"), CAMPOS_DATA)
        if descricao == status:
            descricao = ""
        eventos.append(
            {
                "data_hora": data,
                "cidade": _chave(e, ("cidade", "municipio", "local")),
                "unidade": _chave(e, ("unidade", "filial", "terminal")),
                "status": status,
                "descricao": descricao,
            }
        )
    tempos = [_ts(e["data_hora"]) for e in eventos]
    if eventos and all(t is not None for t in tempos):
        eventos = [e for _, e in sorted(zip(tempos, eventos), key=lambda x: x[0])]  # mais antigo primeiro, como no SSW
    return eventos


def _fmt_data(v):
    """2024-05-13T22:53:00 -> 13/05/2024 22:53 (se não der, devolve como veio)."""
    v = str(v or "")
    try:
        return datetime.fromisoformat(v).strftime("%d/%m/%Y %H:%M")
    except ValueError:
        return v


def _local(d):
    if not isinstance(d, dict):
        return ""
    cid, uf = str(d.get("cidade") or "").strip(), str(d.get("uf") or "").strip()
    return "%s/%s" % (cid, uf) if cid and uf else cid or uf


def _normalizar_jamef(dados, nf):
    """Formato documentado: dado[].rastreamento[].eventosRastreio[]. Devolve (eventos, carga) ou None."""
    if not isinstance(dados, dict) or not isinstance(dados.get("dado"), list):
        return None
    cargas = [r for it in dados["dado"] if isinstance(it, dict) for r in (it.get("rastreamento") or []) if isinstance(r, dict)]
    if not cargas:
        return None
    nf_n = nf.lstrip("0")
    carga = next((r for r in cargas if str((r.get("notaFiscal") or {}).get("numero", "")).lstrip("0") == nf_n), cargas[0])
    eventos = []
    for e in carga.get("eventosRastreio") or []:
        if not isinstance(e, dict):
            continue
        dest = _local(e.get("localDestino"))
        eventos.append({
            "data_hora": _fmt_data(e.get("data")),
            "cidade": _local(e.get("localOrigem")),
            "unidade": "",
            "status": str(e.get("status") or ""),
            "descricao": ("Destino: " + dest) if dest and dest != _local(e.get("localOrigem")) else "",
        })
    tempos = [_ts(e["data_hora"]) for e in eventos]
    if eventos and all(t is not None for t in tempos):
        eventos = [e for _, e in sorted(zip(tempos, eventos), key=lambda x: x[0])]
    rem, des = carga.get("remetente") or {}, carga.get("destinatario") or {}
    nfd, fr, ct = carga.get("notaFiscal") or {}, carga.get("frete") or {}, carga.get("conhecimento") or {}
    info = {
        "transportadora": "JAMEF",
        "remetente": rem.get("nome"),
        "destinatario": ("%s — %s" % (des.get("nome"), _local(des))) if des.get("nome") else None,
        "nota_fiscal": nfd.get("numero"),
        "pedido": nfd.get("pedido"),
        "coleta": ct.get("numero"),
        "previsao_entrega": fr.get("previsaoEntrega"),
        "comprovante_entrega": fr.get("urlComprovanteEntrega"),
    }
    return eventos, {k: str(v) for k, v in info.items() if v}


def _preencher(texto, nf, cnpj):
    return texto.replace("{nf}", nf).replace("{cnpj}", cnpj)


def rastrear(nf, cnpj="", debug=False):
    c = _cfg()
    if not c["rastreio_path"]:
        raise JamefError("Falta configurar JAMEF_RASTREIO_PATH no .env (caminho do rastreio na documentação da JAMEF).", 501)
    nf, cnpj = re.sub(r"\D", "", str(nf or "")), re.sub(r"\D", "", str(cnpj or ""))
    if not nf:
        raise JamefError("Informe o número da NF.", 400)
    if not cnpj and "{cnpj}" in c["rastreio_query"]:
        raise JamefError("Informe o CNPJ do remetente (a JAMEF exige um documento além da NF).", 400)
    params = dict(parse_qsl(_preencher(c["rastreio_query"], nf, cnpj))) if c["rastreio_query"] else None
    corpo = None
    if c["rastreio_body"]:
        try:
            corpo = json.loads(_preencher(c["rastreio_body"], nf, cnpj))
        except ValueError:
            raise JamefError("JAMEF_RASTREIO_BODY no .env não é um JSON válido.", 500)
    dados = _chamar(c["rastreio_metodo"], _preencher(c["rastreio_path"], nf, cnpj), params, corpo)
    if dados is None:
        return {"sucesso": False, "mensagem": "Documento não localizado na JAMEF"}
    esp = _normalizar_jamef(dados, nf)
    if esp and esp[0]:
        resp = {"sucesso": True, "eventos": esp[0], "carga": esp[1]}
        if debug:
            resp["bruto"] = dados
        return resp
    eventos = _normalizar(dados)  # plano B: formato diferente do documentado
    if not eventos:
        resp = {"sucesso": False, "mensagem": "A JAMEF respondeu, mas não encontrei ocorrências no formato esperado."}
        if debug:
            resp["bruto"] = dados
        return resp
    resp = {"sucesso": True, "eventos": eventos, "carga": {"transportadora": "JAMEF"}}
    if debug:
        resp["bruto"] = dados
    return resp


# ---------------------------------------------------------------- rotas
@bp.errorhandler(JamefError)
def _erro(e):
    return jsonify({"sucesso": False, "mensagem": e.mensagem}), e.status


@bp.get("/api/jamef/status")
def api_status():
    c = _cfg()
    t = _ler(c["ambiente"])
    agora = time.time()
    return jsonify(
        {
            "configurado": bool(c["usuario"] and c["senha"]),
            "rastreio_configurado": bool(c["rastreio_path"]),
            "ambiente": c["ambiente"],
            "token_valido": bool(t and t["token"] and t["expira"] > agora + 30),
            "proximo_login_em": max(0, math.ceil(INTERVALO_LOGIN - (agora - t["ultimo_login"]))) if t else 0,
        }
    )


@bp.post("/api/jamef/login-teste")
def api_login_teste():
    """Faz (ou reaproveita) o login e confirma que funcionou. Nunca devolve o token."""
    c = _cfg()
    _login()
    t = _ler(c["ambiente"])
    return jsonify({"ok": True, "ambiente": c["ambiente"], "expira_em": int(t["expira"])})


@bp.post("/api/jamef/rastrear")
def api_rastrear():
    d = request.get_json(silent=True) or {}
    return jsonify(rastrear(d.get("nf") or d.get("nro_nf"), d.get("cnpj"), request.args.get("debug") == "1"))
"""Integração com a API do Mercado Livre.

- OAuth 2.0 (login, callback, renovação automática do token)
- Consultas: anúncios, pedidos, visitas, perguntas e reputação
- Cache em SQLite (ml.db) para não estourar o limite de requisições

Configuração (arquivo .env ao lado deste):
    ML_APP_ID=...
    ML_SECRET=...
    ML_REDIRECT_URI=http://127.0.0.1:5000/ml/callback
"""
import base64
import hashlib
import json
import os
import re
import secrets
import sqlite3
import threading
import time
from datetime import datetime, timedelta, timezone

import requests
from flask import Blueprint, jsonify, redirect, request, session

BASE = os.path.dirname(os.path.abspath(__file__))


def _carregar_env():
    """Lê o .env sem depender de python-dotenv."""
    caminho = os.path.join(BASE, ".env")
    if not os.path.exists(caminho):
        return
    with open(caminho, encoding="utf-8") as f:
        for linha in f:
            linha = linha.strip()
            if not linha or linha.startswith("#") or "=" not in linha:
                continue
            chave, valor = linha.split("=", 1)
            os.environ.setdefault(chave.strip(), valor.strip().strip('"').strip("'"))


_carregar_env()

APP_ID = os.environ.get("ML_APP_ID", "")
SECRET = os.environ.get("ML_SECRET", "")
REDIRECT_URI = os.environ.get("ML_REDIRECT_URI", "http://127.0.0.1:5000/ml/callback")
AUTH_URL = os.environ.get("ML_AUTH_URL", "https://auth.mercadolivre.com.br/authorization")
API = "https://api.mercadolibre.com"
DB_PATH = os.path.join(BASE, "ml.db")

TZ = timezone(timedelta(hours=-3))  # horário de Brasília
TTL_CURTO = 300    # 5 min: resumo, pedidos, perguntas
TTL_LONGO = 600    # 10 min: lista de anúncios (é a consulta mais pesada)
STATUS_VALIDOS = {"active", "paused", "closed"}

_lock = threading.Lock()
bp = Blueprint("ml", __name__)


class MLError(Exception):
    def __init__(self, mensagem, status=502):
        super().__init__(mensagem)
        self.mensagem = mensagem
        self.status = status


# ---------------------------------------------------------------- banco
def _db():
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    con.execute(
        "CREATE TABLE IF NOT EXISTS token ("
        "id INTEGER PRIMARY KEY CHECK (id = 1), access_token TEXT, "
        "refresh_token TEXT, expires_at REAL, user_id INTEGER)"
    )
    con.execute("CREATE TABLE IF NOT EXISTS cache (chave TEXT PRIMARY KEY, ts REAL, dados TEXT)")
    return con


def _ler_token():
    con = _db()
    try:
        row = con.execute("SELECT * FROM token WHERE id = 1").fetchone()
        return dict(row) if row else None
    finally:
        con.close()


def _salvar_token(resp, user_id_antigo=None):
    dados = {
        "access_token": resp["access_token"],
        "refresh_token": resp["refresh_token"],  # o refresh token é de uso único: salvar sempre o novo
        "expires_at": time.time() + int(resp.get("expires_in", 21600)) - 60,
        "user_id": resp.get("user_id") or user_id_antigo,
    }
    con = _db()
    try:
        con.execute(
            "INSERT OR REPLACE INTO token (id, access_token, refresh_token, expires_at, user_id) "
            "VALUES (1, :access_token, :refresh_token, :expires_at, :user_id)",
            dados,
        )
        con.commit()
    finally:
        con.close()
    return dados


def _limpar_tudo():
    con = _db()
    try:
        con.execute("DELETE FROM token")
        con.execute("DELETE FROM cache")
        con.commit()
    finally:
        con.close()


# ---------------------------------------------------------------- OAuth
def _pedir_token(payload):
    try:
        r = requests.post(
            API + "/oauth/token",
            data=payload,
            headers={"Accept": "application/json", "Content-Type": "application/x-www-form-urlencoded"},
            timeout=30,
        )
    except requests.RequestException as e:
        raise MLError("Falha de rede ao autenticar no Mercado Livre: %s" % e, 502)
    if r.status_code != 200:
        try:
            msg = r.json().get("message") or r.text[:200]
        except ValueError:
            msg = r.text[:200]
        raise MLError("Falha na autenticação com o Mercado Livre: %s" % msg, 401)
    return r.json()


def trocar_codigo(code, verifier=None):
    payload = {
        "grant_type": "authorization_code",
        "client_id": APP_ID,
        "client_secret": SECRET,
        "code": code,
        "redirect_uri": REDIRECT_URI,
    }
    if verifier:  # PKCE: exigido quando o app tem PKCE ativado no DevCenter
        payload["code_verifier"] = verifier
    return _salvar_token(_pedir_token(payload))


def _renovar(forcar=False):
    with _lock:
        t = _ler_token()
        if not t:
            raise MLError("Conta do Mercado Livre não conectada.", 401)
        if not forcar and t["expires_at"] > time.time():
            return t
        resp = _pedir_token(
            {
                "grant_type": "refresh_token",
                "client_id": APP_ID,
                "client_secret": SECRET,
                "refresh_token": t["refresh_token"],
            }
        )
        return _salvar_token(resp, t["user_id"])


def _token_valido():
    t = _ler_token()
    if not t:
        raise MLError("Conta do Mercado Livre não conectada.", 401)
    if t["expires_at"] <= time.time():
        t = _renovar()
    return t["access_token"]


def _uid():
    t = _ler_token()
    if not t or not t.get("user_id"):
        raise MLError("Conta do Mercado Livre não conectada.", 401)
    return t["user_id"]


# ---------------------------------------------------------------- HTTP + cache
def _get(caminho, params=None, tentativas=3, headers=None):
    renovou = False
    for i in range(tentativas):
        token = _token_valido()
        cab = {"Authorization": "Bearer " + token, "Accept": "application/json"}
        if headers:
            cab.update(headers)
        try:
            r = requests.get(
                API + caminho,
                params=params,
                headers=cab,
                timeout=30,
            )
        except requests.RequestException as e:
            raise MLError("Falha de rede ao falar com o Mercado Livre: %s" % e, 502)
        if r.status_code == 401 and not renovou:
            renovou = True
            _renovar(forcar=True)
            continue
        if r.status_code == 429:
            time.sleep(1.5 * (i + 1))
            continue
        if r.status_code >= 400:
            try:
                msg = r.json().get("message") or r.text[:200]
            except ValueError:
                msg = r.text[:200]
            raise MLError(
                "Mercado Livre respondeu %d em %s: %s" % (r.status_code, caminho, msg),
                r.status_code if r.status_code < 500 else 502,
            )
        return r.json()
    raise MLError("Limite de requisições do Mercado Livre atingido. Tente de novo em instantes.", 429)


def _cache(chave, ttl, refresh, fn):
    if not refresh:
        con = _db()
        try:
            row = con.execute("SELECT ts, dados FROM cache WHERE chave = ?", (chave,)).fetchone()
        finally:
            con.close()
        if row and time.time() - row["ts"] < ttl:
            dados = json.loads(row["dados"])
            if isinstance(dados, dict):
                dados["_cache_ts"] = row["ts"]
            return dados
    dados = fn()
    agora = time.time()
    con = _db()
    try:
        con.execute("INSERT OR REPLACE INTO cache (chave, ts, dados) VALUES (?, ?, ?)", (chave, agora, json.dumps(dados)))
        con.commit()
    finally:
        con.close()
    if isinstance(dados, dict):
        dados["_cache_ts"] = agora
    return dados


# ---------------------------------------------------------------- consultas
def _https(url):
    return url.replace("http://", "https://", 1) if url else url


def listar_ids(uid, status):
    """IDs de todos os anúncios de um status, usando o modo scan (sem limite de 1000)."""
    ids, scroll = [], None
    while len(ids) < 20000:
        params = {"search_type": "scan", "limit": 100, "status": status}
        if scroll:
            params["scroll_id"] = scroll
        d = _get("/users/%s/items/search" % uid, params)
        lote = d.get("results") or []
        if not lote:
            break
        ids += lote
        scroll = d.get("scroll_id")
        if not scroll:
            break
    return ids


def detalhar_itens(ids):
    itens = []
    for i in range(0, len(ids), 20):
        lote = ids[i:i + 20]
        resp = _get("/items", {"ids": ",".join(lote)})
        for entrada in resp if isinstance(resp, list) else []:
            if entrada.get("code") != 200:
                continue
            b = entrada.get("body") or {}
            fotos = [_https(p.get("secure_url") or p.get("url")) for p in (b.get("pictures") or [])]
            itens.append(
                {
                    "id": b.get("id"),
                    "titulo": b.get("title"),
                    "preco": b.get("price"),
                    "preco_original": b.get("original_price"),
                    "moeda": b.get("currency_id"),
                    "estoque": b.get("available_quantity"),
                    "vendidos": b.get("sold_quantity"),
                    "status": b.get("status"),
                    "sub_status": b.get("sub_status") or [],
                    "tipo": b.get("listing_type_id"),
                    "condicao": b.get("condition"),
                    "thumbnail": _https(b.get("secure_thumbnail") or b.get("thumbnail")),
                    "fotos": [f for f in fotos if f],
                    "permalink": b.get("permalink"),
                    "criado": b.get("date_created"),
                    "atualizado": b.get("last_updated"),
                    "frete_gratis": (b.get("shipping") or {}).get("free_shipping"),
                    "categoria": b.get("category_id"),
                    "sku": b.get("seller_custom_field"),
                    "saude": b.get("health"),
                    "catalogo": b.get("catalog_listing"),
                    "video": b.get("video_id"),
                    "tags": b.get("tags") or [],
                    "variacoes": len(b.get("variations") or []),
                    "atributos": len(b.get("attributes") or []),
                    "logistica": (b.get("shipping") or {}).get("logistic_type"),
                    "inventario": b.get("inventory_id"),
                }
            )
    return itens


def visitas_itens(ids, dias):
    """Visitas por anúncio na janela. Se o endpoint falhar, devolve o que conseguiu."""
    out = {}
    fim = datetime.now(TZ)
    ini = fim - timedelta(days=dias)
    for i in range(0, len(ids), 50):
        lote = ids[i:i + 50]
        try:
            d = _get(
                "/items/visits",
                {"ids": ",".join(lote), "date_from": ini.strftime("%Y-%m-%d"), "date_to": fim.strftime("%Y-%m-%d")},
            )
        except MLError:
            return out
        if isinstance(d, list):
            for x in d:
                if isinstance(x, dict) and x.get("item_id"):
                    out[x["item_id"]] = x.get("total_visits", 0)
        elif isinstance(d, dict):
            for k, v in d.items():
                if isinstance(v, (int, float)):
                    out[k] = v
    return out


def anuncios(status, refresh=False):
    uid = _uid()
    lista = [s for s in status.split(",") if s in STATUS_VALIDOS] or ["active", "paused"]

    def montar():
        ids = []
        for st in lista:
            ids += listar_ids(uid, st)
        itens = detalhar_itens(ids)
        vis = visitas_itens([i["id"] for i in itens], 30)
        for i in itens:
            i["visitas_30d"] = vis.get(i["id"])
        return {"total": len(itens), "itens": itens, "visitas_ok": bool(vis) or not itens}

    return _cache("anuncios2:%s:%s" % (uid, ",".join(lista)), TTL_LONGO, refresh, montar)


def pedidos(dias=30, refresh=False):
    uid = _uid()

    def montar():
        desde = (datetime.now(TZ) - timedelta(days=dias)).strftime("%Y-%m-%dT00:00:00.000-03:00")
        lista, offset, total = [], 0, None
        while (total is None or offset < total) and offset < 5000:
            d = _get(
                "/orders/search",
                {"seller": uid, "order.date_created.from": desde, "sort": "date_desc", "limit": 50, "offset": offset},
            )
            total = (d.get("paging") or {}).get("total", 0)
            resultados = d.get("results") or []
            if not resultados:
                break
            for o in resultados:
                lista.append(
                    {
                        "id": o.get("id"),
                        "data": o.get("date_created"),
                        "status": o.get("status"),
                        "total": o.get("total_amount") or 0,
                        "comprador": (o.get("buyer") or {}).get("nickname"),
                        "envio": (o.get("shipping") or {}).get("id"),
                        "pack": o.get("pack_id"),
                        "itens": [
                            {
                                "id": (i.get("item") or {}).get("id"),
                                "titulo": (i.get("item") or {}).get("title"),
                                "qtd": i.get("quantity"),
                                "preco": i.get("unit_price"),
                                "taxa": i.get("sale_fee"),
                            }
                            for i in o.get("order_items") or []
                        ],
                    }
                )
            offset += 50

        validos = [p for p in lista if p["status"] != "cancelled"]
        por_dia = {}
        for i in range(dias + 1):
            dia = (datetime.now(TZ) - timedelta(days=dias - i)).strftime("%Y-%m-%d")
            por_dia[dia] = {"dia": dia, "pedidos": 0, "faturamento": 0.0}
        for p in validos:
            dia = (p["data"] or "")[:10]
            if dia in por_dia:
                por_dia[dia]["pedidos"] += 1
                por_dia[dia]["faturamento"] += float(p["total"])
        faturamento = sum(float(p["total"]) for p in validos)
        itens_vendidos = sum(int(i["qtd"] or 0) for p in validos for i in p["itens"])
        comissoes = sum(float(i.get("taxa") or 0) * int(i["qtd"] or 0) for p in validos for i in p["itens"])
        por_item = {}
        for p in validos:
            for i in p["itens"]:
                chave = i["id"] or "?"
                x = por_item.setdefault(chave, {"id": chave, "titulo": i["titulo"], "qtd": 0, "receita": 0.0, "comissao": 0.0})
                q = int(i["qtd"] or 0)
                x["qtd"] += q
                x["receita"] += float(i["preco"] or 0) * q
                x["comissao"] += float(i.get("taxa") or 0) * q
        return {
            "comissoes": comissoes,
            "por_item": sorted(por_item.values(), key=lambda x: -x["receita"])[:50],
            "dias": dias,
            "total_pedidos": len(validos),
            "cancelados": len(lista) - len(validos),
            "faturamento": faturamento,
            "itens_vendidos": itens_vendidos,
            "ticket_medio": faturamento / len(validos) if validos else 0,
            "por_dia": list(por_dia.values()),
            "pedidos": lista[:100],
        }

    return _cache("pedidos2:%s:%s" % (uid, dias), TTL_CURTO, refresh, montar)


def perguntas(refresh=False):
    uid = _uid()

    def montar():
        d = _get("/questions/search", {"seller_id": uid, "status": "UNANSWERED", "limit": 50, "api_version": "4"})
        return {
            "total": d.get("total", 0),
            "perguntas": [
                {"id": q.get("id"), "texto": q.get("text"), "item_id": q.get("item_id"), "data": q.get("date_created")}
                for q in d.get("questions") or []
            ],
        }

    return _cache("perguntas:%s" % uid, TTL_CURTO, refresh, montar)


def visitas_serie(dias=30, refresh=False):
    uid = _uid()

    def montar():
        try:
            d = _get("/users/%s/items_visits/time_window" % uid, {"last": dias, "unit": "day"})
        except MLError as e:
            return {"ok": False, "mensagem": e.mensagem, "total": None, "por_dia": []}
        serie = [{"dia": (x.get("date") or "")[:10], "visitas": x.get("total", 0)} for x in d.get("results") or []]
        total = d.get("total_visits")
        if total is None:
            total = sum(x["visitas"] for x in serie)
        return {"ok": True, "total": total, "por_dia": serie}

    return _cache("visitas:%s:%s" % (uid, dias), TTL_CURTO, refresh, montar)


def resumo(refresh=False):
    uid = _uid()

    def montar():
        u = _get("/users/me")
        rep = u.get("seller_reputation") or {}
        trans = rep.get("transactions") or {}
        metricas = rep.get("metrics") or {}
        contagem = {}
        for st in ("active", "paused", "closed"):
            try:
                d = _get("/users/%s/items/search" % uid, {"status": st, "limit": 1})
                contagem[st] = (d.get("paging") or {}).get("total", 0)
            except MLError:
                contagem[st] = None
        return {
            "usuario": {
                "id": u.get("id"),
                "apelido": u.get("nickname"),
                "link": u.get("permalink"),
                "pais": u.get("country_id"),
            },
            "anuncios": contagem,
            "reputacao": {
                "nivel": rep.get("level_id"),
                "mercado_lider": rep.get("power_seller_status"),
                "transacoes_total": trans.get("total"),
                "transacoes_concluidas": trans.get("completed"),
                "transacoes_canceladas": trans.get("canceled"),
                "avaliacoes": trans.get("ratings"),
                "vendas_periodo": (metricas.get("sales") or {}).get("completed"),
                "reclamacoes": (metricas.get("claims") or {}).get("rate"),
                "atrasos": (metricas.get("delayed_handling_time") or {}).get("rate"),
                "cancelamentos": (metricas.get("cancellations") or {}).get("rate"),
            },
        }

    return _cache("resumo:%s" % uid, TTL_CURTO, refresh, montar)


# ---------------------------------------------------------------- módulos extras (somente leitura)
H_ENVIO = {"x-format-new": "true"}
H_ADS = {"api-version": "2"}


def _tentar(fn):
    """Consulta opcional: se falhar (permissão, endpoint indisponível), devolve a mensagem
    em vez de derrubar a tela inteira. Só o erro de login (401) continua subindo."""
    try:
        return {"ok": True, "dados": fn()}
    except MLError as e:
        if e.status == 401:
            raise
        return {"ok": False, "mensagem": e.mensagem}


def _dig(d, *chaves):
    for c in chaves:
        if not isinstance(d, dict):
            return None
        d = d.get(c)
    return d


def envios(dias=30, refresh=False):
    uid = _uid()

    def montar():
        ped = pedidos(dias, refresh)
        com_envio = [p for p in ped["pedidos"] if p["status"] != "cancelled" and p.get("envio")]
        linhas, contagem, falhas = [], {}, 0
        for p in com_envio[:30]:
            try:
                s = _get("/shipments/%s" % p["envio"], headers=H_ENVIO)
            except MLError as e:
                if e.status == 401:
                    raise
                falhas += 1
                continue
            status = s.get("status") or "—"
            contagem[status] = contagem.get(status, 0) + 1
            cidade = _dig(s, "destination", "shipping_address", "city", "name")
            estado = _dig(s, "destination", "shipping_address", "state", "name")
            linhas.append(
                {
                    "pedido": p["id"],
                    "envio": p["envio"],
                    "data": p["data"],
                    "status": status,
                    "substatus": s.get("substatus"),
                    "rastreio": s.get("tracking_number"),
                    "logistica": _dig(s, "logistic", "type"),
                    "destino": ", ".join(x for x in [cidade, estado] if x),
                    "previsao": _dig(s, "lead_time", "estimated_delivery_final", "date")
                    or _dig(s, "lead_time", "estimated_delivery_limit", "date"),
                    "itens": ", ".join("%sx %s" % (i["qtd"], i["titulo"]) for i in p["itens"]),
                }
            )
        return {"linhas": linhas, "contagem": contagem, "falhas": falhas, "limite": 30, "total_com_envio": len(com_envio)}

    return _cache("envios:%s:%s" % (uid, dias), TTL_CURTO, refresh, montar)


def envio_detalhe(envio_id):
    base = "/shipments/%s" % envio_id
    return {
        "detalhe": _tentar(lambda: _get(base, headers=H_ENVIO)),
        "historico": _tentar(lambda: _get(base + "/history", headers=H_ENVIO)),
        "custos": _tentar(lambda: _get(base + "/costs", headers=H_ENVIO)),
        "transportadora": _tentar(lambda: _get(base + "/carrier", headers=H_ENVIO)),
        "prazo": _tentar(lambda: _get(base + "/lead_time", headers=H_ENVIO)),
        "atrasos": _tentar(lambda: _get(base + "/delays", headers=H_ENVIO)),
    }


def financeiro(dias=30, refresh=False):
    uid = _uid()

    def montar():
        ped = pedidos(dias, refresh)
        validos = [p for p in ped["pedidos"] if p["status"] != "cancelled"]
        com_envio = [p for p in validos if p.get("envio")]
        soma, lidos = 0.0, 0
        for p in com_envio[:40]:
            try:
                c = _get("/shipments/%s/costs" % p["envio"], headers=H_ENVIO)
            except MLError as e:
                if e.status == 401:
                    raise
                continue
            lidos += 1
            soma += sum(float(s.get("cost") or 0) for s in c.get("senders") or [])
        # frete médio por pedido com envio, projetado para todos os pedidos do período
        frete_medio = soma / lidos if lidos else 0.0
        parte_com_envio = len(com_envio) / len(validos) if validos else 0.0
        frete = frete_medio * parte_com_envio * ped["total_pedidos"]
        receita = ped["faturamento"]
        liquido = receita - ped["comissoes"] - frete
        return {
            "dias": dias,
            "receita": receita,
            "comissoes": ped["comissoes"],
            "frete_estimado": frete,
            "frete_amostra": lidos,
            "liquido": liquido,
            "margem": liquido / receita if receita else None,
            "pedidos": ped["total_pedidos"],
            "por_item": [dict(x, liquido_antes_frete=x["receita"] - x["comissao"]) for x in ped["por_item"]],
            "por_dia": ped["por_dia"],
        }

    return _cache("financeiro:%s:%s" % (uid, dias), TTL_CURTO, refresh, montar)


def faturas(refresh=False):
    uid = _uid()

    def montar():
        d = _get("/billing/integration/monthly/periods", {"group": "ML", "document_type": "BILL"})
        return {"periodos": d}

    return _cache("faturas:%s" % uid, 3600, refresh, montar)


def _avaliacoes():
    an = anuncios("active,paused")
    top = sorted((i for i in an["itens"] if (i.get("vendidos") or 0) > 0), key=lambda i: -i["vendidos"])[:15]
    saida = []
    for it in top:
        try:
            r = _get("/reviews/item/%s" % it["id"])
        except MLError as e:
            if e.status == 401:
                raise
            continue
        saida.append(
            {
                "id": it["id"],
                "titulo": it["titulo"],
                "media": r.get("rating_average"),
                "total": (r.get("paging") or {}).get("total"),
                "niveis": r.get("rating_levels"),
            }
        )
    return sorted(saida, key=lambda x: (x["media"] is None, x["media"] or 0))


def posvenda(refresh=False):
    uid = _uid()

    def montar():
        return {
            "reclamacoes": _tentar(lambda: _get("/post-purchase/v1/claims/search", {"status": "opened"})),
            # só conta as mensagens não lidas; abrir uma conversa marcaria como lida, por isso não lemos o texto
            "nao_lidas": _tentar(lambda: _get("/messages/unread", {"tag": "post_sale", "role": "seller"})),
            "avaliacoes": _tentar(_avaliacoes),
        }

    return _cache("posvenda:%s" % uid, TTL_CURTO, refresh, montar)


def qualidade(refresh=False):
    an = anuncios("active,paused", refresh)
    contagem, itens = {}, []
    for it in an["itens"]:
        ativo = it["status"] == "active"
        f = []
        if len(it["fotos"]) < 4:
            f.append("poucas_fotos")
        if not it.get("video"):
            f.append("sem_video")
        if it.get("saude") is not None and it["saude"] < 0.6:
            f.append("saude_baixa")
        if ativo and it.get("visitas_30d") == 0:
            f.append("sem_visitas")
        if ativo and not (it.get("vendidos") or 0):
            f.append("sem_vendas")
        if ativo and it.get("estoque") is not None and it["estoque"] <= 2:
            f.append("estoque_baixo")
        if not it.get("sku"):
            f.append("sem_sku")
        if it["status"] == "paused":
            f.append("pausado")
        if it.get("sub_status"):
            f.append("restricao")
        for x in f:
            contagem[x] = contagem.get(x, 0) + 1
        itens.append(
            {
                "id": it["id"],
                "titulo": it["titulo"],
                "thumbnail": it["thumbnail"],
                "status": it["status"],
                "saude": it.get("saude"),
                "fotos": len(it["fotos"]),
                "atributos": it.get("atributos"),
                "variacoes": it.get("variacoes"),
                "visitas_30d": it.get("visitas_30d"),
                "vendidos": it.get("vendidos"),
                "estoque": it.get("estoque"),
                "sub_status": it.get("sub_status"),
                "permalink": it.get("permalink"),
                "alertas": f,
            }
        )
    itens.sort(key=lambda x: -len(x["alertas"]))
    return {"total": len(itens), "contagem": contagem, "itens": itens[:300]}


def anuncio_detalhe(item_id):
    item = _get("/items/%s" % item_id)
    preco, cat = item.get("price"), item.get("category_id")
    return {
        "id": item.get("id"),
        "titulo": item.get("title"),
        "preco": preco,
        "categoria": cat,
        "tipo": item.get("listing_type_id"),
        "garantia": item.get("warranty"),
        "atributos": [
            {"nome": a.get("name"), "valor": a.get("value_name")}
            for a in item.get("attributes") or []
            if a.get("value_name")
        ],
        "variacoes": [
            {
                "id": v.get("id"),
                "preco": v.get("price"),
                "estoque": v.get("available_quantity"),
                "vendidos": v.get("sold_quantity"),
                "combinacao": ", ".join(str(c.get("value_name")) for c in v.get("attribute_combinations") or []),
            }
            for v in item.get("variations") or []
        ],
        "descricao": _tentar(lambda: _get("/items/%s/description" % item_id).get("plain_text")),
        "taxas": _tentar(lambda: _get("/sites/MLB/listing_prices", {"price": preco, "category_id": cat})),
        "avaliacoes": _tentar(lambda: _get("/reviews/item/%s" % item_id)),
        "desempenho": _tentar(lambda: _get("/item/%s/performance" % item_id)),
    }


def full(refresh=False):
    uid = _uid()

    def montar():
        an = anuncios("active,paused", refresh)
        todos = [i for i in an["itens"] if i.get("logistica") == "fulfillment" and i.get("inventario")]
        linhas = []
        for it in todos[:40]:
            linhas.append(
                {
                    "id": it["id"],
                    "titulo": it["titulo"],
                    "inventario": it["inventario"],
                    "estoque": _tentar(lambda it=it: _get("/inventories/%s/stock/fulfillment" % it["inventario"])),
                }
            )
        return {"total": len(todos), "linhas": linhas}

    return _cache("full:%s" % uid, TTL_CURTO, refresh, montar)


def publicidade(dias=30, refresh=False):
    uid = _uid()

    def montar():
        adv = _get("/advertising/advertisers", {"product_id": "PADS"}, headers={"Api-Version": "1"})
        lista = (adv.get("advertisers") if isinstance(adv, dict) else adv) or []
        alvo = next((a for a in lista if a.get("site_id") == "MLB"), lista[0] if lista else None)
        if not alvo:
            raise MLError("Nenhuma conta de Product Ads encontrada para este usuário.", 404)
        aid = alvo.get("advertiser_id")
        fim = datetime.now(TZ)
        base = {
            "date_from": (fim - timedelta(days=dias)).strftime("%Y-%m-%d"),
            "date_to": fim.strftime("%Y-%m-%d"),
            "metrics_summary": "true",
            "limit": 50,
        }
        metricas = "clicks,prints,cost,cpc,acos,direct_amount,indirect_amount,total_amount,units_quantity"

        def pedir(caminho):
            try:
                return _get(caminho, dict(base, metrics=metricas), headers=H_ADS)
            except MLError as e:
                if e.status == 401:
                    raise
                return _get(caminho, base, headers=H_ADS)  # sem a lista de métricas, se ela for recusada

        return {
            "anunciante": alvo,
            "campanhas": _tentar(lambda: pedir("/advertising/advertisers/%s/product_ads/campaigns" % aid)),
            "anuncios": _tentar(lambda: pedir("/advertising/advertisers/%s/product_ads/items" % aid)),
        }

    return _cache("publicidade:%s:%s" % (uid, dias), TTL_CURTO, refresh, montar)


def tendencias(refresh=False):
    uid = _uid()
    return _cache("tendencias:%s" % uid, 3600, refresh, lambda: {"itens": _get("/trends/MLB")})


def busca_mercado(q):
    d = _get("/sites/MLB/search", {"q": q, "limit": 30})
    return {
        "total": (d.get("paging") or {}).get("total"),
        "itens": [
            {
                "id": r.get("id"),
                "titulo": r.get("title"),
                "preco": r.get("price"),
                "vendidos": r.get("sold_quantity"),
                "condicao": r.get("condition"),
                "frete_gratis": (r.get("shipping") or {}).get("free_shipping"),
                "vendedor": (r.get("seller") or {}).get("nickname"),
                "thumbnail": _https(r.get("thumbnail")),
                "permalink": r.get("permalink"),
            }
            for r in d.get("results") or []
        ],
    }


# ---------------------------------------------------------------- rotas
def _refresh():
    return request.args.get("refresh") == "1"


def _dias():
    try:
        return max(1, min(int(request.args.get("dias", 30)), 90))
    except ValueError:
        return 30


@bp.errorhandler(MLError)
def _erro_ml(e):
    return jsonify({"mensagem": e.mensagem}), e.status


@bp.get("/ml/login")
def ml_login():
    if not (APP_ID and SECRET):
        return "Configure ML_APP_ID e ML_SECRET no arquivo .env e reinicie o app.py.", 500
    state = secrets.token_urlsafe(16)
    session["ml_state"] = state
    verifier = secrets.token_urlsafe(64)
    session["ml_verifier"] = verifier
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("ascii")).digest()).rstrip(b"=").decode("ascii")
    url = "%s?response_type=code&client_id=%s&redirect_uri=%s&state=%s&code_challenge=%s&code_challenge_method=S256" % (
        AUTH_URL,
        requests.utils.quote(APP_ID, safe=""),
        requests.utils.quote(REDIRECT_URI, safe=""),
        state,
        challenge,
    )
    return redirect(url)


@bp.get("/ml/callback")
def ml_callback():
    esperado = session.pop("ml_state", None)
    if not esperado or request.args.get("state") != esperado:
        return "Estado de autenticação inválido. Volte ao dashboard e clique em Conectar de novo.", 400
    code = request.args.get("code")
    if not code:
        return "O Mercado Livre não devolveu o código de autorização: %s" % (request.args.get("error_description") or request.args.get("error") or "sem detalhes"), 400
    trocar_codigo(code, session.pop("ml_verifier", None))
    return redirect("/dashboard")


def _extrair_code(texto):
    """Aceita só o code ou o endereço inteiro devolvido pelo Mercado Livre."""
    texto = (texto or "").strip()
    m_code = re.search(r"[?&]code=([^&\s#]+)", texto)
    m_state = re.search(r"[?&]state=([^&\s#]+)", texto)
    code = m_code.group(1) if m_code else texto
    return code, (m_state.group(1) if m_state else None)


@bp.post("/ml/codigo")
def ml_codigo():
    """Conexão manual: usada quando a Redirect URI cadastrada não aponta para este app."""
    dados = request.get_json(silent=True) or {}
    code, state = _extrair_code(dados.get("codigo"))
    if not code or " " in code:
        raise MLError("Cole o código (ou o endereço inteiro) que o Mercado Livre devolveu.", 400)
    esperado = session.get("ml_state")
    if state and esperado and state != esperado:
        raise MLError("Esse código veio de outra tentativa de login. Clique em Conectar de novo.", 400)
    session.pop("ml_state", None)
    trocar_codigo(code, session.pop("ml_verifier", None))
    return jsonify({"ok": True})


@bp.get("/ml/logout")
def ml_logout():
    _limpar_tudo()
    return redirect("/dashboard")


@bp.get("/api/ml/status")
def api_status():
    t = _ler_token()
    return jsonify({"configurado": bool(APP_ID and SECRET), "conectado": bool(t)})


@bp.get("/api/ml/resumo")
def api_resumo():
    return jsonify(resumo(_refresh()))


@bp.get("/api/ml/anuncios")
def api_anuncios():
    return jsonify(anuncios(request.args.get("status", "active,paused"), _refresh()))


@bp.get("/api/ml/pedidos")
def api_pedidos():
    try:
        dias = int(request.args.get("dias", 30))
    except ValueError:
        dias = 30
    return jsonify(pedidos(max(1, min(dias, 90)), _refresh()))


@bp.get("/api/ml/visitas")
def api_visitas():
    try:
        dias = int(request.args.get("dias", 30))
    except ValueError:
        dias = 30
    return jsonify(visitas_serie(max(1, min(dias, 90)), _refresh()))


@bp.get("/api/ml/perguntas")
def api_perguntas():
    return jsonify(perguntas(_refresh()))


# ---------------------------------------------------------------- rotas dos módulos extras
@bp.get("/api/ml/envios")
def api_envios():
    return jsonify(envios(_dias(), _refresh()))


@bp.get("/api/ml/envio/<envio_id>")
def api_envio(envio_id):
    if not envio_id.isdigit():
        raise MLError("Número de envio inválido.", 400)
    return jsonify(envio_detalhe(envio_id))


@bp.get("/api/ml/financeiro")
def api_financeiro():
    return jsonify(financeiro(_dias(), _refresh()))


@bp.get("/api/ml/faturas")
def api_faturas():
    return jsonify(_tentar(lambda: faturas(_refresh())))


@bp.get("/api/ml/posvenda")
def api_posvenda():
    return jsonify(posvenda(_refresh()))


@bp.get("/api/ml/qualidade")
def api_qualidade():
    return jsonify(qualidade(_refresh()))


@bp.get("/api/ml/anuncio/<item_id>")
def api_anuncio(item_id):
    if not re.fullmatch(r"[A-Za-z]{3}\d+", item_id):
        raise MLError("ID de anúncio inválido.", 400)
    return jsonify(anuncio_detalhe(item_id))


@bp.get("/api/ml/full")
def api_full():
    return jsonify(full(_refresh()))


@bp.get("/api/ml/publicidade")
def api_publicidade():
    return jsonify(publicidade(_dias(), _refresh()))


@bp.get("/api/ml/tendencias")
def api_tendencias():
    return jsonify(tendencias(_refresh()))


@bp.get("/api/ml/mercado/busca")
def api_busca():
    q = (request.args.get("q") or "").strip()
    if len(q) < 2 or len(q) > 100:
        raise MLError("Digite entre 2 e 100 caracteres para buscar.", 400)
    return jsonify(busca_mercado(q))
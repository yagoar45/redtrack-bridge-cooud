// Cooud -> RedTrack bridge
//
// O Cooud envia POST com JSON assinado; o postback do RedTrack espera GET com
// query string. Esta função faz a tradução.
//
//   Cooud (POST assinado)  ->  bridge  ->  RedTrack (GET postback)
//
// Três coisas que o Cooud exige e que moldam o desenho:
//   1. responder 200 rapidamente  -> o postback sai depois da resposta
//   2. dedupe por event id        -> ele faz até 3 retries por evento
//   3. verificar X-Cooud-Signature -> o endpoint é público

import express from 'express';
import crypto from 'node:crypto';

const {
  PORT = 3000,
  COOUD_WEBHOOK_SECRET,
  RTK_POSTBACK_URL = 'https://jisrr.ttrk.io/postback',
  RTK_PTOKEN = '',
  // Qual campo do pedido representa o que você de fato recebe.
  // net_amount = após as taxas da plataforma. Ver README antes de mudar.
  AMOUNT_FIELD = 'net_amount',
  FX_TTL_HOURS = '6',
  FX_FALLBACK_USDBRL = '5.40',
  FX_FALLBACK_EURUSD = '1.08',
} = process.env;

if (!COOUD_WEBHOOK_SECRET) {
  console.error('[boot] COOUD_WEBHOOK_SECRET ausente — o bridge não sobe sem assinatura.');
  process.exit(1);
}

/* ------------------------------------------------------------------ *
 * Assinatura
 * ------------------------------------------------------------------ */

// Header: X-Cooud-Signature: t=<unix>,v1=<hex>
// Assinado: HMAC-SHA256 de "{t}.{raw_body}"
function assinaturaValida(rawBody, header, secret, toleranciaSeg = 300) {
  if (!header) return false;
  const partes = {};
  for (const seg of String(header).split(',')) {
    const i = seg.indexOf('=');
    if (i === -1) continue;
    partes[seg.slice(0, i).trim()] = seg.slice(i + 1).trim();
  }

  const t = Number(partes.t);
  const recebida = partes.v1;
  if (!t || !recebida) return false;

  // Janela de tolerância barra replay de payload antigo capturado.
  if (Math.abs(Math.floor(Date.now() / 1000) - t) > toleranciaSeg) return false;

  const esperada = crypto
    .createHmac('sha256', secret)
    .update(`${t}.${rawBody.toString('utf8')}`)
    .digest('hex');

  const a = Buffer.from(esperada, 'hex');
  const b = Buffer.from(recebida, 'hex');
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}

/* ------------------------------------------------------------------ *
 * Dedupe
 * ------------------------------------------------------------------ */

// O Cooud reenvia até 3x. Sem dedupe uma venda vira três no relatório.
// Set em memória basta porque o processo do Railway fica vivo; um restart
// perde o histórico, e aí a proteção de postback do RedTrack é a segunda
// camada. Para dedupe durável, trocar por Redis.
const MAX_EVENTOS = 5000;
const eventosVistos = new Set();

function jaProcessado(eventId) {
  if (!eventId) return false;
  if (eventosVistos.has(eventId)) return true;
  eventosVistos.add(eventId);
  if (eventosVistos.size > MAX_EVENTOS) {
    // Set preserva ordem de inserção: descarta os mais antigos.
    const sobrando = eventosVistos.size - MAX_EVENTOS;
    let i = 0;
    for (const k of eventosVistos) {
      if (i++ >= sobrando) break;
      eventosVistos.delete(k);
    }
  }
  return false;
}

/* ------------------------------------------------------------------ *
 * Câmbio
 * ------------------------------------------------------------------ */

// O RedTrack está configurado em USD, mas o repasse vem em BRL e o comprador
// pode pagar em EUR. Converter aqui trava o valor na cotação do dia da venda.
//
// O fallback nunca repassa o valor cru: mandar BRL como USD infla a receita
// em ~5x, que é pior do que errar 10% numa cotação defasada.
const FX_TTL_MS = Number(FX_TTL_HOURS) * 60 * 60 * 1000;
let fxCache = { at: 0, usdbrl: null, eurusd: null, fonte: null };

// Dois provedores: o primeiro é global e o segundo é brasileiro. A AwesomeAPI
// tem a melhor cotação de BRL, mas recusou as chamadas vindas do datacenter do
// Railway — provedor único vira ponto único de falha.
const FX_PROVIDERS = [
  {
    nome: 'open.er-api',
    url: 'https://open.er-api.com/v6/latest/USD',
    extrair: (j) => ({
      usdbrl: Number(j?.rates?.BRL),
      eurusd: j?.rates?.EUR ? 1 / Number(j.rates.EUR) : NaN,
    }),
  },
  {
    nome: 'awesomeapi',
    url: 'https://economia.awesomeapi.com.br/last/USD-BRL,EUR-USD',
    extrair: (j) => ({
      usdbrl: parseFloat(j?.USDBRL?.bid),
      eurusd: parseFloat(j?.EURUSD?.bid),
    }),
  },
];

const valida = (n) => Number.isFinite(n) && n > 0;

async function getCotacoes() {
  const agora = Date.now();
  if (fxCache.usdbrl && agora - fxCache.at < FX_TTL_MS) return fxCache;

  for (const p of FX_PROVIDERS) {
    let bruto = '';
    try {
      const r = await fetch(p.url, { signal: AbortSignal.timeout(5000) });
      bruto = await r.text();
      const { usdbrl, eurusd } = p.extrair(JSON.parse(bruto));

      // Aceita resultado parcial: USD-BRL é o par que importa para o repasse.
      // Derrubar os dois porque o EUR falhou seria perder a cotação boa.
      if (valida(usdbrl)) {
        fxCache = {
          at: agora,
          usdbrl,
          eurusd: valida(eurusd) ? eurusd : fxCache.eurusd || Number(FX_FALLBACK_EURUSD),
          fonte: p.nome,
        };
        console.log(`[fx] ${p.nome}: USDBRL=${usdbrl.toFixed(4)} EURUSD=${fxCache.eurusd.toFixed(4)}`);
        return fxCache;
      }
      // Sem o corpo da resposta no log, a falha anterior ficou incógnita.
      console.warn(`[fx] ${p.nome} respondeu sem cotação válida:`, bruto.slice(0, 200));
    } catch (e) {
      console.warn(`[fx] ${p.nome} falhou: ${e.message}`, bruto.slice(0, 200));
    }
  }

  console.error('[fx] todos os provedores falharam — usando fallback fixo');
  return {
    at: fxCache.at,
    usdbrl: fxCache.usdbrl || Number(FX_FALLBACK_USDBRL),
    eurusd: fxCache.eurusd || Number(FX_FALLBACK_EURUSD),
    fonte: 'fallback',
  };
}

// centavos + moeda de origem -> unidades em USD
async function paraUsd(centavos, moeda) {
  const valor = Number(centavos) / 100;
  if (!Number.isFinite(valor)) return { usd: 0, taxa: null, fonte: null };

  const m = String(moeda || '').toLowerCase();
  if (m === 'usd') return { usd: arredonda(valor), taxa: 1, fonte: 'n/a' };

  const fx = await getCotacoes();
  if (m === 'brl') return { usd: arredonda(valor / fx.usdbrl), taxa: fx.usdbrl, fonte: fx.fonte };
  if (m === 'eur') return { usd: arredonda(valor * fx.eurusd), taxa: fx.eurusd, fonte: fx.fonte };

  // Moeda não prevista: registra e repassa sem converter, para não inventar
  // número. Se aparecer no log, é config nova que precisa de tratamento.
  console.warn(`[fx] moeda não tratada: "${m}" — repassando sem conversão`);
  return { usd: arredonda(valor), taxa: null, fonte: null };
}

const arredonda = (n) => Math.round(n * 100) / 100;

/* ------------------------------------------------------------------ *
 * Mapeamento de eventos
 * ------------------------------------------------------------------ */

// A doc do Cooud usa `order.paid` em um lugar e `cooud.order.paid` no schema
// OpenAPI. Normaliza os dois para não depender de qual chega.
//
// `type` é o tipo de evento no RedTrack; `status` é o estado do pagamento.
// Trocar os dois faz o RedTrack gravar a conversão como Error, sem avisar.
const EVENTOS = {
  'order.paid':     { type: 'Purchase', status: 'approved' },
  'order.refunded': { type: 'refund',   status: 'refund'   },
};

function mapearEvento(tipoBruto) {
  const t = String(tipoBruto || '').replace(/^cooud\./, '');
  return EVENTOS[t] || null;
}

/* ------------------------------------------------------------------ *
 * Envio ao RedTrack
 * ------------------------------------------------------------------ */

async function enviarPostback({ clickid, sum, tipo, status, orderId }) {
  const params = new URLSearchParams();
  if (RTK_PTOKEN) params.set('ptoken', RTK_PTOKEN);
  params.set('clickid', clickid);
  params.set('sum', String(sum));
  params.set('type', tipo);
  params.set('status', status);
  if (orderId) params.set('order_id', orderId);

  const url = `${RTK_POSTBACK_URL}?${params.toString()}`;
  const r = await fetch(url, { signal: AbortSignal.timeout(8000) });
  const corpo = await r.text();
  return { ok: r.ok, http: r.status, corpo };
}

/* ------------------------------------------------------------------ *
 * Processamento
 * ------------------------------------------------------------------ */

async function processar(evento) {
  const eventId = evento?.id;
  const mapeado = mapearEvento(evento?.type);

  if (!mapeado) {
    console.log(`[skip] evento não mapeado: ${evento?.type}`);
    return;
  }
  if (jaProcessado(eventId)) {
    console.log(`[skip] retry duplicado: ${eventId}`);
    return;
  }

  const pedido = evento?.data || {};

  // O clickid do RedTrack viaja em utm_term, gravado no metadata do pedido
  // quando a checkout session é criada.
  const clickid = pedido?.metadata?.utm_term;
  if (!clickid) {
    // Sem clickid não há a quem atribuir. Loga alto: significa que a UTM se
    // perdeu no caminho até o checkout, e a venda fica órfã no relatório.
    console.error(`[ERRO] ${eventId} sem utm_term no metadata — venda não atribuída`, {
      order: pedido?.id,
      metadata: pedido?.metadata,
    });
    return;
  }

  const centavos = pedido[AMOUNT_FIELD] ?? pedido.amount ?? pedido.total_amount;
  const { usd, taxa, fonte } = await paraUsd(centavos, pedido.currency);

  try {
    const r = await enviarPostback({
      clickid,
      sum: usd,
      tipo: mapeado.type,
      status: mapeado.status,
      orderId: pedido?.id,
    });
    // A taxa aplicada precisa ficar no log: sem ela, um valor questionado
    // daqui a dois meses vira inauditável.
    console.log(`[ok] ${mapeado.type} ${eventId}`, {
      order: pedido?.id,
      origem: `${Number(centavos) / 100} ${pedido.currency}`,
      enviado: `${usd} USD`,
      taxa,
      fonte, // "fallback" aqui significa cotação fixa: o valor não é confiável
      resposta: r.corpo,
    });
  } catch (e) {
    console.error(`[ERRO] postback falhou ${eventId}:`, e.message);
  }
}

/* ------------------------------------------------------------------ *
 * HTTP
 * ------------------------------------------------------------------ */

const app = express();

app.get('/health', (_req, res) => res.json({ ok: true, eventos: eventosVistos.size }));

// raw() e não json(): o HMAC é calculado sobre os bytes literais do corpo.
// Qualquer reserialização quebra a verificação.
app.post('/cooud', express.raw({ type: '*/*', limit: '1mb' }), (req, res) => {
  if (!assinaturaValida(req.body, req.get('X-Cooud-Signature'), COOUD_WEBHOOK_SECRET)) {
    console.warn('[401] assinatura inválida');
    return res.status(401).send('invalid signature');
  }

  let evento;
  try {
    evento = JSON.parse(req.body.toString('utf8'));
  } catch {
    return res.status(400).send('invalid json');
  }

  // Responde antes de processar: o Cooud considera falha (e reenvia) se a
  // resposta demorar. O postback ao RedTrack sai fora do ciclo da requisição.
  res.status(200).send('ok');
  processar(evento).catch((e) => console.error('[ERRO] processar:', e));
});

app.listen(PORT, () => console.log(`[boot] bridge ouvindo na porta ${PORT}`));

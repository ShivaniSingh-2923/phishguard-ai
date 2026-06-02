import { useState, useEffect } from 'react';
import { scanUrl, scanSms } from '../api';
import {
  ShieldCheck, AlertTriangle, CheckCircle2, AlertCircle,
  Loader2, Lightbulb, Info, Link as LinkIcon, MessageSquare,
  ChevronDown, ChevronUp, ShieldAlert, ShieldX, Sparkles,
  HelpCircle, Flag
} from 'lucide-react';

// ── Status config ──────────────────────────────────────────────────────────────
const STATUS = {
  SAFE:    { color: 'text-emerald-600', bg: 'bg-emerald-50', bar: 'bg-emerald-500', icon: CheckCircle2,  label: 'Content is Safe'  },
  SCAM:    { color: 'text-red-600',     bg: 'bg-red-50',     bar: 'bg-red-500',     icon: AlertTriangle, label: 'Scam Detected'    },
  WARNING: { color: 'text-amber-600',   bg: 'bg-amber-50',   bar: 'bg-amber-400',   icon: AlertCircle,   label: 'Suspicious URL'   },
  UNKNOWN: { color: 'text-gray-500',    bg: 'bg-gray-100',   bar: 'bg-gray-400',    icon: HelpCircle,    label: 'Unknown'          },
};

const VERDICT_STYLE = {
  'CRITICAL':   { color: 'text-red-700',     bg: 'bg-red-100',    border: 'border-red-300',    dot: 'bg-red-500'     },
  'HIGH RISK':  { color: 'text-red-600',     bg: 'bg-red-50',     border: 'border-red-200',    dot: 'bg-red-400'     },
  'SUSPICIOUS': { color: 'text-amber-700',   bg: 'bg-amber-50',   border: 'border-amber-200',  dot: 'bg-amber-500'   },
  'CAUTION':    { color: 'text-amber-600',   bg: 'bg-amber-50',   border: 'border-amber-200',  dot: 'bg-amber-400'   },
  'LOW RISK':   { color: 'text-blue-600',    bg: 'bg-blue-50',    border: 'border-blue-200',   dot: 'bg-blue-400'    },
  'SAFE':       { color: 'text-emerald-700', bg: 'bg-emerald-50', border: 'border-emerald-200',dot: 'bg-emerald-500' },
};

// ── Collapsible indicator row ──────────────────────────────────────────────────
function IndicatorRow({ indicator, isScam }) {
  const [open, setOpen] = useState(false);
  return (
    <div
      className="border border-gray-100 rounded-xl overflow-hidden cursor-pointer select-none"
      onClick={() => setOpen(o => !o)}
    >
      <div className="flex items-center justify-between px-4 py-3 hover:bg-gray-50 transition-colors">
        <div className="flex items-center gap-2">
          <span className={`w-2 h-2 rounded-full shrink-0 ${isScam ? 'bg-red-400' : 'bg-emerald-400'}`} />
          <span className="text-xs font-bold uppercase tracking-wide text-gray-700">
            {indicator.label}
          </span>
        </div>
        {open
          ? <ChevronUp size={13} className="text-gray-400 shrink-0" />
          : <ChevronDown size={13} className="text-gray-400 shrink-0" />
        }
      </div>
      {open && indicator.explanation && (
        <div className="px-4 pb-3 pt-1 text-sm text-gray-600 bg-gray-50 border-t border-gray-100 leading-relaxed">
          {indicator.explanation}
        </div>
      )}
    </div>
  );
}

// ── ResultCard (the real one, inline — no separate import needed) ──────────────
function ResultCard({ result, input, onReset }) {
  const [showLLM, setShowLLM]       = useState(false);
  const [loadingLLM, setLoadingLLM] = useState(false);
  const [llmText, setLlmText]       = useState('');

  useEffect(() => {
    setLlmText(result?.llm_explanation || '');
    setShowLLM(false);
  }, [result]);

  if (!result) return null;

  const score           = parseFloat(result.score)      || 0;
  const confidence      = parseFloat(result.confidence) || 0;
  const cfg             = STATUS[result.status]         || STATUS.UNKNOWN;
  const Icon            = cfg.icon;
  const isScam          = result.status === 'SCAM';

  // XAI fields — populated by the fixed /detect route
  const verdict         = result.verdict          || result.status || 'UNKNOWN';
  const verdictStyle    = VERDICT_STYLE[verdict]  || VERDICT_STYLE['SAFE'];
  const summary         = result.summary          || '';
  const recommendation  = result.recommendation   || '';
  const positiveSignals = Array.isArray(result.positive_signals) ? result.positive_signals : [];

  // Prefer rich indicators; fall back to raw reasons so card is never empty
  const indicators = Array.isArray(result.indicators) && result.indicators.length > 0
    ? result.indicators
    : (result.reasons || []).map(r => ({ label: r, explanation: '', raw: r }));

  const handleExplainMore = async () => {
    if (llmText) { setShowLLM(v => !v); return; }
    setLoadingLLM(true);
    try {
      const res  = await fetch('http://localhost:5000/explain', {
        method:  'POST',
        headers: { 'Content-Type': 'application/json' },
        body:    JSON.stringify({
          url:        result.url,
          reasons:    result.reasons,
          score:      result.score,
          confidence: result.confidence,
        }),
      });
      const data = await res.json();
      const text = data.llm_explanation || data.explanation || '';
      setLlmText(text);
      setShowLLM(!!text);
    } catch (err) {
      console.error('Failed to fetch AI explanation:', err);
    } finally {
      setLoadingLLM(false);
    }
  };

  return (
    <div className="bg-white border border-gray-200 rounded-3xl p-8 animate-in zoom-in-95 duration-300 space-y-6">

      {/* ── Header ── */}
      <div className="flex justify-between items-start">
        <div className="flex gap-4 items-center">
          <div className={`p-4 rounded-2xl ${cfg.bg}`}>
            <Icon className={cfg.color} size={28} />
          </div>
          <div>
            <h3 className={`text-xl font-bold ${cfg.color}`}>{cfg.label}</h3>
            <p className="text-gray-400 text-xs mt-1">
              Analysis for: <span className="italic">"{input}"</span>
            </p>
          </div>
        </div>
        <div className="text-right shrink-0">
          <p className="text-[10px] font-black text-gray-400 uppercase tracking-widest">Risk Score</p>
          <p className={`text-3xl font-black ${cfg.color}`}>{score}%</p>
          {confidence > 0 && (
            <p className="text-xs text-gray-400 mt-0.5">{confidence}% AI confidence</p>
          )}
        </div>
      </div>

      {/* ── Progress bar ── */}
      <div className="h-2 bg-gray-100 rounded-full overflow-hidden">
        <div
          className={`h-full transition-all duration-1000 rounded-full ${cfg.bar}`}
          style={{ width: `${score}%` }}
        />
      </div>

      {/* ── Verdict badge + summary ── */}
      {(verdict || summary) && (
        <div className={`rounded-xl px-4 py-3 border ${verdictStyle.bg} ${verdictStyle.border}`}>
          <div className="flex items-center gap-2 mb-1">
            <span className={`w-2 h-2 rounded-full ${verdictStyle.dot}`} />
            <span className={`text-xs font-bold uppercase tracking-wider ${verdictStyle.color}`}>
              {verdict}
            </span>
          </div>
          {summary && (
            <p className={`text-sm ${verdictStyle.color} opacity-90`}>{summary}</p>
          )}
        </div>
      )}

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* ── Detection flags ── */}
        {indicators.length > 0 && (
          <div className="space-y-2">
            <p className="text-[10px] font-bold text-gray-400 uppercase tracking-widest">
              Detection Flags
            </p>
            <div className="space-y-1.5">
              {indicators.map((ind, i) => (
                <IndicatorRow key={i} indicator={ind} isScam={isScam} />
              ))}
            </div>
          </div>
        )}

        {/* ── Positive signals ── */}
        {positiveSignals.length > 0 && (
          <div className="space-y-2">
            <p className="text-[10px] font-bold text-gray-400 uppercase tracking-widest">
              Legitimate Signals
            </p>
            <div className="space-y-1.5">
              {positiveSignals.map((sig, i) => (
                <div key={i} className="flex items-center gap-2 text-sm text-emerald-700 px-1">
                  <ShieldCheck size={13} className="shrink-0 text-emerald-500" />
                  {sig}
                </div>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* ── Recommendation ── */}
      {recommendation && (
        <div className="flex gap-3 bg-gray-50 border border-gray-100 rounded-xl px-4 py-3">
          <ShieldAlert size={15} className="text-gray-400 shrink-0 mt-0.5" />
          <p className="text-sm text-gray-600 leading-relaxed">{recommendation}</p>
        </div>
      )}

      {/* ── Action row ── */}
      <div className="flex items-center justify-between pt-1 flex-wrap gap-3">
        <button
          onClick={handleExplainMore}
          disabled={loadingLLM}
          className="flex items-center gap-2 px-4 py-2.5 bg-indigo-600 hover:bg-indigo-700
                     disabled:opacity-60 text-white rounded-xl text-sm font-semibold
                     transition-colors shadow-sm"
        >
          {loadingLLM
            ? <><Loader2 size={14} className="animate-spin" /> AI is thinking...</>
            : <><Sparkles size={14} /> {showLLM ? 'Hide AI Report' : 'View AI Forensic Report'}</>
          }
        </button>

        <button
          onClick={onReset}
          className="px-6 py-2.5 bg-gray-900 text-white rounded-xl font-bold text-sm
                     hover:bg-gray-800 transition"
        >
          Perform New Analysis
        </button>
      </div>

      {/* ── LLM explanation panel ── */}
      {showLLM && llmText && (
        <div className="bg-indigo-50 border border-indigo-100 rounded-xl p-4 space-y-2">
          <div className="flex items-center gap-2">
            <div className="w-6 h-6 rounded-full bg-indigo-100 flex items-center justify-center">
              <Sparkles size={12} className="text-indigo-600" />
            </div>
            <h4 className="text-sm font-bold text-indigo-800">AI Forensic Analysis</h4>
          </div>
          <p className="text-sm text-indigo-900 leading-relaxed whitespace-pre-wrap">{llmText}</p>
        </div>
      )}
    </div>
  );
}

// ── ScannerPage ────────────────────────────────────────────────────────────────
export default function ScannerPage({ mode = 'url' }) {
  const [loading, setLoading] = useState(false);
  const [result, setResult]   = useState(null);
  const [input, setInput]     = useState('');

  useEffect(() => {
    setResult(null);
    setInput('');
  }, [mode]);

  const config = {
    url: {
      title:       'URL Scanner',
      placeholder: 'https://example.com...',
      icon:        LinkIcon,
      gradient:    'from-blue-600 to-blue-700',
    },
    sms: {
      title:       'SMS Detector',
      placeholder: 'Paste the SMS text here...',
      icon:        MessageSquare,
      gradient:    'from-indigo-600 to-indigo-700',
    },
  };

  const active = config[mode];

  const handleScan = async (e) => {
    e.preventDefault();
    if (!input.trim()) return;
    setLoading(true);
    setResult(null);
    try {
      const r = mode === 'url' ? await scanUrl(input) : await scanSms(input);
      setResult(r.data);        // ← r.data is the full response from /detect
    } catch (err) {
      console.error('Scan failed:', err);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="max-w-[1000px] mx-auto space-y-8 animate-in fade-in duration-500">
      {/* Header */}
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold text-gray-900">{active.title}</h1>
        <div className="flex items-center gap-2 text-emerald-600 bg-emerald-50 px-3 py-1 rounded-full border border-emerald-100">
          <ShieldCheck size={14} />
          <span className="text-[10px] font-black uppercase tracking-wider">AI Guard Active</span>
        </div>
      </div>

      {/* Scanner box */}
      <div className={`bg-gradient-to-br ${active.gradient} rounded-3xl p-10 shadow-xl relative overflow-hidden`}>
        <div className="relative z-10">
          <h2 className="text-white text-xl font-bold mb-2">Analyze {mode.toUpperCase()} instantly</h2>
          <p className="text-white/70 text-sm mb-8">Powered by AI — detects phishing, malware &amp; social engineering.</p>
          <form onSubmit={handleScan} className="flex gap-3">
            <div className="relative flex-1">
              <active.icon size={18} className="absolute left-4 top-1/2 -translate-y-1/2 text-white/40" />
              <input
                value={input}
                onChange={e => setInput(e.target.value)}
                placeholder={active.placeholder}
                className="w-full pl-12 pr-4 py-4 bg-white/10 border border-white/20 rounded-2xl
                           text-white placeholder:text-white/40 focus:outline-none focus:ring-2
                           focus:ring-white/40 backdrop-blur-md transition"
              />
            </div>
            <button
              disabled={loading || !input}
              className="px-10 bg-white text-gray-900 font-bold rounded-2xl hover:bg-gray-100
                         disabled:opacity-50 transition shadow-lg flex items-center gap-2"
            >
              {loading ? <Loader2 className="animate-spin" size={20} /> : 'Scan now'}
            </button>
          </form>
        </div>
        <div className="absolute -right-10 -top-10 w-48 h-48 bg-white/10 rounded-full blur-3xl" />
      </div>

      {/* Insight cards (hidden once result is shown) */}
      {!result && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <div className="bg-amber-50 border border-amber-100 p-6 rounded-2xl flex gap-4">
            <div className="p-3 bg-amber-100 text-amber-600 rounded-xl h-fit">
              <Lightbulb size={20} />
            </div>
            <div>
              <h4 className="font-bold text-amber-900 text-sm">Security Tip</h4>
              <p className="text-amber-700 text-xs mt-1 leading-relaxed">
                Check for "Urgency". Scammers often use threats like "Your account will be suspended"
                to make you act without thinking.
              </p>
            </div>
          </div>
          <div className="bg-slate-50 border border-slate-200 p-6 rounded-2xl flex gap-4">
            <div className="p-3 bg-slate-200 text-slate-600 rounded-xl h-fit">
              <Info size={20} />
            </div>
            <div>
              <h4 className="font-bold text-slate-900 text-sm">How it works</h4>
              <p className="text-slate-600 text-xs mt-1 leading-relaxed">
                Our model analyzes intent, sender reputation, and URL redirects to calculate
                a risk score in seconds.
              </p>
            </div>
          </div>
        </div>
      )}

      {/* Result */}
      {result && (
        <ResultCard
          result={result}
          input={input}
          onReset={() => { setResult(null); setInput(''); }}
        />
      )}
    </div>
  );
}
import { useState, useEffect } from 'react'
import {
  CheckCircle2, AlertTriangle, AlertCircle,
  HelpCircle, ShieldCheck, ShieldAlert, ShieldX,
  ChevronDown, ChevronUp, Loader2, Sparkles, Flag
} from 'lucide-react'

// ── Status config ──────────────────────────────────────────────────────────────
const STATUS = {
  SAFE:    { color: 'text-emerald-600', bg: 'bg-emerald-50',  border: 'border-emerald-200', bar: 'bg-emerald-500', icon: CheckCircle2,   label: 'Content is Safe'   },
  SCAM:    { color: 'text-red-600',     bg: 'bg-red-50',      border: 'border-red-200',     bar: 'bg-red-500',     icon: AlertTriangle,  label: 'Scam Detected'     },
  WARNING: { color: 'text-amber-600',   bg: 'bg-amber-50',    border: 'border-amber-200',   bar: 'bg-amber-400',   icon: AlertCircle,    label: 'Suspicious URL'    },
  UNKNOWN: { color: 'text-gray-500',    bg: 'bg-gray-100',    border: 'border-gray-200',    bar: 'bg-gray-400',    icon: HelpCircle,     label: 'Unknown'           },
}

// Verdict → style mapping (from explainer.py)
const VERDICT_STYLE = {
  'CRITICAL':   { color: 'text-red-700',    bg: 'bg-red-100',    border: 'border-red-300',    dot: 'bg-red-500'    },
  'HIGH RISK':  { color: 'text-red-600',    bg: 'bg-red-50',     border: 'border-red-200',    dot: 'bg-red-400'    },
  'SUSPICIOUS': { color: 'text-amber-700',  bg: 'bg-amber-50',   border: 'border-amber-200',  dot: 'bg-amber-500'  },
  'CAUTION':    { color: 'text-amber-600',  bg: 'bg-amber-50',   border: 'border-amber-200',  dot: 'bg-amber-400'  },
  'LOW RISK':   { color: 'text-blue-600',   bg: 'bg-blue-50',    border: 'border-blue-200',   dot: 'bg-blue-400'   },
  'SAFE':       { color: 'text-emerald-700',bg: 'bg-emerald-50', border: 'border-emerald-200',dot: 'bg-emerald-500'},
}

// ── Sub-components ─────────────────────────────────────────────────────────────

function IndicatorRow({ indicator }) {
  const [open, setOpen] = useState(false)
  return (
    <div
      className="border border-gray-100 rounded-xl overflow-hidden cursor-pointer"
      onClick={() => setOpen(o => !o)}
    >
      <div className="flex items-center justify-between px-4 py-3 hover:bg-gray-50 transition-colors">
        <div className="flex items-center gap-2">
          <span className="w-2 h-2 rounded-full bg-red-400 shrink-0" />
          <span className="text-sm font-semibold text-gray-800">{indicator.label}</span>
        </div>
        {open ? <ChevronUp size={14} className="text-gray-400" /> : <ChevronDown size={14} className="text-gray-400" />}
      </div>
      {open && (
        <div className="px-4 pb-3 pt-1 text-sm text-gray-600 bg-gray-50 border-t border-gray-100">
          {indicator.explanation}
        </div>
      )}
    </div>
  )
}

function PositiveSignal({ text }) {
  return (
    <div className="flex items-center gap-2 text-sm text-emerald-700">
      <ShieldCheck size={14} className="shrink-0 text-emerald-500" />
      {text}
    </div>
  )
}

// ── Main component ─────────────────────────────────────────────────────────────
export default function ResultCard({ result, onReport }) {
  const [showLLM, setShowLLM]       = useState(false)
  const [loadingLLM, setLoadingLLM] = useState(false)
  const [llmText, setLlmText]       = useState('')

  useEffect(() => {
    setLlmText(result?.llm_explanation || '')
    setShowLLM(false)
  }, [result])

  if (!result) return null

  // ── Pull all fields from the flattened result ──
  const score          = parseFloat(result.score)      || 0
  const confidence     = parseFloat(result.confidence) || 0
  const cfg            = STATUS[result.status]         || STATUS.UNKNOWN
  const Icon           = cfg.icon

  // XAI fields (from explainer.py, merged to top-level in detect route)
  const verdict        = result.verdict         || result.status || 'UNKNOWN'
  const verdictStyle   = VERDICT_STYLE[verdict] || VERDICT_STYLE['SAFE']
  const summary        = result.summary         || ''
  const indicators     = Array.isArray(result.indicators)       ? result.indicators       : []
  const positiveSignals= Array.isArray(result.positive_signals) ? result.positive_signals : []
  const recommendation = result.recommendation  || ''

  // Fallback: if new XAI fields missing, at least show raw reasons as indicators
  const displayIndicators = indicators.length > 0
    ? indicators
    : (result.reasons || []).map(r => ({ label: r, explanation: r, raw: r }))

  const handleExplainMore = async () => {
    if (llmText) { setShowLLM(v => !v); return }
    setLoadingLLM(true)
    try {
      const res  = await fetch('http://localhost:5000/explain', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          url:        result.url,
          reasons:    result.reasons,
          score:      result.score,
          confidence: result.confidence,
        }),
      })
      const data = await res.json()
      const text = data.llm_explanation || data.explanation || ''
      setLlmText(text)
      setShowLLM(!!text)
    } catch (err) {
      console.error('Failed to fetch AI explanation:', err)
    } finally {
      setLoadingLLM(false)
    }
  }

  return (
    <div className="bg-white border border-gray-100 rounded-3xl p-6 shadow-xl shadow-gray-100/50 space-y-5">

      {/* ── Status header ── */}
      <div className="flex justify-between items-start">
        <div className="flex gap-4 items-center">
          <div className={`p-3 rounded-2xl ${cfg.bg}`}>
            <Icon className={cfg.color} size={28} />
          </div>
          <div>
            <h3 className={`text-xl font-bold ${cfg.color}`}>{cfg.label}</h3>
            <p className="text-gray-400 text-sm italic truncate max-w-xs">
              Analysis for: &quot;{result.url}&quot;
            </p>
          </div>
        </div>
        <div className="text-right shrink-0">
          <p className="text-[10px] uppercase font-bold text-gray-400 tracking-widest">Risk Score</p>
          <p className={`text-3xl font-black ${cfg.color}`}>{score}%</p>
          {confidence > 0 && (
            <p className="text-xs text-gray-400 mt-0.5">
              {confidence}% AI confidence
            </p>
          )}
        </div>
      </div>

      {/* ── Progress bar ── */}
      <div className="h-2 bg-gray-100 rounded-full overflow-hidden">
        <div
          className={`h-full transition-all duration-1000 ${cfg.bar}`}
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

      {/* ── Risk indicators (collapsible) ── */}
      {displayIndicators.length > 0 && (
        <div className="space-y-2">
          <p className="text-xs font-bold uppercase tracking-widest text-gray-400">
            Detection Flags
          </p>
          <div className="space-y-1.5">
            {displayIndicators.map((ind, i) => (
              <IndicatorRow key={i} indicator={ind} />
            ))}
          </div>
        </div>
      )}

      {/* ── Positive signals ── */}
      {positiveSignals.length > 0 && (
        <div className="space-y-2">
          <p className="text-xs font-bold uppercase tracking-widest text-gray-400">
            Legitimate Signals
          </p>
          <div className="space-y-1.5 px-1">
            {positiveSignals.map((sig, i) => (
              <PositiveSignal key={i} text={sig} />
            ))}
          </div>
        </div>
      )}

      {/* ── Recommendation ── */}
      {recommendation && (
        <div className="flex gap-3 bg-gray-50 border border-gray-100 rounded-xl px-4 py-3">
          <ShieldAlert size={16} className="text-gray-400 shrink-0 mt-0.5" />
          <p className="text-sm text-gray-600">{recommendation}</p>
        </div>
      )}

      {/* ── AI Forensic Report button ── */}
      <div className="flex items-center gap-3 pt-1">
        <button
          onClick={handleExplainMore}
          disabled={loadingLLM}
          className="flex items-center gap-2 px-4 py-2.5 bg-indigo-600 hover:bg-indigo-700 
                     disabled:opacity-60 text-white rounded-xl text-sm font-semibold 
                     transition-colors shadow-sm shadow-indigo-200"
        >
          {loadingLLM
            ? <><Loader2 size={15} className="animate-spin" /> AI is thinking...</>
            : <><Sparkles size={15} /> {showLLM ? 'Hide AI Report' : 'View AI Forensic Report'}</>
          }
        </button>

        {onReport && (
          <button
            onClick={() => onReport(result)}
            className="flex items-center gap-2 px-4 py-2.5 border border-gray-200 
                       hover:bg-gray-50 text-gray-600 rounded-xl text-sm font-semibold 
                       transition-colors"
          >
            <Flag size={14} /> Report
          </button>
        )}
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
  )
}
import { useState, useRef } from 'react'
import axios from 'axios'
import { voiceScan } from '../api'
import {
  Mic, Upload, CheckCircle2, AlertTriangle,
  Loader2, RotateCcw, X, Waves, ShieldCheck,
  ShieldAlert, AlertCircle, ChevronDown, ChevronUp,
  Sparkles, HelpCircle
} from 'lucide-react'

const BASE_URL = 'http://localhost:5000'

// ── Shared style maps ──────────────────────────────────────────────────────────
const STATUS = {
  FAKE:    { color: 'text-red-600',     bg: 'bg-red-50',     bar: 'bg-red-500',     icon: AlertTriangle, label: 'Deepfake / AI voice detected' },
  REAL:    { color: 'text-emerald-600', bg: 'bg-emerald-50', bar: 'bg-emerald-500', icon: ShieldCheck,   label: 'Likely authentic voice'       },
  WARNING: { color: 'text-amber-600',   bg: 'bg-amber-50',   bar: 'bg-amber-400',   icon: AlertCircle,   label: 'Suspicious audio patterns'    },
  UNKNOWN: { color: 'text-gray-500',    bg: 'bg-gray-100',   bar: 'bg-gray-400',    icon: HelpCircle,    label: 'Unknown'                      },
}

const VERDICT_STYLE = {
  'CRITICAL':   { color: 'text-red-700',     bg: 'bg-red-100',    border: 'border-red-300',    dot: 'bg-red-500'     },
  'HIGH RISK':  { color: 'text-red-600',     bg: 'bg-red-50',     border: 'border-red-200',    dot: 'bg-red-400'     },
  'SUSPICIOUS': { color: 'text-amber-700',   bg: 'bg-amber-50',   border: 'border-amber-200',  dot: 'bg-amber-500'   },
  'CAUTION':    { color: 'text-amber-600',   bg: 'bg-amber-50',   border: 'border-amber-200',  dot: 'bg-amber-400'   },
  'LOW RISK':   { color: 'text-blue-600',    bg: 'bg-blue-50',    border: 'border-blue-200',   dot: 'bg-blue-400'    },
  'SAFE':       { color: 'text-emerald-700', bg: 'bg-emerald-50', border: 'border-emerald-200',dot: 'bg-emerald-500' },
}

// ── Collapsible indicator row ──────────────────────────────────────────────────
function IndicatorRow({ indicator, isFake }) {
  const [open, setOpen] = useState(false)
  return (
    <div
      className="border border-gray-100 rounded-xl overflow-hidden cursor-pointer select-none"
      onClick={() => setOpen(o => !o)}
    >
      <div className="flex items-center justify-between px-4 py-3 hover:bg-gray-50 transition-colors">
        <div className="flex items-center gap-2">
          <span className={`w-2 h-2 rounded-full shrink-0 ${isFake ? 'bg-red-400' : 'bg-emerald-400'}`} />
          <span className="text-xs font-bold uppercase tracking-wide text-gray-700">
            {indicator.label}
          </span>
        </div>
        {open ? <ChevronUp size={13} className="text-gray-400 shrink-0" />
               : <ChevronDown size={13} className="text-gray-400 shrink-0" />}
      </div>
      {open && indicator.explanation && (
        <div className="px-4 pb-3 pt-1 text-sm text-gray-600 bg-gray-50 border-t border-gray-100 leading-relaxed">
          {indicator.explanation}
        </div>
      )}
    </div>
  )
}

// ── Rich result card ───────────────────────────────────────────────────────────
function VoiceResultCard({ result, file, onReset }) {
  const [showLLM,    setShowLLM]    = useState(false)
  const [loadingLLM, setLoadingLLM] = useState(false)
  const [llmText,    setLlmText]    = useState(result?.llm_explanation || '')

  // Voice scan returns label: FAKE/REAL + risk_score
  // Map to a common status key
  const statusKey  = result.label === 'FAKE' ? 'FAKE'
                   : result.label === 'REAL' ? 'REAL'
                   : result.status || 'UNKNOWN'

  const cfg        = STATUS[statusKey] || STATUS.UNKNOWN
  const Icon       = cfg.icon
  const isFake     = statusKey === 'FAKE'
  const risk       = parseFloat(result.risk_score ?? result.score) || 0
  const confidence = parseFloat(result.confidence) || 0

  // XAI fields
  const verdict        = result.verdict         || (isFake ? 'HIGH RISK' : 'SAFE')
  const verdictStyle   = VERDICT_STYLE[verdict] || VERDICT_STYLE['SAFE']
  const summary        = result.summary         || ''
  const recommendation = result.recommendation  || ''
  const positiveSignals= Array.isArray(result.positive_signals) ? result.positive_signals : []

  // Rich indicators — fallback to detected_patterns then reasons
  const rawFlags = result.detected_patterns || result.reasons || []
  const indicators = Array.isArray(result.indicators) && result.indicators.length > 0
    ? result.indicators
    : rawFlags.map(r => ({ label: r, explanation: '', raw: r }))

  const handleExplainMore = async () => {
    if (llmText) { setShowLLM(v => !v); return }
    setLoadingLLM(true)
    try {
      const res  = await axios.post(`${BASE_URL}/explain`, {
        url:        '[Voice scan]',
        reasons:    rawFlags,
        score:      risk,
        confidence: confidence,
      })
      const text = res.data.llm_explanation || res.data.explanation || ''
      setLlmText(text)
      setShowLLM(!!text)
    } catch (err) {
      console.error('LLM explain failed:', err)
    } finally {
      setLoadingLLM(false)
    }
  }

  return (
    <div className="bg-white border border-gray-200 rounded-2xl p-6 animate-fade-up space-y-5">

      {/* ── Header ── */}
      <div className="flex justify-between items-start">
        <div className="flex gap-3 items-center">
          <div className={`w-11 h-11 rounded-xl flex items-center justify-center shrink-0 ${cfg.bg}`}>
            <Icon size={22} className={cfg.color} />
          </div>
          <div>
            <h3 className={`text-[16px] font-bold ${cfg.color}`}>{cfg.label}</h3>
            <p className="text-[12px] text-gray-400 mt-0.5">
              {isFake
                ? 'This audio shows signs of AI generation or manipulation.'
                : 'No significant signs of AI manipulation detected.'}
            </p>
          </div>
        </div>
        <div className="text-right shrink-0">
          <p className="text-[10px] font-black text-gray-400 uppercase tracking-widest">Risk Score</p>
          <p className={`text-2xl font-black ${cfg.color}`}>{risk}%</p>
          {confidence > 0 && (
            <p className="text-xs text-gray-400 mt-0.5">{confidence}% AI confidence</p>
          )}
        </div>
      </div>

      {/* ── Progress bar ── */}
      <div className="h-2 bg-gray-100 rounded-full overflow-hidden">
        <div className={`h-full rounded-full transition-all duration-1000 ${cfg.bar}`}
          style={{ width: `${risk}%` }} />
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

      <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
        {/* ── Detection flags ── */}
        {indicators.length > 0 && (
          <div className="space-y-2">
            <p className="text-[10px] font-bold text-gray-400 uppercase tracking-widest">Detected Patterns</p>
            <div className="space-y-1.5">
              {indicators.map((ind, i) => (
                <IndicatorRow key={i} indicator={ind} isFake={isFake} />
              ))}
            </div>
          </div>
        )}

        {/* ── Positive signals ── */}
        {positiveSignals.length > 0 && (
          <div className="space-y-2">
            <p className="text-[10px] font-bold text-gray-400 uppercase tracking-widest">Legitimate Signals</p>
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
      <div className="flex items-center justify-between flex-wrap gap-3 pt-1 border-t border-gray-100">
        <button
          onClick={handleExplainMore}
          disabled={loadingLLM}
          className="flex items-center gap-2 px-4 py-2.5 bg-indigo-600 hover:bg-indigo-700
                     disabled:opacity-60 text-white rounded-xl text-sm font-semibold transition-colors shadow-sm"
        >
          {loadingLLM
            ? <><Loader2 size={14} className="animate-spin" /> AI is thinking...</>
            : <><Sparkles size={14} /> {showLLM ? 'Hide AI Report' : 'View AI Forensic Report'}</>
          }
        </button>
        <button onClick={onReset}
          className="flex items-center gap-1.5 px-4 py-2.5 text-[13px] font-semibold text-gray-600 bg-gray-100 hover:bg-gray-200 rounded-xl transition">
          <RotateCcw size={13} /> Analyse another
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
  )
}

// ── Main page ──────────────────────────────────────────────────────────────────
export default function VoiceScan() {
  const [file,    setFile]    = useState(null)
  const [result,  setResult]  = useState(null)
  const [loading, setLoading] = useState(false)
  const [error,   setError]   = useState('')
  const [drag,    setDrag]    = useState(false)
  const inputRef = useRef()

  const handleFile = (f) => {
    if (!f) return
    if (!f.type.startsWith('audio/')) { setError('Please upload an audio file (MP3, WAV, OGG, M4A).'); return }
    if (f.size > 20 * 1024 * 1024)   { setError('File too large — max 20MB.'); return }
    setFile(f); setError(''); setResult(null)
  }

  const onDrop  = (e) => { e.preventDefault(); setDrag(false); handleFile(e.dataTransfer.files?.[0]) }
  const onReset = ()  => { setFile(null); setResult(null); setError('') }

  const handleScan = async () => {
    if (!file) { setError('Upload an audio file first.'); return }
    setLoading(true); setError(''); setResult(null)
    try {
      const fd = new FormData()
      fd.append('file', file)
      const r = await voiceScan(fd)
      setResult(r.data)
    } catch (e) {
      setError(e.response?.data?.error || 'Analysis failed. Please try again.')
    } finally { setLoading(false) }
  }

  return (
    <div className="max-w-[780px] space-y-5">

      {/* Hero */}
      <div className="bg-gradient-to-br from-brand-600 to-brand-700 rounded-2xl p-6 relative overflow-hidden">
        <div className="absolute right-0 top-0 w-48 h-48 bg-white/5 rounded-full -translate-y-1/4 translate-x-1/4 pointer-events-none" />
        <div className="flex items-center gap-2 mb-1">
          <Mic size={18} className="text-blue-200" />
          <h2 className="font-display font-bold text-xl text-white">Voice Deepfake Detector</h2>
        </div>
        <p className="text-blue-200 text-[13px]">
          Upload a voice recording to detect AI-generated or scam audio using ML analysis.
        </p>
      </div>

      {/* Upload card */}
      <div className="bg-white border border-gray-200 rounded-2xl p-5 space-y-4">
        <div
          onDragOver={e => { e.preventDefault(); setDrag(true) }}
          onDragLeave={() => setDrag(false)}
          onDrop={onDrop}
          onClick={() => !file && inputRef.current.click()}
          className={`relative border-2 border-dashed rounded-xl transition-all
            ${file ? 'border-emerald-300 bg-emerald-50 cursor-default p-5'
            : drag ? 'border-brand-600 bg-brand-50 cursor-copy py-12 px-6'
            : 'border-gray-200 hover:border-brand-400 hover:bg-brand-50/30 cursor-pointer py-12 px-6'}`}
        >
          <input ref={inputRef} type="file" accept="audio/*"
            onChange={e => handleFile(e.target.files?.[0])} className="hidden" />

          {file ? (
            <div className="space-y-3">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <div className="w-9 h-9 bg-emerald-100 rounded-lg flex items-center justify-center shrink-0">
                    <Waves size={16} className="text-emerald-600" />
                  </div>
                  <div>
                    <p className="text-[13px] font-semibold text-gray-800">{file.name}</p>
                    <p className="text-[11px] text-gray-400">{(file.size / 1024 / 1024).toFixed(2)} MB</p>
                  </div>
                </div>
                <button onClick={e => { e.stopPropagation(); onReset() }}
                  className="p-1.5 rounded-lg hover:bg-gray-100 text-gray-400 hover:text-gray-600 transition">
                  <X size={14} />
                </button>
              </div>
              <audio controls src={URL.createObjectURL(file)}
                className="w-full rounded-lg" style={{ height: '36px' }} />
            </div>
          ) : (
            <div className="text-center">
              <div className="w-12 h-12 bg-gray-100 rounded-xl flex items-center justify-center mx-auto mb-3">
                <Upload size={20} className="text-gray-400" />
              </div>
              <p className="text-[14px] text-gray-600">
                <span className="font-semibold text-brand-600">Click to upload</span> or drag & drop
              </p>
              <p className="text-[12px] text-gray-400 mt-1">MP3, WAV, OGG, M4A — max 20MB</p>
            </div>
          )}
        </div>

        {error && (
          <div className="flex items-center gap-2 p-3.5 bg-red-50 border border-red-100 rounded-xl text-red-600 text-[13px]">
            <AlertTriangle size={14} className="flex-shrink-0" /> {error}
          </div>
        )}

        <div className="flex gap-2">
          {file && (
            <button onClick={onReset}
              className="flex items-center gap-1.5 px-4 py-2.5 text-[13px] font-semibold text-gray-600 bg-gray-100 hover:bg-gray-200 rounded-xl transition">
              <RotateCcw size={13} /> Reset
            </button>
          )}
          <button onClick={handleScan} disabled={loading || !file}
            className="flex-1 flex items-center justify-center gap-2 py-2.5 bg-brand-600 hover:bg-brand-700 disabled:bg-gray-200 disabled:cursor-not-allowed text-white text-[14px] font-semibold rounded-xl transition shadow-brand">
            {loading
              ? <><Loader2 size={16} className="animate-spin" /> Analysing audio…</>
              : <><Mic size={15} /> Analyse voice</>
            }
          </button>
        </div>
      </div>

      {loading && (
        <div className="bg-white border border-gray-200 rounded-2xl p-8 text-center animate-fade-up">
          <div className="w-12 h-12 border-4 border-brand-100 border-t-brand-600 rounded-full animate-spin mx-auto mb-4" />
          <p className="font-semibold text-gray-700">Analysing audio with ML model...</p>
          <p className="text-[12px] text-gray-400 mt-1">Checking for AI-generated voice patterns</p>
        </div>
      )}

      {result && !loading && <VoiceResultCard result={result} file={file} onReset={onReset} />}

      {/* Info cards */}
      {!result && !loading && (
        <div className="bg-white border border-gray-100 rounded-2xl p-5">
          <p className="text-[11px] font-semibold uppercase tracking-wider text-gray-400 mb-3">What we detect</p>
          <div className="grid grid-cols-2 gap-2">
            {['AI-synthesised speech','Voice cloning attacks','Deepfake audio','Unusual frequency patterns','Unnatural speech cadence','Digital audio artifacts'].map(t => (
              <div key={t} className="flex items-center gap-2 text-[12px] text-gray-600">
                <CheckCircle2 size={13} className="text-emerald-500 shrink-0" />
                {t}
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}
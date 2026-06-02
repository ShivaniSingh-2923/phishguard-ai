import { useState, useRef } from 'react'
import axios from 'axios'
import {
  FileImage, Upload, CheckCircle2, AlertTriangle,
  AlertCircle, Loader2, RotateCcw, X, Info,
  ChevronDown, ChevronUp, ShieldCheck, ShieldAlert, Sparkles
} from 'lucide-react'

const BASE_URL = 'http://localhost:5000'

async function callOcrScan(file) {
  const formData = new FormData()
  formData.append('image', file, file.name)
  const token = localStorage.getItem('access_token')
  return axios.post(`${BASE_URL}/analyze-image`, formData, {
    headers: { ...(token ? { Authorization: `Bearer ${token}` } : {}) },
    timeout: 60000,
    withCredentials: true,
  })
}

// ── Shared style maps ──────────────────────────────────────────────────────────
const STATUS = {
  SAFE:    { color: 'text-emerald-600', bg: 'bg-emerald-50', bar: 'bg-emerald-500', icon: CheckCircle2,  label: 'No threats found'        },
  SCAM:    { color: 'text-red-600',     bg: 'bg-red-50',     bar: 'bg-red-500',     icon: AlertTriangle, label: 'Scam content detected'   },
  WARNING: { color: 'text-amber-600',   bg: 'bg-amber-50',   bar: 'bg-amber-400',   icon: AlertCircle,   label: 'Suspicious content'      },
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
function IndicatorRow({ indicator, isScam }) {
  const [open, setOpen] = useState(false)
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
function ResultSection({ result, onReset }) {
  const [showLines,  setShowLines]  = useState(false)
  const [showLLM,    setShowLLM]    = useState(false)
  const [loadingLLM, setLoadingLLM] = useState(false)
  const [llmText,    setLlmText]    = useState(result?.llm_explanation || '')

  const score        = parseFloat(result.score) || 0
  const confidence   = parseFloat(result.confidence) || 0
  const cfg          = STATUS[result.status] || STATUS.WARNING
  const Icon         = cfg.icon
  const isScam       = result.status === 'SCAM'

  // XAI fields
  const verdict        = result.verdict          || result.status || 'UNKNOWN'
  const verdictStyle   = VERDICT_STYLE[verdict]  || VERDICT_STYLE['SAFE']
  const summary        = result.summary          || ''
  const recommendation = result.recommendation   || ''
  const positiveSignals= Array.isArray(result.positive_signals) ? result.positive_signals : []

  // Rich indicators, fallback to raw reasons
  const indicators = Array.isArray(result.indicators) && result.indicators.length > 0
    ? result.indicators
    : (result.reasons || []).map(r => ({ label: r, explanation: '', raw: r }))

  const extractedText = result.extracted_text || result.text || ''
  const flaggedLines  = (result.lines || []).filter(l => l.status === 'SCAM' || l.status === 'WARNING')

  const handleExplainMore = async () => {
    if (llmText) { setShowLLM(v => !v); return }
    setLoadingLLM(true)
    try {
      const res  = await axios.post(`${BASE_URL}/explain`, {
        url:        result.url || '[OCR scan]',
        reasons:    result.reasons,
        score:      result.score,
        confidence: result.confidence,
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
            {result.message && (
              <p className="text-[12px] text-gray-400 mt-0.5">{result.message}</p>
            )}
          </div>
        </div>
        <div className="text-right shrink-0">
          <p className="text-[10px] font-black text-gray-400 uppercase tracking-widest">Risk Score</p>
          <p className={`text-2xl font-black ${cfg.color}`}>{score}%</p>
          {confidence > 0 && (
            <p className="text-xs text-gray-400 mt-0.5">{confidence}% AI confidence</p>
          )}
        </div>
      </div>

      {/* ── Progress bar ── */}
      <div className="h-2 bg-gray-100 rounded-full overflow-hidden">
        <div className={`h-full rounded-full transition-all duration-1000 ${cfg.bar}`}
          style={{ width: `${score}%` }} />
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
            <p className="text-[10px] font-bold text-gray-400 uppercase tracking-widest">Detection Flags</p>
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

      {/* ── Flagged lines (OCR specific) ── */}
      {flaggedLines.length > 0 && (
        <div>
          <button
            onClick={() => setShowLines(v => !v)}
            className="flex items-center gap-1.5 text-[12px] font-semibold text-indigo-600 hover:underline"
          >
            {showLines ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
            {flaggedLines.length} suspicious line{flaggedLines.length > 1 ? 's' : ''} found
          </button>
          {showLines && (
            <div className="mt-2 space-y-2">
              {flaggedLines.map((line, i) => (
                <div key={i} className="bg-red-50 border border-red-100 rounded-xl px-3 py-2.5">
                  <p className="text-[12px] text-red-700 font-mono leading-relaxed">{line.content}</p>
                  {line.reasons?.length > 0 && (
                    <p className="text-[10px] text-red-400 mt-1">{line.reasons.join(' · ')}</p>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* ── Extracted text (OCR specific) ── */}
      {extractedText ? (
        <div className="border-t border-gray-100 pt-4">
          <p className="text-[11px] font-bold uppercase tracking-widest text-gray-400 mb-2">Extracted Text</p>
          <div className="bg-gray-50 rounded-xl p-4 max-h-48 overflow-y-auto">
            <p className="text-[12px] text-gray-700 font-mono whitespace-pre-wrap leading-relaxed">
              {extractedText}
            </p>
          </div>
        </div>
      ) : (
        <div className="border-t border-gray-100 pt-4 text-[12px] text-gray-400 italic">
          No text could be extracted from this image.
        </div>
      )}

      {/* ── Action row ── */}
      <div className="flex items-center justify-between flex-wrap gap-3 pt-1">
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
        <button
          onClick={onReset}
          className="flex items-center gap-1.5 px-4 py-2.5 text-[13px] font-semibold
                     text-gray-600 bg-gray-100 hover:bg-gray-200 rounded-xl transition"
        >
          <RotateCcw size={13} /> Scan another
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
export default function OcrScan() {
  const [file,    setFile]    = useState(null)
  const [preview, setPreview] = useState(null)
  const [result,  setResult]  = useState(null)
  const [loading, setLoading] = useState(false)
  const [error,   setError]   = useState('')
  const [drag,    setDrag]    = useState(false)
  const inputRef = useRef()

  const handleFile = (f) => {
    if (!f) return
    const allowed = ['image/jpeg', 'image/png', 'image/webp']
    if (!allowed.includes(f.type)) { setError('Please use JPG, PNG, or WEBP.'); return }
    if (f.size > 5 * 1024 * 1024)  { setError('File too large (max 5MB).'); return }
    setFile(f); setPreview(URL.createObjectURL(f)); setError(''); setResult(null)
  }

  const onDrop  = (e) => { e.preventDefault(); setDrag(false); handleFile(e.dataTransfer.files?.[0]) }
  const onReset = ()  => { setFile(null); setPreview(null); setResult(null); setError('') }

  const handleScan = async () => {
    if (!file) { setError('Upload an image first.'); return }
    setLoading(true); setError(''); setResult(null)
    try {
      const r = await callOcrScan(file)
      setResult(r.data)
    } catch (e) {
      setError(e.response?.data?.error || e.message || 'Scan failed. Please try again.')
    } finally { setLoading(false) }
  }

  return (
    <div className="max-w-[780px] space-y-5">

      {/* Hero */}
      <div className="bg-gradient-to-br from-brand-600 to-brand-700 rounded-2xl p-6 relative overflow-hidden">
        <div className="absolute right-0 top-0 w-48 h-48 bg-white/5 rounded-full -translate-y-1/4 translate-x-1/4 pointer-events-none" />
        <div className="flex items-center gap-2 mb-1">
          <FileImage size={18} className="text-blue-200" />
          <h2 className="font-display font-bold text-xl text-white">OCR Scam Scanner</h2>
        </div>
        <p className="text-blue-200 text-[13px]">
          Upload a screenshot of any suspicious message, email, or ad. We'll extract and analyse the text.
        </p>
      </div>

      {/* Notice */}
      <div className="flex items-center gap-2.5 px-4 py-3 bg-amber-50 border border-amber-100 rounded-xl text-[13px] text-amber-700">
        <Info size={15} className="flex-shrink-0" />
        OCR scan may take 10–30 seconds. Please wait after clicking scan.
      </div>

      {/* Upload */}
      <div className="bg-white border border-gray-200 rounded-2xl p-5 space-y-4">
        <div
          onDragOver={e => { e.preventDefault(); setDrag(true) }}
          onDragLeave={() => setDrag(false)}
          onDrop={onDrop}
          onClick={() => !file && inputRef.current.click()}
          className={`relative border-2 border-dashed rounded-xl transition-all
            ${file    ? 'border-emerald-300 bg-emerald-50 cursor-default'
            : drag    ? 'border-brand-600 bg-brand-50 cursor-copy'
            : 'border-gray-200 hover:border-brand-400 hover:bg-brand-50/30 cursor-pointer'}`}
        >
          <input ref={inputRef} type="file" accept="image/jpeg,image/png,image/webp"
            onChange={e => handleFile(e.target.files?.[0])} className="hidden" />

          {file ? (
            <div className="p-5">
              {preview && (
                <img src={preview} alt="Preview"
                  className="w-full max-h-56 object-contain rounded-xl border border-gray-200 mb-3" />
              )}
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2 text-[13px] text-emerald-600 font-medium">
                  <CheckCircle2 size={15} />
                  {file.name}
                  <span className="text-gray-400 font-normal">({(file.size / 1024).toFixed(0)} KB)</span>
                </div>
                <button onClick={e => { e.stopPropagation(); onReset() }}
                  className="p-1.5 rounded-lg hover:bg-gray-100 text-gray-400 hover:text-gray-600 transition">
                  <X size={14} />
                </button>
              </div>
            </div>
          ) : (
            <div className="py-12 px-6 text-center">
              <div className="w-12 h-12 bg-gray-100 rounded-xl flex items-center justify-center mx-auto mb-3">
                <Upload size={20} className="text-gray-400" />
              </div>
              <p className="text-[14px] text-gray-600">
                <span className="font-semibold text-brand-600">Click to upload</span> or drag & drop
              </p>
              <p className="text-[12px] text-gray-400 mt-1">JPG, PNG, WEBP — max 5MB</p>
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
              ? <><Loader2 size={16} className="animate-spin" /> Analysing image…</>
              : <><FileImage size={15} /> Scan image</>
            }
          </button>
        </div>
      </div>

      {loading && (
        <div className="bg-white border border-gray-200 rounded-2xl p-8 text-center animate-fade-up">
          <div className="w-12 h-12 border-4 border-brand-100 border-t-brand-600 rounded-full animate-spin mx-auto mb-4" />
          <p className="font-semibold text-gray-700">Extracting & analysing text...</p>
          <p className="text-[12px] text-gray-400 mt-1">Running OCR — please wait up to 30 seconds</p>
        </div>
      )}

      {result && !loading && <ResultSection result={result} onReset={onReset} />}
    </div>
  )
}
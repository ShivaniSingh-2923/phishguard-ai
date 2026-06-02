// pages/ForgotPassword.jsx
// Matches the exact visual style of your Login.jsx and Register.jsx
// Uses Tailwind classes, lucide-react icons, and the same brand-600 color system.

import { useState, useRef, useEffect, useCallback } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import {
  ShieldCheck, Mail, Lock, ArrowLeft, ArrowRight,
  AlertCircle, Loader2, CheckCircle2, Eye, EyeOff,
  RotateCcw, KeyRound
} from 'lucide-react'

const API_BASE = import.meta.env.VITE_API_URL || 'http://localhost:5000'

// ── Tiny fetch helper ─────────────────────────────────────────────────────────
async function apiFetch(path, body, token = null) {
  const headers = { 'Content-Type': 'application/json' }
  if (token) headers['Authorization'] = `Bearer ${token}`
  const res = await fetch(`${API_BASE}${path}`, {
    method: 'POST',
    headers,
    body: JSON.stringify(body),
  })
  const data = await res.json()
  if (!res.ok) throw { status: res.status, ...data }
  return data
}

// ── Password strength ─────────────────────────────────────────────────────────
function pwStrength(pw) {
  if (!pw) return null
  if (pw.length < 8) return 'weak'
  if (pw.length < 12 && !/[^A-Za-z0-9]/.test(pw)) return 'good'
  return 'strong'
}

// ── Step indicator ────────────────────────────────────────────────────────────
function Steps({ current }) {
  const list = ['Email', 'OTP', 'Reset']
  const idx  = { email: 0, otp: 1, reset: 2, done: 3 }[current] ?? 0
  return (
    <div className="flex items-center gap-0 mb-7">
      {list.map((label, i) => {
        const done   = idx > i
        const active = idx === i
        return (
          <div key={label} className="flex items-center flex-1 last:flex-none">
            <div className={`w-7 h-7 rounded-full flex items-center justify-center text-[11px] font-bold flex-shrink-0 transition-all
              ${done   ? 'bg-emerald-500 text-white'
              : active ? 'bg-brand-600 text-white ring-4 ring-brand-600/20'
              :          'bg-gray-100 text-gray-400'}`}
            >
              {done ? <CheckCircle2 size={14} /> : i + 1}
            </div>
            <span className={`text-[10px] ml-1.5 font-semibold uppercase tracking-wide
              ${active ? 'text-brand-600' : done ? 'text-emerald-500' : 'text-gray-300'}`}>
              {label}
            </span>
            {i < list.length - 1 && (
              <div className={`flex-1 h-px mx-3 transition-colors ${idx > i ? 'bg-emerald-300' : 'bg-gray-150'}`} />
            )}
          </div>
        )
      })}
    </div>
  )
}

// ══════════════════════════════════════════════════════════════════════════════
// STEP 1 — Email
// ══════════════════════════════════════════════════════════════════════════════
function EmailStep({ onNext }) {
  const [email,   setEmail]   = useState('')
  const [error,   setError]   = useState('')
  const [loading, setLoading] = useState(false)

  const submit = async () => {
    setError('')
    if (!email.trim()) return setError('Email is required.')
    if (!/^[\w.-]+@[\w.-]+\.\w{2,}$/.test(email)) return setError('Invalid email address.')
    setLoading(true)
    try {
      const data = await apiFetch('/forgot-password', { email: email.trim().toLowerCase() })
      onNext(email.trim().toLowerCase(), data.resend_cooldown ?? 30)
    } catch (err) {
      if (err.status === 429 && err.seconds_remaining) {
        setError(`Wait ${err.seconds_remaining}s before requesting a new OTP.`)
      } else {
        setError(err.error || 'Something went wrong. Please try again.')
      }
    } finally {
      setLoading(false)
    }
  }

  return (
    <>
      <div className="text-center mb-7">
        <div className="w-12 h-12 bg-brand-50 rounded-2xl flex items-center justify-center mx-auto mb-4 border border-brand-100">
          <KeyRound size={22} className="text-brand-600" />
        </div>
        <h2 className="font-display font-bold text-2xl text-gray-900">Forgot Password?</h2>
        <p className="text-gray-400 text-sm mt-1">Enter your email and we'll send a 6-digit code</p>
      </div>

      <Steps current="email" />

      {error && (
        <div className="flex items-center gap-2 p-3.5 bg-red-50 text-red-600 rounded-xl border border-red-100 mb-4 animate-shake">
          <AlertCircle size={15} className="flex-shrink-0" />
          <p className="text-xs font-semibold">{error}</p>
        </div>
      )}

      <div className="mb-4">
        <label className="block text-[11px] font-semibold uppercase tracking-widest text-gray-400 mb-1.5">
          Email Address
        </label>
        <div className="relative">
          <Mail size={15} className="absolute left-3.5 top-1/2 -translate-y-1/2 text-gray-400 pointer-events-none" />
          <input
            type="email" autoFocus
            placeholder="name@company.com"
            value={email}
            onChange={e => setEmail(e.target.value)}
            onKeyDown={e => e.key === 'Enter' && submit()}
            className="w-full pl-10 pr-4 py-3 bg-gray-50 border border-gray-200 rounded-xl text-[14px] text-gray-900 placeholder:text-gray-300 focus:outline-none focus:bg-white focus:border-brand-600 focus:ring-2 focus:ring-brand-600/10 transition font-body"
          />
        </div>
      </div>

      <button
        onClick={submit} disabled={loading || !email.trim()}
        className="w-full py-3.5 bg-brand-600 hover:bg-brand-700 disabled:bg-gray-200 disabled:cursor-not-allowed text-white rounded-xl font-semibold text-[14px] shadow-brand hover:shadow-lg transition-all flex items-center justify-center gap-2 group"
      >
        {loading
          ? <Loader2 size={18} className="animate-spin" />
          : <>Send OTP <ArrowRight size={16} className="group-hover:translate-x-0.5 transition-transform" /></>
        }
      </button>
    </>
  )
}

// ══════════════════════════════════════════════════════════════════════════════
// STEP 2 — OTP
// ══════════════════════════════════════════════════════════════════════════════
function OtpStep({ email, initialCooldown, onNext, onBack }) {
  const [digits,  setDigits]  = useState(['','','','','',''])
  const [error,   setError]   = useState('')
  const [loading, setLoading] = useState(false)
  const [cooldown,setCooldown]= useState(initialCooldown)
  const [shake,   setShake]   = useState(false)
  const refs = Array.from({ length: 6 }, () => useRef(null))

  // Cooldown timer
  useEffect(() => {
    if (cooldown <= 0) return
    const t = setInterval(() => setCooldown(c => (c <= 1 ? (clearInterval(t), 0) : c - 1)), 1000)
    return () => clearInterval(t)
  }, [cooldown])

  useEffect(() => { refs[0].current?.focus() }, [])

  const handleChange = (i, val) => {
    const d = val.replace(/\D/g, '').slice(-1)
    const next = [...digits]; next[i] = d; setDigits(next)
    if (d && i < 5) refs[i + 1].current?.focus()
    if (next.every(Boolean)) submitOtp(next.join(''))
  }

  const handleKeyDown = (i, e) => {
    if (e.key === 'Backspace' && !digits[i] && i > 0) {
      const next = [...digits]; next[i - 1] = ''; setDigits(next)
      refs[i - 1].current?.focus()
    }
  }

  const handlePaste = (e) => {
    e.preventDefault()
    const pasted = e.clipboardData.getData('text').replace(/\D/g, '').slice(0, 6)
    if (pasted.length === 6) {
      setDigits(pasted.split(''))
      refs[5].current?.focus()
      submitOtp(pasted)
    }
  }

  const submitOtp = async (otp) => {
    setError(''); setLoading(true)
    try {
      const data = await apiFetch('/verify-otp', { email, otp })
      onNext(data.reset_token)
    } catch (err) {
      setShake(true); setTimeout(() => setShake(false), 500)
      setDigits(['','','','','','']); refs[0].current?.focus()
      const code = err.code || ''
      if (code === 'OTP_EXPIRED')       setError('OTP expired — request a new one below.')
      else if (code === 'OTP_MAX_ATTEMPTS') setError('Too many attempts. Please request a new OTP.')
      else setError(err.error || 'Incorrect OTP. Please try again.')
    } finally {
      setLoading(false)
    }
  }

  const resend = async () => {
    if (cooldown > 0) return
    setError('')
    try {
      const data = await apiFetch('/forgot-password', { email })
      setCooldown(data.resend_cooldown ?? 30)
      setDigits(['','','','','','']); refs[0].current?.focus()
    } catch (err) {
      setError(err.error || 'Failed to resend. Try again.')
    }
  }

  return (
    <>
      <div className="text-center mb-7">
        <div className="w-12 h-12 bg-brand-50 rounded-2xl flex items-center justify-center mx-auto mb-4 border border-brand-100">
          <Mail size={22} className="text-brand-600" />
        </div>
        <h2 className="font-display font-bold text-2xl text-gray-900">Check Your Email</h2>
        <p className="text-gray-400 text-sm mt-1">
          Code sent to <span className="text-gray-700 font-semibold">{email}</span>
        </p>
      </div>

      <Steps current="otp" />

      {error && (
        <div className="flex items-center gap-2 p-3.5 bg-red-50 text-red-600 rounded-xl border border-red-100 mb-4">
          <AlertCircle size={15} className="flex-shrink-0" />
          <p className="text-xs font-semibold">{error}</p>
        </div>
      )}

      <div className="mb-1">
        <label className="block text-[11px] font-semibold uppercase tracking-widest text-gray-400 mb-3 text-center">
          6-digit code · expires in 5 minutes
        </label>
        <div
          onPaste={handlePaste}
          className={`flex gap-2 justify-center ${shake ? 'animate-shake' : ''}`}
        >
          {digits.map((d, i) => (
            <input
              key={i} ref={refs[i]}
              type="text" inputMode="numeric" maxLength={1}
              value={d}
              onChange={e => handleChange(i, e.target.value)}
              onKeyDown={e => handleKeyDown(i, e)}
              disabled={loading}
              className={`w-11 h-13 text-center text-xl font-bold font-mono rounded-xl border-2 transition-all outline-none
                bg-gray-50 text-gray-900
                ${d ? 'border-brand-400 bg-brand-50 text-brand-700' : 'border-gray-200'}
                focus:border-brand-600 focus:ring-2 focus:ring-brand-600/10 focus:scale-105
                disabled:opacity-50`}
              style={{ height: '52px' }}
            />
          ))}
        </div>
      </div>

      <div className="text-center mt-3 mb-5">
        <span className="text-[12px] text-gray-400">Didn't get it? </span>
        <button
          onClick={resend} disabled={cooldown > 0 || loading}
          className="inline-flex items-center gap-1 text-[12px] font-semibold text-brand-600 hover:underline disabled:text-gray-300 disabled:no-underline"
        >
          <RotateCcw size={11} />
          {cooldown > 0 ? `Resend in ${cooldown}s` : 'Resend OTP'}
        </button>
      </div>

      <button
        onClick={() => submitOtp(digits.join(''))}
        disabled={loading || digits.some(d => !d)}
        className="w-full py-3.5 bg-brand-600 hover:bg-brand-700 disabled:bg-gray-200 disabled:cursor-not-allowed text-white rounded-xl font-semibold text-[14px] shadow-brand hover:shadow-lg transition-all flex items-center justify-center gap-2 group"
      >
        {loading
          ? <Loader2 size={18} className="animate-spin" />
          : <>Verify Code <ArrowRight size={16} className="group-hover:translate-x-0.5 transition-transform" /></>
        }
      </button>

      <button onClick={onBack} className="w-full mt-2 py-2 text-[12px] text-gray-400 hover:text-gray-600 flex items-center justify-center gap-1 transition-colors">
        <ArrowLeft size={13} /> Back
      </button>
    </>
  )
}

// ══════════════════════════════════════════════════════════════════════════════
// STEP 3 — Reset Password
// ══════════════════════════════════════════════════════════════════════════════
function ResetStep({ resetToken, onDone }) {
  const [form,    setForm]    = useState({ pw: '', cpw: '' })
  const [show,    setShow]    = useState({ pw: false, cpw: false })
  const [error,   setError]   = useState('')
  const [loading, setLoading] = useState(false)
  const strength = pwStrength(form.pw)

  const submit = async () => {
    setError('')
    if (!form.pw || !form.cpw)    return setError('Both fields are required.')
    if (form.pw !== form.cpw)     return setError('Passwords do not match.')
    if (form.pw.length < 8)       return setError('Password must be at least 8 characters.')
    if (!/\d/.test(form.pw))      return setError('Password must contain at least one number.')
    setLoading(true)
    try {
      await apiFetch('/reset-password', { new_password: form.pw, confirm_password: form.cpw }, resetToken)
      onDone()
    } catch (err) {
      setError(err.error || 'Reset failed. Please try again.')
    } finally {
      setLoading(false)
    }
  }

  const strengthColor = { weak: 'bg-red-400', good: 'bg-amber-400', strong: 'bg-emerald-500' }
  const strengthWidth = { weak: 'w-1/3',      good: 'w-2/3',        strong: 'w-full' }
  const strengthText  = { weak: 'Weak',        good: 'Good',          strong: 'Strong' }

  return (
    <>
      <div className="text-center mb-7">
        <div className="w-12 h-12 bg-brand-50 rounded-2xl flex items-center justify-center mx-auto mb-4 border border-brand-100">
          <Lock size={22} className="text-brand-600" />
        </div>
        <h2 className="font-display font-bold text-2xl text-gray-900">Set New Password</h2>
        <p className="text-gray-400 text-sm mt-1">Choose a strong password you haven't used before</p>
      </div>

      <Steps current="reset" />

      {error && (
        <div className="flex items-center gap-2 p-3.5 bg-red-50 text-red-600 rounded-xl border border-red-100 mb-4 animate-shake">
          <AlertCircle size={15} className="flex-shrink-0" />
          <p className="text-xs font-semibold">{error}</p>
        </div>
      )}

      {/* New password */}
      <div className="mb-4">
        <label className="block text-[11px] font-semibold uppercase tracking-widest text-gray-400 mb-1.5">
          New Password
        </label>
        <div className="relative">
          <Lock size={15} className="absolute left-3.5 top-1/2 -translate-y-1/2 text-gray-400 pointer-events-none" />
          <input
            type={show.pw ? 'text' : 'password'} autoFocus
            placeholder="Min. 8 characters"
            value={form.pw}
            onChange={e => setForm(f => ({ ...f, pw: e.target.value }))}
            className="w-full pl-10 pr-10 py-3 bg-gray-50 border border-gray-200 rounded-xl text-[14px] text-gray-900 placeholder:text-gray-300 focus:outline-none focus:bg-white focus:border-brand-600 focus:ring-2 focus:ring-brand-600/10 transition font-body"
          />
          <button type="button" onClick={() => setShow(s => ({ ...s, pw: !s.pw }))}
            className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-400 hover:text-gray-600">
            {show.pw ? <EyeOff size={15} /> : <Eye size={15} />}
          </button>
        </div>
        {strength && (
          <div className="mt-1.5">
            <div className="h-1 bg-gray-100 rounded-full overflow-hidden">
              <div className={`h-full rounded-full transition-all duration-500 ${strengthColor[strength]} ${strengthWidth[strength]}`} />
            </div>
            <p className={`text-[11px] mt-0.5 font-medium ${strength === 'weak' ? 'text-red-500' : strength === 'good' ? 'text-amber-500' : 'text-emerald-600'}`}>
              {strengthText[strength]} password
            </p>
          </div>
        )}
      </div>

      {/* Confirm password */}
      <div className="mb-5">
        <label className="block text-[11px] font-semibold uppercase tracking-widest text-gray-400 mb-1.5">
          Confirm Password
        </label>
        <div className="relative">
          <Lock size={15} className="absolute left-3.5 top-1/2 -translate-y-1/2 text-gray-400 pointer-events-none" />
          <input
            type={show.cpw ? 'text' : 'password'}
            placeholder="Repeat password"
            value={form.cpw}
            onChange={e => setForm(f => ({ ...f, cpw: e.target.value }))}
            className={`w-full pl-10 pr-10 py-3 bg-gray-50 border rounded-xl text-[14px] text-gray-900 placeholder:text-gray-300 focus:outline-none focus:bg-white focus:ring-2 transition font-body
              ${form.cpw && form.pw !== form.cpw
                ? 'border-red-300 focus:border-red-400 focus:ring-red-400/10'
                : 'border-gray-200 focus:border-brand-600 focus:ring-brand-600/10'}`}
          />
          <button type="button" onClick={() => setShow(s => ({ ...s, cpw: !s.cpw }))}
            className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-400 hover:text-gray-600">
            {show.cpw ? <EyeOff size={15} /> : <Eye size={15} />}
          </button>
        </div>
        {form.cpw && form.pw !== form.cpw && (
          <p className="text-[11px] text-red-500 mt-0.5 font-medium">Passwords don't match</p>
        )}
      </div>

      <button
        onClick={submit}
        disabled={loading || !form.pw || !form.cpw || form.pw !== form.cpw}
        className="w-full py-3.5 bg-brand-600 hover:bg-brand-700 disabled:bg-gray-200 disabled:cursor-not-allowed text-white rounded-xl font-semibold text-[14px] shadow-brand hover:shadow-lg transition-all flex items-center justify-center gap-2 group"
      >
        {loading
          ? <Loader2 size={18} className="animate-spin" />
          : <>Reset Password <ArrowRight size={16} className="group-hover:translate-x-0.5 transition-transform" /></>
        }
      </button>
    </>
  )
}

// ══════════════════════════════════════════════════════════════════════════════
// DONE screen
// ══════════════════════════════════════════════════════════════════════════════
function DoneScreen() {
  const navigate = useNavigate()
  return (
    <div className="text-center py-4">
      <div className="w-16 h-16 bg-emerald-50 rounded-full flex items-center justify-center mx-auto mb-5 border-2 border-emerald-200">
        <CheckCircle2 size={32} className="text-emerald-500" />
      </div>
      <h2 className="font-display font-bold text-2xl text-gray-900 mb-2">Password Reset! 🎉</h2>
      <p className="text-gray-400 text-sm mb-7">
        Your password has been updated successfully.<br />You can now sign in.
      </p>
      <button
        onClick={() => navigate('/login')}
        className="w-full py-3.5 bg-brand-600 hover:bg-brand-700 text-white rounded-xl font-semibold text-[14px] shadow-brand hover:shadow-lg transition-all flex items-center justify-center gap-2 group"
      >
        Back to Login <ArrowRight size={16} className="group-hover:translate-x-0.5 transition-transform" />
      </button>
    </div>
  )
}

// ══════════════════════════════════════════════════════════════════════════════
// ROOT PAGE COMPONENT
// ══════════════════════════════════════════════════════════════════════════════
export default function ForgotPassword() {
  const navigate = useNavigate()
  const [step,       setStep]       = useState('email')   // email | otp | reset | done
  const [email,      setEmail]      = useState('')
  const [cooldown,   setCooldown]   = useState(30)
  const [resetToken, setResetToken] = useState('')

  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-50 px-4 relative overflow-hidden">
      {/* Background blobs — same as Login */}
      <div className="absolute top-[-15%] left-[-10%] w-[45%] h-[45%] bg-blue-100/60 rounded-full blur-[80px] pointer-events-none" />
      <div className="absolute bottom-[-15%] right-[-10%] w-[40%] h-[40%] bg-emerald-100/60 rounded-full blur-[80px] pointer-events-none" />

      <div className="w-full max-w-[420px] relative animate-fade-up">
        <div className="bg-white border border-gray-200 rounded-3xl p-9 shadow-card">

          {/* Brand header */}
          <div className="text-center mb-6">
            <Link to="/" className="inline-flex items-center gap-2.5 group">
              <div className="w-10 h-10 bg-brand-600 rounded-xl flex items-center justify-center shadow-brand group-hover:scale-105 transition-transform">
                <ShieldCheck size={20} className="text-white" strokeWidth={2.2} />
              </div>
              <span className="font-display font-extrabold text-[18px] text-gray-900">
                PhishGuard <span className="text-brand-600">AI</span>
              </span>
            </Link>
          </div>

          {step === 'email' && (
            <EmailStep
              onNext={(em, cd) => { setEmail(em); setCooldown(cd); setStep('otp') }}
            />
          )}
          {step === 'otp' && (
            <OtpStep
              email={email}
              initialCooldown={cooldown}
              onNext={(token) => { setResetToken(token); setStep('reset') }}
              onBack={() => setStep('email')}
            />
          )}
          {step === 'reset' && (
            <ResetStep
              resetToken={resetToken}
              onDone={() => setStep('done')}
            />
          )}
          {step === 'done' && <DoneScreen />}

          {step !== 'done' && (
            <p className="text-center text-[13px] text-gray-400 mt-6">
              Remembered it?{' '}
              <Link to="/login" className="text-brand-600 font-semibold hover:underline">Sign in</Link>
            </p>
          )}
        </div>

        <p className="text-center text-[10px] text-gray-300 font-semibold uppercase tracking-[.25em] mt-6">
          PhishGuard Security Protocol
        </p>
      </div>
    </div>
  )
}
/**
 * components/auth/ProfileSecurity.jsx
 * ─────────────────────────────────────
 * Drop-in replacement for the "Security + Danger" column in Profile.jsx.
 *
 * Usage in Profile.jsx:
 *   import ProfileSecurity from '../components/auth/ProfileSecurity'
 *   ...
 *   <ProfileSecurity user={user} onAccountDeleted={logout} />
 *
 * Features:
 *   1. Change Password — 3-step modal (current pw → OTP → new pw)
 *   2. Delete Account  — 2-step modal (confirm info → password re-auth)
 */

import { useState, useEffect, useRef, useCallback } from 'react'
import {
  Lock, AlertTriangle, CheckCircle2, Loader2, Eye, EyeOff,
  RefreshCw, ArrowLeft, X, KeyRound, Trash2, ShieldCheck,
} from 'lucide-react'
import axios from 'axios'

// ── Shared Axios instance — adjust baseURL to your Flask server ───────────────
const api = axios.create({ baseURL: import.meta.env.VITE_API_URL || 'http://localhost:5000' })
api.interceptors.request.use(cfg => {
  const token = localStorage.getItem('access_token')
  if (token) cfg.headers.Authorization = `Bearer ${token}`
  return cfg
})


// ─────────────────────────── TINY REUSABLE PIECES ────────────────────────────

/** Password input with show/hide toggle */
function PasswordInput({ value, onChange, placeholder, autoFocus = false, disabled = false }) {
  const [show, setShow] = useState(false)
  return (
    <div className="relative">
      <input
        type={show ? 'text' : 'password'}
        value={value}
        onChange={onChange}
        placeholder={placeholder}
        autoFocus={autoFocus}
        disabled={disabled}
        className="w-full px-4 py-2.5 bg-gray-50 border border-gray-200 rounded-xl
                   text-[13px] text-gray-900 pr-10 disabled:opacity-50
                   focus:outline-none focus:bg-white focus:border-indigo-500
                   focus:ring-2 focus:ring-indigo-500/10 transition placeholder:text-gray-300"
      />
      <button
        type="button"
        onClick={() => setShow(s => !s)}
        tabIndex={-1}
        className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-400 hover:text-gray-600"
      >
        {show ? <EyeOff size={14} /> : <Eye size={14} />}
      </button>
    </div>
  )
}

/** Visual strength meter + rule checklist */
function StrengthMeter({ password }) {
  const rules = [
    { label: '8+ characters',     ok: password.length >= 8 },
    { label: 'Uppercase letter',  ok: /[A-Z]/.test(password) },
    { label: 'Number',            ok: /\d/.test(password) },
    { label: 'Special character', ok: /[!@#$%^&*()_+\-=\[\]{}|;:,.<>?]/.test(password) },
  ]
  const score = rules.filter(r => r.ok).length
  const barColor = ['bg-red-400', 'bg-orange-400', 'bg-yellow-400', 'bg-emerald-500'][score - 1] ?? 'bg-gray-200'

  return (
    <div className="mt-2.5 space-y-2">
      <div className="flex gap-1">
        {[0, 1, 2, 3].map(i => (
          <div key={i}
               className={`h-1 flex-1 rounded-full transition-all duration-300
                 ${i < score ? barColor : 'bg-gray-200'}`} />
        ))}
      </div>
      <div className="grid grid-cols-2 gap-x-4 gap-y-0.5">
        {rules.map(r => (
          <p key={r.label}
             className={`text-[11px] flex items-center gap-1 transition-colors
               ${r.ok ? 'text-emerald-600' : 'text-gray-400'}`}>
            <span className="text-[10px]">{r.ok ? '✓' : '○'}</span>
            {r.label}
          </p>
        ))}
      </div>
    </div>
  )
}

/** Inline status banner */
function Banner({ type, message }) {
  if (!message) return null
  const s = {
    error:   'bg-red-50 border-red-100 text-red-700',
    success: 'bg-emerald-50 border-emerald-100 text-emerald-700',
    info:    'bg-indigo-50 border-indigo-100 text-indigo-700',
    warn:    'bg-amber-50 border-amber-100 text-amber-700',
  }[type] ?? 'bg-gray-50 border-gray-100 text-gray-700'

  const icon = {
    error:   <AlertTriangle size={13} className="shrink-0 mt-0.5" />,
    success: <CheckCircle2 size={13} className="shrink-0 mt-0.5" />,
    info:    <ShieldCheck  size={13} className="shrink-0 mt-0.5" />,
    warn:    <AlertTriangle size={13} className="shrink-0 mt-0.5" />,
  }[type]

  return (
    <div className={`flex items-start gap-2 text-[12px] border rounded-xl p-3 ${s}`}>
      {icon}
      <span className="leading-relaxed">{message}</span>
    </div>
  )
}

/** Step progress bar — pass total steps and current step index (0-based) */
function StepBar({ steps, current }) {
  return (
    <div className="flex gap-1.5 px-6 pt-4">
      {Array.from({ length: steps }).map((_, i) => (
        <div key={i}
             className={`h-1 flex-1 rounded-full transition-all duration-500
               ${i < current ? 'bg-indigo-600' : i === current ? 'bg-indigo-400' : 'bg-gray-200'}`} />
      ))}
    </div>
  )
}

/** Modal chrome wrapper */
function Modal({ onClose, children }) {
  // Close on Escape key
  useEffect(() => {
    const fn = e => { if (e.key === 'Escape') onClose() }
    window.addEventListener('keydown', fn)
    return () => window.removeEventListener('keydown', fn)
  }, [onClose])

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center
                    bg-black/40 backdrop-blur-sm p-4"
         onClick={e => e.target === e.currentTarget && onClose()}>
      <div className="bg-white rounded-2xl shadow-2xl w-full max-w-md overflow-hidden
                      animate-in fade-in zoom-in-95 duration-200">
        {children}
      </div>
    </div>
  )
}


// ──────────────────── CHANGE PASSWORD MODAL ───────────────────────────────────

function ChangePasswordModal({ onClose }) {
  // step: 'current' → 'otp' → 'newpw' → 'done'
  const [step, setStep]           = useState('current')
  const [currentPw, setCurrentPw] = useState('')
  const [otp, setOtp]             = useState(['', '', '', '', '', ''])
  const [newPw, setNewPw]         = useState('')
  const [confirmPw, setConfirmPw] = useState('')
  const [loading, setLoading]     = useState(false)
  const [banner, setBanner]       = useState({ type: '', message: '' })
  const [otpTimer, setOtpTimer]   = useState(300)   // seconds
  const [resendCd, setResendCd]   = useState(0)     // resend cooldown
  const otpRefs = useRef([])

  // Countdown for OTP expiry
  useEffect(() => {
    if (step !== 'otp') return
    const id = setInterval(() => setOtpTimer(t => Math.max(0, t - 1)), 1000)
    return () => clearInterval(id)
  }, [step])

  // Countdown for resend cooldown
  useEffect(() => {
    if (resendCd <= 0) return
    const id = setInterval(() => setResendCd(c => c - 1), 1000)
    return () => clearInterval(id)
  }, [resendCd])

  const alert = useCallback((type, message) => setBanner({ type, message }), [])
  const fmtSec = s => `${Math.floor(s / 60)}:${String(s % 60).padStart(2, '0')}`

  // ── Step 1: verify current password ────────────────────────────────────────
  const handleVerifyCurrent = async () => {
    if (!currentPw) return alert('error', 'Please enter your current password.')
    setLoading(true); setBanner({})
    try {
      const { data } = await api.post('/auth/password/verify-current',
        { current_password: currentPw })
      alert('success', data.message)
      setOtpTimer(data.otp_expires_in ?? 300)
      setResendCd(30)
      setTimeout(() => { setStep('otp'); setBanner({}) }, 700)
    } catch (err) {
      const e = err.response?.data
      if (e?.days_remaining) {
        alert('warn', e.error)
      } else {
        alert('error', e?.error ?? 'Verification failed. Please try again.')
      }
    } finally {
      setLoading(false)
    }
  }

  // ── OTP input helpers ───────────────────────────────────────────────────────
  const handleOtpKey = (i, e) => {
    const digit = e.target.value.replace(/\D/g, '').slice(-1)
    const next  = [...otp]
    next[i]     = digit
    setOtp(next)
    if (digit && i < 5) otpRefs.current[i + 1]?.focus()
    if (!digit && e.nativeEvent.inputType === 'deleteContentBackward' && i > 0)
      otpRefs.current[i - 1]?.focus()
  }

  const handleOtpPaste = e => {
    const digits = e.clipboardData.getData('text').replace(/\D/g, '').slice(0, 6)
    if (digits.length === 6) {
      setOtp(digits.split(''))
      otpRefs.current[5]?.focus()
    }
    e.preventDefault()
  }

  // ── Step 2: verify OTP ──────────────────────────────────────────────────────
  const handleVerifyOtp = async () => {
    const code = otp.join('')
    if (code.length !== 6) return alert('error', 'Please fill in all 6 digits.')
    setLoading(true); setBanner({})
    try {
      const { data } = await api.post('/auth/password/verify-otp', { otp: code })
      alert('success', data.message)
      setTimeout(() => { setStep('newpw'); setBanner({}) }, 600)
    } catch (err) {
      alert('error', err.response?.data?.error ?? 'OTP verification failed.')
      if (err.response?.status === 429) {
        // Force restart
        setOtp(['', '', '', '', '', ''])
        setTimeout(() => { setStep('current'); setBanner({}) }, 2000)
      }
    } finally {
      setLoading(false)
    }
  }

  // ── Resend OTP ──────────────────────────────────────────────────────────────
  const handleResend = async () => {
    if (resendCd > 0) return
    setLoading(true); setBanner({})
    try {
      const { data } = await api.post('/auth/password/resend-otp')
      alert('info', data.message)
      setOtp(['', '', '', '', '', ''])
      setOtpTimer(300)
      setResendCd(30)
      setTimeout(() => otpRefs.current[0]?.focus(), 100)
    } catch (err) {
      const e = err.response?.data
      alert('error', e?.error ?? 'Could not resend OTP.')
      if (e?.cooldown_remaining) setResendCd(e.cooldown_remaining)
    } finally {
      setLoading(false)
    }
  }

  // ── Step 3: set new password ────────────────────────────────────────────────
  const handleSetNew = async () => {
    if (!newPw || !confirmPw) return alert('error', 'Please fill in both fields.')
    if (newPw !== confirmPw)  return alert('error', 'Passwords do not match.')
    setLoading(true); setBanner({})
    try {
      const { data } = await api.post('/auth/password/set-new',
        { new_password: newPw, confirm_password: confirmPw })
      alert('success', data.message)
      setStep('done')
    } catch (err) {
      alert('error', err.response?.data?.error ?? 'Failed to change password.')
    } finally {
      setLoading(false)
    }
  }

  const stepIndex = { current: 0, otp: 1, newpw: 2 }[step] ?? 3

  return (
    <Modal onClose={onClose}>
      {/* ── Header ── */}
      <div className="flex items-center justify-between px-6 py-4 border-b border-gray-100">
        <div className="flex items-center gap-3">
          {step !== 'current' && step !== 'done' && (
            <button onClick={() => { setStep(step === 'otp' ? 'current' : 'otp'); setBanner({}) }}
                    className="text-gray-400 hover:text-gray-700 transition">
              <ArrowLeft size={16} />
            </button>
          )}
          <div className="w-8 h-8 rounded-xl bg-indigo-50 flex items-center justify-center">
            <KeyRound size={15} className="text-indigo-600" />
          </div>
          <div>
            <p className="font-semibold text-[14px] text-gray-900">Change Password</p>
            <p className="text-[11px] text-gray-400">
              {step === 'current' && 'Step 1 of 3 — Verify identity'}
              {step === 'otp'     && 'Step 2 of 3 — Enter OTP'}
              {step === 'newpw'   && 'Step 3 of 3 — New password'}
              {step === 'done'    && 'All done!'}
            </p>
          </div>
        </div>
        <button onClick={onClose} className="text-gray-400 hover:text-gray-600 transition">
          <X size={18} />
        </button>
      </div>

      {/* ── Step bar ── */}
      {step !== 'done' && <StepBar steps={3} current={stepIndex} />}

      {/* ── Body ── */}
      <div className="px-6 py-5 space-y-4">

        {/* STEP 1 — current password */}
        {step === 'current' && (
          <>
            <div>
              <label className="block text-[11px] font-semibold uppercase tracking-widest
                                text-gray-400 mb-1.5">
                Current Password
              </label>
              <PasswordInput
                value={currentPw}
                onChange={e => setCurrentPw(e.target.value)}
                placeholder="Enter your current password"
                autoFocus
                disabled={loading}
              />
            </div>
            <Banner {...banner} />
            <button onClick={handleVerifyCurrent} disabled={loading}
                    className="w-full py-2.5 bg-indigo-600 hover:bg-indigo-700
                               disabled:bg-gray-200 disabled:cursor-not-allowed
                               text-white text-[13px] font-semibold rounded-xl
                               flex items-center justify-center gap-2 transition">
              {loading
                ? <Loader2 size={15} className="animate-spin" />
                : 'Verify & Send OTP'}
            </button>
          </>
        )}

        {/* STEP 2 — OTP */}
        {step === 'otp' && (
          <>
            <p className="text-[13px] text-gray-500 leading-relaxed">
              A 6-digit OTP was sent to your registered email.
              Enter it below within 5 minutes.
            </p>

            {/* Six digit boxes */}
            <div className="flex justify-center gap-2 py-1" onPaste={handleOtpPaste}>
              {otp.map((digit, i) => (
                <input
                  key={i}
                  ref={el => otpRefs.current[i] = el}
                  type="text"
                  inputMode="numeric"
                  maxLength={2}
                  value={digit}
                  onChange={e => handleOtpKey(i, e)}
                  onKeyDown={e => {
                    if (e.key === 'Backspace' && !digit && i > 0)
                      otpRefs.current[i - 1]?.focus()
                  }}
                  className={`w-11 h-12 text-center text-lg font-bold rounded-xl border-2
                              transition focus:outline-none
                              ${digit
                                ? 'border-indigo-500 bg-indigo-50 text-indigo-700'
                                : 'border-gray-200 bg-gray-50 text-gray-900'}
                              focus:border-indigo-500 focus:ring-2 focus:ring-indigo-500/10`}
                />
              ))}
            </div>

            {/* Expiry + resend row */}
            <div className="flex items-center justify-between">
              <span className={`text-[12px] font-medium tabular-nums
                                ${otpTimer < 60 ? 'text-red-500' : 'text-gray-400'}`}>
                {otpTimer > 0 ? `Expires in ${fmtSec(otpTimer)}` : '⚠ OTP expired'}
              </span>
              <button onClick={handleResend} disabled={resendCd > 0 || loading}
                      className="flex items-center gap-1 text-[12px] font-semibold
                                 text-indigo-600 hover:underline
                                 disabled:text-gray-300 disabled:no-underline transition">
                <RefreshCw size={11} />
                {resendCd > 0 ? `Resend in ${resendCd}s` : 'Resend OTP'}
              </button>
            </div>

            <Banner {...banner} />

            <button onClick={handleVerifyOtp}
                    disabled={loading || otp.join('').length !== 6}
                    className="w-full py-2.5 bg-indigo-600 hover:bg-indigo-700
                               disabled:bg-gray-200 disabled:cursor-not-allowed
                               text-white text-[13px] font-semibold rounded-xl
                               flex items-center justify-center gap-2 transition">
              {loading ? <Loader2 size={15} className="animate-spin" /> : 'Verify OTP'}
            </button>
          </>
        )}

        {/* STEP 3 — new password */}
        {step === 'newpw' && (
          <>
            <div className="space-y-3">
              <div>
                <label className="block text-[11px] font-semibold uppercase tracking-widest
                                  text-gray-400 mb-1.5">
                  New Password
                </label>
                <PasswordInput
                  value={newPw}
                  onChange={e => setNewPw(e.target.value)}
                  placeholder="Create a strong password"
                  autoFocus
                  disabled={loading}
                />
                {newPw && <StrengthMeter password={newPw} />}
              </div>
              <div>
                <label className="block text-[11px] font-semibold uppercase tracking-widest
                                  text-gray-400 mb-1.5">
                  Confirm Password
                </label>
                <PasswordInput
                  value={confirmPw}
                  onChange={e => setConfirmPw(e.target.value)}
                  placeholder="Repeat your new password"
                  disabled={loading}
                />
                {confirmPw && newPw !== confirmPw && (
                  <p className="text-[11px] text-red-500 mt-1">Passwords don't match</p>
                )}
              </div>
            </div>
            <Banner {...banner} />
            <button onClick={handleSetNew} disabled={loading}
                    className="w-full py-2.5 bg-indigo-600 hover:bg-indigo-700
                               disabled:bg-gray-200 disabled:cursor-not-allowed
                               text-white text-[13px] font-semibold rounded-xl
                               flex items-center justify-center gap-2 transition">
              {loading
                ? <Loader2 size={15} className="animate-spin" />
                : 'Change Password'}
            </button>
          </>
        )}

        {/* DONE */}
        {step === 'done' && (
          <div className="py-4 text-center space-y-4">
            <div className="w-14 h-14 rounded-full bg-emerald-100 flex items-center
                            justify-center mx-auto">
              <CheckCircle2 size={28} className="text-emerald-600" />
            </div>
            <div>
              <p className="font-bold text-[16px] text-gray-900">Password Changed!</p>
              <p className="text-[13px] text-gray-500 mt-1">
                Please log in again with your new credentials.
              </p>
            </div>
            <button
              onClick={() => {
                localStorage.removeItem('access_token')
                window.location.href = '/login'
              }}
              className="w-full py-2.5 bg-indigo-600 hover:bg-indigo-700
                         text-white text-[13px] font-semibold rounded-xl transition">
              Go to Login
            </button>
          </div>
        )}
      </div>
    </Modal>
  )
}


// ──────────────────── DELETE ACCOUNT MODAL ───────────────────────────────────

function DeleteAccountModal({ onClose, onDeleted }) {
  // step: 'info' → 'confirm' → 'done'
  const [step, setStep]     = useState('info')
  const [password, setPw]   = useState('')
  const [loading, setLoading] = useState(false)
  const [banner, setBanner]   = useState({ type: '', message: '' })

  const handleDelete = async () => {
    if (!password) return setBanner({ type: 'error', message: 'Password is required.' })
    setLoading(true); setBanner({})
    try {
      await api.delete('/auth/account/delete', { data: { password } })
      setStep('done')
    } catch (err) {
      setBanner({ type: 'error', message: err.response?.data?.error ?? 'Deletion failed.' })
    } finally {
      setLoading(false)
    }
  }

  return (
    <Modal onClose={onClose}>

      {/* STEP INFO */}
      {step === 'info' && (
        <>
          <div className="bg-red-50 px-6 py-5 text-center border-b border-red-100">
            <div className="w-12 h-12 rounded-full bg-red-100 flex items-center
                            justify-center mx-auto mb-3">
              <Trash2 size={22} className="text-red-500" />
            </div>
            <p className="font-bold text-[15px] text-red-700">Delete Your Account</p>
            <p className="text-[12px] text-red-400 mt-1">
              This action is permanent and cannot be reversed
            </p>
          </div>
          <div className="px-6 py-5 space-y-4">
            <div className="space-y-2">
              {[
                { icon: '✕', color: 'text-red-500',     text: 'Your login access will stop immediately' },
                { icon: '✕', color: 'text-red-500',     text: 'Your name and email will be permanently erased' },
                { icon: '✕', color: 'text-red-500',     text: 'Your password will be cleared' },
                { icon: '✓', color: 'text-emerald-600', text: 'Scan history is anonymised and retained for security research' },
                { icon: '✓', color: 'text-emerald-600', text: 'You may register a new account at any time' },
              ].map(item => (
                <div key={item.text} className="flex items-start gap-2.5">
                  <span className={`text-[13px] font-bold mt-0.5 shrink-0 ${item.color}`}>
                    {item.icon}
                  </span>
                  <p className="text-[13px] text-gray-600">{item.text}</p>
                </div>
              ))}
            </div>
            <div className="flex gap-2 pt-1">
              <button onClick={onClose}
                      className="flex-1 py-2.5 text-[13px] font-semibold text-gray-700
                                 bg-gray-100 hover:bg-gray-200 rounded-xl transition">
                Cancel
              </button>
              <button onClick={() => setStep('confirm')}
                      className="flex-1 py-2.5 text-[13px] font-semibold text-white
                                 bg-red-500 hover:bg-red-600 rounded-xl transition">
                I understand, continue
              </button>
            </div>
          </div>
        </>
      )}

      {/* STEP CONFIRM */}
      {step === 'confirm' && (
        <>
          <div className="flex items-center justify-between px-6 py-4 border-b border-gray-100">
            <div className="flex items-center gap-3">
              <button onClick={() => { setStep('info'); setBanner({}) }}
                      className="text-gray-400 hover:text-gray-700 transition">
                <ArrowLeft size={16} />
              </button>
              <p className="font-semibold text-[14px] text-gray-900">Confirm Deletion</p>
            </div>
            <button onClick={onClose} className="text-gray-400 hover:text-gray-600 transition">
              <X size={18} />
            </button>
          </div>
          <div className="px-6 py-5 space-y-4">
            <p className="text-[13px] text-gray-500 leading-relaxed">
              Enter your current password to confirm you authorise this deletion.
            </p>
            <div>
              <label className="block text-[11px] font-semibold uppercase tracking-widest
                                text-gray-400 mb-1.5">
                Password
              </label>
              <PasswordInput
                value={password}
                onChange={e => setPw(e.target.value)}
                placeholder="Enter your current password"
                autoFocus
                disabled={loading}
              />
            </div>
            <Banner {...banner} />
            <div className="flex gap-2">
              <button onClick={() => { setStep('info'); setBanner({}) }}
                      className="flex-1 py-2.5 text-[13px] font-semibold text-gray-700
                                 bg-gray-100 hover:bg-gray-200 rounded-xl transition">
                Back
              </button>
              <button onClick={handleDelete} disabled={loading}
                      className="flex-1 py-2.5 text-[13px] font-semibold text-white
                                 bg-red-500 hover:bg-red-600 disabled:bg-gray-200
                                 rounded-xl flex items-center justify-center gap-2 transition">
                {loading
                  ? <Loader2 size={14} className="animate-spin" />
                  : <><Trash2 size={13} /> Delete my account</>}
              </button>
            </div>
          </div>
        </>
      )}

      {/* DONE */}
      {step === 'done' && (
        <div className="px-6 py-10 text-center space-y-4">
          <div className="w-14 h-14 rounded-full bg-gray-100 flex items-center
                          justify-center mx-auto">
            <CheckCircle2 size={28} className="text-gray-500" />
          </div>
          <div>
            <p className="font-bold text-[15px] text-gray-900">Account Deleted</p>
            <p className="text-[13px] text-gray-500 mt-1 leading-relaxed">
              Your personal data has been permanently removed.
              Thank you for using PhishGuard.
            </p>
          </div>
          <button
            onClick={() => {
              localStorage.clear()
              onDeleted?.()               // e.g. call logout() from AuthContext
              window.location.href = '/login'
            }}
            className="w-full py-2.5 bg-gray-900 hover:bg-gray-800
                       text-white text-[13px] font-semibold rounded-xl transition">
            Return to Login
          </button>
        </div>
      )}

    </Modal>
  )
}


// ──────────────────── EXPORTED COMPONENT ─────────────────────────────────────

/**
 * ProfileSecurity
 * ────────────────
 * Props:
 *   user           — user object from AuthContext (must have password_changed_at)
 *   onAccountDeleted — callback to call after successful soft-delete (e.g. logout)
 *
 * In Profile.jsx, replace the right column with:
 *   <ProfileSecurity user={user} onAccountDeleted={logout} />
 */
export default function ProfileSecurity({ user, onAccountDeleted }) {
  const [showChangePw, setShowChangePw]   = useState(false)
  const [showDelete,   setShowDelete]     = useState(false)

  // ── Calculate remaining cooldown days ─────────────────────────────────────
  const daysLeft = (() => {
    if (!user?.password_changed_at) return 0
    const elapsed = (Date.now() - new Date(user.password_changed_at).getTime()) / 86_400_000
    return Math.max(0, 15 - Math.floor(elapsed))
  })()
  const canChange = daysLeft === 0

  // ── Days-since display ────────────────────────────────────────────────────
  const daysSince = user?.password_changed_at
    ? Math.floor((Date.now() - new Date(user.password_changed_at).getTime()) / 86_400_000)
    : null

  return (
    <>
      <div className="space-y-4">

        {/* ── Security card ── */}
        <div className="bg-white border border-gray-200 rounded-2xl p-5">
          <div className="flex items-center gap-2 mb-4">
            <Lock size={15} className="text-gray-400" />
            <h3 className="font-semibold text-[14px] text-gray-900">Security</h3>
          </div>

          <div className="divide-y divide-gray-50">

            {/* Password row */}
            <div className="flex items-center justify-between py-3">
              <div>
                <p className="text-[13px] font-medium text-gray-700">Password</p>
                <p className="text-[11px] text-gray-400 mt-0.5">
                  {daysSince !== null
                    ? `Changed ${daysSince} day${daysSince !== 1 ? 's' : ''} ago`
                    : 'Never changed'}
                </p>
                {!canChange && (
                  <p className="text-[11px] text-amber-500 mt-0.5 flex items-center gap-1">
                    <AlertTriangle size={10} />
                    Available in {daysLeft} day{daysLeft !== 1 ? 's' : ''}
                  </p>
                )}
              </div>
              <button
                onClick={() => canChange && setShowChangePw(true)}
                disabled={!canChange}
                title={!canChange ? `Available in ${daysLeft} days` : 'Change password'}
                className={`text-[12px] font-semibold transition
                  ${canChange
                    ? 'text-indigo-600 hover:underline cursor-pointer'
                    : 'text-gray-300 cursor-not-allowed'}`}>
                Change
              </button>
            </div>

            {/* 2FA row */}
            <div className="flex items-center justify-between py-3">
              <div>
                <p className="text-[13px] font-medium text-gray-700">Two-factor auth</p>
                <p className="text-[11px] text-gray-400">Add extra protection</p>
              </div>
              <button className="text-[12px] font-semibold text-indigo-600 hover:underline">
                Enable
              </button>
            </div>

          </div>
        </div>

        {/* ── Danger zone card ── */}
        <div className="bg-white border border-red-100 rounded-2xl p-5">
          <div className="flex items-center gap-2 mb-3">
            <AlertTriangle size={15} className="text-red-400" />
            <h3 className="font-semibold text-[14px] text-red-600">Danger Zone</h3>
          </div>
          <p className="text-[12px] text-gray-400 leading-relaxed mb-4">
            Deletes your account permanently. Your PII is removed immediately;
            anonymised scan history is kept for security research (GDPR-compliant).
          </p>
          <button
            onClick={() => setShowDelete(true)}
            className="w-full py-2.5 border border-red-200 text-red-600 text-[13px]
                       font-semibold rounded-xl hover:bg-red-50
                       flex items-center justify-center gap-2 transition">
            <Trash2 size={14} /> Delete account
          </button>
        </div>

      </div>

      {/* Modals — rendered outside the card flow via portals (auto in React 18+) */}
      {showChangePw && (
        <ChangePasswordModal onClose={() => setShowChangePw(false)} />
      )}
      {showDelete && (
        <DeleteAccountModal
          onClose={() => setShowDelete(false)}
          onDeleted={onAccountDeleted}
        />
      )}
    </>
  )
}
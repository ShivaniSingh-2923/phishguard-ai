/**
 * pages/Profile.jsx  — UPDATED (minimal change from your existing file)
 * ───────────────────────────────────────────────────────────────────────
 * Changes from your original:
 *   1. Import ProfileSecurity (new component)
 *   2. Pass `user` and `logout` to it in the right column
 *   3. Remove the old inline security/danger-zone JSX
 *
 * Everything else (header, stats, edit form) is unchanged.
 */

import { useState, useEffect } from 'react'
import { useAuth } from '../context/AuthContext'
import { getUserProfile, updateProfile, getMyStats } from '../api'
import {
  User, Mail, ShieldCheck, CheckCircle2, AlertTriangle,
  Loader2, Edit3, Save,
} from 'lucide-react'

// ← NEW import
import ProfileSecurity from '../components/auth/ProfileSecurity'

function StatBox({ label, value, color = 'text-gray-900' }) {
  return (
    <div className="bg-gray-50 rounded-xl p-4 text-center">
      <p className={`font-display font-bold text-2xl ${color}`}>{value}</p>
      <p className="text-[11px] text-gray-400 mt-1">{label}</p>
    </div>
  )
}

export default function Profile() {
  const { user, setUser, logout } = useAuth()
  const [form, setForm]   = useState({ name: user?.name || '', email: user?.email || '' })
  const [stats, setStats] = useState({ total_scans: 0, scams_detected: 0, community_reports: 0 })
  const [saving, setSaving]   = useState(false)
  const [success, setSuccess] = useState(false)
  const [error, setError]     = useState('')

  useEffect(() => {
    getMyStats().then(r => setStats(r.data)).catch(() => {})
  }, [])

  const initials = user?.name
    ? user.name.split(' ').map(w => w[0]).join('').slice(0, 2).toUpperCase()
    : 'U'

  const onSave = async e => {
    e.preventDefault()
    setError(''); setSuccess(false); setSaving(true)
    try {
      const r = await updateProfile(form)
      setUser(prev => ({ ...prev, ...r.data }))
      setSuccess(true)
      setTimeout(() => setSuccess(false), 3000)
    } catch (err) {
      setError(err.response?.data?.error || 'Failed to update profile.')
    } finally {
      setSaving(false)
    }
  }

  const memberSince = user?.created_at
    ? new Date(user.created_at).toLocaleDateString('en-US', { month: 'long', year: 'numeric' })
    : 'Recently'

  return (
    <div className="max-w-[860px] space-y-5">

      {/* Profile header — unchanged */}
      <div className="bg-gradient-to-br from-brand-50 to-white border border-gray-200
                      rounded-2xl p-6 flex items-center gap-5">
        <div className="w-16 h-16 rounded-2xl bg-gradient-to-br from-brand-600 to-purple-600
                        flex items-center justify-center text-white font-display font-bold
                        text-2xl flex-shrink-0">
          {initials}
        </div>
        <div className="flex-1 min-w-0">
          <h2 className="font-display font-bold text-xl text-gray-900">{user?.name}</h2>
          <p className="text-[13px] text-gray-400 mt-0.5">
            {user?.email} · Member since {memberSince}
          </p>
          <div className="flex items-center gap-2 mt-2">
            <span className="flex items-center gap-1 px-2.5 py-1 bg-brand-50 text-brand-600
                             text-[11px] font-semibold rounded-full">
              <ShieldCheck size={11} /> Pro plan
            </span>
            <span className="flex items-center gap-1 px-2.5 py-1 bg-emerald-50 text-emerald-600
                             text-[11px] font-semibold rounded-full">
              <CheckCircle2 size={11} /> Verified
            </span>
          </div>
        </div>
      </div>

      {/* Stats — unchanged */}
      <div className="grid grid-cols-3 gap-4">
        <StatBox label="Total scans"   value={stats.total_scans.toLocaleString()}       color="text-brand-600"   />
        <StatBox label="Threats caught" value={stats.scams_detected.toLocaleString()}   color="text-red-600"     />
        <StatBox label="Reports filed"  value={stats.community_reports.toLocaleString()} color="text-emerald-600" />
      </div>

      {/* Two-col grid — unchanged left col, NEW right col */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-5">

        {/* Edit form — unchanged */}
        <div className="bg-white border border-gray-200 rounded-2xl p-5">
          <div className="flex items-center gap-2 mb-4">
            <Edit3 size={15} className="text-gray-400" />
            <h3 className="font-semibold text-[14px] text-gray-900">Account details</h3>
          </div>
          <form onSubmit={onSave} className="space-y-4">
            <div>
              <label className="block text-[11px] font-semibold uppercase tracking-widest
                                text-gray-400 mb-1.5">Full name</label>
              <div className="relative">
                <User size={14} className="absolute left-3.5 top-1/2 -translate-y-1/2 text-gray-400" />
                <input
                  value={form.name}
                  onChange={e => setForm(f => ({ ...f, name: e.target.value }))}
                  className="w-full pl-10 pr-4 py-2.5 bg-gray-50 border border-gray-200 rounded-xl
                             text-[13px] text-gray-900 focus:outline-none focus:bg-white
                             focus:border-brand-600 focus:ring-2 focus:ring-brand-600/10
                             transition font-body"
                />
              </div>
            </div>
            <div>
              <label className="block text-[11px] font-semibold uppercase tracking-widest
                                text-gray-400 mb-1.5">Email</label>
              <div className="relative">
                <Mail size={14} className="absolute left-3.5 top-1/2 -translate-y-1/2 text-gray-400" />
                <input
                  type="email" value={form.email}
                  onChange={e => setForm(f => ({ ...f, email: e.target.value }))}
                  className="w-full pl-10 pr-4 py-2.5 bg-gray-50 border border-gray-200 rounded-xl
                             text-[13px] text-gray-900 focus:outline-none focus:bg-white
                             focus:border-brand-600 focus:ring-2 focus:ring-brand-600/10
                             transition font-body"
                />
              </div>
            </div>
            {error && (
              <div className="flex items-center gap-2 text-[12px] text-red-600
                              bg-red-50 border border-red-100 rounded-xl p-3">
                <AlertTriangle size={13} /> {error}
              </div>
            )}
            {success && (
              <div className="flex items-center gap-2 text-[12px] text-emerald-600
                              bg-emerald-50 border border-emerald-100 rounded-xl p-3">
                <CheckCircle2 size={13} /> Profile updated successfully
              </div>
            )}
            <button type="submit" disabled={saving}
                    className="w-full py-2.5 bg-brand-600 hover:bg-brand-700
                               disabled:bg-gray-200 text-white text-[13px] font-semibold
                               rounded-xl flex items-center justify-center gap-2
                               transition shadow-brand">
              {saving ? <Loader2 size={15} className="animate-spin" /> : <><Save size={14} /> Save changes</>}
            </button>
          </form>
        </div>

        {/*
         * ← CHANGED: Replace the old inline Security + Danger zone JSX
         *   with the new ProfileSecurity component.
         *
         *   user.password_changed_at comes from /auth/me (add it there — see app_patch.py)
         *   onAccountDeleted triggers logout + redirect via the modal's "Return to Login" button
         */}
        <ProfileSecurity
          user={user}
          onAccountDeleted={logout}
        />

      </div>
    </div>
  )
}
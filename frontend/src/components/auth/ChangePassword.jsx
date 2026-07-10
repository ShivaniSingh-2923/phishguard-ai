// components/auth/ChangePassword.jsx
// Drop this anywhere inside your profile/settings page.
// Usage: <ChangePassword />
//
// Calls POST /reset-password with the user's current access_token
// Backend needs a separate route for authenticated password change
// (see the backend snippet at the bottom of this file)

import { useState } from 'react'
import { Lock, Eye, EyeOff, Loader2, CheckCircle2, AlertCircle } from 'lucide-react'

const API_BASE = import.meta.env.VITE_API_URL || 'http://localhost:5000'

export default function ChangePassword() {
  const [form,    setForm]    = useState({ current: '', pw: '', cpw: '' })
  const [show,    setShow]    = useState({ current: false, pw: false, cpw: false })
  const [status,  setStatus]  = useState(null)   // null | 'success' | 'error'
  const [message, setMessage] = useState('')
  const [loading, setLoading] = useState(false)

  const toggle = (field) => setShow(s => ({ ...s, [field]: !s[field] }))

  const pwStrength = (pw) => {
    if (!pw) return null
    if (pw.length < 8) return 'weak'
    if (pw.length < 12 && !/[^A-Za-z0-9]/.test(pw)) return 'good'
    return 'strong'
  }
  const strength = pwStrength(form.pw)

  const submit = async (e) => {
    e.preventDefault()
    setStatus(null)

    if (!form.current) return (setStatus('error'), setMessage('Current password is required.'))
    if (form.pw.length < 8) return (setStatus('error'), setMessage('New password must be at least 8 characters.'))
    if (form.pw !== form.cpw) return (setStatus('error'), setMessage('New passwords do not match.'))
    if (!/\d/.test(form.pw)) return (setStatus('error'), setMessage('New password must contain at least one number.'))

    setLoading(true)
    try {
      const token = localStorage.getItem('access_token')
      const res   = await fetch(`${API_BASE}/auth/change-password`, {
        method:  'POST',
        headers: {
          'Content-Type':  'application/json',
          'Authorization': `Bearer ${token}`,
        },
        body: JSON.stringify({
          current_password: form.current,
          new_password:     form.pw,
          confirm_password: form.cpw,
        }),
      })
      const data = await res.json()
      if (!res.ok) throw new Error(data.error || 'Failed to update password.')

      setStatus('success')
      setMessage('Password updated successfully!')
      setForm({ current: '', pw: '', cpw: '' })
    } catch (err) {
      setStatus('error')
      setMessage(err.message)
    } finally {
      setLoading(false)
    }
  }

  const strengthColor = { weak: 'bg-red-400', good: 'bg-amber-400', strong: 'bg-emerald-500' }
  const strengthWidth = { weak: 'w-1/3',      good: 'w-2/3',        strong: 'w-full' }

  const fields = [
    { key: 'current', label: 'Current Password',  placeholder: 'Your current password' },
    { key: 'pw',      label: 'New Password',       placeholder: 'Min. 8 characters'     },
    { key: 'cpw',     label: 'Confirm New Password',placeholder: 'Repeat new password'  },
  ]

  return (
    <div className="bg-white border border-gray-200 rounded-2xl p-6 shadow-sm">
      <div className="flex items-center gap-3 mb-5 pb-4 border-b border-gray-100">
        <div className="w-9 h-9 bg-brand-50 rounded-xl flex items-center justify-center border border-brand-100">
          <Lock size={16} className="text-brand-600" />
        </div>
        <div>
          <h3 className="font-display font-bold text-[15px] text-gray-900">Change Password</h3>
          <p className="text-[12px] text-gray-400">Update your account password</p>
        </div>
      </div>

      <form onSubmit={submit} className="space-y-4">
        {fields.map(({ key, label, placeholder }) => (
          <div key={key}>
            <label className="block text-[11px] font-semibold uppercase tracking-widest text-gray-400 mb-1.5">
              {label}
            </label>
            <div className="relative">
              <Lock size={14} className="absolute left-3.5 top-1/2 -translate-y-1/2 text-gray-400 pointer-events-none" />
              <input
                type={show[key] ? 'text' : 'password'}
                placeholder={placeholder}
                value={form[key]}
                onChange={e => setForm(f => ({ ...f, [key]: e.target.value }))}
                className={`w-full pl-10 pr-10 py-2.5 bg-gray-50 border rounded-xl text-[14px] text-gray-900
                  placeholder:text-gray-300 focus:outline-none focus:bg-white focus:ring-2 transition font-body
                  ${key === 'cpw' && form.cpw && form.pw !== form.cpw
                    ? 'border-red-300 focus:border-red-400 focus:ring-red-400/10'
                    : 'border-gray-200 focus:border-brand-600 focus:ring-brand-600/10'}`}
              />
              <button type="button" onClick={() => toggle(key)}
                className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-400 hover:text-gray-600">
                {show[key] ? <EyeOff size={14} /> : <Eye size={14} />}
              </button>
            </div>
            {/* Strength bar only for new password */}
            {key === 'pw' && strength && (
              <div className="mt-1.5">
                <div className="h-1 bg-gray-100 rounded-full overflow-hidden">
                  <div className={`h-full rounded-full transition-all duration-500 ${strengthColor[strength]} ${strengthWidth[strength]}`} />
                </div>
                <p className={`text-[11px] mt-0.5 font-medium capitalize
                  ${strength === 'weak' ? 'text-red-500' : strength === 'good' ? 'text-amber-500' : 'text-emerald-600'}`}>
                  {strength} password
                </p>
              </div>
            )}
            {key === 'cpw' && form.cpw && form.pw !== form.cpw && (
              <p className="text-[11px] text-red-500 mt-0.5 font-medium">Passwords don't match</p>
            )}
          </div>
        ))}

        {/* Status message */}
        {status && (
          <div className={`flex items-center gap-2 p-3 rounded-xl border text-xs font-semibold
            ${status === 'success'
              ? 'bg-emerald-50 text-emerald-700 border-emerald-100'
              : 'bg-red-50 text-red-600 border-red-100'}`}>
            {status === 'success'
              ? <CheckCircle2 size={14} className="flex-shrink-0" />
              : <AlertCircle  size={14} className="flex-shrink-0" />}
            {message}
          </div>
        )}

        <button
          type="submit"
          disabled={loading || !form.current || !form.pw || form.pw !== form.cpw}
          className="w-full py-3 bg-brand-600 hover:bg-brand-700 disabled:bg-gray-200 disabled:cursor-not-allowed text-white rounded-xl font-semibold text-[14px] shadow-brand hover:shadow-lg transition-all flex items-center justify-center gap-2"
        >
          {loading ? <Loader2 size={16} className="animate-spin" /> : 'Update Password'}
        </button>
      </form>
    </div>
  )
}

/*
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
BACKEND: add this route to your app.py (or password_reset.py)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

@app.route("/auth/change-password", methods=["POST"])
@jwt_required()
def change_password():
    from bson import ObjectId
    user_id = get_jwt_identity()
    data    = request.get_json() or {}

    current_password  = data.get("current_password", "")
    new_password      = data.get("new_password", "")
    confirm_password  = data.get("confirm_password", "")

    if not current_password or not new_password or not confirm_password:
        return jsonify({"error": "All fields are required."}), 400

    if new_password != confirm_password:
        return jsonify({"error": "New passwords do not match."}), 400

    if len(new_password) < 8 or not any(c.isdigit() for c in new_password):
        return jsonify({"error": "Password must be 8+ characters with at least one number."}), 400

    user = users_collection.find_one({"_id": ObjectId(user_id)})
    if not user:
        return jsonify({"error": "User not found."}), 404

    if not check_password_hash(user["password"], current_password):
        return jsonify({"error": "Current password is incorrect."}), 401

    users_collection.update_one(
        {"_id": ObjectId(user_id)},
        {"$set": {
            "password": generate_password_hash(new_password),
            "password_changed_at": datetime.now(timezone.utc),
        }}
    )
    return jsonify({"message": "Password updated successfully."}), 200
*/
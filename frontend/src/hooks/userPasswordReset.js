// hooks/usePasswordReset.js
// Central state machine for the 3-step forgot-password flow.
// Steps: 'email' → 'otp' → 'reset' → 'done'

import { useState, useCallback, useRef } from 'react';

const API_BASE = import.meta.env.VITE_API_URL || 'http://localhost:5000';

const apiFetch = async (path, body) => {
  const res = await fetch(`${API_BASE}${path}`, {
    method:  'POST',
    headers: { 'Content-Type': 'application/json' },
    body:    JSON.stringify(body),
  });
  const data = await res.json();
  if (!res.ok) throw { status: res.status, ...data };
  return data;
};

export function usePasswordReset() {
  const [step, setStep]           = useState('email');   // 'email' | 'otp' | 'reset' | 'done'
  const [loading, setLoading]     = useState(false);
  const [error, setError]         = useState('');
  const [email, setEmail]         = useState('');
  const [cooldown, setCooldown]   = useState(0);         // resend cooldown seconds
  const [resetToken, setResetToken] = useState('');
  const cooldownTimer = useRef(null);

  // ── Start cooldown countdown ──────────────────────────────────────────────
  const startCooldown = useCallback((seconds) => {
    setCooldown(seconds);
    clearInterval(cooldownTimer.current);
    cooldownTimer.current = setInterval(() => {
      setCooldown(prev => {
        if (prev <= 1) { clearInterval(cooldownTimer.current); return 0; }
        return prev - 1;
      });
    }, 1000);
  }, []);

  // ── Step 1: request OTP ───────────────────────────────────────────────────
  const requestOtp = useCallback(async (emailInput) => {
    setError('');
    setLoading(true);
    try {
      const data = await apiFetch('/forgot-password', { email: emailInput });
      setEmail(emailInput.toLowerCase().trim());
      startCooldown(data.resend_cooldown ?? 30);
      setStep('otp');
      return data;
    } catch (err) {
      if (err.status === 429 && err.seconds_remaining) {
        startCooldown(err.seconds_remaining);
      }
      setError(err.error || 'Failed to send OTP. Try again.');
      throw err;
    } finally {
      setLoading(false);
    }
  }, [startCooldown]);

  // ── Resend OTP ────────────────────────────────────────────────────────────
  const resendOtp = useCallback(async () => {
    if (cooldown > 0) return;
    return requestOtp(email);
  }, [email, cooldown, requestOtp]);

  // ── Step 2: verify OTP ────────────────────────────────────────────────────
  const verifyOtp = useCallback(async (otp) => {
    setError('');
    setLoading(true);
    try {
      const data = await apiFetch('/verify-otp', { email, otp });
      setResetToken(data.reset_token);
      setStep('reset');
      return data;
    } catch (err) {
      const code = err.code || '';
      if (code === 'OTP_EXPIRED')       setError('OTP expired. Please request a new one.');
      else if (code === 'OTP_MAX_ATTEMPTS') setError('Too many attempts. Request a new OTP.');
      else setError(err.error || 'Invalid OTP. Please try again.');
      throw err;
    } finally {
      setLoading(false);
    }
  }, [email]);

  // ── Step 3: reset password ────────────────────────────────────────────────
  const resetPassword = useCallback(async (newPassword, confirmPassword) => {
    setError('');
    setLoading(true);
    try {
      const data = await fetch(`${API_BASE}/reset-password`, {
        method:  'POST',
        headers: {
          'Content-Type':  'application/json',
          'Authorization': `Bearer ${resetToken}`,
        },
        body: JSON.stringify({ new_password: newPassword, confirm_password: confirmPassword }),
      }).then(async res => {
        const d = await res.json();
        if (!res.ok) throw { status: res.status, ...d };
        return d;
      });
      setStep('done');
      return data;
    } catch (err) {
      setError(err.error || 'Password reset failed. Please try again.');
      throw err;
    } finally {
      setLoading(false);
    }
  }, [resetToken]);

  const goBack = useCallback(() => {
    setError('');
    if (step === 'otp')   setStep('email');
    if (step === 'reset') setStep('otp');
  }, [step]);

  return {
    step, loading, error, email, cooldown, resetToken,
    requestOtp, resendOtp, verifyOtp, resetPassword, goBack,
  };
}
import React, { useState } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { useTheme } from '../context/ThemeContext';
import {
  ShieldCheck,
  Mail,
  Lock,
  Eye,
  EyeOff,
  AlertCircle,
  CheckCircle2,
  Loader2,
  Shield,
  Zap,
  Lock as LockIcon,
} from 'lucide-react';

export default function Login() {
  const { login, register } = useAuth();
  const { isDark } = useTheme();
  const navigate = useNavigate();
  const location = useLocation();
  const from = '/';

  const [mode, setMode] = useState('login');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');

  const handleSubmit = async () => {
    setError('');
    setSuccess('');
    if (!email || !password) {
      setError('Please fill in both fields.');
      return;
    }
    setLoading(true);
    try {
      if (mode === 'login') {
        await login(email, password);
        navigate(from, { replace: true });
      } else {
        await register(email, password);
        setSuccess('Account created. You can now sign in.');
        setMode('login');
        setPassword('');
      }
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div
      className="relative flex min-h-screen w-full items-center justify-center overflow-hidden"
      style={{
        background: isDark
          ? 'linear-gradient(160deg, #0b1120 0%, #0f172a 40%, #1e293b 80%, #0b1120 100%)'
          : 'linear-gradient(160deg, #dbeafe 0%, #eff6ff 25%, #f8faff 50%, #eef2ff 75%, #dbeafe 100%)',
      }}
    >

      {/* ── BACKGROUND ── */}
      <div className="pointer-events-none absolute inset-0 overflow-hidden">

        {/* large soft blobs — same family, different positions */}
        <div className="absolute -left-64 -top-64 h-[800px] w-[800px] rounded-full"
          style={{ background: 'radial-gradient(circle, rgba(191,219,254,0.55) 0%, transparent 60%)' }} />

        <div className="absolute -right-48 -top-32 h-[600px] w-[600px] rounded-full"
          style={{ background: 'radial-gradient(circle, rgba(165,180,252,0.35) 0%, transparent 60%)' }} />

        <div className="absolute -bottom-48 -left-32 h-[650px] w-[650px] rounded-full"
          style={{ background: 'radial-gradient(circle, rgba(147,197,253,0.40) 0%, transparent 60%)' }} />

        <div className="absolute -bottom-32 -right-48 h-[600px] w-[600px] rounded-full"
          style={{ background: 'radial-gradient(circle, rgba(196,181,253,0.30) 0%, transparent 60%)' }} />

        {/* center soft halo — lifts the card area */}
        <div className="absolute left-1/2 top-1/2 h-[500px] w-[700px] -translate-x-1/2 -translate-y-1/2 rounded-full"
          style={{ background: 'radial-gradient(ellipse, rgba(255,255,255,0.85) 0%, transparent 65%)' }} />

        {/* single gentle wave — top, very low opacity */}
        <svg className="absolute left-0 top-0 w-full opacity-[0.18]"
          viewBox="0 0 1440 280" preserveAspectRatio="none" xmlns="http://www.w3.org/2000/svg">
          <path fill="#93c5fd"
            d="M0,128L80,117.3C160,107,320,85,480,96C640,107,800,149,960,154.7C1120,160,1280,128,1360,112L1440,96L1440,0L0,0Z" />
        </svg>

        {/* single gentle wave — bottom */}
        <svg className="absolute bottom-0 left-0 w-full opacity-[0.15]"
          viewBox="0 0 1440 280" preserveAspectRatio="none" xmlns="http://www.w3.org/2000/svg"
          style={{ transform: 'scaleX(-1)' }}>
          <path fill="#a5b4fc"
            d="M0,160L80,149.3C160,139,320,117,480,122.7C640,128,800,160,960,165.3C1120,171,1280,149,1360,138.7L1440,128L1440,280L0,280Z" />
        </svg>

      </div>

      {/* dot grid — very subtle */}
      <div
        className="pointer-events-none absolute inset-0 opacity-[0.09]"
        style={{
          backgroundImage: 'radial-gradient(circle, #3b82f6 1px, transparent 1px)',
          backgroundSize: '36px 36px',
        }}
      />

      {/* ── CARD ── */}
      <div className="relative z-10 w-full max-w-[400px] px-4">

        {/* brand */}
        <div className="mb-7 flex flex-col items-center gap-2.5">
          <div className="flex h-14 w-14 items-center justify-center rounded-2xl border border-blue-100 dark:border-blue-900/60 bg-white dark:bg-slate-800 shadow-md shadow-blue-100/50 dark:shadow-black/50">
            <img
              src="/SMS.png"
              alt="SecureMailScope"
              className="h-9 w-9 object-contain"
            />
          </div>
          <div className="text-center">
            <p className="text-[15px] font-bold tracking-tight text-slate-900 dark:text-white">
              Secure<span className="text-blue-600 dark:text-blue-400">Mail</span>Scope
            </p>
            <p className="mt-0.5 text-[11px] text-slate-400 dark:text-slate-500">
              Email Security Analysis Platform
            </p>
          </div>
        </div>

        {/* main card */}
        <div className="overflow-hidden rounded-2xl border border-slate-200/80 dark:border-slate-800 bg-white dark:bg-slate-900 shadow-xl dark:shadow-2xl shadow-slate-200/60 dark:shadow-black/60">

          {/* mode tabs */}
          <div className="relative flex border-b border-slate-100 dark:border-slate-800">
            {['login', 'register'].map((m) => (
              <button
                key={m}
                type="button"
                onClick={() => { setMode(m); setError(''); setSuccess(''); }}
                className={`flex-1 py-3.5 text-xs font-semibold transition-all ${
                  mode === m
                    ? 'text-blue-600 dark:text-blue-400'
                    : 'text-slate-400 dark:text-slate-500 hover:text-slate-600 dark:hover:text-slate-300'
                }`}
              >
                {m === 'login' ? 'Sign in' : 'Create account'}
              </button>
            ))}
            {/* sliding underline */}
            <div
              className="absolute bottom-0 h-[2px] w-1/2 rounded-full bg-blue-600 dark:bg-blue-400 transition-all duration-300"
              style={{ left: mode === 'login' ? '0%' : '50%' }}
            />
          </div>

          <div className="p-7">

            {/* heading */}
            <div className="mb-6">
              <h2 className="text-[18px] font-bold tracking-tight text-slate-900 dark:text-white">
                {mode === 'login' ? 'Welcome back' : 'Get started'}
              </h2>
              <p className="mt-1 text-xs leading-5 text-slate-500 dark:text-slate-400">
                {mode === 'login'
                  ? 'Sign in to inspect email captures and security posture.'
                  : 'Create an account to begin analyzing PCAP captures.'}
              </p>
            </div>

            {/* error */}
            {error && (
              <div className="mb-5 flex items-start gap-2.5 rounded-xl border border-red-100 dark:border-red-900/60 bg-red-50 dark:bg-red-950/40 px-3.5 py-3">
                <AlertCircle className="mt-0.5 h-3.5 w-3.5 shrink-0 text-red-500" />
                <p className="text-xs font-medium text-red-600 dark:text-red-400">{error}</p>
              </div>
            )}

            {/* success */}
            {success && (
              <div className="mb-5 flex items-start gap-2.5 rounded-xl border border-yellow-100 dark:border-yellow-900/60 bg-yellow-50 dark:bg-yellow-950/40 px-3.5 py-3">
                <CheckCircle2 className="mt-0.5 h-3.5 w-3.5 shrink-0 text-yellow-600 dark:text-yellow-400" />
                <p className="text-xs font-medium text-yellow-700 dark:text-yellow-300">{success}</p>
              </div>
            )}

            {/* fields */}
            <div className="space-y-4">

              {/* email */}
              <div>
                <label className="mb-1.5 block text-xs font-semibold text-slate-600 dark:text-slate-300">
                  Email address
                </label>
                <div className="relative">
                  <Mail className="pointer-events-none absolute left-3.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-slate-400" />
                  <input
                    type="email"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    onKeyDown={(e) => e.key === 'Enter' && handleSubmit()}
                    placeholder="you@example.com"
                    autoComplete="email"
                    className="
                      w-full rounded-xl border border-slate-200 dark:border-slate-700
                      bg-slate-50 dark:bg-slate-800/80 py-2.5 pl-10 pr-4
                      text-sm text-slate-900 dark:text-slate-100 placeholder-slate-400 dark:placeholder-slate-500
                      outline-none transition-all
                      focus:border-blue-400 focus:bg-white dark:focus:bg-slate-800 focus:ring-3 focus:ring-blue-100 dark:focus:ring-blue-900/30
                      hover:border-slate-300 dark:hover:border-slate-600
                    "
                  />
                </div>
              </div>

              {/* password */}
              <div>
                <label className="mb-1.5 block text-xs font-semibold text-slate-600 dark:text-slate-300">
                  Password
                </label>
                <div className="relative">
                  <Lock className="pointer-events-none absolute left-3.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-slate-400" />
                  <input
                    type={showPassword ? 'text' : 'password'}
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    onKeyDown={(e) => e.key === 'Enter' && handleSubmit()}
                    placeholder="••••••••"
                    autoComplete={mode === 'login' ? 'current-password' : 'new-password'}
                    className="
                      w-full rounded-xl border border-slate-200 dark:border-slate-700
                      bg-slate-50 dark:bg-slate-800/80 py-2.5 pl-10 pr-10
                      text-sm text-slate-900 dark:text-slate-100 placeholder-slate-400 dark:placeholder-slate-500
                      outline-none transition-all
                      focus:border-blue-400 focus:bg-white dark:focus:bg-slate-800 focus:ring-3 focus:ring-blue-100 dark:focus:ring-blue-900/30
                      hover:border-slate-300 dark:hover:border-slate-600
                    "
                  />
                  <button
                    type="button"
                    onClick={() => setShowPassword(!showPassword)}
                    className="absolute right-3.5 top-1/2 -translate-y-1/2 text-slate-400 transition-colors hover:text-slate-600 dark:hover:text-slate-200"
                  >
                    {showPassword
                      ? <EyeOff className="h-3.5 w-3.5" />
                      : <Eye className="h-3.5 w-3.5" />}
                  </button>
                </div>
              </div>

              {/* submit */}
              <button
                type="button"
                onClick={handleSubmit}
                disabled={loading}
                className="
                  mt-1 flex w-full items-center justify-center gap-2
                  rounded-xl bg-blue-600 py-2.5
                  text-sm font-semibold text-white
                  shadow-md shadow-blue-200
                  transition-all
                  hover:bg-blue-700 hover:shadow-lg hover:shadow-blue-200
                  active:scale-[0.98]
                  disabled:cursor-not-allowed disabled:opacity-60
                "
              >
                {loading ? (
                  <Loader2 className="h-4 w-4 animate-spin" />
                ) : (
                  <ShieldCheck className="h-4 w-4" />
                )}
                {loading
                  ? (mode === 'login' ? 'Signing in...' : 'Creating account...')
                  : (mode === 'login' ? 'Sign in securely' : 'Create account')}
              </button>

            </div>

          </div>

         

        </div>

        <p className="mt-5 text-center text-[10px] text-slate-400">
          © 2026 Team PORT587 · SIH PS ID 26159
        </p>

      </div>
    </div>
  );
}
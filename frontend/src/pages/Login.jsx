import React, { useState } from 'react';
import { useNavigate, useLocation, Link } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import {
  ShieldCheck,
  Mail,
  Lock,
  Eye,
  EyeOff,
  AlertCircle,
  CheckCircle2,
  Loader2,
  UserPlus,
  LogIn,
} from 'lucide-react';

export default function Login() {
  const { login, register } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();

  const from = location.state?.from?.pathname
    ? `${location.state.from.pathname}${location.state.from.hash || ''}`
    : typeof location.state?.from === 'string'
    ? location.state.from
    : '/';

  const [mode, setMode] = useState('login');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');

  const handleSubmit = async (e) => {
    if (e) e.preventDefault();
    setError('');
    setSuccess('');

    if (!email.trim() || !password.trim()) {
      setError('Please fill in both email and password.');
      return;
    }

    if (mode === 'register' && password.length < 8) {
      setError('Password must be at least 8 characters long.');
      return;
    }

    setLoading(true);
    try {
      if (mode === 'login') {
        await login(email, password);
        navigate(from, { replace: true });
      } else {
        await register(email, password);
        setSuccess('Account created successfully! You can now sign in.');
        setMode('login');
        setPassword('');
      }
    } catch (err) {
      setError(err.message || 'Authentication failed. Please check your credentials.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="w-full flex-1 flex flex-col justify-center items-center px-4 py-8 sm:py-12 my-auto">
      
      {/* BRAND LOGO HEADER */}
      <div className="w-full max-w-[420px] mb-6 flex flex-col items-center">
        <Link
          to="/"
          className="group inline-flex items-center gap-2.5 transition-transform hover:scale-105"
        >
          <img
            src="/new_sms_logo.png"
            alt="SecureMailScope"
            className="h-10 w-10 object-contain drop-shadow-sm"
          />
          <div className="text-left">
            <span className="font-extrabold tracking-tight text-slate-900 dark:text-white text-lg">
              Secure<span className="text-brand-600 dark:text-brand-400">Mail</span>Scope
            </span>
            <p className="text-[10px] text-slate-500 dark:text-slate-400 font-medium">
              Email Security Analysis Platform
            </p>
          </div>
        </Link>
      </div>

      {/* MAIN AUTHENTICATION CARD */}
      <div className="w-full max-w-[420px] rounded-2xl border border-slate-200/90 dark:border-slate-800 bg-white dark:bg-slate-900 shadow-xl shadow-slate-200/50 dark:shadow-black/40 overflow-hidden transition-colors">
        
        {/* TAB SWITCHER */}
        <div className="flex border-b border-slate-100 dark:border-slate-800 bg-slate-50/60 dark:bg-slate-850/60 p-1.5 gap-1.5">
          <button
            type="button"
            onClick={() => {
              setMode('login');
              setError('');
              setSuccess('');
            }}
            className={`flex-1 py-2 text-xs font-semibold rounded-xl transition-all cursor-pointer ${
              mode === 'login'
                ? 'bg-white dark:bg-slate-800 text-slate-900 dark:text-white shadow-xs border border-slate-200/80 dark:border-slate-700'
                : 'text-slate-500 dark:text-slate-400 hover:text-slate-800 dark:hover:text-slate-200'
            }`}
          >
            Sign In
          </button>
          <button
            type="button"
            onClick={() => {
              setMode('register');
              setError('');
              setSuccess('');
            }}
            className={`flex-1 py-2 text-xs font-semibold rounded-xl transition-all cursor-pointer ${
              mode === 'register'
                ? 'bg-white dark:bg-slate-800 text-slate-900 dark:text-white shadow-xs border border-slate-200/80 dark:border-slate-700'
                : 'text-slate-500 dark:text-slate-400 hover:text-slate-800 dark:hover:text-slate-200'
            }`}
          >
            Create Account
          </button>
        </div>

        {/* CARD BODY */}
        <div className="p-6 sm:p-7">
          <div className="mb-6">
            <h1 className="text-xl font-bold tracking-tight text-slate-900 dark:text-white">
              {mode === 'login' ? 'Welcome back' : 'Create an analyst account'}
            </h1>
            <p className="mt-1 text-xs text-slate-500 dark:text-slate-400 leading-relaxed font-normal">
              {mode === 'login'
                ? 'Sign in to inspect email captures, view threat telemetry, and export reports.'
                : 'Register your account to upload and analyze PCAP email network traffic.'}
            </p>
          </div>

          {/* ERROR ALERT */}
          {error && (
            <div className="mb-5 flex items-start gap-2.5 rounded-xl border border-rose-200 dark:border-rose-900/60 bg-rose-50 dark:bg-rose-950/40 p-3 text-xs text-rose-700 dark:text-rose-300">
              <AlertCircle className="h-4 w-4 shrink-0 text-rose-500 mt-0.5" />
              <p className="font-medium leading-relaxed">{error}</p>
            </div>
          )}

          {/* SUCCESS ALERT */}
          {success && (
            <div className="mb-5 flex items-start gap-2.5 rounded-xl border border-emerald-200 dark:border-emerald-900/60 bg-emerald-50 dark:bg-emerald-950/40 p-3 text-xs text-emerald-700 dark:text-emerald-300">
              <CheckCircle2 className="h-4 w-4 shrink-0 text-emerald-500 mt-0.5" />
              <p className="font-medium leading-relaxed">{success}</p>
            </div>
          )}

          {/* FORM FIELDS */}
          <form onSubmit={handleSubmit} className="space-y-4">
            
            {/* EMAIL INPUT */}
            <div>
              <label
                htmlFor="email"
                className="mb-1.5 block text-xs font-semibold text-slate-700 dark:text-slate-300"
              >
                Email address
              </label>
              <div className="relative">
                <Mail className="pointer-events-none absolute left-3.5 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-400" />
                <input
                  id="email"
                  type="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder="analyst@organization.local"
                  autoComplete="email"
                  required
                  className="w-full rounded-xl border border-slate-200 dark:border-slate-700 bg-slate-50/50 dark:bg-slate-800/80 py-2.5 pl-10 pr-4 text-sm text-slate-900 dark:text-white placeholder:text-slate-400 focus:outline-none focus:bg-white dark:focus:bg-slate-800 focus:border-brand-500 focus:ring-2 focus:ring-brand-500/20 transition-all hover:border-slate-300 dark:hover:border-slate-600"
                />
              </div>
            </div>

            {/* PASSWORD INPUT */}
            <div>
              <label
                htmlFor="password"
                className="mb-1.5 block text-xs font-semibold text-slate-700 dark:text-slate-300"
              >
                Password
              </label>
              <div className="relative">
                <Lock className="pointer-events-none absolute left-3.5 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-400" />
                <input
                  id="password"
                  type={showPassword ? 'text' : 'password'}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder={mode === 'login' ? '••••••••' : 'Minimum 8 characters'}
                  autoComplete={mode === 'login' ? 'current-password' : 'new-password'}
                  required
                  className="w-full rounded-xl border border-slate-200 dark:border-slate-700 bg-slate-50/50 dark:bg-slate-800/80 py-2.5 pl-10 pr-10 text-sm text-slate-900 dark:text-white placeholder:text-slate-400 focus:outline-none focus:bg-white dark:focus:bg-slate-800 focus:border-brand-500 focus:ring-2 focus:ring-brand-500/20 transition-all hover:border-slate-300 dark:hover:border-slate-600"
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  aria-label={showPassword ? 'Hide password' : 'Show password'}
                  className="absolute right-3 top-1/2 -translate-y-1/2 p-1 text-slate-400 hover:text-slate-600 dark:hover:text-slate-200 transition-colors cursor-pointer"
                >
                  {showPassword ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                </button>
              </div>
            </div>

            {/* SUBMIT BUTTON */}
            <button
              type="submit"
              disabled={loading}
              className="mt-2 w-full inline-flex items-center justify-center gap-2 rounded-xl bg-brand-600 hover:bg-brand-700 dark:bg-brand-500 dark:hover:bg-brand-400 py-2.5 text-sm font-semibold text-white shadow-sm shadow-brand-500/25 transition-all duration-150 hover:-translate-y-0.5 active:translate-y-0 active:scale-[0.99] disabled:opacity-60 disabled:cursor-not-allowed cursor-pointer"
            >
              {loading ? (
                <>
                  <Loader2 className="h-4 w-4 animate-spin" />
                  <span>{mode === 'login' ? 'Signing in...' : 'Creating account...'}</span>
                </>
              ) : mode === 'login' ? (
                <>
                  <ShieldCheck className="h-4 w-4" />
                  <span>Sign in securely</span>
                </>
              ) : (
                <>
                  <UserPlus className="h-4 w-4" />
                  <span>Create analyst account</span>
                </>
              )}
            </button>
          </form>

        </div>
      </div>

    </div>
  );
}
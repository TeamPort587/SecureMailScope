import React, { useState } from 'react';
import { useNavigate, useLocation, Link } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { ShieldCheck, Mail, Lock, Eye, EyeOff, AlertCircle } from 'lucide-react';

export default function Login() {
    const { login, register } = useAuth();
    const navigate = useNavigate();
    const location = useLocation();
    const from = location.state?.from?.pathname || '/';

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
            setError('Please fill in all fields.');
            return;
        }

        setLoading(true);
        try {
            if (mode === 'login') {
                await login(email, password);
                navigate(from, { replace: true });
            } else {
                await register(email, password);
                setSuccess('Account created! You can now log in.');
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
        <div className="flex min-h-screen bg-slate-50">

            {/* LEFT PANEL */}
            <div className="hidden lg:flex lg:w-1/2 flex-col justify-between bg-gradient-to-br from-brand-700 via-brand-600 to-brand-500 p-12">

                <div className="flex items-center gap-3">
                    <img src="/SMS.png" alt="SecureMailScope" className="h-10 w-10 object-contain" />
                    <div>
                        <p className="text-[15px] font-bold text-white leading-tight">
                            Secure<span className="text-brand-200">Mail</span>Scope
                        </p>
                        <p className="text-[10px] text-brand-200 mt-0.5">Email Security Analysis</p>
                    </div>
                </div>

                <div>
                    <div className="mb-6 inline-flex items-center gap-2 rounded-full border border-brand-400/40 bg-brand-500/30 px-3 py-1.5 backdrop-blur-sm">
                        <ShieldCheck className="h-3.5 w-3.5 text-brand-200" />
                        <span className="text-[11px] font-semibold uppercase tracking-wider text-brand-100">
                            Email Protocol Inspector
                        </span>
                    </div>

                    <h1 className="text-4xl font-bold leading-tight text-white">
                        Assess. Analyze.<br />Strengthen.
                    </h1>

                    <p className="mt-4 max-w-sm text-sm leading-6 text-brand-100/80">
                        Reconstruct email sessions, evaluate TLS protection,
                        detect exposed credentials, and score protocol-level
                        security risk from PCAP captures.
                    </p>

                    <div className="mt-10 grid grid-cols-3 gap-4">
                        {[
                            { label: 'SMTP', desc: 'Mail transfer' },
                            { label: 'IMAP', desc: 'Mailbox access' },
                            { label: 'POP3', desc: 'Mail retrieval' },
                        ].map((p) => (
                            <div key={p.label} className="rounded-xl border border-brand-400/30 bg-brand-500/20 px-3 py-3 backdrop-blur-sm">
                                <p className="font-mono text-sm font-bold text-white">{p.label}</p>
                                <p className="mt-0.5 text-[10px] text-brand-200">{p.desc}</p>
                            </div>
                        ))}
                    </div>
                </div>

                <p className="text-[10px] text-brand-300">
                    © 2026 Team PORT587 · SIH PS ID 26159
                </p>
            </div>

            {/* RIGHT PANEL */}
            <div className="flex flex-1 flex-col items-center justify-center px-6 py-12">

                {/* Mobile brand */}
                <div className="mb-8 flex items-center gap-2 lg:hidden">
                    <img src="/SMS.png" alt="SecureMailScope" className="h-9 w-9 object-contain" />
                    <p className="text-[15px] font-bold text-slate-900">
                        Secure<span className="text-brand-600">Mail</span>Scope
                    </p>
                </div>

                <div className="w-full max-w-sm">

                    {/* Heading */}
                    <div className="mb-8">
                        <h2 className="text-2xl font-bold tracking-tight text-slate-900">
                            {mode === 'login' ? 'Sign in to your account' : 'Create an account'}
                        </h2>
                        <p className="mt-1.5 text-sm text-slate-500">
                            {mode === 'login'
                                ? 'Enter your credentials to access the platform.'
                                : 'Register to start analyzing email captures.'}
                        </p>
                    </div>

                    {/* Error */}
                    {error && (
                        <div className="mb-5 flex items-start gap-2.5 rounded-xl border border-red-200 bg-red-50 px-4 py-3">
                            <AlertCircle className="mt-0.5 h-4 w-4 shrink-0 text-red-500" />
                            <p className="text-xs font-medium text-red-700">{error}</p>
                        </div>
                    )}

                    {/* Success */}
                    {success && (
                        <div className="mb-5 flex items-start gap-2.5 rounded-xl border border-green-200 bg-green-50 px-4 py-3">
                            <ShieldCheck className="mt-0.5 h-4 w-4 shrink-0 text-green-600" />
                            <p className="text-xs font-medium text-green-700">{success}</p>
                        </div>
                    )}

                    {/* Form */}
                    <div className="space-y-4">

                        {/* Email */}
                        <div>
                            <label className="mb-1.5 block text-xs font-semibold text-slate-700">
                                Email address
                            </label>
                            <div className="relative">
                                <Mail className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-400" />
                                <input
                                    type="email"
                                    value={email}
                                    onChange={(e) => setEmail(e.target.value)}
                                    onKeyDown={(e) => e.key === 'Enter' && handleSubmit()}
                                    placeholder="you@example.com"
                                    className="ui-input pl-10"
                                    autoComplete="email"
                                />
                            </div>
                        </div>

                        {/* Password */}
                        <div>
                            <label className="mb-1.5 block text-xs font-semibold text-slate-700">
                                Password
                            </label>
                            <div className="relative">
                                <Lock className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-400" />
                                <input
                                    type={showPassword ? 'text' : 'password'}
                                    value={password}
                                    onChange={(e) => setPassword(e.target.value)}
                                    onKeyDown={(e) => e.key === 'Enter' && handleSubmit()}
                                    placeholder="••••••••"
                                    className="ui-input pl-10 pr-10"
                                    autoComplete={mode === 'login' ? 'current-password' : 'new-password'}
                                />
                                <button
                                    type="button"
                                    onClick={() => setShowPassword(!showPassword)}
                                    className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-600"
                                >
                                    {showPassword ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                                </button>
                            </div>
                        </div>

                        {/* Submit */}
                        <button
                            type="button"
                            onClick={handleSubmit}
                            disabled={loading}
                            className="w-full rounded-xl bg-brand-600 px-4 py-2.5 text-sm font-semibold text-white shadow-sm transition-all hover:bg-brand-700 hover:shadow-md disabled:cursor-not-allowed disabled:opacity-60"
                        >
                            {loading
                                ? (mode === 'login' ? 'Signing in...' : 'Creating account...')
                                : (mode === 'login' ? 'Sign in' : 'Create account')}
                        </button>

                    </div>

                    {/* Toggle mode */}
                    <p className="mt-6 text-center text-xs text-slate-500">
                        {mode === 'login' ? "Don't have an account?" : 'Already have an account?'}{' '}
                        <button
                            type="button"
                            onClick={() => { setMode(mode === 'login' ? 'register' : 'login'); setError(''); setSuccess(''); }}
                            className="font-semibold text-brand-600 hover:text-brand-700"
                        >
                            {mode === 'login' ? 'Create one' : 'Sign in'}
                        </button>
                    </p>

                </div>
            </div>

        </div>
    );
}
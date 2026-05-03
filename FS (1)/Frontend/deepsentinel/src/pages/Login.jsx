import React, { useState, useEffect, useRef } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Shield, Lock, Mail, ArrowRight, Smartphone, ArrowLeft } from 'lucide-react';
import { Link } from 'react-router-dom';
import Particles from "react-tsparticles";
import { loadSlim } from "tsparticles-slim";
import QRCode from 'qrcode';
import { register, login, verifyOtp } from '../api/auth';

const BACKEND_DASHBOARD_URL = import.meta.env.VITE_BACKEND_DASHBOARD_URL || 'http://localhost:5000/dashboard';

export default function Login() {
  const [mode, setMode] = useState('login');
  const [step, setStep] = useState(1); // 1 = Credentials, 2 = 2FA
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [cursor, setCursor] = useState({ x: 0, y: 0 });
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [authError, setAuthError] = useState('');
  const [successMessage, setSuccessMessage] = useState('');
  const [otp, setOtp] = useState(['', '', '', '', '', '']);
  const [otpauthUrl, setOtpauthUrl] = useState('');
  const [qrCodeUrl, setQrCodeUrl] = useState('');
  const otpRefs = useRef([]);

  useEffect(() => {
    const move = (e) => requestAnimationFrame(() => setCursor({ x: e.clientX, y: e.clientY }));
    window.addEventListener("mousemove", move);

    return () => window.removeEventListener("mousemove", move);
  }, []);

  useEffect(() => {
    if (!otpauthUrl) {
      setQrCodeUrl('');
      return;
    }

    QRCode.toDataURL(otpauthUrl)
      .then((url) => setQrCodeUrl(url))
      .catch((error) => {
        console.error('QR code generation failed', error);
        setQrCodeUrl('');
      });
  }, [otpauthUrl]);

  const handleInitialSubmit = async (e) => {
    e.preventDefault();
    if (!email || !password) {
      setAuthError('Please enter your email and passphrase.');
      return;
    }

    setAuthError('');
    setIsSubmitting(true);

    try {
      if (mode === 'register') {
        const data = await register({ email, password });
        setOtpauthUrl(data.otpauthUrl);
        setStep(2);
        setSuccessMessage('Account created. Scan the QR code and verify the code to finish registration. Then sign in to access the dashboard.');
      } else {
        await login({ email, password });
        setStep(2);
        setSuccessMessage('');
      }
    } catch (error) {
      setAuthError(error.message);
    } finally {
      setIsSubmitting(false);
    }
  };

  const handle2FASubmit = async (e) => {
    e.preventDefault();
    const otpValue = otp.join('');
    if (otpValue.length < 6) {
      setAuthError('Enter all 6 digits of the authentication code.');
      return;
    }

    setAuthError('');
    setIsSubmitting(true);

    try {
      const data = await verifyOtp({ email, token: otpValue });
      if (mode === 'register') {
        setSuccessMessage('Registration complete. Now sign in using your email, passphrase, and 2FA code.');
        setMode('login');
        setStep(1);
        setOtp(['', '', '', '', '', '']);
        setOtpauthUrl('');
        setQrCodeUrl('');
        setAuthError('');
      } else {
        window.localStorage.setItem('deepsentinelToken', data.token);
        window.location.href = BACKEND_DASHBOARD_URL;
      }
    } catch (error) {
      setAuthError(error.message);
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleOtpChange = (index, value) => {
    if (value && isNaN(value)) return;
    const newOtp = [...otp];
    newOtp[index] = value.substring(value.length - 1);
    setOtp(newOtp);

    if (value !== '' && index < 5) {
      otpRefs.current[index + 1]?.focus();
    }
  };

  const handleOtpKeyDown = (index, e) => {
    if (e.key === 'Backspace' && !otp[index] && index > 0) {
      otpRefs.current[index - 1]?.focus();
    }
  };

  const particlesInit = async (engine) => {
    await loadSlim(engine);
  };

  return (
    <div className="min-h-screen bg-brand-darker text-white relative flex items-center justify-center overflow-hidden font-sans">
      
      {/* Background Ambience */}
      <div
        className="fixed pointer-events-none w-[500px] h-[500px] rounded-full bg-brand-blue/10 blur-[120px] transition-transform duration-75 ease-out z-0"
        style={{ transform: `translate(${cursor.x - 250}px, ${cursor.y - 250}px)` }}
      />
      
      <Particles
        id="tsparticles-login"
        init={particlesInit}
        options={{
          background: { color: { value: "transparent" } },
          fpsLimit: 60,
          particles: {
            color: { value: "#38bdf8" },
            links: { color: "#1d4ed8", distance: 120, enable: true, opacity: 0.2, width: 1 },
            move: { enable: true, speed: 0.5, direction: "top", outModes: "out" },
            number: { value: 30 },
            opacity: { value: 0.3 },
            shape: { type: "circle" },
            size: { value: { min: 1, max: 2 } },
          },
        }}
        className="absolute inset-0 z-0 pointer-events-none"
      />

      {/* Main Login Card Container */}
      <motion.div 
        initial={{ opacity: 0, scale: 0.95, y: 20 }}
        animate={{ opacity: 1, scale: 1, y: 0 }}
        transition={{ duration: 0.8, ease: "easeOut" }}
        className="relative z-10 w-full max-w-md"
      >
        <div className="absolute inset-0 bg-brand-blue/20 blur-[100px] -z-10 rounded-[40px]"></div>
        
        <div className="bg-brand-dark/80 backdrop-blur-2xl border border-white/10 p-10 rounded-[32px] shadow-2xl relative overflow-hidden group min-h-[600px] flex flex-col justify-center">
          
          <div className="absolute inset-0 bg-gradient-to-tr from-transparent via-white/[0.03] to-transparent transform -translate-x-[100%] group-hover:translate-x-[100%] transition-transform duration-1000"></div>

          <div className="flex flex-col items-center mb-8">
            <Link to="/">
              <motion.div 
                whileHover={{ scale: 1.1, rotate: 5 }}
                className="w-16 h-16 bg-brand-blue/20 rounded-2xl border border-brand-blue/30 flex items-center justify-center mb-6 cursor-pointer shadow-[0_0_20px_rgba(29,78,216,0.4)]"
              >
                <Shield className="w-8 h-8 text-brand-accent" />
              </motion.div>
            </Link>
            <h1 className="text-3xl font-display font-bold text-white mb-2">DeepSentinel</h1>
            <p className="text-gray-400 font-medium tracking-wide">Secure Systems Access</p>
          </div>

          {/* Form Stages */}
          <div className="relative">
            <AnimatePresence mode="wait">
              {step === 1 && (
                <motion.div
                  key="step1"
                  initial={{ opacity: 0, x: -30 }}
                  animate={{ opacity: 1, x: 0 }}
                  exit={{ opacity: 0, x: -30 }}
                  transition={{ duration: 0.4 }}
                >
                  <form onSubmit={handleInitialSubmit} className="space-y-6">
                    <div className="flex flex-col gap-4 mb-4">
                      <div className="flex rounded-full bg-white/5 p-1 border border-white/10 overflow-hidden text-sm">
                        <button
                          type="button"
                          onClick={() => {
                            setMode('login');
                            setAuthError('');
                            setSuccessMessage('');
                            setStep(1);
                            setOtpauthUrl('');
                            setQrCodeUrl('');
                          }}
                          className={`flex-1 py-3 font-semibold transition ${mode === 'login' ? 'bg-white text-black' : 'text-gray-300 hover:text-white'}`}
                        >
                          Login
                        </button>
                        <button
                          type="button"
                          onClick={() => {
                            setMode('register');
                            setAuthError('');
                            setSuccessMessage('');
                            setStep(1);
                            setOtpauthUrl('');
                            setQrCodeUrl('');
                          }}
                          className={`flex-1 py-3 font-semibold transition ${mode === 'register' ? 'bg-white text-black' : 'text-gray-300 hover:text-white'}`}
                        >
                          Register
                        </button>
                      </div>
                      <p className="text-sm text-gray-400">
                        {mode === 'register'
                          ? 'Create your DeepSentinel account and configure Google Authenticator 2FA.'
                          : 'Sign in securely with your email and complete two-factor authentication.'}
                      </p>
                    </div>
                    {authError && (
                      <div className="rounded-2xl bg-red-500/10 border border-red-400/20 p-4 text-red-200 text-sm font-medium">
                        {authError}
                      </div>
                    )}
                    {successMessage && (
                      <div className="rounded-2xl bg-emerald-500/10 border border-emerald-400/20 p-4 text-emerald-200 text-sm font-medium">
                        {successMessage}
                      </div>
                    )}
                    <div className="space-y-4">
                      <div className="relative group/input">
                        <Mail className="absolute left-4 top-1/2 -translate-y-1/2 w-5 h-5 text-gray-400 group-focus-within/input:text-brand-accent transition-colors" />
                        <input 
                          type="email" 
                          value={email}
                          onChange={(e) => setEmail(e.target.value)}
                          placeholder="Email address" 
                          className="w-full bg-black/40 border border-white/10 rounded-xl py-4 pl-12 pr-4 text-white placeholder-gray-500 focus:outline-none focus:border-brand-accent focus:ring-1 focus:ring-brand-accent transition-all duration-300"
                        />
                      </div>

                      <div className="relative group/input">
                        <Lock className="absolute left-4 top-1/2 -translate-y-1/2 w-5 h-5 text-gray-400 group-focus-within/input:text-brand-accent transition-colors" />
                        <input 
                          type="password" 
                          value={password}
                          onChange={(e) => setPassword(e.target.value)}
                          placeholder="Passphrase" 
                          className="w-full bg-black/40 border border-white/10 rounded-xl py-4 pl-12 pr-4 text-white placeholder-gray-500 focus:outline-none focus:border-brand-accent focus:ring-1 focus:ring-brand-accent transition-all duration-300"
                        />
                      </div>
                    </div>

                    <div className="flex items-center justify-between text-sm">
                      <label className="flex items-center gap-2 cursor-pointer group/check">
                        <input type="checkbox" className="w-4 h-4 rounded appearance-none border border-white/20 bg-black/40 checked:bg-brand-accent group-hover/check:border-brand-accent transition-colors cursor-pointer" />
                        <span className="text-gray-400 hover:text-white transition-colors">Trust this device</span>
                      </label>
                      <a href="#" className="text-brand-lightBlue hover:text-brand-accent transition-colors">Forgot keys?</a>
                    </div>

                    <motion.button 
                      whileHover={{ scale: 1.02 }}
                      whileTap={{ scale: 0.98 }}
                      disabled={isSubmitting}
                      className="w-full py-4 bg-brand-blue hover:bg-blue-600 rounded-xl font-bold flex flex-row items-center justify-center gap-2 transition-colors shadow-[0_0_20px_rgba(29,78,216,0.3)] disabled:opacity-70 group/btn overflow-hidden relative"
                    >
                      <div className="absolute inset-0 w-0 bg-white/20 transition-all duration-300 ease-out group-hover/btn:w-full"></div>
                      <span className="relative flex items-center justify-center gap-2">
                        {isSubmitting ? (
                          <div className="w-5 h-5 border-2 border-white/30 border-t-white rounded-full animate-spin"></div>
                        ) : (
                          <>
                            {mode === 'register' ? 'Create account' : 'Authenticate'}{' '}
                            <ArrowRight className="w-5 h-5 group-hover/btn:translate-x-1 transition-transform" />
                          </>
                        )}
                      </span>
                    </motion.button>
                  </form>
                </motion.div>
              )}

              {step === 2 && (
                <motion.div
                  key="step2"
                  initial={{ opacity: 0, x: 30 }}
                  animate={{ opacity: 1, x: 0 }}
                  exit={{ opacity: 0, x: 30 }}
                  transition={{ duration: 0.4 }}
                  className="flex flex-col items-center pt-2"
                >
                  <div className="w-16 h-16 bg-brand-lightBlue/10 rounded-full flex items-center justify-center mb-4 border border-brand-lightBlue/20">
                    <Smartphone className="w-8 h-8 text-brand-lightBlue animate-pulse" />
                  </div>
                  
                  <h2 className="text-xl font-display font-bold text-white mb-2">
                    {mode === 'register' ? 'Set up your authenticator' : 'Two-Factor Required'}
                  </h2>
                  <p className="text-gray-400 text-center text-sm leading-relaxed mb-8">
                    {mode === 'register'
                      ? 'Scan the QR code below with Google Authenticator or another TOTP app, then enter the code it provides.'
                      : 'Open your authenticator app and enter the 6-digit verification code.'}
                  </p>

                  {mode === 'register' && (
                    <div className="flex justify-center mb-6">
                      {qrCodeUrl ? (
                        <img
                          src={qrCodeUrl}
                          alt="DeepSentinel setup QR code"
                          className="w-56 h-56 rounded-3xl border border-white/10 bg-black/70"
                        />
                      ) : (
                        <div className="w-56 h-56 rounded-3xl border border-white/10 bg-black/70 flex items-center justify-center text-gray-400">
                          Generating QR code...
                        </div>
                      )}
                    </div>
                  )}

                  <form onSubmit={handle2FASubmit} className="w-full space-y-8">
                    {authError && (
                      <div className="rounded-2xl bg-red-500/10 border border-red-400/20 p-4 text-red-200 text-sm font-medium">
                        {authError}
                      </div>
                    )}
                    <div className="text-sm text-gray-400 mb-4">
                      {mode === 'register'
                        ? 'Scan the code, then enter the time-based code displayed in your authenticator app.'
                        : 'Enter the 6-digit verification code from your authenticator app.'}
                    </div>
                    <div className="flex justify-between gap-2">
                      {otp.map((digit, i) => (
                        <input
                          key={i}
                          ref={(el) => otpRefs.current[i] = el}
                          type="text"
                          inputMode="numeric"
                          maxLength={1}
                          value={digit}
                          onChange={(e) => handleOtpChange(i, e.target.value)}
                          onKeyDown={(e) => handleOtpKeyDown(i, e)}
                          className="w-11 h-14 bg-black/40 border border-white/10 rounded-xl text-center text-2xl font-bold text-white focus:outline-none focus:border-brand-accent focus:ring-1 focus:ring-brand-accent transition-all duration-300 shadow-inner"
                        />
                      ))}
                    </div>

                    <div className="space-y-4">
                      <motion.button 
                        whileHover={{ scale: 1.02 }}
                        whileTap={{ scale: 0.98 }}
                        disabled={isSubmitting || otp.some(d => d === '')}
                        className="w-full py-4 bg-brand-lightBlue hover:bg-blue-400 text-brand-darker rounded-xl font-bold flex flex-row items-center justify-center gap-2 transition-colors shadow-[0_0_20px_rgba(96,165,250,0.3)] disabled:opacity-50 disabled:cursor-not-allowed group/btn relative overflow-hidden"
                      >
                        <span className="relative flex items-center justify-center gap-2">
                          {isSubmitting ? (
                            <div className="w-5 h-5 border-2 border-brand-darker/30 border-t-brand-darker rounded-full animate-spin"></div>
                          ) : (
                            <>Verify Identity <Shield className="w-5 h-5 group-hover/btn:scale-110 transition-transform" /></>
                          )}
                        </span>
                      </motion.button>

                      <button 
                        type="button"
                        onClick={() => setStep(1)}
                        className="w-full py-4 bg-transparent hover:bg-white/5 border border-transparent rounded-xl font-medium flex flex-row items-center justify-center gap-2 transition-colors text-gray-400 hover:text-white"
                      >
                        <ArrowLeft className="w-4 h-4" /> Return to Login
                      </button>
                    </div>
                  </form>
                </motion.div>
              )}
            </AnimatePresence>
          </div>

          <div className="mt-8 text-center text-sm text-gray-600 flex items-center justify-center gap-2">
            <Lock className="w-4 h-4" /> End-to-end encrypted connection
          </div>
        </div>
      </motion.div>
    </div>
  );
}

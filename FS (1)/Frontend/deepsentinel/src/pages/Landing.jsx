import React, { useEffect, useState, lazy, Suspense, useRef } from "react";
import { motion, useScroll, useTransform } from "framer-motion";
import { Shield, Activity, Brain, ChevronRight, Server, Eye, Zap } from "lucide-react";
import Particles from "react-tsparticles";
import { loadSlim } from "tsparticles-slim";
import { Link, useNavigate } from "react-router-dom";

// Lazy load
const Spline = lazy(() => import("@splinetool/react-spline"));

const NavItem = ({ label, href }) => {
  return (
    <a href={href} className="relative group text-gray-300 font-medium hover:text-brand-accent transition-colors duration-300 px-1 py-1">
      {label}
      <span className="absolute -bottom-1 left-0 w-0 h-[2px] bg-brand-accent transition-all duration-300 group-hover:w-full rounded-full"></span>
    </a>
  )
}

const FeatureCard = ({ icon, title, desc, delay }) => {
  const [mousePosition, setMousePosition] = useState({ x: 0, y: 0 });
  const cardRef = useRef(null);

  const handleMouseMove = (e) => {
    if(!cardRef.current) return;
    const rect = cardRef.current.getBoundingClientRect();
    setMousePosition({
      x: e.clientX - rect.left,
      y: e.clientY - rect.top,
    });
  };

  return (
    <motion.div
      ref={cardRef}
      onMouseMove={handleMouseMove}
      initial={{ opacity: 0, y: 30 }}
      whileInView={{ opacity: 1, y: 0 }}
      viewport={{ once: true, margin: "-50px" }}
      transition={{ delay, duration: 0.6, ease: "easeOut" }}
      whileHover={{ y: -5, scale: 1.02 }}
      className="relative p-[1px] rounded-2xl overflow-hidden bg-white/5 shadow-2xl group"
    >
      {/* Spotlight effect */}
      <div 
        className="absolute inset-0 z-0 opacity-0 group-hover:opacity-100 transition-opacity duration-500 ease-out pointer-events-none"
        style={{
          background: `radial-gradient(circle 250px at ${mousePosition.x}px ${mousePosition.y}px, rgba(56, 189, 248, 0.15), transparent 80%)`
        }}
      />
      
      <div className="relative h-full bg-brand-darker/90 backdrop-blur-xl p-8 rounded-2xl border border-white/5 flex flex-col items-start z-10 transition-colors group-hover:border-white/10">
        <div className="p-3 bg-brand-blue/10 rounded-xl border border-brand-lightBlue/20 text-brand-accent mb-6 group-hover:scale-110 group-hover:bg-brand-blue/20 transition-all duration-300">
          {icon}
        </div>
        <h3 className="text-2xl font-display font-semibold mb-3 text-white group-hover:text-brand-lightBlue transition-colors">{title}</h3>
        <p className="text-gray-400 leading-relaxed font-sans">{desc}</p>
      </div>
    </motion.div>
  )
}

export default function Landing() {
  const navigate = useNavigate();
  const { scrollYProgress } = useScroll();
  const yHero = useTransform(scrollYProgress, [0, 1], ["0%", "50%"]);
  const opacityHero = useTransform(scrollYProgress, [0, 0.5], [1, 0]);
  const scaleHeroTitle = useTransform(scrollYProgress, [0, 1], [1, 1.2]);

  const [cursor, setCursor] = useState({ x: 0, y: 0 });
  const [isScrolled, setIsScrolled] = useState(false);

  useEffect(() => {
    const move = (e) => {
      // Fast cursor track
      requestAnimationFrame(() => setCursor({ x: e.clientX, y: e.clientY }));
    };
    window.addEventListener("mousemove", move);
    
    const handleScroll = () => {
      setIsScrolled(window.scrollY > 50);
    };
    window.addEventListener("scroll", handleScroll);

    return () => {
      window.removeEventListener("mousemove", move);
      window.removeEventListener("scroll", handleScroll);
    }
  }, []);

  const particlesInit = async (engine) => {
    await loadSlim(engine);
  };

  return (
    <div className="bg-brand-darker text-white relative selection:bg-brand-blue/30 selection:text-brand-accent font-sans overflow-x-hidden">

      {/* Global Glow Cursor */}
      <div
        className="fixed pointer-events-none w-[520px] h-[520px] rounded-full bg-brand-blue/15 blur-[120px] z-0 transition-transform duration-75 ease-out"
        style={{ transform: `translate(${cursor.x - 260}px, ${cursor.y - 260}px)` }}
      />

      {/* Ambient Background Clusters */}
      <div className="fixed top-[-12%] left-[-12%] w-[28rem] h-[28rem] bg-blue-600/25 rounded-full mix-blend-screen filter blur-[140px] animate-blob z-0"></div>
      <div className="fixed top-[18%] right-[-14%] w-[24rem] h-[24rem] bg-cyan-600/25 rounded-full mix-blend-screen filter blur-[140px] animate-blob animation-delay-2000 z-0"></div>
      <div className="fixed bottom-[5%] left-[15%] w-72 h-72 bg-sky-500/20 rounded-full mix-blend-screen filter blur-[120px] animate-blob animation-delay-1500 z-0"></div>
      <div className="fixed bottom-[20%] right-[10%] w-64 h-64 bg-teal-400/15 rounded-full mix-blend-screen filter blur-[120px] animate-blob animation-delay-2500 z-0"></div>

      {/* Navbar */}
      <motion.nav 
        initial={{ y: -100 }}
        animate={{ y: 0 }}
        transition={{ duration: 0.8, ease: "easeOut" }}
        className={`fixed top-0 w-full flex justify-between items-center px-8 md:px-16 py-5 z-50 transition-all duration-500 ${isScrolled ? 'bg-brand-darker/80 backdrop-blur-md border-b border-white/5 shadow-lg shadow-black/20 py-4' : 'bg-transparent py-6'}`}
      >
        <div className="flex items-center gap-2 group cursor-pointer">
          <Shield className="text-brand-accent w-8 h-8 group-hover:text-white transition-colors duration-300" />
          <h1 className="text-2xl font-display font-bold tracking-tight text-white group-hover:text-brand-accent transition-colors duration-300">
            Deep<span className="text-brand-lightBlue">Sentinel</span>
          </h1>
        </div>
        <div className="hidden md:flex space-x-10 items-center">
          <NavItem label="Features" href="#features" />
          <NavItem label="About" href="#about" />
          <motion.button
            whileHover={{ scale: 1.05 }}
            whileTap={{ scale: 0.95 }}
            onClick={() => navigate('/login')}
            className="px-6 py-2.5 bg-brand-blue/10 border border-brand-blue text-brand-lightBlue rounded-full hover:bg-brand-blue hover:text-white font-medium transition-all duration-300 flex items-center gap-2 shadow-[0_0_15px_rgba(29,78,216,0.3)] hover:shadow-[0_0_25px_rgba(29,78,216,0.6)]"
          >
            Enter System
          </motion.button>
        </div>
      </motion.nav>

      <main className="relative z-10 w-full flex flex-col">
          
        {/* HERO SECTION */}
        <section className="relative min-h-screen flex flex-col md:flex-row justify-center items-center px-6 md:px-16 pt-24 pb-12 w-full overflow-hidden">
          
          <Particles
            id="tsparticles"
            init={particlesInit}
            options={{
              background: { color: { value: "transparent" } },
              fpsLimit: 60,
              particles: {
                color: { value: "#60a5fa" },
                links: { color: "#1d4ed8", distance: 150, enable: true, opacity: 0.15, width: 1 },
                move: { enable: true, speed: 0.6, direction: "none", random: false, straight: false, outModes: "out" },
                number: { density: { enable: true, area: 900 }, value: 25 },
                opacity: { value: 0.35 },
                shape: { type: "circle" },
                size: { value: { min: 1, max: 2.5 } },
              },
              detectRetina: true,
            }}
            className="absolute inset-0 z-0 pointer-events-none"
          />

          {/* Hero Content */}
          <motion.div 
            style={{ y: yHero, opacity: opacityHero }}
            className="w-full md:w-1/2 flex flex-col items-start z-10 mt-10 md:mt-0"
          >
            <motion.div
              initial={{ opacity: 0, scale: 0.9 }}
              animate={{ opacity: 1, scale: 1 }}
              transition={{ duration: 0.8 }}
              className="inline-flex items-center gap-2 px-4 py-2 rounded-full bg-brand-blue/10 border border-brand-blue/30 text-brand-lightBlue text-sm font-semibold mb-8 backdrop-blur-sm shadow-[0_0_15px_rgba(29,78,216,0.3)]"
            >
              <span className="relative flex h-2 w-2">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-brand-accent opacity-75"></span>
                <span className="relative inline-flex rounded-full h-2 w-2 bg-brand-lightBlue"></span>
              </span>
              Real-time threat intelligence
            </motion.div>

            <motion.h1
              style={{ scale: scaleHeroTitle }}
              className="text-5xl md:text-7xl lg:text-8xl font-display font-bold leading-tight bg-gradient-to-br from-white via-blue-100 to-brand-blue bg-clip-text text-transparent transform-origin-left"
            >
              Predict. <br className="hidden md:block"/> Prevent. <br className="hidden md:block"/> Protect.
            </motion.h1>

            <motion.p 
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.8, delay: 0.2 }}
              className="mt-8 text-lg md:text-xl text-gray-400 max-w-xl font-light leading-relaxed"
            >
              AI-powered insider threat detection that analyzes behavioral patterns to stop breaches <strong className="text-white font-medium">before they happen</strong>.
            </motion.p>

            <motion.div 
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.8, delay: 0.4 }}
              className="mt-10 flex flex-col sm:flex-row gap-4 w-full"
            >
              <button 
                onClick={() => navigate('/login')}
                className="group relative px-8 py-4 bg-brand-blue rounded-xl font-semibold overflow-hidden shadow-[0_0_40px_rgba(29,78,216,0.5)] transition-all hover:shadow-[0_0_60px_rgba(29,78,216,0.6)]"
              >
                <div className="absolute inset-0 w-0 bg-white/20 transition-all duration-[250ms] ease-out group-hover:w-full"></div>
                <span className="relative flex items-center justify-center gap-2">
                  Deploy Sentinel <ChevronRight className="w-5 h-5 group-hover:translate-x-1 transition-transform" />
                </span>
              </button>
            </motion.div>
          </motion.div>

          {/* 3D Visual */}
          <motion.div 
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ duration: 1.3, delay: 0.5, ease: 'easeOut' }}
            className="w-full md:w-1/2 h-[50vh] md:h-[80vh] relative z-10 flex items-center justify-center pointer-events-none md:pointer-events-auto"
          >
            {/* Soft glow behind 3D object */}
            <div className="absolute inset-0 bg-brand-blue/20 blur-[60px] rounded-full scale-75 -z-10"></div>
            <Suspense fallback={
              <div className="flex flex-col items-center gap-4">
                <div className="w-10 h-10 border-4 border-brand-blue border-t-brand-accent rounded-full animate-spin"></div>
                <p className="text-brand-lightBlue font-display animate-pulse">Initializing Matrix...</p>
              </div>
            }>
              <Spline scene="https://prod.spline.design/m06N8XI1DOBTO8Le/scene.splinecode" />
            </Suspense>
          </motion.div>

        </section>

        {/* FEATURES GRID */}
        <section id="features" className="py-32 px-6 md:px-16 relative w-full z-20">
          
          <div className="text-center max-w-3xl mx-auto mb-20 relative">
            <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-64 h-32 bg-brand-blue/30 blur-[100px] -z-10"></div>
            
            <motion.h2 
              initial={{ opacity: 0, y: 20 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true }}
              className="text-4xl md:text-5xl font-display font-bold text-white mb-6"
            >
              Beyond the <span className="text-brand-accent">Perimeter</span>
            </motion.h2>
            <motion.p 
              initial={{ opacity: 0, y: 20 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true }}
              transition={{ delay: 0.2 }}
              className="text-lg text-gray-400 font-sans"
            >
              Traditional firewalls aren't enough when the threat comes from within. DeepSentinel provides full-spectrum visibility into user actions.
            </motion.p>
          </div>

          <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-6 max-w-7xl mx-auto">
            <FeatureCard 
              icon={<Activity className="w-6 h-6" />} 
              title="Continuous Auditing" 
              desc="Real-time monitoring of endpoints, file transfers, and privilege escalations without degrading user performance."
              delay={0}
            />
            <FeatureCard 
              icon={<Brain className="w-6 h-6" />} 
              title="Behavioral Anomalies" 
              desc="Machine learning models baseline normal behavior and immediately flag deviations outside normal operating parameters."
              delay={0.1}
            />
            <FeatureCard 
              icon={<Eye className="w-6 h-6" />} 
              title="Explainable Intelligence" 
              desc="Alerts provide rich context, translating raw network telemetry into human-readable narratives of potential threats."
              delay={0.2}
            />
            <FeatureCard 
              icon={<Shield className="w-6 h-6" />} 
              title="Zero-Trust Enforcer" 
              desc="Auto-isolate compromised accounts instantly. Micro-segmentation stops lateral movement proactively."
              delay={0.3}
            />
            <FeatureCard 
              icon={<Server className="w-6 h-6" />} 
              title="Seamless Integration" 
              desc="Natively connects with your existing SIEM, SOAR, and Identity Providers for unified SecOps workflows."
              delay={0.4}
            />
            <FeatureCard 
              icon={<Zap className="w-6 h-6" />} 
              title="Automated Response" 
              desc="Trigger customizable playbooks to lock down data and notify stakeholders before exfiltration completes."
              delay={0.5}
            />
          </div>
        </section>

        {/* PARALLAX SCROLL MESSAGE */}
        <section className="relative h-[80vh] flex items-center justify-center overflow-hidden border-y border-white/10 w-full z-20">
          <div className="absolute inset-0 bg-gradient-to-b from-brand-darker via-brand-blue/10 to-brand-darker z-0"></div>
          
          <motion.div
            initial={{ scale: 0.92, opacity: 0 }}
            whileInView={{ scale: 1, opacity: 1 }}
            viewport={{ amount: 0.3, margin: "-100px" }}
            transition={{ duration: 1, ease: "easeOut" }}
            className="text-center z-10 px-6"
          >
            <h2 className="text-5xl md:text-8xl lg:text-9xl font-display font-black tracking-tighter mix-blend-plus-lighter opacity-90 pb-8 text-transparent bg-clip-text bg-gradient-to-r from-blue-300 via-white to-brand-accent">
              SEE THE UNSEEN.
            </h2>
            <div className="h-1 w-32 bg-brand-lightBlue mx-auto rounded-full shadow-[0_0_15px_rgba(96,165,250,0.8)]"></div>
          </motion.div>
          
          <motion.div 
            animate={{ rotate: 360 }}
            transition={{ duration: 120, repeat: Infinity, ease: "linear" }}
            className="absolute -top-[50%] -left-[20%] w-[1000px] h-[1000px] border border-white/5 rounded-full pointer-events-none"
          />
        </section>

        {/* FOOTER CTA */}
        <section id="about" className="py-32 px-6 text-center w-full relative z-20 flex flex-col items-center">
            
            <div className="absolute inset-0 bg-[radial-gradient(ellipse_at_center,_var(--tw-gradient-stops))] from-brand-blue/10 via-brand-darker to-brand-darker -z-10" />

            <Shield className="w-16 h-16 text-brand-blue/50 mb-6 drop-shadow-[0_0_30px_rgba(29,78,216,0.8)]" />
            <h2 className="text-4xl md:text-5xl font-display font-bold text-white mb-6">Stronger insider threat defense starts here</h2>
            
            <p className="max-w-2xl mx-auto text-gray-400 mb-10 text-lg">
              DeepSentinel blends behavioral analytics, anomaly detection, and automated response so your security team can detect compromised accounts and stop attacks before they spread.
            </p>
            
            <button className="px-10 py-5 bg-white text-black font-semibold rounded-xl hover:bg-brand-accent hover:text-white transition-all duration-300 transform hover:-translate-y-1 shadow-[0_10px_40px_rgba(255,255,255,0.1)] hover:shadow-[0_10px_40px_rgba(56,189,248,0.4)]">
                Explore the Platform
            </button>
        </section>

        {/* Footer */}
        <footer className="w-full py-8 border-t border-white/10 flex flex-col md:flex-row items-center justify-between px-6 md:px-16 text-sm text-gray-500 z-20 bg-black/40">
            <div className="flex items-center gap-2 mb-4 md:mb-0">
                <Shield className="w-4 h-4" /> 
                <span className="font-display font-semibold text-gray-400">DeepSentinel</span>
                <span>© 2026. All rights reserved.</span>
            </div>
            <div className="flex gap-6">
                <a href="#" className="hover:text-white transition-colors">Privacy Policy</a>
                <a href="#" className="hover:text-white transition-colors">Terms of Service</a>
                <a href="#" className="hover:text-white transition-colors">Contact</a>
            </div>
        </footer>

      </main>
    </div>
  );
}
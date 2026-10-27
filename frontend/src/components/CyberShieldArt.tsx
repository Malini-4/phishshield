import React from 'react';

export const CyberShieldArt: React.FC = () => {
  return (
    <div className="auth-visual-panel" aria-hidden="true">
      <div className="auth-visual-glow" />
      <svg
        className="auth-shield-svg"
        viewBox="0 0 500 500"
        fill="none"
        xmlns="http://www.w3.org/2000/svg"
      >
        <defs>
          {/* Ambient Glow Filter */}
          <filter id="cyanGlow" x="-20%" y="-20%" width="140%" height="140%">
            <feGaussianBlur stdDeviation="12" result="blur" />
            <feComposite in="SourceGraphic" in2="blur" operator="over" />
          </filter>
          <filter id="intenseGlow" x="-30%" y="-30%" width="160%" height="160%">
            <feGaussianBlur stdDeviation="18" result="blur1" />
            <feGaussianBlur stdDeviation="6" result="blur2" />
            <feMerge>
              <feMergeNode in="blur1" />
              <feMergeNode in="blur2" />
              <feMergeNode in="SourceGraphic" />
            </feMerge>
          </filter>

          {/* Gradients */}
          <linearGradient id="shieldBorderGrad" x1="0%" y1="0%" x2="100%" y2="100%">
            <stop offset="0%" stopColor="#16C8FF" />
            <stop offset="50%" stopColor="#087FF5" />
            <stop offset="100%" stopColor="#00E5FF" />
          </linearGradient>

          <radialGradient id="shieldFillGrad" cx="50%" cy="40%" r="60%">
            <stop offset="0%" stopColor="#00F0FF" stopOpacity="0.9" />
            <stop offset="45%" stopColor="#087FF5" stopOpacity="0.8" />
            <stop offset="100%" stopColor="#051B44" stopOpacity="0.95" />
          </radialGradient>

          <linearGradient id="waveGrad" x1="0%" y1="0%" x2="100%" y2="100%">
            <stop offset="0%" stopColor="#087FF5" stopOpacity="0.6" />
            <stop offset="50%" stopColor="#16C8FF" stopOpacity="0.4" />
            <stop offset="100%" stopColor="#051433" stopOpacity="0.1" />
          </linearGradient>

          <radialGradient id="radialBackdrop" cx="50%" cy="50%" r="50%">
            <stop offset="0%" stopColor="#087FF5" stopOpacity="0.35" />
            <stop offset="50%" stopColor="#05163A" stopOpacity="0.2" />
            <stop offset="100%" stopColor="#050B1C" stopOpacity="0" />
          </radialGradient>
        </defs>

        {/* Ambient background aura */}
        <circle cx="250" cy="250" r="220" fill="url(#radialBackdrop)" />

        {/* Dynamic Curved Network Waves / Mesh */}
        <g stroke="url(#waveGrad)" strokeWidth="1" opacity="0.75">
          <ellipse cx="250" cy="250" rx="210" ry="170" transform="rotate(-25 250 250)" strokeDasharray="3 4" />
          <ellipse cx="250" cy="250" rx="190" ry="145" transform="rotate(-15 250 250)" strokeDasharray="2 3" />
          <ellipse cx="250" cy="250" rx="170" ry="120" transform="rotate(-5 250 250)" strokeDasharray="4 4" />
          <ellipse cx="250" cy="250" rx="150" ry="100" transform="rotate(10 250 250)" strokeDasharray="2 4" />
          <ellipse cx="250" cy="250" rx="230" ry="180" transform="rotate(-35 250 250)" strokeDasharray="1 5" />
          <ellipse cx="250" cy="250" rx="250" ry="190" transform="rotate(-45 250 250)" strokeDasharray="3 6" />
        </g>

        {/* Radiating Cyberspace Rays */}
        <g stroke="#16C8FF" strokeWidth="1" opacity="0.35" strokeDasharray="2 6">
          <line x1="250" y1="250" x2="50" y2="100" />
          <line x1="250" y1="250" x2="70" y2="390" />
          <line x1="250" y1="250" x2="430" y2="90" />
          <line x1="250" y1="250" x2="450" y2="380" />
          <line x1="250" y1="250" x2="250" y2="30" />
          <line x1="250" y1="250" x2="250" y2="470" />
          <line x1="250" y1="250" x2="20" y2="250" />
          <line x1="250" y1="250" x2="480" y2="250" />
        </g>

        {/* Outer Shield Neon Glow Backing */}
        <path
          d="M250 110 C310 110 350 135 350 200 C350 280 290 345 250 375 C210 345 150 280 150 200 C150 135 190 110 250 110 Z"
          fill="none"
          stroke="#00E5FF"
          strokeWidth="10"
          opacity="0.3"
          filter="url(#cyanGlow)"
        />

        {/* Main Cyber Shield Body */}
        <path
          d="M250 115 C305 115 342 138 342 198 C342 272 288 335 250 365 C212 335 158 272 158 198 C158 138 195 115 250 115 Z"
          fill="url(#shieldFillGrad)"
          stroke="url(#shieldBorderGrad)"
          strokeWidth="4"
          filter="url(#intenseGlow)"
        />

        {/* Inner Shield Circuit Details */}
        <g stroke="#EAF5FF" strokeWidth="1.5" opacity="0.65" fill="none">
          {/* Circuit tracks */}
          <path d="M190 180 L220 180 L235 200 L235 230" />
          <circle cx="190" cy="180" r="2.5" fill="#16C8FF" />
          <circle cx="235" cy="230" r="2" fill="#FFFFFF" />

          <path d="M310 180 L280 180 L265 200 L265 230" />
          <circle cx="310" cy="180" r="2.5" fill="#16C8FF" />
          <circle cx="265" cy="230" r="2" fill="#FFFFFF" />

          <path d="M195 240 L215 260 L215 290 L240 315" />
          <circle cx="195" cy="240" r="2.5" fill="#00E5FF" />
          <circle cx="240" cy="315" r="2" fill="#FFFFFF" />

          <path d="M305 240 L285 260 L285 290 L260 315" />
          <circle cx="305" cy="240" r="2.5" fill="#00E5FF" />
          <circle cx="260" cy="315" r="2" fill="#FFFFFF" />

          <path d="M220 145 L250 160 L280 145" />
          <circle cx="220" cy="145" r="2" fill="#FFFFFF" />
          <circle cx="280" cy="145" r="2" fill="#FFFFFF" />
        </g>

        {/* Center Keyhole Silhouette (Reference 1) */}
        <g filter="url(#cyanGlow)">
          {/* Keyhole outer glow ring */}
          <circle cx="250" cy="225" r="24" fill="#050B1C" stroke="#16C8FF" strokeWidth="2.5" />
          {/* Keyhole slot */}
          <path
            d="M243 238 L257 238 L261 270 L239 270 Z"
            fill="#050B1C"
            stroke="#16C8FF"
            strokeWidth="2.5"
          />
        </g>
        {/* Crisp keyhole cutout */}
        <circle cx="250" cy="225" r="22" fill="#060C1F" />
        <path d="M244 238 L256 238 L260 268 L240 268 Z" fill="#060C1F" />

        {/* Glowing cyber sparkles */}
        <circle cx="140" cy="120" r="2" fill="#16C8FF" opacity="0.8" />
        <circle cx="370" cy="130" r="2.5" fill="#00E5FF" opacity="0.9" filter="url(#cyanGlow)" />
        <circle cx="390" cy="280" r="2" fill="#16C8FF" opacity="0.7" />
        <circle cx="110" cy="320" r="2" fill="#087FF5" opacity="0.8" />
        <circle cx="320" cy="390" r="1.5" fill="#00E5FF" opacity="0.9" />
        <circle cx="180" cy="420" r="2" fill="#16C8FF" opacity="0.6" />
      </svg>
    </div>
  );
};

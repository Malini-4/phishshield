import React from 'react';
import { NavLink, useNavigate } from 'react-router-dom';
import {
  Shield,
  Search,
  History,
  User,
  LogOut,
  Globe,
  Smartphone,
  MessageSquare,
  Receipt,
  FolderOpen,
} from 'lucide-react';
import { useAuth } from '../context/AuthContext';

interface SidebarProps {
  isOpen: boolean;
  onClose?: () => void;
}

export const Sidebar: React.FC<SidebarProps> = ({ isOpen, onClose }) => {
  const { user, logout } = useAuth();
  const navigate = useNavigate();

  const handleLogout = async () => {
    if (onClose) onClose();
    await logout();
    navigate('/login', { replace: true });
  };

  const mainNavItems = [
    { to: '/', label: 'Analyse', icon: Search },
    { to: '/history', label: 'My investigations', icon: History },
    { to: '/cases', label: 'Cases', icon: FolderOpen },
    { to: '/account', label: 'My account', icon: User },
  ];

  const moduleShortcuts = [
    { to: '/url', label: 'URL Threat Analysis', icon: Globe },
    { to: '/apk', label: 'Android APK Analysis', icon: Smartphone },
    { to: '/sms', label: 'SMS Scam Verification', icon: MessageSquare },
    { to: '/screenshot', label: 'Payment Screenshot OCR', icon: Receipt },
  ];

  return (
    <aside
      className={`sidebar ${isOpen ? 'open' : ''}`}
      style={{
        display: isOpen ? 'flex' : undefined,
      }}
    >
      <div className="sidebar-header">
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem' }}>
          <div style={{ width: '34px', height: '34px', borderRadius: '8px', background: 'rgba(8, 127, 245, 0.25)', border: '1px solid rgba(22, 200, 255, 0.4)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
            <Shield size={20} color="#16C8FF" />
          </div>
          <span className="brand-title">PhishShield</span>
        </div>
      </div>

      <nav className="sidebar-nav">
        <div style={{ marginBottom: '0.25rem' }}>
          <span style={{ padding: '0 0.85rem', fontSize: '0.72rem', textTransform: 'uppercase', letterSpacing: '0.05em', fontWeight: 700, color: 'var(--text-subtle)' }}>
            Navigation
          </span>
        </div>

        {mainNavItems.map((item) => {
          const Icon = item.icon;
          return (
            <NavLink
              key={item.to}
              to={item.to}
              end={item.to === '/'}
              className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}
              onClick={onClose}
            >
              <Icon size={18} />
              <span>{item.label}</span>
            </NavLink>
          );
        })}

        <div style={{ marginTop: '1.25rem', marginBottom: '0.25rem' }}>
          <span style={{ padding: '0 0.85rem', fontSize: '0.72rem', textTransform: 'uppercase', letterSpacing: '0.05em', fontWeight: 700, color: 'var(--text-subtle)' }}>
            Modules
          </span>
        </div>

        {moduleShortcuts.map((item) => {
          const Icon = item.icon;
          return (
            <NavLink
              key={item.to}
              to={item.to}
              className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}
              onClick={onClose}
              style={{ fontSize: '0.85rem' }}
            >
              <Icon size={16} />
              <span>{item.label}</span>
            </NavLink>
          );
        })}

        {/* Logout action */}
        <div style={{ marginTop: 'auto', paddingTop: '1rem', borderTop: '1px solid var(--border-light)' }}>
          <button
            type="button"
            className="nav-item"
            onClick={handleLogout}
            style={{
              width: '100%',
              background: 'transparent',
              border: 'none',
              textAlign: 'left',
              color: '#DC2626',
              cursor: 'pointer',
            }}
          >
            <LogOut size={18} />
            <span>Logout</span>
          </button>
        </div>
      </nav>

      {/* User profile footer */}
      {user && (
        <div
          style={{
            padding: '0.85rem 1rem',
            borderTop: '1px solid var(--border-light)',
            background: 'rgba(3, 11, 28, 0.85)',
            display: 'flex',
            alignItems: 'center',
            gap: '0.65rem',
          }}
        >
          <div style={{ width: '30px', height: '30px', borderRadius: '50%', background: 'rgba(8, 127, 245, 0.25)', border: '1px solid rgba(22, 200, 255, 0.4)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
            <User size={15} color="#16C8FF" />
          </div>
          <div style={{ overflow: 'hidden' }}>
            <p style={{ fontSize: '0.82rem', fontWeight: 600, color: 'var(--text-main)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
              {user.full_name}
            </p>
            <p style={{ fontSize: '0.72rem', color: 'var(--text-subtle)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
              {user.email}
            </p>
          </div>
        </div>
      )}
    </aside>
  );
};

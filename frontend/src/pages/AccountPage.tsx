import React from 'react';
import { User as UserIcon, Mail, ShieldCheck, LogOut, KeyRound } from 'lucide-react';
import { useAuth } from '../context/AuthContext';
import { useNavigate } from 'react-router-dom';

export const AccountPage: React.FC = () => {
  const { user, logout } = useAuth();
  const navigate = useNavigate();

  const handleLogout = async () => {
    await logout();
    navigate('/login', { replace: true });
  };

  return (
    <div className="page-wrapper">
      <div className="page-header">
        <h1 className="page-title">My Account</h1>
        <p className="page-subtitle">
          Manage your PhishShield analyst profile and local workspace session.
        </p>
      </div>

      <div style={{ maxWidth: '640px', display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
        {/* Profile Details Card */}
        <div className="card">
          <div style={{ display: 'flex', alignItems: 'center', gap: '1rem', marginBottom: '1.5rem', paddingBottom: '1rem', borderBottom: '1px solid var(--border-light)' }}>
            <div style={{ width: '56px', height: '56px', borderRadius: '50%', background: 'var(--primary-subtle)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
              <UserIcon size={28} color="var(--primary)" />
            </div>
            <div>
              <h2 style={{ fontSize: '1.2rem', fontWeight: 700, color: 'var(--text-main)' }}>
                {user?.full_name || 'Analyst'}
              </h2>
              <p style={{ fontSize: '0.88rem', color: 'var(--text-muted)' }}>
                {user?.email}
              </p>
            </div>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: '1.25rem' }}>
            <div style={{ padding: '0.85rem', background: 'rgba(4, 15, 38, 0.7)', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border-light)' }}>
              <span style={{ fontSize: '0.78rem', textTransform: 'uppercase', fontWeight: 600, color: 'var(--text-subtle)' }}>
                Analyst ID
              </span>
              <p style={{ fontFamily: 'monospace', fontSize: '0.85rem', color: '#16C8FF', marginTop: '0.2rem', wordBreak: 'break-all' }}>
                {user?.id}
              </p>
            </div>

            <div style={{ padding: '0.85rem', background: 'rgba(4, 15, 38, 0.7)', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border-light)' }}>
              <span style={{ fontSize: '0.78rem', textTransform: 'uppercase', fontWeight: 600, color: 'var(--text-subtle)' }}>
                Session Status
              </span>
              <p style={{ fontSize: '0.88rem', fontWeight: 600, color: '#10B981', marginTop: '0.2rem', display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                <span style={{ width: '8px', height: '8px', borderRadius: '50%', background: '#10B981', boxShadow: '0 0 8px #10B981', display: 'inline-block' }} />
                Authenticated (Active)
              </p>
            </div>
          </div>
        </div>

        {/* Workspace Isolation Notice */}
        <div className="card" style={{ borderLeft: '4px solid var(--primary)' }}>
          <div style={{ display: 'flex', alignItems: 'flex-start', gap: '0.75rem' }}>
            <ShieldCheck size={22} color="#16C8FF" style={{ flexShrink: 0, marginTop: '0.1rem' }} />
            <div>
              <h3 style={{ fontSize: '0.98rem', fontWeight: 700, color: 'var(--text-main)', marginBottom: '0.35rem' }}>
                Per-User Investigation Isolation
              </h3>
              <p style={{ fontSize: '0.86rem', color: 'var(--text-muted)', lineHeight: 1.5 }}>
                Your scanned URLs, uploaded APKs, SMS logs, and payment receipts are linked exclusively to your account.
                Other local users cannot view, search, or download your forensic investigation reports.
              </p>
            </div>
          </div>
        </div>

        {/* Actions Card */}
        <div className="card">
          <h3 style={{ fontSize: '1rem', fontWeight: 700, color: 'var(--text-main)', marginBottom: '1rem' }}>
            Session Actions
          </h3>
          <div style={{ display: 'flex', gap: '1rem', flexWrap: 'wrap' }}>
            <button
              onClick={handleLogout}
              className="btn-secondary"
              style={{ color: '#FCA5A5', borderColor: 'rgba(239, 68, 68, 0.4)', background: 'rgba(239, 68, 68, 0.15)' }}
            >
              <LogOut size={16} />
              <span>Log Out of PhishShield</span>
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};

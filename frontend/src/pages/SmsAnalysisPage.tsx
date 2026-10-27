import React, { useState } from 'react';
import { MessageSquare, ExternalLink, ArrowRight, Shield } from 'lucide-react';
import { smsService } from '../services/smsService';
import { AnalysisResult } from '../types';
import { ResultSummary } from '../components/ResultSummary';
import { ScanProgress } from '../components/ScanProgress';
import { ErrorMessage } from '../components/ErrorMessage';
import { Link } from 'react-router-dom';

export const SmsAnalysisPage: React.FC = () => {
  const [message, setMessage] = useState<string>('');
  const [sender, setSender] = useState<string>('');
  const [loading, setLoading] = useState<boolean>(false);
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!message.trim()) {
      setError('Please paste or type the SMS message text.');
      return;
    }

    setError(null);
    setLoading(true);
    setResult(null);

    try {
      const data = await smsService.analyze(message, sender.trim() || undefined);
      setResult(data);
    } catch (err: any) {
      setError(err.message || 'SMS analysis failed.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="page-wrapper">
      <div className="page-header">
        <h1 className="page-title">SMS & Sender-Header Scam Verification</h1>
        <p className="page-subtitle">
          Detect credential theft, fake bank alerts, KYC pressure, electricity disconnection scams, and spoofed Indian TRAI DLT header identifiers.
        </p>
      </div>

      <div className="card">
        <form onSubmit={handleSubmit}>
          <div className="form-group">
            <label htmlFor="sms-sender" className="form-label">
              Sender Header / Number (Optional)
            </label>
            <input
              id="sms-sender"
              type="text"
              className="form-input"
              placeholder="e.g., VK-HDFCBK, SBIINB, AD-AMAZON, or mobile number"
              value={sender}
              onChange={(e) => setSender(e.target.value)}
              disabled={loading}
              style={{ maxWidth: '380px' }}
            />
            <p style={{ fontSize: '0.8rem', color: 'var(--text-subtle)', marginTop: '0.35rem' }}>
              Checked against official verified Indian DLT alphanumeric headers.
            </p>
          </div>

          <div className="form-group">
            <label htmlFor="sms-message" className="form-label">
              SMS Message Text
            </label>
            <textarea
              id="sms-message"
              className="form-input"
              rows={4}
              placeholder="Paste the received message here (e.g., 'Dear customer your account will be blocked today due to pending KYC. Update at https://...')"
              value={message}
              onChange={(e) => setMessage(e.target.value)}
              disabled={loading}
              style={{ resize: 'vertical' }}
            />
          </div>

          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: '1rem', flexWrap: 'wrap', gap: '1rem' }}>
            <span style={{ fontSize: '0.82rem', color: 'var(--text-subtle)' }}>
              🔒 Sensitive credentials (OTPs, cards, Aadhaar) are automatically redacted in storage.
            </span>
            <button
              type="submit"
              className="btn-primary"
              disabled={loading || !message.trim()}
            >
              <MessageSquare size={18} />
              <span>Verify Message</span>
            </button>
          </div>
        </form>
      </div>

      {error && <ErrorMessage message={error} onRetry={() => setError(null)} />}

      {loading && (
        <ScanProgress
          message="Analyzing linguistic scam patterns and sender headers..."
          step="Scanning for urgency, credential coercion, and extracted URLs..."
        />
      )}

      {result && <ResultSummary result={result} />}
    </div>
  );
};

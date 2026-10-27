import React, { useState, useEffect } from 'react';
import { Receipt, AlertTriangle, AlertCircle, Info, Image as ImageIcon, X } from 'lucide-react';
import { screenshotService } from '../services/screenshotService';
import { historyService } from '../services/historyService';
import { AnalysisResult, HealthStatus } from '../types';
import { FileUpload } from '../components/FileUpload';
import { ResultSummary } from '../components/ResultSummary';
import { ScanProgress } from '../components/ScanProgress';
import { ErrorMessage } from '../components/ErrorMessage';

export const ScreenshotAnalysisPage: React.FC = () => {
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [previewUrl, setPreviewUrl] = useState<string | null>(null);
  const [loading, setLoading] = useState<boolean>(false);
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [health, setHealth] = useState<HealthStatus | null>(null);

  useEffect(() => {
    historyService.getHealth().then(setHealth).catch(() => {});
  }, []);

  useEffect(() => {
    if (!selectedFile) {
      setPreviewUrl(null);
      return;
    }
    const objectUrl = URL.createObjectURL(selectedFile);
    setPreviewUrl(objectUrl);
    return () => URL.revokeObjectURL(objectUrl);
  }, [selectedFile]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedFile) {
      setError('Please select an image file to upload.');
      return;
    }

    setError(null);
    setLoading(true);
    setResult(null);

    try {
      const data = await screenshotService.analyze(selectedFile);
      setResult(data);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Screenshot analysis failed.';
      setError(msg);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="page-wrapper">
      <div className="page-header">
        <h1 className="page-title">Payment Screenshot Investigation</h1>
        <p className="page-subtitle">
          Extract text and verify transaction indicators from UPI and digital payment receipts (GPay, PhonePe, Paytm, BHIM) to detect forged amounts, contradictory status text, and missing reference numbers.
        </p>
      </div>

      {health && !health.ocr_available && (
        <div
          style={{
            padding: '1rem',
            background: 'rgba(245, 158, 11, 0.12)',
            border: '1px solid rgba(245, 158, 11, 0.35)',
            borderRadius: 'var(--radius-sm)',
            color: '#FCD34D',
            marginBottom: '1.5rem',
            display: 'flex',
            alignItems: 'center',
            gap: '0.75rem',
          }}
        >
          <AlertTriangle size={20} color="#F59E0B" />
          <div>
            <strong>OCR Engine Notice:</strong> {health.ocr_detail}.
          </div>
        </div>
      )}

      <div className="card">
        <form onSubmit={handleSubmit}>
          <FileUpload
            accept="image/png,image/jpeg,image/webp"
            maxSizeMb={10}
            label="Upload Payment Confirmation Screenshot"
            description="PNG, JPG, or WEBP image format (Max: 10 MB)"
            selectedFile={selectedFile}
            onFileSelect={setSelectedFile}
            disabled={loading}
          />

          {/* Image Preview */}
          {previewUrl && (
            <div
              style={{
                marginTop: '1.25rem',
                padding: '1rem',
                background: 'var(--bg-secondary)',
                borderRadius: 'var(--radius-sm)',
                border: '1px solid var(--border-light)',
                display: 'flex',
                alignItems: 'center',
                gap: '1rem',
              }}
            >
              <img
                src={previewUrl}
                alt="Payment screenshot preview"
                style={{
                  maxHeight: '120px',
                  maxWidth: '160px',
                  objectFit: 'contain',
                  borderRadius: '4px',
                  border: '1px solid var(--border-medium)',
                  background: '#FFFFFF',
                }}
              />
              <div style={{ flex: 1, minWidth: 0 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.25rem' }}>
                  <ImageIcon size={16} color="var(--primary)" />
                  <span style={{ fontSize: '0.88rem', fontWeight: 600, color: 'var(--text-main)' }}>
                    {selectedFile?.name}
                  </span>
                </div>
                <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>
                  Size: {selectedFile ? `${(selectedFile.size / 1024).toFixed(1)} KB` : ''} • Ready for optical character extraction
                </p>
              </div>
            </div>
          )}

          <div style={{ display: 'flex', justifyContent: 'flex-end', marginTop: '1.25rem' }}>
            <button
              type="submit"
              className="btn-primary"
              disabled={loading || !selectedFile}
            >
              <Receipt size={18} />
              <span>Analyse Screenshot</span>
            </button>
          </div>
        </form>

        <div
          style={{
            marginTop: '1.25rem',
            padding: '0.85rem 1rem',
            background: 'var(--bg-secondary)',
            borderRadius: 'var(--radius-sm)',
            border: '1px solid var(--border-light)',
            fontSize: '0.84rem',
            color: 'var(--text-muted)',
            lineHeight: 1.5,
          }}
        >
          <strong>Critical Forensic Notice:</strong> A screenshot <strong>cannot prove money was actually deposited</strong> into your account. Fake payment generators can produce realistic images in seconds. Always open your own official banking or UPI app to verify that funds were received.
        </div>
      </div>

      {error && <ErrorMessage message={error} onRetry={() => setError(null)} />}

      {loading && (
        <ScanProgress
          message="Running optical character extraction & image contrast enhancement..."
          step="Extracting amount, UTR reference number, and validating status consistency..."
        />
      )}

      {result && <ResultSummary result={result} />}
    </div>
  );
};

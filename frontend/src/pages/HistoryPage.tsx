import React, { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { History, Search, Filter, Trash2, Eye, Download, ChevronLeft, ChevronRight } from 'lucide-react';
import { historyService } from '../services/historyService';
import { HistoryItem } from '../types';
import { StatusBadge } from '../components/StatusBadge';
import { EmptyState } from '../components/EmptyState';
import { ErrorMessage } from '../components/ErrorMessage';

export const HistoryPage: React.FC = () => {
  const [items, setItems] = useState<HistoryItem[]>([]);
  const [total, setTotal] = useState<number>(0);
  const [page, setPage] = useState<number>(1);
  const [pageSize] = useState<number>(15);
  const [typeFilter, setTypeFilter] = useState<string>('');
  const [verdictFilter, setVerdictFilter] = useState<string>('');
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  const fetchHistory = () => {
    setLoading(true);
    historyService
      .list({
        type: typeFilter || undefined,
        verdict: verdictFilter || undefined,
        q: searchQuery.trim() || undefined,
        page,
        page_size: pageSize,
      })
      .then((res) => {
        setItems(res.items);
        setTotal(res.total);
        setLoading(false);
      })
      .catch((err) => {
        setError(err.message || 'Failed to fetch investigation history.');
        setLoading(false);
      });
  };

  useEffect(() => {
    fetchHistory();
  }, [page, typeFilter, verdictFilter]);

  const handleSearch = (e: React.FormEvent) => {
    e.preventDefault();
    setPage(1);
    fetchHistory();
  };

  const handleDelete = async (id: string, e: React.MouseEvent) => {
    e.preventDefault();
    e.stopPropagation();
    if (!window.confirm('Are you sure you want to delete this investigation record?')) {
      return;
    }

    try {
      await historyService.delete(id);
      fetchHistory();
    } catch (err: any) {
      alert(`Delete failed: ${err.message}`);
    }
  };

  const handleDownload = async (id: string, e: React.MouseEvent) => {
    e.preventDefault();
    e.stopPropagation();
    try {
      await historyService.exportPdf(id);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Export failed';
      alert(`PDF download failed: ${msg}`);
    }
  };

  const totalPages = Math.ceil(total / pageSize) || 1;

  return (
    <div className="page-wrapper">
      <div className="page-header">
        <h1 className="page-title">Investigation Records & History</h1>
        <p className="page-subtitle">
          Audit trail of past scans across all analysis modules stored in the local SQLite database.
        </p>
      </div>

      {/* Filter and Search Bar */}
      <div className="card" style={{ padding: '1rem 1.25rem' }}>
        <form onSubmit={handleSearch} style={{ display: 'flex', gap: '0.75rem', flexWrap: 'wrap', alignItems: 'center' }}>
          <div style={{ flex: 1, minWidth: '220px', position: 'relative' }}>
            <input
              type="text"
              className="form-input"
              placeholder="Search by target input text or domain..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
            />
          </div>

          <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap' }}>
            <select
              className="form-input"
              style={{ width: 'auto' }}
              value={typeFilter}
              onChange={(e) => { setTypeFilter(e.target.value); setPage(1); }}
            >
              <option value="">All Types</option>
              <option value="url">URL Analysis</option>
              <option value="apk">APK Static</option>
              <option value="sms">SMS & Sender</option>
              <option value="screenshot">Screenshot OCR</option>
            </select>

            <select
              className="form-input"
              style={{ width: 'auto' }}
              value={verdictFilter}
              onChange={(e) => { setVerdictFilter(e.target.value); setPage(1); }}
            >
              <option value="">All Verdicts</option>
              <option value="malicious">Likely Malicious</option>
              <option value="suspicious">Suspicious</option>
              <option value="clean_no_findings">No Known Threat</option>
              <option value="inconclusive">Could Not Verify</option>
            </select>

            <button type="submit" className="btn-secondary">
              <Search size={16} />
              <span>Search</span>
            </button>
          </div>
        </form>
      </div>

      {error && <ErrorMessage message={error} onRetry={fetchHistory} />}

      {/* Results Table / List */}
      <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
        {loading ? (
          <p style={{ padding: '3rem', textAlign: 'center', color: 'var(--text-muted)' }}>
            Loading records from database...
          </p>
        ) : items.length === 0 ? (
          <div style={{ padding: '2rem' }}>
            <EmptyState
              title="No Matching Investigations Found"
              description="No investigation records matched the selected filters. Try clearing your search parameters."
              actionText="Clear Filters"
              onAction={() => { setTypeFilter(''); setVerdictFilter(''); setSearchQuery(''); setPage(1); }}
            />
          </div>
        ) : (
          <div style={{ overflowX: 'auto' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '0.9rem' }}>
              <thead>
                <tr style={{ background: 'rgba(8, 26, 64, 0.95)', borderBottom: '1px solid var(--border-light)', color: '#EAF5FF' }}>
                  <th style={{ padding: '0.85rem 1.25rem', fontWeight: 600 }}>Date & Time</th>
                  <th style={{ padding: '0.85rem 1rem', fontWeight: 600 }}>Module</th>
                  <th style={{ padding: '0.85rem 1rem', fontWeight: 600 }}>Target Summary</th>
                  <th style={{ padding: '0.85rem 1rem', fontWeight: 600 }}>Verdict</th>
                  <th style={{ padding: '0.85rem 1.25rem', fontWeight: 600, textAlign: 'right' }}>Actions</th>
                </tr>
              </thead>
              <tbody>
                {items.map((item, idx) => (
                  <tr
                    key={item.id}
                    style={{
                      borderBottom: idx < items.length - 1 ? '1px solid var(--border-light)' : 'none',
                      transition: 'background 0.15s',
                    }}
                  >
                    <td style={{ padding: '0.85rem 1.25rem', color: 'var(--text-subtle)', whiteSpace: 'nowrap' }}>
                      {new Date(item.created_at).toLocaleString()}
                    </td>
                    <td style={{ padding: '0.85rem 1rem' }}>
                      <span
                        style={{
                          textTransform: 'uppercase',
                          fontSize: '0.74rem',
                          fontWeight: 700,
                          padding: '0.2rem 0.45rem',
                          borderRadius: '4px',
                          background: 'rgba(8, 127, 245, 0.2)',
                          color: '#16C8FF',
                          border: '1px solid rgba(22, 200, 255, 0.3)',
                        }}
                      >
                        {item.type}
                      </span>
                    </td>
                    <td style={{ padding: '0.85rem 1rem', maxWidth: '350px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', fontWeight: 500 }}>
                      {item.input_display}
                    </td>
                    <td style={{ padding: '0.85rem 1rem', whiteSpace: 'nowrap' }}>
                      <StatusBadge verdict={item.verdict} label={item.display_label} />
                    </td>
                    <td style={{ padding: '0.85rem 1.25rem', textAlign: 'right', whiteSpace: 'nowrap' }}>
                      <div style={{ display: 'inline-flex', gap: '0.5rem', alignItems: 'center' }}>
                        <Link
                          to={`/history/${item.id}`}
                          className="btn-secondary"
                          style={{ padding: '0.35rem 0.65rem', fontSize: '0.8rem', textDecoration: 'none' }}
                        >
                          <Eye size={14} />
                          <span>View</span>
                        </Link>
                        <button
                          type="button"
                          onClick={(e) => handleDownload(item.id, e)}
                          className="btn-secondary"
                          style={{ padding: '0.35rem 0.65rem', fontSize: '0.8rem' }}
                          title="Download PDF report"
                        >
                          <Download size={14} />
                          <span>PDF</span>
                        </button>
                        <button
                          type="button"
                          onClick={(e) => handleDelete(item.id, e)}
                          style={{
                            background: 'rgba(239, 68, 68, 0.15)',
                            border: '1px solid rgba(239, 68, 68, 0.4)',
                            borderRadius: 'var(--radius-sm)',
                            color: '#FCA5A5',
                            padding: '0.35rem 0.5rem',
                            cursor: 'pointer',
                          }}
                          aria-label="Delete investigation"
                        >
                          <Trash2 size={14} />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {/* Pagination Bar */}
        {total > pageSize && (
          <div
            style={{
              padding: '0.85rem 1.25rem',
              borderTop: '1px solid var(--border-light)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              fontSize: '0.86rem',
              color: 'var(--text-muted)',
            }}
          >
            <span>
              Showing {((page - 1) * pageSize) + 1}–{Math.min(page * pageSize, total)} of {total} records
            </span>
            <div style={{ display: 'flex', gap: '0.5rem' }}>
              <button
                type="button"
                className="btn-secondary"
                disabled={page <= 1}
                onClick={() => setPage(page - 1)}
                style={{ padding: '0.35rem 0.65rem' }}
              >
                <ChevronLeft size={16} />
              </button>
              <span style={{ display: 'flex', alignItems: 'center', padding: '0 0.5rem', fontWeight: 600 }}>
                {page} / {totalPages}
              </span>
              <button
                type="button"
                className="btn-secondary"
                disabled={page >= totalPages}
                onClick={() => setPage(page + 1)}
                style={{ padding: '0.35rem 0.65rem' }}
              >
                <ChevronRight size={16} />
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

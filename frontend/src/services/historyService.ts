import { request } from './apiClient';
import { DashboardStats, HealthStatus, HistoryResponse, InvestigationDetail } from '../types';

export const historyService = {
  getHealth: (): Promise<HealthStatus> => {
    return request<HealthStatus>('/health');
  },

  getStats: (): Promise<DashboardStats> => {
    return request<DashboardStats>('/dashboard/stats');
  },

  list: (params: {
    type?: string;
    verdict?: string;
    q?: string;
    from?: string;
    to?: string;
    page?: number;
    page_size?: number;
    sort?: string;
  } = {}): Promise<HistoryResponse> => {
    const query = new URLSearchParams();
    if (params.type) query.append('type', params.type);
    if (params.verdict) query.append('verdict', params.verdict);
    if (params.q) query.append('q', params.q);
    if (params.from) query.append('from', params.from);
    if (params.to) query.append('to', params.to);
    if (params.page) query.append('page', params.page.toString());
    if (params.page_size) query.append('page_size', params.page_size.toString());
    if (params.sort) query.append('sort', params.sort);

    return request<HistoryResponse>(`/history?${query.toString()}`);
  },

  getById: (id: string): Promise<InvestigationDetail> => {
    return request<InvestigationDetail>(`/history/${id}`);
  },

  delete: (id: string): Promise<{ success: boolean; message: string }> => {
    return request<{ success: boolean; message: string }>(`/history/${id}`, {
      method: 'DELETE',
    });
  },

  exportPdf: async (id: string): Promise<void> => {
    const blob = await request<Blob>(`/history/${id}/export.pdf`);
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `phishshield_${id.slice(0, 8)}.pdf`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    window.URL.revokeObjectURL(url);
  },
};

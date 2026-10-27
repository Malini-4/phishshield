import { request } from './apiClient';
import { AnalysisResult } from '../types';

export const smsService = {
  analyze: (message: string, sender?: string): Promise<AnalysisResult> => {
    return request<AnalysisResult>('/sms/analyze', {
      method: 'POST',
      body: JSON.stringify({ message, sender: sender || undefined }),
    });
  },
};

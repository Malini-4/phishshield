import { request } from './apiClient';
import { AnalysisResult } from '../types';

export const apkService = {
  analyze: (file: File): Promise<AnalysisResult> => {
    const formData = new FormData();
    formData.append('file', file);
    return request<AnalysisResult>('/apk/analyze', {
      method: 'POST',
      body: formData,
    });
  },
};

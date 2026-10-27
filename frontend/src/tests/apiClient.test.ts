import { describe, it, expect } from 'vitest';
import { ApiError } from '../services/apiClient';

describe('ApiError class', () => {
  it('creates error with message, code, and status', () => {
    const err = new ApiError('Test error message', 'INVALID_INPUT', 422);
    expect(err.message).toBe('Test error message');
    expect(err.code).toBe('INVALID_INPUT');
    expect(err.status).toBe(422);
    expect(err.name).toBe('ApiError');
  });

  it('uses default code and status if omitted', () => {
    const err = new ApiError('Default error');
    expect(err.code).toBe('UNKNOWN_ERROR');
    expect(err.status).toBe(500);
  });
});

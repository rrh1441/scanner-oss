/**
 * HTTP Client
 *
 * Unified HTTP client with retry logic, timeout handling, and rate limiting.
 * Provides both axios-style and simple interfaces.
 */

import { createModuleLogger } from '../core/logger.js';

const log = createModuleLogger('httpClient');

export interface HttpRequestConfig {
  url: string;
  method?: 'GET' | 'POST' | 'PUT' | 'DELETE' | 'PATCH' | 'HEAD' | 'OPTIONS';
  headers?: Record<string, string>;
  data?: unknown;
  body?: unknown;  // Alias for data
  params?: Record<string, string>;
  timeout?: number;
  responseType?: 'json' | 'text' | 'arraybuffer';
  maxRedirects?: number;
  validateStatus?: (status: number) => boolean;
  // Compatibility options (accepted but may be no-ops in fetch implementation)
  maxContentLength?: number;
  maxBodyBytes?: number;
  httpsAgent?: unknown;
  totalTimeoutMs?: number;
  connectTimeoutMs?: number;
  firstByteTimeoutMs?: number;
  idleSocketTimeoutMs?: number;
  forceIPv4?: boolean;
  // Tracing metadata (passed through but not used by fetch)
  scanId?: string;
}

// Alias for backward compatibility with axios-style code
export type AxiosRequestConfig = HttpRequestConfig;

export interface HttpResponse<T = unknown> {
  data: T;
  status: number;
  statusText: string;
  headers: Record<string, string>;
  // Alias for compatibility
  body?: T;
  // Request info for redirect tracking
  request?: {
    res?: {
      responseUrl?: string;
    };
  };
}

const DEFAULT_TIMEOUT = 30000;
const DEFAULT_USER_AGENT = 'Mozilla/5.0 (compatible; SecurityScanner/1.0)';

/**
 * Build URL with query parameters
 */
function buildUrl(url: string, params?: Record<string, string>): string {
  if (!params || Object.keys(params).length === 0) return url;
  const urlObj = new URL(url);
  for (const [key, value] of Object.entries(params)) {
    urlObj.searchParams.append(key, value);
  }
  return urlObj.toString();
}

/**
 * Parse response headers
 */
function parseHeaders(headers: Headers): Record<string, string> {
  const result: Record<string, string> = {};
  headers.forEach((value, key) => {
    result[key.toLowerCase()] = value;
  });
  return result;
}

/**
 * Core request function
 */
async function request<T = unknown>(config: HttpRequestConfig): Promise<HttpResponse<T>> {
  const {
    url,
    method = 'GET',
    headers = {},
    data,
    params,
    timeout = DEFAULT_TIMEOUT,
    responseType = 'json',
    validateStatus = (status) => status >= 200 && status < 300,
  } = config;

  const finalUrl = buildUrl(url, params);
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), timeout);

  const requestHeaders: Record<string, string> = {
    'User-Agent': DEFAULT_USER_AGENT,
    ...headers,
  };

  if (data && !requestHeaders['Content-Type']) {
    requestHeaders['Content-Type'] = 'application/json';
  }

  try {
    const response = await fetch(finalUrl, {
      method,
      headers: requestHeaders,
      body: data ? JSON.stringify(data) : undefined,
      signal: controller.signal,
      redirect: 'follow',
    });

    clearTimeout(timeoutId);

    let responseData: T;
    if (responseType === 'text') {
      responseData = await response.text() as T;
    } else if (responseType === 'arraybuffer') {
      responseData = await response.arrayBuffer() as T;
    } else {
      const text = await response.text();
      try {
        responseData = text ? JSON.parse(text) : null;
      } catch {
        responseData = text as T;
      }
    }

    const result: HttpResponse<T> = {
      data: responseData,
      status: response.status,
      statusText: response.statusText,
      headers: parseHeaders(response.headers),
      body: responseData, // Alias for compatibility
    };

    if (!validateStatus(response.status)) {
      const error = new Error(`Request failed with status ${response.status}`) as Error & { response: HttpResponse<T> };
      error.response = result;
      throw error;
    }

    return result;
  } catch (error) {
    clearTimeout(timeoutId);
    if ((error as Error).name === 'AbortError') {
      throw new Error(`Request timeout after ${timeout}ms: ${url}`);
    }
    throw error;
  }
}

/**
 * HTTP Client with axios-like interface
 */
export const httpClient = {
  async request<T = unknown>(config: HttpRequestConfig): Promise<HttpResponse<T>> {
    return request<T>(config);
  },

  async get<T = unknown>(url: string, config?: Partial<HttpRequestConfig>): Promise<HttpResponse<T>> {
    return request<T>({ ...config, url, method: 'GET' });
  },

  async post<T = unknown>(url: string, data?: unknown, config?: Partial<HttpRequestConfig>): Promise<HttpResponse<T>> {
    return request<T>({ ...config, url, method: 'POST', data });
  },

  async put<T = unknown>(url: string, data?: unknown, config?: Partial<HttpRequestConfig>): Promise<HttpResponse<T>> {
    return request<T>({ ...config, url, method: 'PUT', data });
  },

  async delete<T = unknown>(url: string, config?: Partial<HttpRequestConfig>): Promise<HttpResponse<T>> {
    return request<T>({ ...config, url, method: 'DELETE' });
  },

  async head<T = unknown>(url: string, config?: Partial<HttpRequestConfig>): Promise<HttpResponse<T>> {
    return request<T>({ ...config, url, method: 'HEAD' });
  },
};

/**
 * Simple HTTP request function
 */
export async function httpRequest(config: HttpRequestConfig): Promise<HttpResponse> {
  return request(config);
}

/**
 * Simple GET text helper
 */
export async function httpGetText(url: string, timeout = DEFAULT_TIMEOUT): Promise<string> {
  const response = await request<string>({ url, timeout, responseType: 'text' });
  return response.data;
}

/**
 * Simple GET JSON helper
 */
export async function httpGetJson<T = unknown>(url: string, timeout = DEFAULT_TIMEOUT): Promise<T> {
  const response = await request<T>({ url, timeout, responseType: 'json' });
  return response.data;
}

export default httpClient;

import pino, { Logger } from 'pino';

// Determine environment
const isDev = process.env.NODE_ENV !== 'production';

// Configure pino transport
const transport = isDev
  ? {
      target: 'pino-pretty',
      options: {
        colorize: true,
        translateTime: 'HH:MM:ss.l',
        ignore: 'pid,hostname',
        singleLine: false,
      },
    }
  : undefined;

// Create base logger
export const logger = pino({
  level: process.env.LOG_LEVEL?.toLowerCase() || 'info',
  transport,
  formatters: {
    level: (label) => ({ level: label }),
  },
  base: {
    service: 'scanner-workers',
  },
  timestamp: pino.stdTimeFunctions.isoTime,
  redact: {
    paths: ['*.password', '*.apiKey', '*.token', '*.secret', '*.credential', '*.auth'],
    censor: '[REDACTED]',
  },
});

// Logger function type that's also callable
export interface ModuleLogger {
  // Callable as log('message', ...args)
  (objOrMsg: object | string, msgOrArg?: string | unknown, ...args: unknown[]): void;
  // Method-based access
  info(objOrMsg: object | string, msgOrArg?: string | unknown, ...args: unknown[]): void;
  debug(objOrMsg: object | string, msgOrArg?: string | unknown, ...args: unknown[]): void;
  warn(objOrMsg: object | string, msgOrArg?: string | unknown, ...args: unknown[]): void;
  error(objOrMsg: object | string, msgOrArg?: string | unknown, ...args: unknown[]): void;
  fatal(objOrMsg: object | string, msgOrArg?: string | unknown, ...args: unknown[]): void;
  child(bindings: Record<string, unknown>): ModuleLogger;
}

// Child logger factory for modules - wraps pino for flexible usage
export function createModuleLogger(module: string): ModuleLogger {
  const pinoLogger = logger.child({ module });

  const wrapMethod = (method: 'info' | 'debug' | 'warn' | 'error' | 'fatal') => {
    return (objOrMsg: object | string, msgOrArg?: string | unknown, ...rest: unknown[]) => {
      // Case 1: log.info({ context }, 'message') - pino style
      if (typeof objOrMsg === 'object' && objOrMsg !== null && typeof msgOrArg === 'string') {
        pinoLogger[method](objOrMsg, msgOrArg);
      }
      // Case 2: log.info('message') - single string
      else if (typeof objOrMsg === 'string' && msgOrArg === undefined) {
        pinoLogger[method](objOrMsg);
      }
      // Case 3: log.info('message', value1, value2...) - string with extra args
      else if (typeof objOrMsg === 'string') {
        const allArgs = [msgOrArg, ...rest];
        const extra = allArgs.map(a => {
          if (a instanceof Error) return a.message;
          if (typeof a === 'object' && a !== null) return JSON.stringify(a);
          return String(a);
        }).join(' ');
        pinoLogger[method](`${objOrMsg} ${extra}`);
      }
      // Fallback
      else {
        pinoLogger[method](String(objOrMsg));
      }
    };
  };

  // Create a callable function that also has methods
  const logFn = wrapMethod('info') as ModuleLogger;
  logFn.info = wrapMethod('info');
  logFn.debug = wrapMethod('debug');
  logFn.warn = wrapMethod('warn');
  logFn.error = wrapMethod('error');
  logFn.fatal = wrapMethod('fatal');
  logFn.child = (bindings) => {
    const childPino = pinoLogger.child(bindings);
    return createModuleLogger(module);
  };

  return logFn;
}

// Re-export log level enum for backward compatibility
export enum LogLevel {
  DEBUG = 0,
  INFO = 1,
  WARN = 2,
  ERROR = 3,
}

// Structured logging interface (matches existing LogContext)
export interface LogContext {
  module?: string;
  scanId?: string;
  domain?: string;
  action?: string;
  duration?: number;
  error?: Error;
  [key: string]: unknown;
}

// Legacy support - keep old interface for gradual migration
export function logLegacy(...args: unknown[]) {
  logger.info({ legacy: true }, args.map(String).join(' '));
}

// Backward-compatible functions that match existing interface
export function log(message: string, context?: LogContext) {
  const { error: err, ...rest } = context || {};
  if (err) {
    logger.info({ err, ...rest }, message);
  } else {
    logger.info(rest, message);
  }
}

export function debug(message: string, context?: LogContext) {
  const { error: err, ...rest } = context || {};
  if (err) {
    logger.debug({ err, ...rest }, message);
  } else {
    logger.debug(rest, message);
  }
}

export function info(message: string, context?: LogContext) {
  const { error: err, ...rest } = context || {};
  if (err) {
    logger.info({ err, ...rest }, message);
  } else {
    logger.info(rest, message);
  }
}

export function warn(message: string, context?: LogContext) {
  const { error: err, ...rest } = context || {};
  if (err) {
    logger.warn({ err, ...rest }, message);
  } else {
    logger.warn(rest, message);
  }
}

export function error(message: string, context?: LogContext) {
  const { error: err, ...rest } = context || {};
  if (err) {
    logger.error({ err, ...rest }, message);
  } else {
    logger.error(rest, message);
  }
}
